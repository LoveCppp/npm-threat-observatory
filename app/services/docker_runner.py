from __future__ import annotations

import io
import tarfile
from urllib.parse import urlparse

import docker
from docker.errors import DockerException

from app.config import get_settings
from app.models import Analysis
from app.sample_catalog import sample_id_from_registry_url
from app.security import allowed_hosts_from_urls


class DockerRunner:
    def __init__(self) -> None:
        settings = get_settings()
        self.settings = settings
        self.client = docker.DockerClient(base_url=settings.docker_base_url)

    def ensure_network(self) -> None:
        try:
            self.client.networks.get(self.settings.analysis_network_name)
        except DockerException:
            self.client.networks.create(self.settings.analysis_network_name, driver="bridge")

    def run_phase(self, analysis: Analysis, phase: str):
        self.ensure_network()
        name = f"analysis-{analysis.id[:8]}-{phase}"
        labels = {
            "npm_security_check.analysis_id": analysis.id,
            "npm_security_check.phase": phase,
        }
        allowed_internal_hosts = allowed_hosts_from_urls([self.settings.callback_base_url])
        registry_host = ""
        if analysis.egress_mode == "registry_only":
            registry_host = urlparse(analysis.registry_url).hostname or ""
        env = {
            "ANALYSIS_ID": analysis.id,
            "PACKAGE_NAME": analysis.package_name,
            "PACKAGE_VERSION": analysis.version,
            "REGISTRY_URL": analysis.registry_url,
            "RUNTIME_MODE": analysis.runtime_mode,
            "PHASE": phase,
            "CALLBACK_BASE_URL": self.settings.callback_base_url,
            "PUBLIC_ONLY_EGRESS": str(self.settings.public_only_egress).lower(),
            "ALLOWED_INTERNAL_HOSTS": ",".join(sorted(allowed_internal_hosts)),
            "REGISTRY_HOST": registry_host,
            "EGRESS_MODE": analysis.egress_mode,
            "SOURCE_TYPE": analysis.source_type,
        }
        sample_id = sample_id_from_registry_url(analysis.registry_url)
        volumes = None
        if analysis.source_type == "sample" and sample_id:
            env["SAMPLE_ID"] = sample_id
            env["SAMPLE_PATH"] = f"/opt/npm-security-check/samples/{sample_id}"
            env["REGISTRY_HOST"] = ""
        elif analysis.source_type == "upload" and analysis.upload_path:
            env["LOCAL_PACKAGE_PATH"] = f"/var/lib/npm-security-check/{analysis.upload_path}"
            volumes = {
                self.settings.analysis_artifacts_volume: {
                    "bind": "/var/lib/npm-security-check",
                    "mode": "ro",
                }
            }
        command = ["/bin/bash", f"/opt/npm-security-check/scripts/{phase}.sh"]
        container = self.client.containers.run(
            self.settings.analyzer_image,
            command=command,
            detach=True,
            remove=False,
            labels=labels,
            name=name,
            environment=env,
            network=self.settings.analysis_network_name,
            user="node",
            read_only=self.settings.analyzer_read_only_rootfs,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit=self.settings.analyzer_memory_limit,
            pids_limit=self.settings.analyzer_pids_limit,
            volumes=volumes,
            tmpfs={
                "/workspace": f"rw,exec,nosuid,nodev,mode=1777,size={self.settings.analyzer_tmpfs_size}",
                "/tmp": f"rw,exec,nosuid,nodev,mode=1777,size={self.settings.analyzer_tmpfs_size}",
            },
        )
        result = container.wait(timeout=self.settings.analysis_timeout_seconds)
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        return container, result, logs

    def copy_runtime_trigger(self, container_id: str, content: str) -> None:
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as tar:
            payload = content.encode("utf-8")
            info = tarfile.TarInfo(name="runtime-trigger.js")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        data.seek(0)
        container = self.client.containers.get(container_id)
        container.put_archive("/workspace", data.read())

    def ping(self) -> bool:
        self.client.ping()
        return True

    def cleanup_container(self, container_id: str) -> None:
        try:
            self.client.containers.get(container_id).remove(force=True)
        except DockerException:
            return


def build_runtime_trigger(package_name: str) -> str:
    return (
        "const pkg = process.env.PACKAGE_NAME;\n"
        "try {\n"
        "  const mod = require(pkg);\n"
        "  if (typeof mod === 'function') mod();\n"
        "} catch (error) {\n"
        "  console.error('runtime trigger failed', error.message);\n"
        "}\n"
    ).replace("PACKAGE_NAME", package_name)
