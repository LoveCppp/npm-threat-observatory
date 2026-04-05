from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "npm-security-check"
    database_url: str = Field(
        default="postgresql+psycopg://postgres:postgres@db:5432/npm_security_check"
    )
    docker_base_url: str = Field(default="unix://var/run/docker.sock")
    worker_poll_interval_seconds: int = 3
    analysis_timeout_seconds: int = 240
    analysis_network_name: str = "analysis-net"
    analyzer_image: str = "localhost/npm-security-check/analyzer:latest"
    detection_backend: str = "portable"
    default_registry_url: str = "https://registry.npmjs.org"
    verdaccio_url: str = "http://verdaccio:4873"
    work_root: str = "/var/lib/npm-security-check"
    callback_base_url: str = "http://control-api:8000"
    public_only_egress: bool = True
    analyzer_read_only_rootfs: bool = True
    analyzer_memory_limit: str = "512m"
    analyzer_pids_limit: int = 256
    analyzer_tmpfs_size: str = "256m"
    analysis_artifacts_volume: str = "analysis-artifacts"
    upload_max_bytes: int = 8 * 1024 * 1024
    upload_max_files: int = 512
    upload_max_unpacked_bytes: int = 64 * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
