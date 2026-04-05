from __future__ import annotations

import io
import tarfile
import zipfile

import pytest
from fastapi import HTTPException
from starlette.datastructures import UploadFile

from app.config import Settings
from app.services.upload_service import normalize_egress_mode, stage_uploaded_package


def test_stage_uploaded_package_supports_zip(tmp_path):
    archive = tmp_path / "package.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("package/package.json", '{"name":"zip-sample","version":"1.2.3"}')
        handle.writestr("package/index.js", "module.exports = () => 'ok';")

    upload = UploadFile(filename="package.zip", file=archive.open("rb"))
    staged = stage_uploaded_package(upload, settings=Settings(work_root=str(tmp_path / "work")))

    assert staged.package_name == "zip-sample"
    assert staged.version == "1.2.3"
    assert staged.upload_path.startswith("uploads/")


def test_stage_uploaded_package_supports_tgz(tmp_path):
    archive = tmp_path / "package.tgz"
    with tarfile.open(archive, "w:gz") as handle:
        package_json = b'{"name":"tgz-sample","version":"0.9.0"}'
        info = tarfile.TarInfo("package/package.json")
        info.size = len(package_json)
        handle.addfile(info, io.BytesIO(package_json))

    upload = UploadFile(filename="package.tgz", file=archive.open("rb"))
    staged = stage_uploaded_package(upload, settings=Settings(work_root=str(tmp_path / "work")))

    assert staged.package_name == "tgz-sample"
    assert staged.version == "0.9.0"


def test_stage_uploaded_package_rejects_unsafe_paths(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escape/package.json", '{"name":"evil","version":"1.0.0"}')

    upload = UploadFile(filename="evil.zip", file=archive.open("rb"))
    with pytest.raises(HTTPException):
        stage_uploaded_package(upload, settings=Settings(work_root=str(tmp_path / "work")))


def test_normalize_egress_mode_defaults_by_source():
    assert normalize_egress_mode("", "upload") == "offline"
    assert normalize_egress_mode("", "sample") == "offline"
    assert normalize_egress_mode("", "registry") == "registry_only"
