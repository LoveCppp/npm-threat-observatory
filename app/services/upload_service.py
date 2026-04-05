from __future__ import annotations

import io
import json
import os
import shutil
import tarfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.models import Analysis, AnalysisStatus


ALLOWED_UPLOAD_SUFFIXES = (".tgz", ".zip", ".tar.gz")


@dataclass
class StagedUpload:
    analysis_id: str
    package_name: str
    version: str
    upload_path: str


def create_uploaded_analysis(
    db: Session,
    upload: UploadFile,
    runtime_mode: str,
    egress_mode: str,
    settings: Settings | None = None,
) -> Analysis:
    settings = settings or get_settings()
    staged = stage_uploaded_package(upload, settings=settings)
    analysis = Analysis(
        id=staged.analysis_id,
        package_name=staged.package_name,
        version=staged.version,
        registry_url=settings.default_registry_url,
        source_type="upload",
        egress_mode=normalize_egress_mode(egress_mode, "upload"),
        upload_path=staged.upload_path,
        runtime_mode=runtime_mode,
        status=AnalysisStatus.QUEUED,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    return analysis


def stage_uploaded_package(upload: UploadFile, settings: Settings | None = None) -> StagedUpload:
    settings = settings or get_settings()
    filename = upload.filename or "package"
    suffix = _normalized_suffix(filename)
    if suffix not in ALLOWED_UPLOAD_SUFFIXES:
        raise HTTPException(status_code=400, detail="Only .tgz, .tar.gz, and .zip uploads are supported")

    analysis_id = str(uuid.uuid4())
    analysis_dir = Path(settings.work_root) / "uploads" / analysis_id
    extract_dir = analysis_dir / "extract"
    archive_path = analysis_dir / f"artifact{suffix}"
    analysis_dir.mkdir(parents=True, exist_ok=True)

    try:
        _save_upload(upload, archive_path, settings.upload_max_bytes)
        extract_dir.mkdir(parents=True, exist_ok=True)
        if suffix == ".zip":
            _extract_zip(archive_path, extract_dir, settings)
        else:
            _extract_tgz(archive_path, extract_dir, settings)
        package_dir = _find_package_dir(extract_dir)
        package_json = _load_package_json(package_dir / "package.json")
        package_name = str(package_json.get("name") or "uploaded-package")
        version = str(package_json.get("version") or "local")
        upload_path = os.path.relpath(package_dir, settings.work_root)
        return StagedUpload(
            analysis_id=analysis_id,
            package_name=package_name,
            version=version,
            upload_path=upload_path,
        )
    except Exception:
        shutil.rmtree(analysis_dir, ignore_errors=True)
        raise


def cleanup_uploaded_artifacts(upload_path: str | None, settings: Settings | None = None) -> None:
    if not upload_path:
        return
    settings = settings or get_settings()
    upload_rel = Path(upload_path)
    parts = upload_rel.parts
    if len(parts) < 2 or parts[0] != "uploads":
        return
    analysis_dir = Path(settings.work_root).joinpath(parts[0], parts[1])
    shutil.rmtree(analysis_dir, ignore_errors=True)


def normalize_egress_mode(value: str | None, source_type: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized in {"offline", "registry_only"}:
        return normalized
    if source_type == "registry":
        return "registry_only"
    return "offline"


def _save_upload(upload: UploadFile, archive_path: Path, max_bytes: int) -> None:
    bytes_written = 0
    with archive_path.open("wb") as handle:
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            bytes_written += len(chunk)
            if bytes_written > max_bytes:
                raise HTTPException(status_code=400, detail="Uploaded archive exceeds the size limit")
            handle.write(chunk)
    upload.file.seek(0)


def _extract_zip(archive_path: Path, extract_dir: Path, settings: Settings) -> None:
    total_size = 0
    file_count = 0
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            _validate_member_name(member.filename)
            if _zip_member_is_symlink(member):
                raise HTTPException(status_code=400, detail="Symbolic links are not allowed in uploaded archives")
            file_count += 1
            total_size += int(member.file_size)
            _enforce_archive_limits(file_count, total_size, settings)
            destination = extract_dir / PurePosixPath(member.filename)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, destination.open("wb") as target:
                shutil.copyfileobj(source, target)


def _extract_tgz(archive_path: Path, extract_dir: Path, settings: Settings) -> None:
    total_size = 0
    file_count = 0
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive.getmembers():
            if member.isdir():
                continue
            _validate_member_name(member.name)
            if member.issym() or member.islnk():
                raise HTTPException(status_code=400, detail="Symbolic links are not allowed in uploaded archives")
            if member.isdev():
                raise HTTPException(status_code=400, detail="Device files are not allowed in uploaded archives")
            file_count += 1
            total_size += int(member.size)
            _enforce_archive_limits(file_count, total_size, settings)
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            destination = extract_dir / PurePosixPath(member.name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with extracted, destination.open("wb") as target:
                shutil.copyfileobj(extracted, target)


def _find_package_dir(extract_dir: Path) -> Path:
    candidates = sorted(path.parent for path in extract_dir.rglob("package.json"))
    if not candidates:
        raise HTTPException(status_code=400, detail="Uploaded archive does not contain a package.json")
    if len(candidates) > 1:
        candidates = sorted(set(candidates), key=lambda item: len(item.parts))
    return candidates[0]


def _load_package_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise HTTPException(status_code=400, detail=f"Failed to read package.json: {error}") from error


def _validate_member_name(name: str) -> None:
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        raise HTTPException(status_code=400, detail="Archive contains an unsafe path")


def _enforce_archive_limits(file_count: int, total_size: int, settings: Settings) -> None:
    if file_count > settings.upload_max_files:
        raise HTTPException(status_code=400, detail="Uploaded archive contains too many files")
    if total_size > settings.upload_max_unpacked_bytes:
        raise HTTPException(status_code=400, detail="Uploaded archive expands beyond the size limit")


def _normalized_suffix(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".tar.gz"):
        return ".tar.gz"
    if lower.endswith(".tgz"):
        return ".tgz"
    if lower.endswith(".zip"):
        return ".zip"
    return Path(lower).suffix


def _zip_member_is_symlink(member: zipfile.ZipInfo) -> bool:
    mode = member.external_attr >> 16
    return (mode & 0o170000) == 0o120000
