from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from sqlalchemy import select

from app.config import get_settings
from app.db import Base, SessionLocal, get_engine
from app.models import Analysis, AnalysisContainer, AnalysisStatus
from app.services.analysis_service import (
    mark_analysis_completed,
    mark_analysis_failed,
    mark_analysis_started,
)
from app.services.docker_runner import DockerRunner
from app.services.upload_service import cleanup_uploaded_artifacts

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def claim_next_analysis() -> Analysis | None:
    with SessionLocal() as db:
        analysis = db.scalar(
            select(Analysis)
            .where(Analysis.status == AnalysisStatus.QUEUED)
            .order_by(Analysis.created_at.asc())
            .limit(1)
        )
        if not analysis:
            return None
        analysis.status = AnalysisStatus.RUNNING_INSTALL
        analysis.started_at = datetime.now(timezone.utc)
        db.add(analysis)
        db.commit()
        db.refresh(analysis)
        return analysis


def record_container(analysis_id: str, phase: str, container) -> None:
    with SessionLocal() as db:
        row = AnalysisContainer(
            analysis_id=analysis_id,
            phase=phase,
            container_id=container.id,
            container_name=container.name,
            image=container.image.tags[0] if container.image.tags else container.image.short_id,
        )
        db.add(row)
        db.commit()


def run_worker_loop() -> None:
    Base.metadata.create_all(bind=get_engine())
    settings = get_settings()
    runner = DockerRunner()
    while True:
        analysis = claim_next_analysis()
        if not analysis:
            time.sleep(settings.worker_poll_interval_seconds)
            continue
        logger.info("picked analysis %s", analysis.id)
        try:
            _run_analysis(analysis, runner)
        except Exception as error:
            logger.exception("analysis %s failed", analysis.id)
            with SessionLocal() as db:
                fresh = db.get(Analysis, analysis.id)
                if fresh:
                    mark_analysis_failed(db, fresh, str(error))


def _run_analysis(analysis: Analysis, runner: DockerRunner) -> None:
    install_container = None
    runtime_container = None
    with SessionLocal() as db:
        fresh = db.get(Analysis, analysis.id)
        if not fresh:
            return
        mark_analysis_started(db, fresh, AnalysisStatus.RUNNING_INSTALL)

    try:
        install_container, install_result, install_logs = runner.run_phase(analysis, "install")
        record_container(analysis.id, "install", install_container)
        if install_result["StatusCode"] != 0:
            raise RuntimeError(f"install phase failed: {install_logs}")

        with SessionLocal() as db:
            fresh = db.get(Analysis, analysis.id)
            if not fresh:
                return
            mark_analysis_started(db, fresh, AnalysisStatus.RUNNING_RUNTIME)

        runtime_container, runtime_result, runtime_logs = runner.run_phase(analysis, "runtime")
        record_container(analysis.id, "runtime", runtime_container)
        if runtime_result["StatusCode"] != 0:
            raise RuntimeError(f"runtime phase failed: {runtime_logs}")

        with SessionLocal() as db:
            fresh = db.get(Analysis, analysis.id)
            if not fresh:
                return
            mark_analysis_completed(db, fresh)
    finally:
        if install_container is not None:
            runner.cleanup_container(install_container.id)
        if runtime_container is not None:
            runner.cleanup_container(runtime_container.id)
        if analysis.source_type == "upload":
            cleanup_uploaded_artifacts(analysis.upload_path)


if __name__ == "__main__":
    run_worker_loop()
