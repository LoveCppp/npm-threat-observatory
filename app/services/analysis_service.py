from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Analysis, AnalysisStatus, SecurityEvent
from app.sample_catalog import get_sample, sample_registry_url
from app.schemas import AnalysisCreate
from app.services.upload_service import normalize_egress_mode
from app.verdicts import summarize_events


def create_analysis(db: Session, payload: AnalysisCreate, registry_url: str) -> Analysis:
    package_name = payload.package_name
    version = payload.version
    runtime_mode = payload.runtime_mode
    resolved_registry_url = registry_url
    source_type = "registry"

    if payload.sample_id:
        sample = get_sample(payload.sample_id)
        if not sample:
            raise ValueError(f"unknown sample: {payload.sample_id}")
        package_name = sample["package_name"]
        version = sample["version"]
        runtime_mode = payload.runtime_mode or sample["runtime_mode"]
        resolved_registry_url = sample_registry_url(payload.sample_id)
        source_type = "sample"

    analysis = Analysis(
        package_name=package_name,
        version=version,
        registry_url=resolved_registry_url,
        source_type=source_type,
        egress_mode=normalize_egress_mode(payload.egress_mode, source_type),
        runtime_mode=runtime_mode,
        status=AnalysisStatus.QUEUED,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    return analysis


def mark_analysis_started(db: Session, analysis: Analysis, status: AnalysisStatus) -> Analysis:
    if not analysis.started_at:
        analysis.started_at = datetime.now(timezone.utc)
    analysis.status = status
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    return analysis


def mark_analysis_failed(db: Session, analysis: Analysis, error_message: str) -> Analysis:
    analysis.status = AnalysisStatus.FAILED
    analysis.summary = "Analysis execution failed before a verdict was produced."
    analysis.risk_level = "error"
    analysis.error_message = error_message
    analysis.completed_at = datetime.now(timezone.utc)
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    return analysis


def mark_analysis_completed(db: Session, analysis: Analysis) -> Analysis:
    events = db.scalars(select(SecurityEvent).where(SecurityEvent.analysis_id == analysis.id)).all()
    verdict, risk_level, summary = summarize_events(events)

    analysis.status = AnalysisStatus.COMPLETED
    analysis.verdict = verdict
    analysis.risk_level = risk_level
    analysis.summary = summary
    analysis.completed_at = datetime.now(timezone.utc)
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    return analysis
