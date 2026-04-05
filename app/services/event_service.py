from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Analysis, AnalysisContainer, SecurityEvent, Severity
from app.schemas import FalcoSidekickEvent, PortableEventIn
from app.verdicts import severity_from_rule


def ingest_falco_event(db: Session, payload: FalcoSidekickEvent) -> SecurityEvent | None:
    output_fields = payload.output_fields or {}
    container_id = _extract_container_id(output_fields)
    if not container_id:
        return None

    container = db.scalar(
        select(AnalysisContainer).where(AnalysisContainer.container_id.like(f"{container_id}%"))
    )
    if not container:
        return None

    event = SecurityEvent(
        analysis_id=container.analysis_id,
        container_id=container.container_id,
        phase=container.phase,
        rule=payload.rule,
        priority=payload.priority,
        severity=severity_from_rule(payload.rule, payload.priority),
        source=payload.source,
        output=payload.output,
        event_time=payload.time.astimezone(timezone.utc),
        details=payload.output_fields,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def ingest_portable_event(db: Session, payload: PortableEventIn) -> SecurityEvent | None:
    analysis = db.get(Analysis, payload.analysis_id)
    if not analysis:
        return None

    severity = _coerce_severity(payload.severity)
    event_time = payload.event_time.astimezone(timezone.utc) if payload.event_time else datetime.now(timezone.utc)
    event = SecurityEvent(
        analysis_id=payload.analysis_id,
        container_id=_extract_portable_container_id(payload.details),
        phase=payload.phase,
        rule=payload.rule,
        priority=severity.value,
        severity=severity,
        source=payload.source,
        output=payload.output,
        event_time=event_time,
        details=payload.details,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def _extract_container_id(output_fields: dict) -> str | None:
    for key in ("container.id", "container_id", "container.id.full"):
        value = output_fields.get(key)
        if value:
            return str(value)
    return None


def _extract_portable_container_id(details: dict) -> Optional[str]:
    value = details.get("container_id") or details.get("hostname")
    return str(value) if value else None


def _coerce_severity(value: str) -> Severity:
    normalized = (value or "").lower()
    if normalized == Severity.HIGH.value:
        return Severity.HIGH
    if normalized == Severity.MEDIUM.value:
        return Severity.MEDIUM
    return Severity.LOW
