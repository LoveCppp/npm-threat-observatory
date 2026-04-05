from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.models import Analysis, AnalysisContainer, AnalysisStatus
from app.schemas import FalcoSidekickEvent
from app.services.event_service import ingest_falco_event


def setup_db() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    analysis = Analysis(
        id="analysis-1",
        package_name="left-pad",
        version="1.3.0",
        registry_url="https://registry.npmjs.org",
        runtime_mode="require",
        status=AnalysisStatus.QUEUED,
    )
    container = AnalysisContainer(
        analysis_id="analysis-1",
        phase="install",
        container_id="abc123def456",
        container_name="analysis-install",
        image="npm-security-check/analyzer:latest",
    )
    session.add(analysis)
    session.add(container)
    session.commit()
    return session


def test_ingest_falco_event_associates_container_to_analysis():
    db = setup_db()
    payload = FalcoSidekickEvent(
        output="npm suspicious network activity",
        priority="warning",
        rule="npm suspicious network activity",
        time=datetime.now(timezone.utc),
        output_fields={"container.id": "abc123def456"},
    )

    event = ingest_falco_event(db, payload)

    assert event is not None
    assert event.analysis_id == "analysis-1"
    assert event.phase == "install"


def test_ingest_falco_event_ignores_unknown_container():
    db = setup_db()
    payload = FalcoSidekickEvent(
        output="npm suspicious network activity",
        priority="warning",
        rule="npm suspicious network activity",
        time=datetime.now(timezone.utc),
        output_fields={"container.id": "missing"},
    )

    assert ingest_falco_event(db, payload) is None
