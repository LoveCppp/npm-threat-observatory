from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import Analysis, AnalysisStatus, Severity
from app.schemas import PortableEventIn
from app.services.event_service import ingest_portable_event


def test_ingest_portable_event_associates_by_analysis_id():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(
        Analysis(
            id="analysis-1",
            package_name="left-pad",
            version="1.3.0",
            registry_url="https://registry.npmjs.org",
            runtime_mode="require",
            status=AnalysisStatus.QUEUED,
        )
    )
    session.commit()

    event = ingest_portable_event(
        session,
        PortableEventIn(
            analysis_id="analysis-1",
            phase="runtime",
            rule="portable suspicious network activity",
            severity="medium",
            output="http.request observed",
            details={"hostname": "container-1"},
            event_time=datetime.now(timezone.utc),
        ),
    )

    assert event is not None
    assert event.analysis_id == "analysis-1"
    assert event.severity == Severity.MEDIUM
