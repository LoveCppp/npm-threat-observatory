from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import Analysis, AnalysisStatus
from app.services.analysis_service import mark_analysis_failed


def test_mark_analysis_failed_sets_error_summary_and_risk():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    analysis = Analysis(
        package_name="left-pad",
        version="1.3.0",
        registry_url="https://registry.npmjs.org",
        runtime_mode="require",
        status=AnalysisStatus.RUNNING_INSTALL,
    )
    session.add(analysis)
    session.commit()
    session.refresh(analysis)

    updated = mark_analysis_failed(session, analysis, "install phase failed")

    assert updated.status == AnalysisStatus.FAILED
    assert updated.risk_level == "error"
    assert updated.summary == "Analysis execution failed before a verdict was produced."
    assert updated.error_message == "install phase failed"
    assert updated.completed_at is not None
