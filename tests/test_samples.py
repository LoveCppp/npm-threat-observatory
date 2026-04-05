from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.schemas import AnalysisCreate
from app.services.analysis_service import create_analysis


def test_create_analysis_supports_sample_submission():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()

    analysis = create_analysis(
        session,
        AnalysisCreate(sample_id="malicious-runtime", runtime_mode="require"),
        "https://registry.npmjs.org",
    )

    assert analysis.package_name == "malicious-runtime"
    assert analysis.version == "local"
    assert analysis.registry_url == "sample://malicious-runtime"
    assert analysis.source_type == "sample"
    assert analysis.egress_mode == "offline"


def test_create_analysis_defaults_registry_tasks_to_registry_only():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()

    analysis = create_analysis(
        session,
        AnalysisCreate(package_name="left-pad", version="1.3.0", runtime_mode="require"),
        "https://registry.npmjs.org",
    )

    assert analysis.source_type == "registry"
    assert analysis.egress_mode == "registry_only"
