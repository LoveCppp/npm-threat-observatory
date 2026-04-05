from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import inspect
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import Base, get_engine
from app.deps import get_db
from app.models import Analysis, SecurityEvent
from app.sample_catalog import SAMPLES
from app.schemas import (
    AnalysisCreate,
    AnalysisRead,
    EventRead,
    FalcoSidekickEvent,
    HealthRead,
    PortableEventIn,
    SampleRead,
)
from app.services.analysis_service import create_analysis
from app.services.docker_runner import DockerRunner
from app.services.event_service import ingest_falco_event, ingest_portable_event
from app.services.upload_service import create_uploaded_analysis


@asynccontextmanager
async def lifespan(_: FastAPI):
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    _ensure_analysis_columns(engine)
    yield


app = FastAPI(title="npm security check", lifespan=lifespan)
settings = get_settings()
static_dir = Path(__file__).parent / "static"

app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.post("/analyses", response_model=AnalysisRead, status_code=202)
def submit_analysis(payload: AnalysisCreate, db: Session = Depends(get_db)) -> Analysis:
    registry_url = payload.registry_url or settings.default_registry_url
    analysis = create_analysis(db, payload, registry_url)
    return analysis


@app.post("/analyses/upload", response_model=AnalysisRead, status_code=202)
def submit_uploaded_analysis(
    file: UploadFile = File(...),
    runtime_mode: str = Form("require"),
    egress_mode: str = Form("offline"),
    db: Session = Depends(get_db),
) -> Analysis:
    analysis = create_uploaded_analysis(db, file, runtime_mode=runtime_mode, egress_mode=egress_mode)
    return analysis


@app.get("/samples", response_model=list[SampleRead])
def list_samples() -> list[SampleRead]:
    return [SampleRead(**sample) for sample in SAMPLES]


@app.get("/analyses", response_model=list[AnalysisRead])
def list_analyses(db: Session = Depends(get_db)) -> list[Analysis]:
    return db.scalars(select(Analysis).order_by(Analysis.created_at.desc()).limit(20)).all()


@app.get("/analyses/{analysis_id}", response_model=AnalysisRead)
def get_analysis(analysis_id: str, db: Session = Depends(get_db)) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="analysis not found")
    return analysis


@app.get("/analyses/{analysis_id}/events", response_model=list[EventRead])
def get_analysis_events(analysis_id: str, db: Session = Depends(get_db)) -> list[SecurityEvent]:
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="analysis not found")
    return sorted(analysis.events, key=lambda item: item.event_time)


@app.post("/webhooks/falco", status_code=202)
def falco_webhook(payload: FalcoSidekickEvent, db: Session = Depends(get_db)) -> Response:
    ingest_falco_event(db, payload)
    return Response(status_code=202)


@app.post("/internal/events", status_code=202)
def portable_event(payload: PortableEventIn, db: Session = Depends(get_db)) -> Response:
    ingest_portable_event(db, payload)
    return Response(status_code=202)


@app.get("/health", response_model=HealthRead)
def health(db: Session = Depends(get_db)) -> HealthRead:
    db.execute(text("SELECT 1"))
    docker_status = "ok"
    try:
        DockerRunner().ping()
    except Exception:
        docker_status = "degraded"
    falco_webhook = "not_enabled" if settings.detection_backend != "falco" else docker_status
    return HealthRead(
        status="ok",
        database="ok",
        falco_webhook=falco_webhook,
        detection_backend=settings.detection_backend,
    )


def _ensure_analysis_columns(engine) -> None:
    inspector = inspect(engine)
    existing = {column["name"] for column in inspector.get_columns("analyses")}
    statements: list[str] = []
    if "source_type" not in existing:
        statements.append("ALTER TABLE analyses ADD COLUMN source_type VARCHAR(16) DEFAULT 'registry'")
    if "egress_mode" not in existing:
        statements.append("ALTER TABLE analyses ADD COLUMN egress_mode VARCHAR(32) DEFAULT 'offline'")
    if "upload_path" not in existing:
        statements.append("ALTER TABLE analyses ADD COLUMN upload_path VARCHAR(512)")
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
        connection.execute(
            text(
                "UPDATE analyses SET source_type = COALESCE(source_type, 'registry'), "
                "egress_mode = COALESCE(egress_mode, 'offline')"
            )
        )
