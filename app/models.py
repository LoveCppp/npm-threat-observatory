from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class AnalysisStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING_INSTALL = "running_install"
    RUNNING_RUNTIME = "running_runtime"
    COMPLETED = "completed"
    FAILED = "failed"


class Verdict(str, enum.Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    registry_url: Mapped[str] = mapped_column(String(512), nullable=False)
    source_type: Mapped[str] = mapped_column(String(16), nullable=False, default="registry")
    egress_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="offline")
    upload_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    runtime_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="require")
    status: Mapped[AnalysisStatus] = mapped_column(
        Enum(AnalysisStatus), nullable=False, default=AnalysisStatus.QUEUED
    )
    verdict: Mapped[Verdict] = mapped_column(Enum(Verdict), nullable=False, default=Verdict.CLEAN)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="none")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    containers: Mapped[List["AnalysisContainer"]] = relationship(back_populates="analysis")
    events: Mapped[List["SecurityEvent"]] = relationship(back_populates="analysis")


class AnalysisContainer(Base):
    __tablename__ = "analysis_containers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    container_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    container_name: Mapped[str] = mapped_column(String(255), nullable=False)
    image: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    analysis: Mapped[Analysis] = relationship(back_populates="containers")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    container_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    phase: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    rule: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[str] = mapped_column(String(32), nullable=False, default="notice")
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="falco")
    output: Mapped[str] = mapped_column(Text, nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    analysis: Mapped[Analysis] = relationship(back_populates="events")
