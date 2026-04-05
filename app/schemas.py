from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models import AnalysisStatus, Verdict


class AnalysisCreate(BaseModel):
    package_name: str = Field(default="", max_length=255)
    version: str = Field(default="", max_length=64)
    registry_url: Optional[str] = None
    runtime_mode: str = Field(default="require")
    sample_id: Optional[str] = None
    egress_mode: str = Field(default="")


class SampleRead(BaseModel):
    id: str
    title: str
    description: str
    runtime_mode: str
    package_name: str
    version: str


class AnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    package_name: str
    version: str
    registry_url: str
    source_type: str
    egress_mode: str
    runtime_mode: str
    status: AnalysisStatus
    verdict: Verdict
    risk_level: str
    summary: str
    error_message: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


class EventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    analysis_id: str
    container_id: Optional[str]
    phase: Optional[str]
    rule: str
    priority: str
    severity: str
    source: str
    output: str
    event_time: datetime
    details: dict


class HealthRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: str
    database: str
    falco_webhook: str
    detection_backend: str


class FalcoSidekickEvent(BaseModel):
    output: str
    priority: str
    rule: str
    time: datetime
    output_fields: dict = Field(default_factory=dict)
    source: str = "falco"


class PortableEventIn(BaseModel):
    analysis_id: str
    phase: str
    rule: str
    severity: str
    output: str
    details: dict = Field(default_factory=dict)
    event_time: Optional[datetime] = None
    source: str = "portable"
