"""Incident schema. See spec §7.3."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .alert import EntityRef
from .event import Severity
from .versions import INCIDENT_SCHEMA_VERSION


class IncidentStatus(StrEnum):
    open = "open"
    closed = "closed"


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=INCIDENT_SCHEMA_VERSION)
    incident_id: str
    opened_at: datetime
    closed_at: datetime | None
    status: IncidentStatus
    primary_entity: EntityRef
    entity_set: list[EntityRef] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    severity_max: Severity
    narrative: str
    case_id: str | None
