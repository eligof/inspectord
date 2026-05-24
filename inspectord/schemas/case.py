"""Case schema. See spec §7.5."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from .alert import EntityRef
from .versions import CASE_SCHEMA_VERSION


class CaseStatus(StrEnum):
    open = "open"
    closed = "closed"


class CaseEvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    sha256: str | None = None
    captured_at: datetime | None = None
    original_path: str | None = None
    ref: str | None = None


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=CASE_SCHEMA_VERSION)
    case_id: str
    opened_at: datetime
    title: str
    alert_ids: list[str] = Field(default_factory=list)
    incident_ids: list[str] = Field(default_factory=list)
    entities: list[EntityRef] = Field(default_factory=list)
    evidence: list[CaseEvidenceItem] = Field(default_factory=list)
    notes: str = ""
    status: CaseStatus = CaseStatus.open
    exported_at: datetime | None = None
    _extra: dict[str, Any] = PrivateAttr(default_factory=dict)
