"""Alert schema. See spec §7.2."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .event import Severity
from .versions import ALERT_SCHEMA_VERSION


class AlertStatus(StrEnum):
    new = "new"
    acknowledged = "acknowledged"
    resolved = "resolved"
    suppressed = "suppressed"


class RuleRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    ruleset: str
    version: str
    severity: Severity
    why: str
    false_positives: list[str] = Field(default_factory=list)


class EntityRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    key: str


class RenderedAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    short: str
    detail: str


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=ALERT_SCHEMA_VERSION)
    alert_id: str
    rule: RuleRef
    ts: datetime
    severity: Severity
    status: AlertStatus = AlertStatus.new
    category: str
    event_ids: list[str]
    entities: list[EntityRef]
    incident_id: str | None = None
    dedup_key: str
    dedup_count: int = Field(ge=1, default=1)
    first_seen_at: datetime
    last_seen_at: datetime
    evidence_case_id: str | None = None
    notes: list[dict[str, Any]] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    rendered: RenderedAlert
