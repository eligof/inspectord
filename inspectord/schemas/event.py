"""Normalized Event schema (ECS subset). See spec §4.2."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .versions import EVENT_SCHEMA_VERSION


class EventKind(StrEnum):
    event = "event"
    alert = "alert"
    signal = "signal"
    state = "state"
    metric = "metric"


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Outcome(StrEnum):
    success = "success"
    failure = "failure"
    unknown = "unknown"


class Event(BaseModel):
    """A normalized event flowing through the router. ECS-inspired."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    schema_version: str = Field(default=EVENT_SCHEMA_VERSION)
    ts: datetime
    event_id: str
    kind: EventKind
    category: list[str]
    type: list[str]
    action: str
    outcome: Outcome | None = None
    severity: Severity
    module: str
    first_seen: bool = False

    host: dict[str, Any] | None = None
    user: dict[str, Any] | None = None
    process: dict[str, Any] | None = None
    file: dict[str, Any] | None = None
    source: dict[str, Any] | None = None
    destination: dict[str, Any] | None = None
    network: dict[str, Any] | None = None
    service: dict[str, Any] | None = None
    package: dict[str, Any] | None = None
    device: dict[str, Any] | None = None
    rule: dict[str, Any] | None = None
    threat: dict[str, Any] | None = None
    baseline: dict[str, Any] | None = None
    evidence: dict[str, Any] | None = None
    raw: dict[str, Any] | None = None
    labels: list[str] = Field(default_factory=list)
    message: str | None = None
