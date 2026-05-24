"""Allowlist schema. See spec §7.4."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .alert import EntityRef
from .versions import ALLOWLIST_SCHEMA_VERSION


class AllowlistScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str | None = None
    entity: EntityRef | None = None
    user_id: int | None = None
    path_glob: str | None = None


class AllowlistStats(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suppressed_count: int = 0
    last_suppressed_at: datetime | None = None


class AllowlistEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=ALLOWLIST_SCHEMA_VERSION)
    id: str
    scope: AllowlistScope
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime | None = None
    auto_origin: bool = False
    stats: AllowlistStats = Field(default_factory=AllowlistStats)
