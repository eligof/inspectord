"""Pydantic schemas for the dependency_manager subsystem (spec §30)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

DEPS_MANIFEST_VERSION = "1.0.0"
DEPS_PLAN_SCHEMA_VERSION = "1.0.0"
DEPS_HELPER_PROTOCOL_VERSION = "1.0.0"


class ConfigStrategy(StrEnum):
    sidecar = "sidecar"
    edit_with_backup = "edit-with-backup"


class ProbeKind(StrEnum):
    binary_exists_and_runs = "binary_exists_and_runs"
    service_active = "service_active"
    file_exists = "file_exists"
    file_exists_and_growing = "file_exists_and_growing"
    command_exit_zero = "command_exit_zero"
    journal_pattern_recent = "journal_pattern_recent"


class WhenCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profiles: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)


class ServiceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    systemd_unit: str
    enable: bool = True
    start: bool = True


class DropinSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str
    template: str
    owner: str = "root"
    mode: str = "0644"


class ConfigSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    strategy: ConfigStrategy
    include_dir: str | None = None
    target_path: str | None = None
    dropin: DropinSpec | None = None
    validate_cmd: list[str] | None = None
    edit_marker_begin: str | None = None
    edit_marker_end: str | None = None


class GroupMembership(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user: str
    group: str


class EnsureReadable(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    who: str


class PermissionsSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    add_group_membership: list[GroupMembership] = Field(default_factory=list)
    ensure_readable: list[EnsureReadable] = Field(default_factory=list)


class HealthProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: ProbeKind
    path: str | None = None
    grow_window_s: int = 60
    command: list[str] | None = None
    pattern: str | None = None
    window_s: int = 60
    unit: str | None = None


class VerifySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    binary_paths: list[str] = Field(default_factory=list)
    version_cmd: list[str] | None = None
    version_regex: str | None = None
    health_probe: HealthProbe


class PostInstallHook(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: list[str]
    optional: bool = False


class RollbackSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    remove_dropin: bool = False
    reload_service: bool = False
    remove_group_membership: bool = False


class DependencyManifest(BaseModel):
    """One YAML manifest under inspectord/dependencies/manifest_files/."""

    model_config = ConfigDict(extra="forbid")
    version: str = DEPS_MANIFEST_VERSION
    name: str
    description: str
    required_when: WhenCondition = Field(default_factory=WhenCondition)
    optional_when: WhenCondition = Field(default_factory=WhenCondition)
    distro_packages: dict[str, list[str]] = Field(default_factory=dict)
    minimum_version: str | None = None
    service: ServiceSpec | None = None
    config: ConfigSpec | None = None
    permissions: PermissionsSpec | None = None
    verify: VerifySpec
    post_install_hooks: list[PostInstallHook] = Field(default_factory=list)
    rollback: RollbackSpec = Field(default_factory=RollbackSpec)


class DependencyPlanItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    action: str  # "install" | "configure" | "verify"
    packages: list[str] = Field(default_factory=list)
    expected_command: str | None = None
    config_dropin: str | None = None
    service_actions: list[str] = Field(default_factory=list)
    permission_actions: list[str] = Field(default_factory=list)
    post_install_hooks: list[str] = Field(default_factory=list)


class DependencyPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = DEPS_PLAN_SCHEMA_VERSION
    plan_id: str
    created_at: datetime
    created_by: str
    distro: str
    package_manager: str
    items: list[DependencyPlanItem]
    estimated_disk_mb: int = 0
    expires_at: datetime


class DependencyState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    installed: bool = False
    installed_version: str | None = None
    dropin_present: bool = False
    dropin_sha256: str | None = None
    last_verify_ts: datetime | None = None
    last_verify_pass: bool | None = None
    last_verify_detail: str | None = None


class DepAuditEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ts: datetime
    actor: str
    action: str
    target: str | None = None
    plan_id: str | None = None
    before_sha256: str | None = None
    after_sha256: str | None = None
    command: str | None = None
    exit_code: int | None = None
    stderr_tail: str | None = None
