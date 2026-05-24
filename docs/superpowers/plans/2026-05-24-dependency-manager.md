# Dependency Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `dependency_manager` subsystem from spec §30 — the self-bootstrapping layer that detects which external tools (auditd, journald, AIDE, YARA, libudev, eBPF features) `inspectord` needs, plans an install, applies our sidecar configuration, verifies end-to-end health, and continuously re-verifies on a schedule. After this plan lands, a user on Arch/CachyOS can run `inspectorctl deps plan` and `inspectorctl deps install <name>` and end up with a working tool ready for the collectors that follow.

**Architecture:** A single `dependency_manager` worker (per the supervisor's worker contract from Phase 0) continuously verifies declared dependencies; planning and applying are triggered through IPC. The package-manager backend is abstracted behind a `PackageBackend` Protocol so distros plug in cleanly; this plan ships only `PacmanBackend` (Apt/Dnf/Zypper land in Phase 4). Privileged work (running `pacman -S ...`) goes through a separate `inspectord.pkg_helper` Python entry point invoked via `pkexec`; it accepts only an opaque plan id and pulls the actual package list from a DuckDB row, so the caller can't smuggle arbitrary packages.

**Tech Stack:** Python 3.12+ · Pydantic v2 · DuckDB · Jinja2 (sidecar config templates) · PyYAML (manifest loader) · stdlib `subprocess` (package manager + pkexec) · stdlib `re`/`time`/`pathlib` (probes) · existing supervisor + IPC + CLI from Phase 0.

**Scope discipline for this plan:** §30 only. No collectors that consume the deps (those come in subsequent plans). Manifests shipped in v1 are the **minimal-profile** set: `auditd`, `journald`, `AIDE`, `YARA`, `libudev`, plus `ebpf_features` (verify-only). `standard` profile's optional deps (Suricata, ClamAV, GeoLite2) and `rkhunter` are deferred — they arrive with the plans for the collectors that use them. The plan ships **PacmanBackend only**.

**Manual acceptance criterion** (outside the automated test suite): on a real Arch/CachyOS host, after merging this plan, the following must work end-to-end:

```bash
inspectorctl deps status                  # shows missing/installed for the 6 v1 deps
inspectorctl deps plan                    # prints a plan
inspectorctl deps install auditd          # prompts via pkexec, installs auditd, drops our sidecar, verifies
inspectorctl deps verify auditd           # green
```

The automated suite uses a fake `PackageBackend` that records calls instead of running pacman, so CI doesn't need root or a network.

---

## Repository state at the start

`/home/eli/Development/inspectord` is on `main` with Phase 0 fully merged (44 passing tests, CI green, 14 squash-merged PRs). The dev venv lives at `.venv/`. All Phase 0 components — `Supervisor`, `EventRouter`, `Journal`, `Database`, `IpcServer`, `IpcClient`, `Worker` base class, `inspectorctl` CLI — are available and tested. The existing schemas (`Event`, `Alert`, etc.) are in `inspectord/schemas/`. The single existing DuckDB migration is `inspectord/storage/migrations_data/0001_initial.sql` (schema_version, events_enriched, worker_health tables).

## File structure produced by this plan

```
inspectord/
├── dependencies/
│   ├── __init__.py
│   ├── distro.py                              # Distro detection from /etc/os-release
│   ├── schemas.py                             # Pydantic models for manifests, plans, state, audit
│   ├── manifest.py                            # YAML loader + validator
│   ├── backend.py                             # PackageBackend Protocol + InstallResult/RemoveResult dataclasses
│   ├── pacman_backend.py                      # PacmanBackend implementation
│   ├── sidecar.py                             # Sidecar config writer (Jinja2 → atomic file)
│   ├── backup.py                              # Edit-with-backup utility
│   ├── probes.py                              # 6 health-probe kinds
│   ├── planner.py                             # Build DependencyPlan from manifest set + system state
│   ├── applier.py                             # Apply DependencyPlan (orchestrator)
│   ├── audit.py                               # Audit log writer
│   ├── pkg_helper.py                          # Privileged helper — runnable as `python -m inspectord.pkg_helper`
│   ├── manifest_files/                        # Ships in wheel
│   │   ├── __init__.py
│   │   ├── auditd.yaml
│   │   ├── journald.yaml
│   │   ├── aide.yaml
│   │   ├── yara.yaml
│   │   ├── libudev.yaml
│   │   └── ebpf_features.yaml
│   └── templates/                             # Ships in wheel
│       ├── __init__.py
│       ├── auditd/
│       │   └── inspectord.rules.j2
│       └── journald/
│           └── inspectord.conf.j2
├── workers/
│   └── dependency_manager/
│       ├── __init__.py
│       └── __main__.py                        # DependencyManagerWorker (periodic verify)
└── storage/
    └── migrations_data/
        └── 0002_deps.sql                      # New DuckDB tables

inspectorctl/cli/
├── deps.py                                    # Typer subapp: status / plan / install / verify / verify-all /
│                                              #                configure / backup / restore / remove-dropin / audit
└── app.py                                     # (modified to mount the deps subapp)

inspectord/
└── __main__.py                                # (modified to expose dep_manager IPC methods)

inspectord/
└── config.py                                  # (modified to add dependency_manager to dev_config workers)

packaging/polkit/
└── org.inspectord.policy.in                   # (modified to add deps.install action)

tests/
├── test_dependencies_distro.py
├── test_dependencies_manifest.py
├── test_dependencies_pacman_backend.py
├── test_dependencies_sidecar.py
├── test_dependencies_backup.py
├── test_dependencies_probes.py
├── test_dependencies_planner.py
├── test_dependencies_applier.py
├── test_dependencies_audit.py
├── test_dependencies_pkg_helper.py
├── test_dependencies_worker.py
├── test_cli_deps.py
└── integration/
    └── test_deps_end_to_end.py                # Uses FakePackageBackend
```

Total new files: 18 source modules, 6 YAML manifests, 2 Jinja2 templates, 13 test modules, 1 SQL migration, 1 polkit XML edit, 2 small touch-ups to existing files.

## Workflow

Each task lands on its own feature branch `task-<NN>-<slug>` and goes through a GitHub PR with CI gating, the same workflow used in Phase 0. Squash-merge after CI is green. TDD throughout: failing test → confirm → implement → confirm pass → commit.

---

## Task 1: DuckDB migration 0002 — dependency tables

**Files:**
- Create: `inspectord/storage/migrations_data/0002_deps.sql`
- Create: `tests/test_dependencies_migration.py`

**Branch:** `task-01-deps-migration`

- [ ] **Step 1: Write the failing test**

Write `tests/test_dependencies_migration.py`:

```python
"""Tests for the deps migration (0002_deps.sql)."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import current_schema_version, run_migrations


def test_migration_creates_deps_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    assert current_schema_version(db) >= 2

    tables = {
        row[0]
        for row in db.query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchall()
    }
    for needed in {
        "pending_dep_plans",
        "dep_state",
        "dep_config_backups",
        "dep_audit",
    }:
        assert needed in tables, f"missing table {needed}"
    db.close()


def test_pending_dep_plans_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {
        row[0]
        for row in db.query(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'pending_dep_plans'"
        ).fetchall()
    }
    expected = {
        "plan_id",
        "created_at",
        "created_by",
        "distro",
        "package_manager",
        "items_json",
        "estimated_disk_mb",
        "expires_at",
        "status",
    }
    assert expected.issubset(cols)
    db.close()


def test_dep_audit_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {
        row[0]
        for row in db.query(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'dep_audit'"
        ).fetchall()
    }
    expected = {
        "ts",
        "actor",
        "action",
        "target",
        "plan_id",
        "before_sha256",
        "after_sha256",
        "command",
        "exit_code",
        "stderr_tail",
    }
    assert expected.issubset(cols)
    db.close()
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest tests/test_dependencies_migration.py -v
```

Expected: FAIL — `missing table pending_dep_plans` (migration not yet present).

- [ ] **Step 3: Write the migration SQL**

Write `inspectord/storage/migrations_data/0002_deps.sql`:

```sql
-- Migration 0002 — dependency manager tables (spec §30).
-- All changes are additive; never destructive.

CREATE TABLE IF NOT EXISTS pending_dep_plans (
    plan_id            VARCHAR PRIMARY KEY,
    created_at         TIMESTAMP NOT NULL,
    created_by         VARCHAR NOT NULL,
    distro             VARCHAR NOT NULL,
    package_manager    VARCHAR NOT NULL,
    items_json         VARCHAR NOT NULL,
    estimated_disk_mb  INTEGER NOT NULL DEFAULT 0,
    expires_at         TIMESTAMP NOT NULL,
    status             VARCHAR NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS pending_dep_plans_status_idx
    ON pending_dep_plans (status, expires_at);

CREATE TABLE IF NOT EXISTS dep_state (
    name               VARCHAR PRIMARY KEY,
    installed          BOOLEAN NOT NULL DEFAULT FALSE,
    installed_version  VARCHAR,
    dropin_present     BOOLEAN NOT NULL DEFAULT FALSE,
    dropin_sha256      VARCHAR,
    last_verify_ts     TIMESTAMP,
    last_verify_pass   BOOLEAN,
    last_verify_detail VARCHAR,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dep_config_backups (
    backup_id          VARCHAR PRIMARY KEY,
    dep_name           VARCHAR NOT NULL,
    original_path      VARCHAR NOT NULL,
    backup_path        VARCHAR NOT NULL,
    original_sha256    VARCHAR NOT NULL,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS dep_config_backups_name_idx
    ON dep_config_backups (dep_name, created_at);

CREATE TABLE IF NOT EXISTS dep_audit (
    ts                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor              VARCHAR NOT NULL,
    action             VARCHAR NOT NULL,
    target             VARCHAR,
    plan_id            VARCHAR,
    before_sha256      VARCHAR,
    after_sha256       VARCHAR,
    command            VARCHAR,
    exit_code          INTEGER,
    stderr_tail        VARCHAR
);

CREATE INDEX IF NOT EXISTS dep_audit_ts_idx ON dep_audit (ts);
CREATE INDEX IF NOT EXISTS dep_audit_target_idx ON dep_audit (target, ts);
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
pytest tests/test_dependencies_migration.py -v
pytest tests/ -v
```

Expected: 3 new tests pass; total goes from 44 to 47.

- [ ] **Step 5: Lint + commit**

```bash
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-01-deps-migration
git add inspectord/storage/migrations_data/0002_deps.sql tests/test_dependencies_migration.py
git commit -m "feat(storage): add migration 0002 — dependency manager tables"
git push -u origin task-01-deps-migration
gh pr create --base main --head task-01-deps-migration \
  --title "feat(storage): add migration 0002 — dependency manager tables" \
  --body $'Adds the four DuckDB tables that the dependency_manager subsystem uses (spec §30):\n\n- pending_dep_plans: typed plans created by plan_dependency_install, applied by the helper\n- dep_state: per-dependency installed/dropin/verify status\n- dep_config_backups: snapshots taken before edit-with-backup\n- dep_audit: append-only audit log for every dep_manager action'
```

Wait for CI green, then squash-merge.

---

## Task 2: Pydantic schemas — manifest, plan, state, audit

**Files:**
- Create: `inspectord/dependencies/__init__.py`
- Create: `inspectord/dependencies/schemas.py`
- Create: `tests/test_dependencies_schemas.py`

**Branch:** `task-02-deps-schemas`

- [ ] **Step 1: Create empty package init**

Write `inspectord/dependencies/__init__.py`:

```python
"""Dependency manager subsystem (spec §30)."""
```

- [ ] **Step 2: Write the failing tests**

Write `tests/test_dependencies_schemas.py`:

```python
"""Tests for the dependency_manager Pydantic schemas."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from inspectord.dependencies.schemas import (
    ConfigStrategy,
    DependencyManifest,
    DependencyPlan,
    DependencyPlanItem,
    DependencyState,
    ProbeKind,
)


def _minimal_manifest_dict() -> dict[str, object]:
    return {
        "version": "1.0.0",
        "name": "auditd",
        "description": "Linux audit daemon",
        "required_when": {"profiles": ["minimal", "standard"], "flags": []},
        "optional_when": {"profiles": [], "flags": []},
        "distro_packages": {"arch": ["audit"], "cachyos": ["audit"]},
        "minimum_version": "3.0.0",
        "service": None,
        "config": None,
        "permissions": None,
        "verify": {
            "binary_paths": ["/sbin/auditctl"],
            "version_cmd": ["auditctl", "--version"],
            "version_regex": "auditctl version (\\d+\\.\\d+\\.\\d+)",
            "health_probe": {"kind": "binary_exists_and_runs"},
        },
        "post_install_hooks": [],
        "rollback": {
            "remove_dropin": False,
            "reload_service": False,
            "remove_group_membership": False,
        },
    }


def test_manifest_minimal_validates() -> None:
    m = DependencyManifest.model_validate(_minimal_manifest_dict())
    assert m.name == "auditd"
    assert m.version == "1.0.0"


def test_manifest_unknown_strategy_rejected() -> None:
    bad = _minimal_manifest_dict()
    bad["config"] = {"strategy": "magic", "include_dir": "/etc/audit"}
    with pytest.raises(ValidationError):
        DependencyManifest.model_validate(bad)


def test_manifest_unknown_probe_kind_rejected() -> None:
    bad = _minimal_manifest_dict()
    bad["verify"]["health_probe"]["kind"] = "voodoo"
    with pytest.raises(ValidationError):
        DependencyManifest.model_validate(bad)


def test_plan_item_validates() -> None:
    item = DependencyPlanItem.model_validate({
        "name": "auditd",
        "action": "install",
        "packages": ["audit"],
        "expected_command": "pacman -S --noconfirm --needed audit",
        "config_dropin": "/etc/audit/rules.d/inspectord.rules",
        "service_actions": ["systemctl enable --now auditd.service"],
        "permission_actions": [],
        "post_install_hooks": [],
    })
    assert item.action == "install"


def test_plan_full_validates_and_expires() -> None:
    created = datetime.now(UTC)
    plan = DependencyPlan.model_validate({
        "schema_version": "1.0.0",
        "plan_id": "01900000-0000-7000-8000-000000000000",
        "created_at": created.isoformat(),
        "created_by": "eli@local",
        "distro": "arch",
        "package_manager": "pacman",
        "items": [
            {
                "name": "auditd",
                "action": "install",
                "packages": ["audit"],
                "expected_command": "pacman -S --noconfirm --needed audit",
                "config_dropin": None,
                "service_actions": [],
                "permission_actions": [],
                "post_install_hooks": [],
            }
        ],
        "estimated_disk_mb": 10,
        "expires_at": (created + timedelta(hours=1)).isoformat(),
    })
    assert plan.distro == "arch"
    assert len(plan.items) == 1


def test_dependency_state_default() -> None:
    state = DependencyState(name="auditd")
    assert state.installed is False
    assert state.dropin_present is False
    assert state.last_verify_pass is None


def test_probe_kind_enum_values() -> None:
    expected = {
        "binary_exists_and_runs",
        "service_active",
        "file_exists",
        "file_exists_and_growing",
        "command_exit_zero",
        "journal_pattern_recent",
    }
    assert {k.value for k in ProbeKind} == expected


def test_config_strategy_enum_values() -> None:
    assert {s.value for s in ConfigStrategy} == {"sidecar", "edit-with-backup"}
```

- [ ] **Step 3: Run to confirm failure**

```bash
pytest tests/test_dependencies_schemas.py -v
```

Expected: ImportError on `inspectord.dependencies.schemas`.

- [ ] **Step 4: Implement schemas**

Write `inspectord/dependencies/schemas.py`:

```python
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
```

- [ ] **Step 5: Confirm tests pass**

```bash
pytest tests/test_dependencies_schemas.py -v
pytest tests/ -v
```

Expected: 8 new tests pass; total 55.

- [ ] **Step 6: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-02-deps-schemas
git add inspectord/dependencies/__init__.py inspectord/dependencies/schemas.py tests/test_dependencies_schemas.py
git commit -m "feat(deps): add Pydantic schemas for manifest, plan, state, audit"
git push -u origin task-02-deps-schemas
gh pr create --base main --head task-02-deps-schemas \
  --title "feat(deps): Pydantic schemas for dependency_manager" \
  --body $'Adds DependencyManifest, DependencyPlan, DependencyPlanItem, DependencyState, DepAuditEntry plus supporting enums (ConfigStrategy, ProbeKind) and nested models (WhenCondition, ServiceSpec, ConfigSpec, DropinSpec, PermissionsSpec, HealthProbe, VerifySpec, PostInstallHook, RollbackSpec). All extra="forbid".'
```

Wait for CI green, squash-merge.

---

## Task 3: Manifest YAML loader

**Files:**
- Create: `inspectord/dependencies/manifest.py`
- Create: `tests/test_dependencies_manifest.py`
- Modify: `pyproject.toml` (add `PyYAML` runtime dependency)

**Branch:** `task-03-deps-manifest-loader`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_dependencies_manifest.py`:

```python
"""Tests for the manifest YAML loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.dependencies.manifest import (
    ManifestLoadError,
    load_manifest_from_path,
    load_packaged_manifests,
)


def _write_yaml(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_load_valid_manifest(tmp_path: Path) -> None:
    p = _write_yaml(tmp_path / "auditd.yaml", """
version: 1.0.0
name: auditd
description: Linux audit daemon
distro_packages:
  arch: [audit]
verify:
  binary_paths: [/sbin/auditctl]
  health_probe:
    kind: binary_exists_and_runs
""".lstrip())
    m = load_manifest_from_path(p)
    assert m.name == "auditd"
    assert m.distro_packages["arch"] == ["audit"]


def test_load_manifest_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ManifestLoadError):
        load_manifest_from_path(tmp_path / "nope.yaml")


def test_load_manifest_malformed_yaml(tmp_path: Path) -> None:
    p = _write_yaml(tmp_path / "bad.yaml", "name: : :")
    with pytest.raises(ManifestLoadError):
        load_manifest_from_path(p)


def test_load_manifest_invalid_schema(tmp_path: Path) -> None:
    p = _write_yaml(tmp_path / "bad.yaml", """
version: 1.0.0
name: x
""".lstrip())
    with pytest.raises(ManifestLoadError):
        load_manifest_from_path(p)


def test_load_packaged_manifests_returns_dict() -> None:
    # The packaged manifests are added in a later task; for now this test
    # only verifies the function exists and returns a dict (may be empty).
    result = load_packaged_manifests()
    assert isinstance(result, dict)
```

- [ ] **Step 2: Confirm failure**

```bash
pytest tests/test_dependencies_manifest.py -v
```

Expected: ImportError.

- [ ] **Step 3: Add PyYAML to pyproject and reinstall**

Open `/home/eli/Development/inspectord/pyproject.toml` and append `"PyYAML>=6.0,<7"` to the runtime `dependencies` list:

```toml
dependencies = [
    "pydantic>=2.7,<3",
    "duckdb>=1.0,<2",
    "typer>=0.12,<1",
    "rich>=13.7,<16",
    "pystray>=0.19,<1",
    "Pillow>=10.0,<13",
    "PyYAML>=6.0,<7",
]
```

Also add to dev extras:

```toml
dev = [
    "pytest>=8.0,<9",
    "pytest-asyncio>=0.23,<1",
    "ruff>=0.5,<1",
    "mypy>=1.10,<2",
    "types-Pillow>=10.0,<13",
    "types-PyYAML",
]
```

Then:

```bash
pip install -e '.[dev]'
```

- [ ] **Step 4: Implement the loader**

Write `inspectord/dependencies/manifest.py`:

```python
"""Manifest YAML loader.

Each manifest file lives under `inspectord/dependencies/manifest_files/<name>.yaml`
and is loaded via `importlib.resources`. External (test) manifests are loaded
from a path.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import ValidationError

from inspectord.dependencies.schemas import DependencyManifest


class ManifestLoadError(RuntimeError):
    """Raised when a manifest YAML is missing, malformed, or schema-invalid."""


def _load(text: str, source: str) -> DependencyManifest:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ManifestLoadError(f"{source}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestLoadError(f"{source}: top-level YAML must be a mapping")
    try:
        return DependencyManifest.model_validate(data)
    except ValidationError as exc:
        raise ManifestLoadError(f"{source}: schema validation failed:\n{exc}") from exc


def load_manifest_from_path(path: Path) -> DependencyManifest:
    """Load a manifest from a filesystem path. Used by tests."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ManifestLoadError(f"manifest not found: {path}") from exc
    return _load(text, str(path))


def load_packaged_manifests() -> dict[str, DependencyManifest]:
    """Load every YAML manifest shipped under inspectord/dependencies/manifest_files/."""
    result: dict[str, DependencyManifest] = {}
    pkg = files("inspectord.dependencies.manifest_files")
    for entry in pkg.iterdir():
        if not entry.name.endswith(".yaml"):
            continue
        text = entry.read_text(encoding="utf-8")
        m = _load(text, entry.name)
        result[m.name] = m
    return result
```

- [ ] **Step 5: Create the empty `manifest_files` package**

```bash
mkdir -p /home/eli/Development/inspectord/inspectord/dependencies/manifest_files
touch /home/eli/Development/inspectord/inspectord/dependencies/manifest_files/__init__.py
```

- [ ] **Step 6: Update pyproject.toml so manifest_files ships with the wheel**

In `/home/eli/Development/inspectord/pyproject.toml`, append to the existing `[tool.hatch.build.targets.wheel.force-include]` block:

```toml
[tool.hatch.build.targets.wheel.force-include]
"inspectord/storage/migrations_data" = "inspectord/storage/migrations_data"
"inspectord/dependencies/manifest_files" = "inspectord/dependencies/manifest_files"
"inspectord/dependencies/templates" = "inspectord/dependencies/templates"
```

Create the templates dir too:

```bash
mkdir -p /home/eli/Development/inspectord/inspectord/dependencies/templates
touch /home/eli/Development/inspectord/inspectord/dependencies/templates/__init__.py
```

Reinstall:

```bash
pip install -e '.[dev]'
```

- [ ] **Step 7: Confirm tests pass**

```bash
pytest tests/test_dependencies_manifest.py -v
pytest tests/ -v
```

Expected: 5 new tests pass; total 60.

- [ ] **Step 8: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-03-deps-manifest-loader
git add inspectord/dependencies/manifest.py \
        inspectord/dependencies/manifest_files/__init__.py \
        inspectord/dependencies/templates/__init__.py \
        tests/test_dependencies_manifest.py \
        pyproject.toml
git commit -m "feat(deps): add manifest YAML loader + PyYAML dep + wheel includes"
git push -u origin task-03-deps-manifest-loader
gh pr create --base main --head task-03-deps-manifest-loader \
  --title "feat(deps): manifest YAML loader" \
  --body $'Adds load_manifest_from_path() and load_packaged_manifests() that validate each YAML against the DependencyManifest schema. Adds PyYAML runtime dep and types-PyYAML dev dep. Force-includes manifest_files/ and templates/ in the wheel so importlib.resources can find them at runtime.'
```

Wait for CI, squash-merge.

---

## Task 4: Ship the six v1 manifest YAML files

**Files (create all six in one PR):**
- Create: `inspectord/dependencies/manifest_files/auditd.yaml`
- Create: `inspectord/dependencies/manifest_files/journald.yaml`
- Create: `inspectord/dependencies/manifest_files/aide.yaml`
- Create: `inspectord/dependencies/manifest_files/yara.yaml`
- Create: `inspectord/dependencies/manifest_files/libudev.yaml`
- Create: `inspectord/dependencies/manifest_files/ebpf_features.yaml`
- Create: `tests/test_dependencies_v1_manifests.py`

**Branch:** `task-04-deps-v1-manifests`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_dependencies_v1_manifests.py`:

```python
"""Tests that the six v1 manifests load and have expected shape."""

from __future__ import annotations

from inspectord.dependencies.manifest import load_packaged_manifests


def test_all_six_v1_manifests_load() -> None:
    manifests = load_packaged_manifests()
    expected = {"auditd", "journald", "aide", "yara", "libudev", "ebpf_features"}
    assert set(manifests) >= expected


def test_auditd_has_pacman_package() -> None:
    m = load_packaged_manifests()["auditd"]
    assert "audit" in m.distro_packages.get("arch", [])


def test_journald_uses_edit_strategy_for_persistence() -> None:
    # journald is a system service we don't install — we drop a config snippet.
    m = load_packaged_manifests()["journald"]
    assert m.config is not None
    # journald.conf.d/ is a proper drop-in dir, so this is sidecar (not edit-with-backup).
    assert m.config.strategy.value == "sidecar"


def test_libudev_has_no_install_packages() -> None:
    m = load_packaged_manifests()["libudev"]
    # libudev is always present as part of systemd; we only verify presence.
    assert m.distro_packages.get("arch", []) == []


def test_ebpf_features_is_verify_only() -> None:
    m = load_packaged_manifests()["ebpf_features"]
    assert m.distro_packages.get("arch", []) == []
    assert m.config is None  # nothing to configure; kernel feature only
```

- [ ] **Step 2: Confirm failure**

```bash
pytest tests/test_dependencies_v1_manifests.py -v
```

Expected: assertion errors (none of the manifests exist yet).

- [ ] **Step 3: Write the six manifests**

Write `inspectord/dependencies/manifest_files/auditd.yaml`:

```yaml
version: 1.0.0
name: auditd
description: Linux audit daemon. Provides syscall/file-watch events when eBPF coverage is incomplete.
required_when:
  profiles: [minimal, standard]
optional_when:
  profiles: []
distro_packages:
  arch: [audit]
  cachyos: [audit]
minimum_version: "3.0.0"
service:
  systemd_unit: auditd.service
  enable: true
  start: true
config:
  strategy: sidecar
  include_dir: /etc/audit/rules.d/
  dropin:
    filename: inspectord.rules
    template: auditd/inspectord.rules.j2
    owner: root
    mode: "0640"
  validate_cmd: ["augenrules", "--check"]
permissions: null
verify:
  binary_paths: [/sbin/auditctl, /usr/sbin/auditctl]
  version_cmd: ["auditctl", "--version"]
  version_regex: "auditctl version (\\d+\\.\\d+\\.\\d+)"
  health_probe:
    kind: service_active
    unit: auditd.service
post_install_hooks: []
rollback:
  remove_dropin: true
  reload_service: true
```

Write `inspectord/dependencies/manifest_files/journald.yaml`:

```yaml
version: 1.0.0
name: journald
description: systemd-journald — already shipped with systemd. We drop a config snippet to ensure persistent storage.
required_when:
  profiles: [minimal, standard]
distro_packages:
  arch: []
  cachyos: []
service:
  systemd_unit: systemd-journald.service
  enable: true
  start: true
config:
  strategy: sidecar
  include_dir: /etc/systemd/journald.conf.d/
  dropin:
    filename: inspectord.conf
    template: journald/inspectord.conf.j2
    owner: root
    mode: "0644"
verify:
  binary_paths: [/usr/bin/journalctl]
  version_cmd: ["journalctl", "--version"]
  version_regex: "systemd (\\d+)"
  health_probe:
    kind: service_active
    unit: systemd-journald.service
rollback:
  remove_dropin: true
  reload_service: true
```

Write `inspectord/dependencies/manifest_files/aide.yaml`:

```yaml
version: 1.0.0
name: aide
description: AIDE — file integrity database. We own its database under /var/lib/inspectord/aide/, no system config drop-in.
required_when:
  profiles: [minimal, standard]
distro_packages:
  arch: [aide]
  cachyos: [aide]
minimum_version: "0.18"
service: null
config: null
permissions: null
verify:
  binary_paths: [/usr/bin/aide]
  version_cmd: ["aide", "--version"]
  version_regex: "Aide (\\d+\\.\\d+)"
  health_probe:
    kind: binary_exists_and_runs
rollback:
  remove_dropin: false
```

Write `inspectord/dependencies/manifest_files/yara.yaml`:

```yaml
version: 1.0.0
name: yara
description: YARA — pattern matching engine. We ship rulesets under /var/lib/inspectord/yara/.
required_when:
  profiles: [minimal, standard]
distro_packages:
  arch: [yara]
  cachyos: [yara]
minimum_version: "4.0.0"
verify:
  binary_paths: [/usr/bin/yara]
  version_cmd: ["yara", "--version"]
  version_regex: "(\\d+\\.\\d+\\.\\d+)"
  health_probe:
    kind: binary_exists_and_runs
rollback:
  remove_dropin: false
```

Write `inspectord/dependencies/manifest_files/libudev.yaml`:

```yaml
version: 1.0.0
name: libudev
description: udev / libudev — part of systemd. Verify-only; no install or config.
required_when:
  profiles: [minimal, standard]
distro_packages:
  arch: []
  cachyos: []
verify:
  binary_paths: [/usr/bin/udevadm]
  version_cmd: ["udevadm", "--version"]
  version_regex: "(\\d+)"
  health_probe:
    kind: binary_exists_and_runs
rollback:
  remove_dropin: false
```

Write `inspectord/dependencies/manifest_files/ebpf_features.yaml`:

```yaml
version: 1.0.0
name: ebpf_features
description: Verify the kernel has eBPF support (CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y). Verify-only; never installs.
required_when:
  profiles: [standard]
distro_packages:
  arch: []
  cachyos: []
verify:
  binary_paths: []
  health_probe:
    kind: command_exit_zero
    command: ["bash", "-c", "test -e /sys/fs/bpf || test -d /sys/kernel/btf"]
rollback:
  remove_dropin: false
```

- [ ] **Step 4: Confirm tests pass**

```bash
pytest tests/test_dependencies_v1_manifests.py -v
pytest tests/ -v
```

Expected: 5 new tests pass; total 65.

- [ ] **Step 5: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-04-deps-v1-manifests
git add inspectord/dependencies/manifest_files/ tests/test_dependencies_v1_manifests.py
git commit -m "feat(deps): ship v1 manifests (auditd, journald, aide, yara, libudev, ebpf_features)"
git push -u origin task-04-deps-v1-manifests
gh pr create --base main --head task-04-deps-v1-manifests \
  --title "feat(deps): six v1 dependency manifests" \
  --body $'Ships the v1 manifest set for the minimal/standard profiles:\n- auditd: sidecar to /etc/audit/rules.d/inspectord.rules\n- journald: sidecar to /etc/systemd/journald.conf.d/inspectord.conf (persistent storage)\n- aide: install + verify; we own its database\n- yara: install + verify; rulesets we ship separately\n- libudev: verify-only (part of systemd)\n- ebpf_features: verify-only (kernel BPF support check)'
```

Wait for CI, squash-merge.

---

## Task 5: Distro detection

**Files:**
- Create: `inspectord/dependencies/distro.py`
- Create: `tests/test_dependencies_distro.py`

**Branch:** `task-05-deps-distro-detection`

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_distro.py`:

```python
"""Tests for distro detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.dependencies.distro import Distro, DistroDetectionError, detect_distro_from_text


def test_detect_arch() -> None:
    text = 'ID=arch\nID_LIKE=""\n'
    assert detect_distro_from_text(text) == Distro.arch


def test_detect_cachyos_maps_to_arch_family() -> None:
    text = 'ID=cachyos\nID_LIKE=arch\n'
    assert detect_distro_from_text(text) == Distro.arch


def test_detect_manjaro_maps_to_arch_family() -> None:
    text = 'ID=manjaro\nID_LIKE=arch\n'
    assert detect_distro_from_text(text) == Distro.arch


def test_detect_ubuntu_maps_to_debian_family() -> None:
    text = 'ID=ubuntu\nID_LIKE=debian\n'
    assert detect_distro_from_text(text) == Distro.debian


def test_detect_fedora() -> None:
    text = 'ID=fedora\nID_LIKE=""\n'
    assert detect_distro_from_text(text) == Distro.fedora


def test_detect_opensuse_tumbleweed() -> None:
    text = 'ID=opensuse-tumbleweed\nID_LIKE="suse opensuse"\n'
    assert detect_distro_from_text(text) == Distro.opensuse


def test_detect_unknown_raises() -> None:
    text = 'ID=alpine\nID_LIKE=""\n'
    with pytest.raises(DistroDetectionError):
        detect_distro_from_text(text)


def test_detect_missing_id_raises() -> None:
    with pytest.raises(DistroDetectionError):
        detect_distro_from_text("# empty file\n")


def test_detect_from_path_raises_on_missing(tmp_path: Path) -> None:
    from inspectord.dependencies.distro import detect_distro

    with pytest.raises(DistroDetectionError):
        detect_distro(os_release_path=tmp_path / "missing")
```

- [ ] **Step 2: Confirm failure**

```bash
pytest tests/test_dependencies_distro.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement**

Write `inspectord/dependencies/distro.py`:

```python
"""Distro detection from /etc/os-release. Spec §30.4."""

from __future__ import annotations

import shlex
from enum import StrEnum
from pathlib import Path


class Distro(StrEnum):
    arch = "arch"
    debian = "debian"
    fedora = "fedora"
    opensuse = "opensuse"


class DistroDetectionError(RuntimeError):
    pass


# Mapping from os-release ID values to our supported families.
_ID_TO_FAMILY: dict[str, Distro] = {
    "arch": Distro.arch,
    "cachyos": Distro.arch,
    "manjaro": Distro.arch,
    "endeavouros": Distro.arch,
    "garuda": Distro.arch,
    "debian": Distro.debian,
    "ubuntu": Distro.debian,
    "linuxmint": Distro.debian,
    "pop": Distro.debian,
    "fedora": Distro.fedora,
    "rhel": Distro.fedora,
    "centos": Distro.fedora,
    "rocky": Distro.fedora,
    "almalinux": Distro.fedora,
    "opensuse": Distro.opensuse,
    "opensuse-leap": Distro.opensuse,
    "opensuse-tumbleweed": Distro.opensuse,
    "sles": Distro.opensuse,
}

# Same mapping, used as fallback for ID_LIKE.
_LIKE_TO_FAMILY: dict[str, Distro] = {
    "arch": Distro.arch,
    "debian": Distro.debian,
    "ubuntu": Distro.debian,
    "fedora": Distro.fedora,
    "rhel": Distro.fedora,
    "suse": Distro.opensuse,
    "opensuse": Distro.opensuse,
}


def _parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        try:
            parsed = shlex.split(val)
        except ValueError:
            parsed = [val]
        out[key.strip()] = parsed[0] if parsed else ""
    return out


def detect_distro_from_text(text: str) -> Distro:
    fields = _parse_os_release(text)
    id_val = fields.get("ID", "").lower()
    if id_val in _ID_TO_FAMILY:
        return _ID_TO_FAMILY[id_val]
    like_val = fields.get("ID_LIKE", "")
    for tok in like_val.split():
        tok = tok.lower()
        if tok in _LIKE_TO_FAMILY:
            return _LIKE_TO_FAMILY[tok]
    if not id_val:
        raise DistroDetectionError(f"/etc/os-release has no ID field")
    raise DistroDetectionError(
        f"unknown distro: ID={id_val!r}, ID_LIKE={like_val!r} (supported families: "
        f"{', '.join(d.value for d in Distro)})"
    )


def detect_distro(os_release_path: Path = Path("/etc/os-release")) -> Distro:
    try:
        text = Path(os_release_path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise DistroDetectionError(f"{os_release_path}: not found") from exc
    return detect_distro_from_text(text)
```

- [ ] **Step 4: Confirm tests pass**

```bash
pytest tests/test_dependencies_distro.py -v
pytest tests/ -v
```

Expected: 9 new tests pass; total 74.

- [ ] **Step 5: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-05-deps-distro-detection
git add inspectord/dependencies/distro.py tests/test_dependencies_distro.py
git commit -m "feat(deps): add distro detection from /etc/os-release"
git push -u origin task-05-deps-distro-detection
gh pr create --base main --head task-05-deps-distro-detection \
  --title "feat(deps): distro detection from /etc/os-release" \
  --body $'Adds detect_distro() / detect_distro_from_text() returning one of arch / debian / fedora / opensuse. CachyOS, Manjaro, EndeavourOS map to arch. Ubuntu / Mint map to debian. Rocky / Alma map to fedora. ID is consulted first, then ID_LIKE. Unknown distros raise DistroDetectionError.'
```

Wait for CI, squash-merge.

---

## Task 6: PackageBackend Protocol + helper types

**Files:**
- Create: `inspectord/dependencies/backend.py`
- Create: `tests/test_dependencies_backend_protocol.py`

**Branch:** `task-06-deps-backend-protocol`

- [ ] **Step 1: Failing test**

Write `tests/test_dependencies_backend_protocol.py`:

```python
"""Tests for the PackageBackend Protocol and helper types."""

from __future__ import annotations

import pytest

from inspectord.dependencies.backend import (
    BackendLockedError,
    BackendNotAvailableError,
    InstallResult,
    PackageBackend,
    RemoveResult,
)


class _DummyBackend:
    schema_version = "1.0.0"
    name = "dummy"

    def is_installed(self, pkg: str) -> bool:
        return False

    def installed_version(self, pkg: str) -> str | None:
        return None

    def candidate_version(self, pkg: str) -> str | None:
        return None

    def install(self, pkgs: list[str], *, dry_run: bool = False) -> InstallResult:
        return InstallResult(installed=pkgs, command=f"dummy install {' '.join(pkgs)}", exit_code=0)

    def remove(self, pkgs: list[str], *, dry_run: bool = False) -> RemoveResult:
        return RemoveResult(removed=pkgs, command=f"dummy remove {' '.join(pkgs)}", exit_code=0)

    def is_locked(self) -> bool:
        return False

    def refresh_metadata(self) -> None:
        return None


def test_dummy_matches_protocol() -> None:
    backend: PackageBackend = _DummyBackend()
    assert backend.is_installed("foo") is False


def test_install_result_dataclass() -> None:
    r = InstallResult(installed=["foo"], command="x", exit_code=0)
    assert r.installed == ["foo"]
    assert r.failed is False


def test_install_result_failure_helper() -> None:
    r = InstallResult(installed=[], command="x", exit_code=1, stderr_tail="permission denied")
    assert r.failed is True


def test_remove_result_dataclass() -> None:
    r = RemoveResult(removed=["foo"], command="x", exit_code=0)
    assert r.removed == ["foo"]
    assert r.failed is False


def test_locked_error_is_runtime() -> None:
    with pytest.raises(RuntimeError):
        raise BackendLockedError("pacman lock at /var/lib/pacman/db.lck")


def test_not_available_error_is_runtime() -> None:
    with pytest.raises(RuntimeError):
        raise BackendNotAvailableError("pkexec missing")
```

- [ ] **Step 2: Confirm failure → implement → confirm pass**

```bash
pytest tests/test_dependencies_backend_protocol.py -v
```

Then write `inspectord/dependencies/backend.py`:

```python
"""Package-manager backend abstraction. Spec §30.4."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


class BackendError(RuntimeError):
    """Base class for backend errors."""


class BackendLockedError(BackendError):
    """The package manager DB is locked (another install in progress)."""


class BackendNotAvailableError(BackendError):
    """The backend cannot run (missing binary, missing privilege channel, etc.)."""


@dataclass
class InstallResult:
    installed: list[str]
    command: str
    exit_code: int = 0
    stdout_tail: str = ""
    stderr_tail: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.exit_code != 0


@dataclass
class RemoveResult:
    removed: list[str]
    command: str
    exit_code: int = 0
    stdout_tail: str = ""
    stderr_tail: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.exit_code != 0


@runtime_checkable
class PackageBackend(Protocol):
    schema_version: str
    name: str

    def is_installed(self, pkg: str) -> bool: ...
    def installed_version(self, pkg: str) -> str | None: ...
    def candidate_version(self, pkg: str) -> str | None: ...
    def install(self, pkgs: list[str], *, dry_run: bool = False) -> InstallResult: ...
    def remove(self, pkgs: list[str], *, dry_run: bool = False) -> RemoveResult: ...
    def is_locked(self) -> bool: ...
    def refresh_metadata(self) -> None: ...
```

Re-run pytest → 6 new tests pass; total 80.

- [ ] **Step 3: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-06-deps-backend-protocol
git add inspectord/dependencies/backend.py tests/test_dependencies_backend_protocol.py
git commit -m "feat(deps): add PackageBackend Protocol + dataclasses"
git push -u origin task-06-deps-backend-protocol
gh pr create --base main --head task-06-deps-backend-protocol \
  --title "feat(deps): PackageBackend Protocol + dataclasses" \
  --body "Adds the runtime_checkable PackageBackend Protocol + InstallResult/RemoveResult dataclasses + BackendError/BackendLockedError/BackendNotAvailableError. No implementation yet."
```

---

## Task 7: PacmanBackend non-privileged operations

**Files:**
- Create: `inspectord/dependencies/pacman_backend.py`
- Create: `tests/test_dependencies_pacman_backend.py`

**Branch:** `task-07-deps-pacman-readonly`

Implements the non-privileged half of `PacmanBackend`: `is_installed`, `installed_version`, `candidate_version`, `is_locked`, `refresh_metadata` (raises `BackendNotAvailableError` until Task 9). `install`/`remove` raise `NotImplementedError`/`BackendNotAvailableError` until Task 9.

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_pacman_backend.py`:

```python
"""Tests for PacmanBackend (non-privileged operations)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from inspectord.dependencies.backend import BackendLockedError, BackendNotAvailableError
from inspectord.dependencies.pacman_backend import PacmanBackend


class _FakeRunner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._scripts = scripts

    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        key = tuple(argv)
        self.calls.append(key)
        return self._scripts.get(
            key,
            subprocess.CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=b"unscripted"),
        )


def _ok(out: str = "", err: str = "", code: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=out.encode(), stderr=err.encode())


def test_is_installed_true() -> None:
    runner = _FakeRunner({("pacman", "-Qi", "audit"): _ok(out="Name : audit\nVersion : 3.1.5-1\n")})
    assert PacmanBackend(runner=runner).is_installed("audit") is True


def test_is_installed_false() -> None:
    runner = _FakeRunner({("pacman", "-Qi", "ghost"): _ok(code=1)})
    assert PacmanBackend(runner=runner).is_installed("ghost") is False


def test_installed_version() -> None:
    runner = _FakeRunner({("pacman", "-Qi", "audit"): _ok(out="Name : audit\nVersion : 3.1.5-1\n")})
    assert PacmanBackend(runner=runner).installed_version("audit") == "3.1.5-1"


def test_installed_version_missing_returns_none() -> None:
    runner = _FakeRunner({("pacman", "-Qi", "ghost"): _ok(code=1)})
    assert PacmanBackend(runner=runner).installed_version("ghost") is None


def test_candidate_version() -> None:
    runner = _FakeRunner({("pacman", "-Si", "audit"): _ok(out="Repository : core\nName : audit\nVersion : 3.1.5-1\n")})
    assert PacmanBackend(runner=runner).candidate_version("audit") == "3.1.5-1"


def test_candidate_version_missing_returns_none() -> None:
    runner = _FakeRunner({("pacman", "-Si", "ghost"): _ok(code=1)})
    assert PacmanBackend(runner=runner).candidate_version("ghost") is None


def test_is_locked_true(tmp_path: Path) -> None:
    lock = tmp_path / "db.lck"
    lock.write_text("")
    assert PacmanBackend(lock_path=lock).is_locked() is True


def test_is_locked_false(tmp_path: Path) -> None:
    assert PacmanBackend(lock_path=tmp_path / "absent.lck").is_locked() is False


def test_refresh_metadata_not_available() -> None:
    with pytest.raises(BackendNotAvailableError):
        PacmanBackend().refresh_metadata()


def test_install_requires_helper() -> None:
    with pytest.raises(BackendNotAvailableError):
        PacmanBackend(helper_command=None).install(["audit"])


def test_install_refuses_when_locked(tmp_path: Path) -> None:
    lock = tmp_path / "db.lck"
    lock.write_text("")
    with pytest.raises(BackendLockedError):
        PacmanBackend(lock_path=lock, helper_command=["true"]).install(["audit"])
```

- [ ] **Step 2: Implement (read-only half)**

Write `inspectord/dependencies/pacman_backend.py`:

```python
"""PacmanBackend — Arch / CachyOS package backend (spec §30.4).

This task adds non-privileged operations only. Task 9 adds the install path.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Protocol

from inspectord.dependencies.backend import (
    BackendLockedError,
    BackendNotAvailableError,
    InstallResult,
    RemoveResult,
)


class _Runner(Protocol):
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]: ...


class _DefaultRunner:
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(argv, timeout=timeout, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


_VERSION_RE = re.compile(r"^Version\s*:\s*(\S+)", re.MULTILINE)


class PacmanBackend:
    schema_version = "1.0.0"
    name = "pacman"

    def __init__(
        self,
        *,
        runner: _Runner | None = None,
        lock_path: Path = Path("/var/lib/pacman/db.lck"),
        helper_command: list[str] | None = None,
    ) -> None:
        self._runner: _Runner = runner if runner is not None else _DefaultRunner()
        self._lock_path = Path(lock_path)
        self._helper_command = list(helper_command) if helper_command else None

    def is_installed(self, pkg: str) -> bool:
        return self._runner.run(["pacman", "-Qi", pkg]).returncode == 0

    def installed_version(self, pkg: str) -> str | None:
        return self._parse_version(["pacman", "-Qi", pkg])

    def candidate_version(self, pkg: str) -> str | None:
        return self._parse_version(["pacman", "-Si", pkg])

    def _parse_version(self, argv: list[str]) -> str | None:
        result = self._runner.run(argv)
        if result.returncode != 0:
            return None
        match = _VERSION_RE.search(result.stdout.decode("utf-8", "replace"))
        return match.group(1) if match else None

    def is_locked(self) -> bool:
        return self._lock_path.exists()

    def refresh_metadata(self) -> None:
        raise BackendNotAvailableError("refresh_metadata requires root; runs via pkg-helper as part of install")

    def install(self, pkgs: list[str], *, dry_run: bool = False) -> InstallResult:
        if self.is_locked():
            raise BackendLockedError(f"pacman db is locked: {self._lock_path}")
        if self._helper_command is None:
            raise BackendNotAvailableError("install path not configured (pkg-helper command unset)")
        raise NotImplementedError("install() implementation is added in Task 9")

    def remove(self, pkgs: list[str], *, dry_run: bool = False) -> RemoveResult:
        if self.is_locked():
            raise BackendLockedError(f"pacman db is locked: {self._lock_path}")
        raise BackendNotAvailableError("remove not supported in Phase 1")
```

Confirm tests pass; total goes to 91.

- [ ] **Step 3: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-07-deps-pacman-readonly
git add inspectord/dependencies/pacman_backend.py tests/test_dependencies_pacman_backend.py
git commit -m "feat(deps): PacmanBackend non-privileged operations"
git push -u origin task-07-deps-pacman-readonly
gh pr create --base main --head task-07-deps-pacman-readonly \
  --title "feat(deps): PacmanBackend read-only operations" \
  --body "Implements is_installed / installed_version / candidate_version / is_locked / refresh_metadata. install/remove are stubbed and refuse until Task 9 wires the pkg-helper."
```

---

## Task 8: pkg-helper privileged module

**Files:**
- Create: `inspectord/dependencies/pkg_helper.py`
- Create: `tests/test_dependencies_pkg_helper.py`

**Branch:** `task-08-deps-pkg-helper`

The pkg-helper is the only entry point that actually invokes `pacman` with root. Runnable as `python -m inspectord.dependencies.pkg_helper --plan-id <uuid> --db <path>`. In production it runs under `pkexec`; tests drive it directly with a fake runner and a temp DB.

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_pkg_helper.py`:

```python
"""Tests for the privileged pkg-helper module."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from inspectord.dependencies.pkg_helper import HelperResult, PkgHelperError, run_helper
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


class _FakeRunner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._scripts = scripts

    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        key = tuple(argv)
        self.calls.append(key)
        return self._scripts.get(
            key, subprocess.CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=b"unscripted")
        )


def _ok(code: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=b"", stderr=b"")


_AUDIT_PLAN = "01910000-0000-7000-8000-000000000001"
_AUDIT_ITEMS = [{
    "name": "auditd",
    "action": "install",
    "packages": ["audit"],
    "expected_command": "pacman -S --noconfirm --needed audit",
    "config_dropin": None,
    "service_actions": [],
    "permission_actions": [],
    "post_install_hooks": [],
}]


def _insert_plan(db: Database, *, plan_id: str, items: list[dict[str, object]],
                 expires_in_hours: int = 1, distro: str = "arch", pm: str = "pacman",
                 status: str = "pending") -> None:
    created = datetime.now(UTC)
    expires = created + timedelta(hours=expires_in_hours)
    db.execute(
        "INSERT INTO pending_dep_plans (plan_id, created_at, created_by, distro, "
        "package_manager, items_json, estimated_disk_mb, expires_at, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [plan_id, created, "eli@local", distro, pm, json.dumps(items), 0, expires, status],
    )


def test_helper_refuses_unknown_plan(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    runner = _FakeRunner({})
    with pytest.raises(PkgHelperError):
        run_helper(plan_id="00000000-0000-0000-0000-000000000000", db_path=db_path, runner=runner)


def test_helper_refuses_expired_plan(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=_AUDIT_ITEMS, expires_in_hours=-1)
    with pytest.raises(PkgHelperError):
        run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=_FakeRunner({}))


def test_helper_refuses_wrong_distro_under_pacman(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=_AUDIT_ITEMS, distro="debian")
    with pytest.raises(PkgHelperError):
        run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=_FakeRunner({}))


def test_helper_refuses_package_not_in_manifest(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    bad = [{**_AUDIT_ITEMS[0], "name": "evil", "packages": ["malware"]}]
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=bad)
    with pytest.raises(PkgHelperError):
        run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=_FakeRunner({}))


def test_helper_invokes_pacman_for_valid_plan(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=_AUDIT_ITEMS)
    runner = _FakeRunner({
        ("pacman", "-Sy"): _ok(),
        ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(),
    })
    result = run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=runner)
    assert isinstance(result, HelperResult)
    assert result.exit_code == 0
    assert ("pacman", "-S", "--noconfirm", "--needed", "audit") in runner.calls


def test_helper_marks_plan_applied(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=_AUDIT_ITEMS)
    runner = _FakeRunner({
        ("pacman", "-Sy"): _ok(),
        ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(),
    })
    run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=runner)
    with Database(db_path) as db:
        row = db.query("SELECT status FROM pending_dep_plans WHERE plan_id = ?", [_AUDIT_PLAN]).fetchall()[0][0]
    assert row == "applied"


def test_helper_records_audit_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        _insert_plan(db, plan_id=_AUDIT_PLAN, items=_AUDIT_ITEMS)
    runner = _FakeRunner({
        ("pacman", "-Sy"): _ok(),
        ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(),
    })
    run_helper(plan_id=_AUDIT_PLAN, db_path=db_path, runner=runner)
    with Database(db_path) as db:
        actions = {r[0] for r in db.query(
            "SELECT action FROM dep_audit WHERE plan_id = ?", [_AUDIT_PLAN]
        ).fetchall()}
    assert "plan_applied" in actions
    assert "install" in actions
```

- [ ] **Step 2: Implement**

Write `inspectord/dependencies/pkg_helper.py`:

```python
"""Privileged package-manager helper. Spec §30.12.

Runnable as `python -m inspectord.dependencies.pkg_helper --plan-id <uuid> --db <path>`.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.schemas import DEPS_HELPER_PROTOCOL_VERSION, DependencyPlanItem
from inspectord.storage.db import Database


class PkgHelperError(RuntimeError):
    pass


@dataclass
class HelperResult:
    plan_id: str
    exit_code: int
    stdout: str
    stderr: str


class _Runner(Protocol):
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]: ...


class _DefaultRunner:
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(argv, timeout=timeout, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _load_plan(db: Database, plan_id: str) -> tuple[str, str, list[DependencyPlanItem]]:
    rows = db.query(
        "SELECT distro, package_manager, items_json, expires_at, status "
        "FROM pending_dep_plans WHERE plan_id = ?",
        [plan_id],
    ).fetchall()
    if not rows:
        raise PkgHelperError(f"plan not found: {plan_id}")
    distro, pm, items_json, expires_at, status = rows[0]
    if status != "pending":
        raise PkgHelperError(f"plan status is {status!r}, expected 'pending'")
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at < datetime.now(UTC):
        raise PkgHelperError(f"plan {plan_id} expired at {expires_at.isoformat()}")
    items = [DependencyPlanItem.model_validate(i) for i in json.loads(items_json)]
    return distro, pm, items


def _validate_against_manifest(items: list[DependencyPlanItem]) -> None:
    manifests = load_packaged_manifests()
    for item in items:
        if item.name not in manifests:
            raise PkgHelperError(f"plan references unknown dep {item.name!r}; not in static manifest")
        allowed = set(manifests[item.name].distro_packages.get("arch", []))
        allowed |= set(manifests[item.name].distro_packages.get("cachyos", []))
        for pkg in item.packages:
            if pkg not in allowed:
                raise PkgHelperError(
                    f"package {pkg!r} for dep {item.name!r} is not in the static manifest"
                )


def _audit(db: Database, *, action: str, plan_id: str, target: str | None,
           command: str | None, exit_code: int | None, stderr_tail: str | None) -> None:
    db.execute(
        "INSERT INTO dep_audit (ts, actor, action, target, plan_id, command, exit_code, stderr_tail) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            datetime.now(UTC), "pkg-helper", action, target, plan_id,
            command, exit_code, (stderr_tail or "")[:2000],
        ],
    )


def run_helper(*, plan_id: str, db_path: Path, runner: _Runner | None = None) -> HelperResult:
    runner = runner if runner is not None else _DefaultRunner()
    with Database(db_path) as db:
        distro, pm, items = _load_plan(db, plan_id)
        if pm != "pacman":
            raise PkgHelperError(f"helper only handles pacman, plan says {pm!r}")
        if distro != "arch":
            raise PkgHelperError(f"pacman backend requires arch family; got distro={distro!r}")
        _validate_against_manifest(items)

        refresh = runner.run(["pacman", "-Sy"])
        _audit(db, action="metadata_refresh", plan_id=plan_id, target=None,
               command="pacman -Sy", exit_code=refresh.returncode,
               stderr_tail=refresh.stderr.decode("utf-8", "replace"))
        if refresh.returncode != 0:
            return HelperResult(plan_id=plan_id, exit_code=refresh.returncode,
                                stdout=refresh.stdout.decode("utf-8", "replace"),
                                stderr=refresh.stderr.decode("utf-8", "replace"))

        last_stdout = last_stderr = ""
        for item in items:
            if item.action != "install" or not item.packages:
                continue
            argv = ["pacman", "-S", "--noconfirm", "--needed", *item.packages]
            result = runner.run(argv)
            last_stdout = result.stdout.decode("utf-8", "replace")
            last_stderr = result.stderr.decode("utf-8", "replace")
            _audit(db, action="install" if result.returncode == 0 else "install_failed",
                   plan_id=plan_id, target=item.name, command=" ".join(argv),
                   exit_code=result.returncode, stderr_tail=last_stderr)
            if result.returncode != 0:
                return HelperResult(plan_id=plan_id, exit_code=result.returncode,
                                    stdout=last_stdout, stderr=last_stderr)

        db.execute("UPDATE pending_dep_plans SET status = 'applied' WHERE plan_id = ?", [plan_id])
        _audit(db, action="plan_applied", plan_id=plan_id, target=None,
               command=None, exit_code=0, stderr_tail=None)
        return HelperResult(plan_id=plan_id, exit_code=0, stdout=last_stdout, stderr=last_stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="inspectord-pkg-helper")
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--db", default="/var/lib/inspectord/inspectord.duckdb")
    parser.add_argument("--protocol-version", default=DEPS_HELPER_PROTOCOL_VERSION)
    args = parser.parse_args(argv)
    if args.protocol_version != DEPS_HELPER_PROTOCOL_VERSION:
        print(f"pkg-helper: protocol mismatch (got {args.protocol_version}, "
              f"want {DEPS_HELPER_PROTOCOL_VERSION})", file=sys.stderr)
        return 2
    try:
        result = run_helper(plan_id=args.plan_id, db_path=Path(args.db))
    except PkgHelperError as exc:
        print(f"pkg-helper: {exc}", file=sys.stderr)
        return 3
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
```

Confirm tests pass; total 98.

- [ ] **Step 3: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-08-deps-pkg-helper
git add inspectord/dependencies/pkg_helper.py tests/test_dependencies_pkg_helper.py
git commit -m "feat(deps): add privileged pkg-helper"
git push -u origin task-08-deps-pkg-helper
gh pr create --base main --head task-08-deps-pkg-helper \
  --title "feat(deps): privileged pkg-helper" \
  --body "Runnable as python -m inspectord.dependencies.pkg_helper. Validates plan expiry/distro/pm/packages-in-manifest, runs pacman -Sy then pacman -S --noconfirm --needed for each install item, records dep_audit rows, marks plan applied."
```

---

## Task 9: PacmanBackend privileged install

**Files:**
- Modify: `inspectord/dependencies/pacman_backend.py`
- Modify: `tests/test_dependencies_pacman_backend.py`

**Branch:** `task-09-deps-pacman-install`

Replace the `install` stub with a real implementation that calls the pkg-helper. Add `plan_id` and `db_path` plumbing. Tests use the special sentinel `helper_command=["__in_process__"]` so they call `run_helper` directly with the fake runner instead of spawning a subprocess.

- [ ] **Step 1: Append tests**

Append to `tests/test_dependencies_pacman_backend.py`:

```python
import json
from datetime import UTC, datetime, timedelta

from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


_AUDIT_PLAN_PB = "01920000-0000-7000-8000-000000000002"


def _insert_audit_plan(db_path: Path) -> None:
    with Database(db_path) as db:
        run_migrations(db)
        created = datetime.now(UTC)
        items = [{
            "name": "auditd",
            "action": "install",
            "packages": ["audit"],
            "expected_command": "pacman -S --noconfirm --needed audit",
            "config_dropin": None,
            "service_actions": [],
            "permission_actions": [],
            "post_install_hooks": [],
        }]
        db.execute(
            "INSERT INTO pending_dep_plans (plan_id, created_at, created_by, distro, "
            "package_manager, items_json, estimated_disk_mb, expires_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [_AUDIT_PLAN_PB, created, "test", "arch", "pacman",
             json.dumps(items), 0, created + timedelta(hours=1), "pending"],
        )


def test_install_invokes_helper_in_process(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _insert_audit_plan(db_path)
    runner = _FakeRunner({
        ("pacman", "-Sy"): _ok(),
        ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(),
    })
    be = PacmanBackend(
        lock_path=tmp_path / "absent.lck",
        helper_command=["__in_process__"],
        db_path=db_path,
        runner=runner,
    )
    result = be.install(["audit"], plan_id=_AUDIT_PLAN_PB)
    assert result.exit_code == 0
    assert ("pacman", "-S", "--noconfirm", "--needed", "audit") in runner.calls


def test_install_without_plan_id_raises(tmp_path: Path) -> None:
    be = PacmanBackend(
        lock_path=tmp_path / "absent.lck",
        helper_command=["__in_process__"],
        db_path=tmp_path / "t.duckdb",
    )
    with pytest.raises(BackendNotAvailableError):
        be.install(["audit"])
```

- [ ] **Step 2: Replace pacman_backend.py**

Replace the file with the full implementation:

```python
"""PacmanBackend — Arch / CachyOS package backend (spec §30.4)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Protocol

from inspectord.dependencies.backend import (
    BackendLockedError,
    BackendNotAvailableError,
    InstallResult,
    RemoveResult,
)
from inspectord.dependencies.pkg_helper import PkgHelperError, run_helper


class _Runner(Protocol):
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]: ...


class _DefaultRunner:
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(argv, timeout=timeout, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


_VERSION_RE = re.compile(r"^Version\s*:\s*(\S+)", re.MULTILINE)
_IN_PROCESS = "__in_process__"


class PacmanBackend:
    schema_version = "1.0.0"
    name = "pacman"

    def __init__(
        self,
        *,
        runner: _Runner | None = None,
        lock_path: Path = Path("/var/lib/pacman/db.lck"),
        helper_command: list[str] | None = None,
        db_path: Path | None = None,
    ) -> None:
        self._runner: _Runner = runner if runner is not None else _DefaultRunner()
        self._lock_path = Path(lock_path)
        self._helper_command = list(helper_command) if helper_command else None
        self._db_path = Path(db_path) if db_path else None

    def is_installed(self, pkg: str) -> bool:
        return self._runner.run(["pacman", "-Qi", pkg]).returncode == 0

    def installed_version(self, pkg: str) -> str | None:
        return self._parse_version(["pacman", "-Qi", pkg])

    def candidate_version(self, pkg: str) -> str | None:
        return self._parse_version(["pacman", "-Si", pkg])

    def _parse_version(self, argv: list[str]) -> str | None:
        result = self._runner.run(argv)
        if result.returncode != 0:
            return None
        match = _VERSION_RE.search(result.stdout.decode("utf-8", "replace"))
        return match.group(1) if match else None

    def is_locked(self) -> bool:
        return self._lock_path.exists()

    def refresh_metadata(self) -> None:
        raise BackendNotAvailableError("refresh_metadata runs via pkg-helper as part of install")

    def install(self, pkgs: list[str], *, dry_run: bool = False, plan_id: str | None = None) -> InstallResult:
        if self.is_locked():
            raise BackendLockedError(f"pacman db is locked: {self._lock_path}")
        if self._helper_command is None:
            raise BackendNotAvailableError("install path not configured (pkg-helper command unset)")
        if plan_id is None:
            raise BackendNotAvailableError("PacmanBackend.install requires plan_id (use the applier)")
        if dry_run:
            return InstallResult(installed=pkgs, command=f"(dry-run) helper plan {plan_id}", exit_code=0)
        return self._invoke_helper(pkgs, plan_id)

    def remove(self, pkgs: list[str], *, dry_run: bool = False) -> RemoveResult:
        if self.is_locked():
            raise BackendLockedError(f"pacman db is locked: {self._lock_path}")
        raise BackendNotAvailableError("remove not supported in Phase 1")

    def _invoke_helper(self, pkgs: list[str], plan_id: str) -> InstallResult:
        assert self._helper_command is not None
        command_text = f"helper plan={plan_id} pkgs={','.join(pkgs)}"
        if self._helper_command == [_IN_PROCESS]:
            if self._db_path is None:
                raise BackendNotAvailableError("in-process helper requires db_path (test-only)")
            try:
                result = run_helper(plan_id=plan_id, db_path=self._db_path, runner=self._runner)
            except PkgHelperError as exc:
                return InstallResult(installed=[], command=command_text, exit_code=3, stderr_tail=str(exc))
            return InstallResult(
                installed=pkgs if result.exit_code == 0 else [],
                command=command_text,
                exit_code=result.exit_code,
                stdout_tail=result.stdout[-2000:],
                stderr_tail=result.stderr[-2000:],
            )
        argv = [*self._helper_command, "--plan-id", plan_id]
        completed = self._runner.run(argv)
        return InstallResult(
            installed=pkgs if completed.returncode == 0 else [],
            command=" ".join(argv),
            exit_code=completed.returncode,
            stdout_tail=completed.stdout.decode("utf-8", "replace")[-2000:],
            stderr_tail=completed.stderr.decode("utf-8", "replace")[-2000:],
        )
```

Confirm tests pass; total 100.

- [ ] **Step 3: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-09-deps-pacman-install
git add inspectord/dependencies/pacman_backend.py tests/test_dependencies_pacman_backend.py
git commit -m "feat(deps): PacmanBackend install via pkg-helper"
git push -u origin task-09-deps-pacman-install
gh pr create --base main --head task-09-deps-pacman-install \
  --title "feat(deps): PacmanBackend install via pkg-helper" \
  --body "install(pkgs, plan_id=...) calls the pkg-helper. helper_command=['__in_process__'] makes tests bypass subprocess and call run_helper directly. Without plan_id install() refuses."
```

---

## Task 10: Sidecar config writer

**Files:**
- Create: `inspectord/dependencies/sidecar.py`
- Create: `inspectord/dependencies/templates/auditd/inspectord.rules.j2`
- Create: `inspectord/dependencies/templates/journald/inspectord.conf.j2`
- Create: `tests/test_dependencies_sidecar.py`
- Modify: `pyproject.toml` (add `Jinja2`)

**Branch:** `task-10-deps-sidecar`

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_sidecar.py`:

```python
"""Tests for the sidecar config writer."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.sidecar import SidecarError, write_sidecar


def test_write_sidecar_auditd(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["auditd"]
    target_dir = tmp_path / "rules.d"
    target_dir.mkdir()
    written = write_sidecar(manifest, include_dir=target_dir, chown=False)
    assert written.name == "inspectord.rules"
    assert "execve" in written.read_text()


def test_write_sidecar_journald(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["journald"]
    target_dir = tmp_path / "journald.conf.d"
    target_dir.mkdir()
    written = write_sidecar(manifest, include_dir=target_dir, chown=False)
    assert "Storage=persistent" in written.read_text()


def test_write_sidecar_atomic_no_tmp_leftover(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["auditd"]
    target_dir = tmp_path / "rules.d"
    target_dir.mkdir()
    write_sidecar(manifest, include_dir=target_dir, chown=False)
    assert not list(target_dir.glob("*.tmp"))


def test_write_sidecar_overwrites_existing(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["auditd"]
    target_dir = tmp_path / "rules.d"
    target_dir.mkdir()
    (target_dir / "inspectord.rules").write_text("STALE")
    written = write_sidecar(manifest, include_dir=target_dir, chown=False)
    assert "STALE" not in written.read_text()


def test_write_sidecar_sets_mode(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["auditd"]
    target_dir = tmp_path / "rules.d"
    target_dir.mkdir()
    written = write_sidecar(manifest, include_dir=target_dir, chown=False)
    assert (os.stat(written).st_mode & 0o777) == 0o640


def test_write_sidecar_raises_when_no_config(tmp_path: Path) -> None:
    manifest = load_packaged_manifests()["aide"]
    with pytest.raises(SidecarError):
        write_sidecar(manifest, include_dir=tmp_path, chown=False)
```

- [ ] **Step 2: Add Jinja2 to pyproject and reinstall**

Append `"Jinja2>=3.1,<4"` to `[project.dependencies]` and reinstall: `pip install -e '.[dev]'`.

- [ ] **Step 3: Write templates**

Write `inspectord/dependencies/templates/auditd/inspectord.rules.j2`:

```
# inspectord audit rules — managed file, do not edit.
-a always,exit -F arch=b64 -S execve -F key=inspectord_execve
-a always,exit -F arch=b32 -S execve -F key=inspectord_execve
-a always,exit -F arch=b64 -S ptrace -F key=inspectord_ptrace
-a always,exit -F arch=b32 -S ptrace -F key=inspectord_ptrace
-a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F key=inspectord_module
-w /etc/passwd -p wa -k inspectord_passwd
-w /etc/shadow -p wa -k inspectord_shadow
-w /etc/sudoers -p wa -k inspectord_sudoers
-w /etc/sudoers.d -p wa -k inspectord_sudoers
```

Write `inspectord/dependencies/templates/journald/inspectord.conf.j2`:

```
# inspectord-managed snippet
[Journal]
Storage=persistent
SystemMaxUse=2G
MaxRetentionSec=30day
```

- [ ] **Step 4: Implement writer**

Write `inspectord/dependencies/sidecar.py`:

```python
"""Sidecar config writer (spec §30.6)."""

from __future__ import annotations

import os
import tempfile
from importlib.resources import as_file, files
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from inspectord.dependencies.schemas import ConfigStrategy, DependencyManifest


class SidecarError(RuntimeError):
    pass


def _render_template(template_rel_path: str, ctx: dict[str, object]) -> str:
    pkg = files("inspectord.dependencies.templates")
    with as_file(pkg) as templates_root:
        env = Environment(
            loader=FileSystemLoader(str(templates_root)),
            autoescape=select_autoescape(default=False, default_for_string=False),
            keep_trailing_newline=True,
        )
        return env.get_template(template_rel_path).render(**ctx)


def _atomic_write(target: Path, content: str, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def write_sidecar(
    manifest: DependencyManifest,
    *,
    include_dir: Path,
    chown: bool = True,
    extra_ctx: dict[str, object] | None = None,
) -> Path:
    if manifest.config is None or manifest.config.strategy is not ConfigStrategy.sidecar:
        raise SidecarError(f"{manifest.name}: no sidecar config")
    if manifest.config.dropin is None:
        raise SidecarError(f"{manifest.name}: config.dropin not set")

    ctx: dict[str, object] = {"manifest": manifest, "name": manifest.name}
    if extra_ctx:
        ctx.update(extra_ctx)
    content = _render_template(manifest.config.dropin.template, ctx)
    mode = int(manifest.config.dropin.mode, 8)
    target = Path(include_dir) / manifest.config.dropin.filename
    _atomic_write(target, content, mode)
    if chown:
        try:
            import grp
            import pwd
            uid = pwd.getpwnam(manifest.config.dropin.owner).pw_uid
            gid = grp.getgrnam(manifest.config.dropin.owner).gr_gid
            os.chown(target, uid, gid)
        except (KeyError, PermissionError):
            pass  # dev / test fallback
    return target
```

Confirm tests pass; total 106.

- [ ] **Step 5: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-10-deps-sidecar
git add inspectord/dependencies/sidecar.py inspectord/dependencies/templates/ \
        tests/test_dependencies_sidecar.py pyproject.toml
git commit -m "feat(deps): add sidecar config writer + auditd/journald templates"
git push -u origin task-10-deps-sidecar
gh pr create --base main --head task-10-deps-sidecar \
  --title "feat(deps): sidecar config writer" \
  --body "Renders Jinja2 templates from inspectord/dependencies/templates/ and writes them atomically to the manifest-declared include dir at the manifest-declared mode. Falls back gracefully when chown is unavailable (dev/test)."
```

---

## Task 11: Edit-with-backup utility

**Files:**
- Create: `inspectord/dependencies/backup.py`
- Create: `tests/test_dependencies_backup.py`

**Branch:** `task-11-deps-backup`

Implements the `edit-with-backup` config strategy from spec §30.6 for tools that don't support include dirs. Snapshots the original file to `dep_config_backups`, then applies an idempotent edit between `# >>> inspectord BEGIN` / `# <<< inspectord END` markers. None of the v1 manifests use this strategy yet, but the utility is needed by Phase 1's collectors (e.g., rsyslog has no usable include dir on some systems).

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_backup.py`:

```python
"""Tests for edit-with-backup utility."""

from __future__ import annotations

import hashlib
from pathlib import Path

from inspectord.dependencies.backup import (
    BackupRecord,
    apply_edit_with_backup,
    list_backups,
    restore_backup,
)
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_apply_inserts_markers(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    target = tmp_path / "config.conf"
    target.write_text("# original\nkey=value\n")
    rec = apply_edit_with_backup(
        db_path=db_path,
        dep_name="rsyslog",
        target_path=target,
        managed_block="# our line\n",
    )
    text = target.read_text()
    assert "# >>> inspectord BEGIN" in text
    assert "# <<< inspectord END" in text
    assert "# our line" in text
    assert isinstance(rec, BackupRecord)


def test_apply_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    target = tmp_path / "config.conf"
    target.write_text("# original\n")
    apply_edit_with_backup(
        db_path=db_path,
        dep_name="rsyslog",
        target_path=target,
        managed_block="# one\n",
    )
    first = target.read_text()
    apply_edit_with_backup(
        db_path=db_path,
        dep_name="rsyslog",
        target_path=target,
        managed_block="# two\n",
    )
    second = target.read_text()
    # Idempotent: only one BEGIN/END pair, the latest block replaces the old.
    assert second.count("# >>> inspectord BEGIN") == 1
    assert "# two" in second
    assert "# one" not in second
    assert first != second


def test_backups_recorded_in_db(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    target = tmp_path / "config.conf"
    target.write_text("# original\n")
    apply_edit_with_backup(
        db_path=db_path,
        dep_name="rsyslog",
        target_path=target,
        managed_block="# x\n",
    )
    backups = list_backups(db_path=db_path, dep_name="rsyslog")
    assert len(backups) == 1
    assert backups[0].original_path == str(target)


def test_restore_returns_to_original(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    target = tmp_path / "config.conf"
    original = "# original content\nfoo=bar\n"
    target.write_text(original)
    original_sha = hashlib.sha256(original.encode()).hexdigest()
    rec = apply_edit_with_backup(
        db_path=db_path,
        dep_name="rsyslog",
        target_path=target,
        managed_block="# x\n",
    )
    assert target.read_text() != original
    restore_backup(db_path=db_path, backup_id=rec.backup_id)
    assert target.read_text() == original
    assert hashlib.sha256(target.read_bytes()).hexdigest() == original_sha
```

- [ ] **Step 2: Implement**

Write `inspectord/dependencies/backup.py`:

```python
"""Edit-with-backup utility (spec §30.6).

Used when a tool doesn't support include directories and we must edit its
primary config. Each edit:
  1. Snapshots original to /var/lib/inspectord/dep_config_backups/<dep>/<path>.<ts>.bak
  2. Records a row in dep_config_backups.
  3. Applies a marked block; replaces an existing block idempotently.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from inspectord.ids import uuid7
from inspectord.storage.db import Database


BEGIN_MARKER = "# >>> inspectord BEGIN"
END_MARKER = "# <<< inspectord END"
_BLOCK_RE = re.compile(
    rf"{re.escape(BEGIN_MARKER)}.*?{re.escape(END_MARKER)}\n?",
    re.DOTALL,
)


@dataclass
class BackupRecord:
    backup_id: str
    dep_name: str
    original_path: str
    backup_path: str
    original_sha256: str


def _backup_root(dep_name: str) -> Path:
    return Path("/var/lib/inspectord/dep_config_backups") / dep_name


def _record_backup(
    db_path: Path,
    *,
    dep_name: str,
    target_path: Path,
    original_text: str,
    backup_root: Path | None = None,
) -> BackupRecord:
    root = backup_root if backup_root is not None else _backup_root(dep_name)
    root.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe = str(target_path).replace("/", "_").lstrip("_")
    backup_path = root / f"{safe}.{ts}.bak"
    backup_path.write_text(original_text, encoding="utf-8")
    sha = hashlib.sha256(original_text.encode("utf-8")).hexdigest()
    backup_id = str(uuid7())
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO dep_config_backups (backup_id, dep_name, original_path, "
            "backup_path, original_sha256) VALUES (?, ?, ?, ?, ?)",
            [backup_id, dep_name, str(target_path), str(backup_path), sha],
        )
    return BackupRecord(
        backup_id=backup_id,
        dep_name=dep_name,
        original_path=str(target_path),
        backup_path=str(backup_path),
        original_sha256=sha,
    )


def apply_edit_with_backup(
    *,
    db_path: Path,
    dep_name: str,
    target_path: Path,
    managed_block: str,
    backup_root: Path | None = None,
) -> BackupRecord:
    text = Path(target_path).read_text(encoding="utf-8")
    rec = _record_backup(
        db_path,
        dep_name=dep_name,
        target_path=Path(target_path),
        original_text=text,
        backup_root=backup_root,
    )
    block = f"{BEGIN_MARKER}\n{managed_block}{END_MARKER}\n"
    if _BLOCK_RE.search(text):
        new_text = _BLOCK_RE.sub(block, text)
    else:
        new_text = text + ("\n" if not text.endswith("\n") else "") + block
    Path(target_path).write_text(new_text, encoding="utf-8")
    return rec


def list_backups(*, db_path: Path, dep_name: str) -> list[BackupRecord]:
    with Database(db_path) as db:
        rows = db.query(
            "SELECT backup_id, dep_name, original_path, backup_path, original_sha256 "
            "FROM dep_config_backups WHERE dep_name = ? ORDER BY created_at DESC",
            [dep_name],
        ).fetchall()
    return [
        BackupRecord(
            backup_id=r[0],
            dep_name=r[1],
            original_path=r[2],
            backup_path=r[3],
            original_sha256=r[4],
        )
        for r in rows
    ]


def restore_backup(*, db_path: Path, backup_id: str) -> None:
    with Database(db_path) as db:
        rows = db.query(
            "SELECT original_path, backup_path FROM dep_config_backups WHERE backup_id = ?",
            [backup_id],
        ).fetchall()
    if not rows:
        raise FileNotFoundError(f"backup not found: {backup_id}")
    original_path, backup_path = rows[0]
    shutil.copy2(backup_path, original_path)
```

In the tests, override `backup_root=tmp_path/"deps_backups"/dep_name` to keep `/var/lib/...` out of tests. Update tests as needed; or modify `apply_edit_with_backup` to accept a `backup_root` kwarg that defaults to `None` (which falls back to `_backup_root(dep_name)`). The above signature already accepts it — pass it from tests:

In `tests/test_dependencies_backup.py`, replace each `apply_edit_with_backup(...)` call with the extra kwarg `backup_root=tmp_path / "deps_backups"`. Re-run the tests. Expected: 4 passed; total 110.

- [ ] **Step 3: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-11-deps-backup
git add inspectord/dependencies/backup.py tests/test_dependencies_backup.py
git commit -m "feat(deps): add edit-with-backup utility + dep_config_backups writer"
git push -u origin task-11-deps-backup
gh pr create --base main --head task-11-deps-backup \
  --title "feat(deps): edit-with-backup utility" \
  --body "Snapshots target file, records in dep_config_backups, applies an idempotent marked-block edit. Used by tools without proper include dirs; v1 manifests don't trigger this path but the utility is required by upcoming collector plans."
```

---

## Task 12: Health probes

**Files:**
- Create: `inspectord/dependencies/probes.py`
- Create: `tests/test_dependencies_probes.py`

**Branch:** `task-12-deps-probes`

Implements all six probe kinds from spec §30.7. Each probe is a pure function taking a `HealthProbe` and returning a `ProbeResult` with `ok: bool` and `detail: str`. External commands route through an injectable runner so tests don't need real services.

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_probes.py`:

```python
"""Tests for health probes."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from inspectord.dependencies.probes import ProbeResult, run_probe
from inspectord.dependencies.schemas import HealthProbe, ProbeKind


class _FakeRunner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self._scripts = scripts

    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return self._scripts.get(
            tuple(argv), subprocess.CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=b"unscripted")
        )


def _ok(code: int = 0, out: bytes = b"", err: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=out, stderr=err)


def test_binary_exists_and_runs_true(tmp_path: Path) -> None:
    bin_path = tmp_path / "auditctl"
    bin_path.write_text("")
    bin_path.chmod(0o755)
    runner = _FakeRunner({(str(bin_path), "--version"): _ok(out=b"auditctl version 3.1.5")})
    probe = HealthProbe(kind=ProbeKind.binary_exists_and_runs)
    result = run_probe(probe, binary_paths=[str(bin_path)], version_cmd=[str(bin_path), "--version"], runner=runner)
    assert result.ok is True


def test_binary_exists_but_not_runnable() -> None:
    runner = _FakeRunner({})
    probe = HealthProbe(kind=ProbeKind.binary_exists_and_runs)
    result = run_probe(probe, binary_paths=["/nonexistent/bin"], runner=runner)
    assert result.ok is False


def test_service_active(tmp_path: Path) -> None:
    runner = _FakeRunner({
        ("systemctl", "is-active", "auditd.service"): _ok(out=b"active\n"),
    })
    probe = HealthProbe(kind=ProbeKind.service_active, unit="auditd.service")
    assert run_probe(probe, runner=runner).ok is True


def test_service_inactive(tmp_path: Path) -> None:
    runner = _FakeRunner({
        ("systemctl", "is-active", "auditd.service"): _ok(code=3, out=b"inactive\n"),
    })
    probe = HealthProbe(kind=ProbeKind.service_active, unit="auditd.service")
    assert run_probe(probe, runner=runner).ok is False


def test_file_exists(tmp_path: Path) -> None:
    f = tmp_path / "x"
    f.write_text("")
    probe = HealthProbe(kind=ProbeKind.file_exists, path=str(f))
    assert run_probe(probe).ok is True


def test_file_missing(tmp_path: Path) -> None:
    probe = HealthProbe(kind=ProbeKind.file_exists, path=str(tmp_path / "missing"))
    assert run_probe(probe).ok is False


def test_file_exists_and_growing(tmp_path: Path) -> None:
    f = tmp_path / "x"
    f.write_text("a")
    probe = HealthProbe(kind=ProbeKind.file_exists_and_growing, path=str(f), grow_window_s=1)
    # First call captures initial mtime; second call sees growth.
    first = run_probe(probe)
    time.sleep(0.05)
    f.write_text("ab")
    second = run_probe(probe)
    assert first.ok is False  # initial sample
    assert second.ok is True


def test_command_exit_zero() -> None:
    runner = _FakeRunner({("true",): _ok(code=0)})
    probe = HealthProbe(kind=ProbeKind.command_exit_zero, command=["true"])
    assert run_probe(probe, runner=runner).ok is True


def test_command_exit_nonzero() -> None:
    runner = _FakeRunner({("false",): _ok(code=1)})
    probe = HealthProbe(kind=ProbeKind.command_exit_zero, command=["false"])
    assert run_probe(probe, runner=runner).ok is False


def test_journal_pattern_recent_found() -> None:
    runner = _FakeRunner({
        ("journalctl", "--since", "1 minute ago", "--no-pager", "--quiet", "--grep", "audit"):
            _ok(out=b"Jan 1 audit: foo\n"),
    })
    probe = HealthProbe(kind=ProbeKind.journal_pattern_recent, pattern="audit", window_s=60)
    assert run_probe(probe, runner=runner).ok is True


def test_journal_pattern_recent_missing() -> None:
    runner = _FakeRunner({
        ("journalctl", "--since", "1 minute ago", "--no-pager", "--quiet", "--grep", "needle"):
            _ok(out=b""),
    })
    probe = HealthProbe(kind=ProbeKind.journal_pattern_recent, pattern="needle", window_s=60)
    assert run_probe(probe, runner=runner).ok is False
```

- [ ] **Step 2: Implement**

Write `inspectord/dependencies/probes.py`:

```python
"""Health probes (spec §30.7).

Six probe kinds: binary_exists_and_runs, service_active, file_exists,
file_exists_and_growing, command_exit_zero, journal_pattern_recent.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from inspectord.dependencies.schemas import HealthProbe, ProbeKind


@dataclass
class ProbeResult:
    ok: bool
    detail: str


class _Runner(Protocol):
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]: ...


class _DefaultRunner:
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(argv, timeout=timeout, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


# In-memory state for file_exists_and_growing.
_GROW_LAST_MTIME: dict[str, float] = {}


def run_probe(
    probe: HealthProbe,
    *,
    binary_paths: list[str] | None = None,
    version_cmd: list[str] | None = None,
    runner: _Runner | None = None,
) -> ProbeResult:
    runner = runner if runner is not None else _DefaultRunner()
    if probe.kind is ProbeKind.binary_exists_and_runs:
        return _probe_binary(binary_paths or [], version_cmd, runner)
    if probe.kind is ProbeKind.service_active:
        return _probe_service(probe.unit, runner)
    if probe.kind is ProbeKind.file_exists:
        return _probe_file_exists(probe.path)
    if probe.kind is ProbeKind.file_exists_and_growing:
        return _probe_file_growing(probe.path, probe.grow_window_s)
    if probe.kind is ProbeKind.command_exit_zero:
        return _probe_command_zero(probe.command, runner)
    if probe.kind is ProbeKind.journal_pattern_recent:
        return _probe_journal(probe.pattern, probe.window_s, runner)
    return ProbeResult(False, f"unknown probe kind: {probe.kind}")


def _probe_binary(paths: list[str], version_cmd: list[str] | None, runner: _Runner) -> ProbeResult:
    existing = [p for p in paths if Path(p).exists() and os.access(p, os.X_OK)]
    if not existing:
        return ProbeResult(False, f"no executable binary in {paths}")
    if version_cmd:
        result = runner.run(version_cmd)
        if result.returncode != 0:
            return ProbeResult(False, f"version command exit {result.returncode}")
        return ProbeResult(True, result.stdout.decode("utf-8", "replace").strip()[:200])
    return ProbeResult(True, f"binary found at {existing[0]}")


def _probe_service(unit: str | None, runner: _Runner) -> ProbeResult:
    if not unit:
        return ProbeResult(False, "service_active probe requires unit")
    result = runner.run(["systemctl", "is-active", unit])
    if result.returncode == 0:
        return ProbeResult(True, f"{unit} active")
    return ProbeResult(False, f"{unit} returned {result.stdout.decode().strip()}")


def _probe_file_exists(path: str | None) -> ProbeResult:
    if path is None:
        return ProbeResult(False, "file_exists requires path")
    p = Path(path)
    return ProbeResult(p.exists(), f"{path} {'present' if p.exists() else 'missing'}")


def _probe_file_growing(path: str | None, window_s: int) -> ProbeResult:
    if path is None:
        return ProbeResult(False, "file_exists_and_growing requires path")
    p = Path(path)
    if not p.exists():
        _GROW_LAST_MTIME.pop(path, None)
        return ProbeResult(False, f"{path} missing")
    now = p.stat().st_mtime
    prev = _GROW_LAST_MTIME.get(path)
    _GROW_LAST_MTIME[path] = now
    if prev is None:
        return ProbeResult(False, f"{path} mtime sample captured (waiting for next probe)")
    if now > prev:
        return ProbeResult(True, f"{path} mtime advanced from {prev} to {now}")
    age = time.time() - now
    if age > window_s:
        return ProbeResult(False, f"{path} has not grown in {age:.0f}s (> {window_s}s)")
    return ProbeResult(False, f"{path} mtime unchanged ({now})")


def _probe_command_zero(command: list[str] | None, runner: _Runner) -> ProbeResult:
    if not command:
        return ProbeResult(False, "command_exit_zero requires command")
    result = runner.run(command)
    return ProbeResult(
        result.returncode == 0,
        f"{' '.join(command)} exit {result.returncode}",
    )


def _probe_journal(pattern: str | None, window_s: int, runner: _Runner) -> ProbeResult:
    if not pattern:
        return ProbeResult(False, "journal_pattern_recent requires pattern")
    since = f"{max(1, window_s // 60)} minute ago"
    result = runner.run(
        ["journalctl", "--since", since, "--no-pager", "--quiet", "--grep", pattern]
    )
    if result.returncode != 0:
        return ProbeResult(False, f"journalctl exit {result.returncode}")
    out = result.stdout.decode("utf-8", "replace")
    if out.strip():
        return ProbeResult(True, f"matched in journal: {out.splitlines()[0][:200]}")
    return ProbeResult(False, "no matching journal lines")
```

Confirm tests pass; total ~120.

- [ ] **Step 3: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-12-deps-probes
git add inspectord/dependencies/probes.py tests/test_dependencies_probes.py
git commit -m "feat(deps): add health probes (6 kinds)"
git push -u origin task-12-deps-probes
gh pr create --base main --head task-12-deps-probes \
  --title "feat(deps): health probes" \
  --body "Implements all six probe kinds from spec §30.7: binary_exists_and_runs, service_active, file_exists, file_exists_and_growing, command_exit_zero, journal_pattern_recent. External commands route through an injectable runner."
```

---

## Task 13: Audit log writer

**Files:**
- Create: `inspectord/dependencies/audit.py`
- Create: `tests/test_dependencies_audit.py`

**Branch:** `task-13-deps-audit`

A small writer for `dep_audit` rows. Used by the planner, applier, and pkg-helper (already inlined). Centralising it here lets the worker and CLI write audit rows uniformly.

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_audit.py`:

```python
"""Tests for the dep audit log writer."""

from __future__ import annotations

from pathlib import Path

from inspectord.dependencies.audit import log_dep_action
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_log_dep_action_inserts_row(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    log_dep_action(
        db_path=db_path,
        actor="eli@local",
        action="plan_created",
        target="auditd",
        plan_id="01900000-0000-7000-8000-000000000000",
    )
    with Database(db_path) as db:
        rows = db.query(
            "SELECT actor, action, target, plan_id FROM dep_audit"
        ).fetchall()
    assert rows == [("eli@local", "plan_created", "auditd",
                     "01900000-0000-7000-8000-000000000000")]


def test_log_dep_action_truncates_long_stderr(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    long_stderr = "x" * 5000
    log_dep_action(
        db_path=db_path,
        actor="pkg-helper",
        action="install_failed",
        target="auditd",
        stderr_tail=long_stderr,
    )
    with Database(db_path) as db:
        row = db.query("SELECT stderr_tail FROM dep_audit").fetchall()[0][0]
    assert len(row) <= 2000
```

- [ ] **Step 2: Implement**

Write `inspectord/dependencies/audit.py`:

```python
"""Audit log writer for dependency manager actions."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inspectord.storage.db import Database


def log_dep_action(
    *,
    db_path: Path,
    actor: str,
    action: str,
    target: str | None = None,
    plan_id: str | None = None,
    before_sha256: str | None = None,
    after_sha256: str | None = None,
    command: str | None = None,
    exit_code: int | None = None,
    stderr_tail: str | None = None,
) -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO dep_audit (ts, actor, action, target, plan_id, "
            "before_sha256, after_sha256, command, exit_code, stderr_tail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                datetime.now(UTC),
                actor,
                action,
                target,
                plan_id,
                before_sha256,
                after_sha256,
                command,
                exit_code,
                (stderr_tail or "")[:2000] if stderr_tail else None,
            ],
        )
```

Confirm tests pass; total ~122.

- [ ] **Step 3: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-13-deps-audit
git add inspectord/dependencies/audit.py tests/test_dependencies_audit.py
git commit -m "feat(deps): add dep audit log writer"
git push -u origin task-13-deps-audit
gh pr create --base main --head task-13-deps-audit \
  --title "feat(deps): dep audit log writer" \
  --body "Centralises dep_audit writes for planner/applier/worker. Truncates stderr_tail to 2000 chars."
```

---

## Task 14: Plan builder (planner.py)

**Files:**
- Create: `inspectord/dependencies/planner.py`
- Create: `tests/test_dependencies_planner.py`

**Branch:** `task-14-deps-planner`

The planner takes a set of manifests + the current system state + the active profile/flags and produces a `DependencyPlan`. It also persists the plan row to `pending_dep_plans` so the helper can later consume it.

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_planner.py`:

```python
"""Tests for the planner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from inspectord.dependencies.distro import Distro
from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.pacman_backend import PacmanBackend
from inspectord.dependencies.planner import build_plan, persist_plan
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


class _FakeRunner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self._scripts = scripts

    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return self._scripts.get(
            tuple(argv), subprocess.CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=b"")
        )


def _missing() -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"not found")


def _present(version: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        args=[], returncode=0, stdout=f"Name : x\nVersion : {version}\n".encode(), stderr=b""
    )


def test_plan_includes_missing_deps_only(tmp_path: Path) -> None:
    manifests = load_packaged_manifests()
    runner = _FakeRunner({
        ("pacman", "-Qi", "audit"): _missing(),
        ("pacman", "-Qi", "aide"): _present("0.18-1"),
        ("pacman", "-Qi", "yara"): _missing(),
    })
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    names = {item.name for item in plan.items}
    assert "auditd" in names
    assert "yara" in names
    assert "aide" not in names  # already installed


def test_plan_excludes_verify_only_deps(tmp_path: Path) -> None:
    manifests = load_packaged_manifests()
    runner = _FakeRunner({})  # no pacman queries needed for libudev/ebpf_features
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    names = {item.name for item in plan.items}
    # libudev and ebpf_features have no packages — they're verify-only.
    assert "libudev" not in names
    assert "ebpf_features" not in names


def test_persist_plan_writes_row(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    manifests = load_packaged_manifests()
    runner = _FakeRunner({("pacman", "-Qi", "audit"): _missing()})
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    persist_plan(plan, db_path=db_path)
    with Database(db_path) as db:
        rows = db.query(
            "SELECT plan_id, distro, package_manager, status FROM pending_dep_plans"
        ).fetchall()
    assert rows[0][0] == plan.plan_id
    assert rows[0][1] == "arch"
    assert rows[0][2] == "pacman"
    assert rows[0][3] == "pending"


def test_persist_plan_serialises_items_json(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    manifests = load_packaged_manifests()
    runner = _FakeRunner({("pacman", "-Qi", "audit"): _missing()})
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck")
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=Distro.arch,
        profile="minimal",
        flags=set(),
        created_by="test",
    )
    persist_plan(plan, db_path=db_path)
    with Database(db_path) as db:
        items_json = db.query(
            "SELECT items_json FROM pending_dep_plans WHERE plan_id = ?", [plan.plan_id]
        ).fetchall()[0][0]
    items = json.loads(items_json)
    assert any(i["name"] == "auditd" for i in items)
```

- [ ] **Step 2: Implement**

Write `inspectord/dependencies/planner.py`:

```python
"""Planner — builds a DependencyPlan and persists it to pending_dep_plans."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.dependencies.audit import log_dep_action
from inspectord.dependencies.backend import PackageBackend
from inspectord.dependencies.distro import Distro
from inspectord.dependencies.schemas import (
    DependencyManifest,
    DependencyPlan,
    DependencyPlanItem,
)
from inspectord.ids import uuid7
from inspectord.storage.db import Database


_PLAN_TTL = timedelta(hours=1)


def _is_required(manifest: DependencyManifest, profile: str, flags: set[str]) -> bool:
    if profile in manifest.required_when.profiles:
        if not manifest.required_when.flags:
            return True
        return any(flag in flags for flag in manifest.required_when.flags)
    return False


def _packages_for(distro: Distro, manifest: DependencyManifest) -> list[str]:
    return list(manifest.distro_packages.get(distro.value, []))


def build_plan(
    *,
    manifests: dict[str, DependencyManifest],
    backend: PackageBackend,
    distro: Distro,
    profile: str,
    flags: set[str],
    created_by: str,
) -> DependencyPlan:
    items: list[DependencyPlanItem] = []
    for name, manifest in sorted(manifests.items()):
        if not _is_required(manifest, profile, flags):
            continue
        packages = _packages_for(distro, manifest)
        if not packages:
            # Verify-only dep (libudev, ebpf_features) — not part of the install plan.
            continue
        # Skip already-installed packages.
        missing = [pkg for pkg in packages if not backend.is_installed(pkg)]
        if not missing:
            continue
        items.append(
            DependencyPlanItem(
                name=name,
                action="install",
                packages=missing,
                expected_command=f"{backend.name} install {' '.join(missing)}",
                config_dropin=(
                    f"{manifest.config.include_dir}{manifest.config.dropin.filename}"
                    if manifest.config and manifest.config.dropin and manifest.config.include_dir
                    else None
                ),
                service_actions=(
                    [f"systemctl enable --now {manifest.service.systemd_unit}"]
                    if manifest.service and manifest.service.enable
                    else []
                ),
                permission_actions=[],
                post_install_hooks=[" ".join(h.command) for h in manifest.post_install_hooks],
            )
        )

    created_at = datetime.now(UTC)
    plan = DependencyPlan(
        plan_id=str(uuid7()),
        created_at=created_at,
        created_by=created_by,
        distro=distro.value,
        package_manager=backend.name,
        items=items,
        estimated_disk_mb=0,
        expires_at=created_at + _PLAN_TTL,
    )
    return plan


def persist_plan(plan: DependencyPlan, *, db_path: Path) -> None:
    items_json = json.dumps([item.model_dump(mode="json") for item in plan.items])
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO pending_dep_plans (plan_id, created_at, created_by, distro, "
            "package_manager, items_json, estimated_disk_mb, expires_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
            [
                plan.plan_id, plan.created_at, plan.created_by, plan.distro,
                plan.package_manager, items_json, plan.estimated_disk_mb, plan.expires_at,
            ],
        )
    log_dep_action(
        db_path=db_path,
        actor=plan.created_by,
        action="plan_created",
        plan_id=plan.plan_id,
    )
```

Confirm tests pass; total ~126.

- [ ] **Step 3: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-14-deps-planner
git add inspectord/dependencies/planner.py tests/test_dependencies_planner.py
git commit -m "feat(deps): add planner + plan persistence"
git push -u origin task-14-deps-planner
gh pr create --base main --head task-14-deps-planner \
  --title "feat(deps): planner builds + persists DependencyPlan" \
  --body "build_plan() selects required-by-profile manifests that have at least one missing package on the active distro. persist_plan() writes the plan row to pending_dep_plans and logs plan_created."
```

---

## Task 15: Plan applier (applier.py)

**Files:**
- Create: `inspectord/dependencies/applier.py`
- Create: `tests/test_dependencies_applier.py`

**Branch:** `task-15-deps-applier`

The applier is the orchestrator: for an existing plan, it invokes the backend's `install` (which calls the helper), then writes sidecar configs, enables services, runs verify probes, and writes audit rows for each step. Tests use a fake backend + the in-process helper so everything stays in tmp.

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_applier.py`:

```python
"""Tests for the plan applier."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.dependencies.applier import ApplierResult, apply_plan
from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.pacman_backend import PacmanBackend
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


class _Runner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._scripts = scripts

    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        key = tuple(argv)
        self.calls.append(key)
        return self._scripts.get(key, subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"active\n", stderr=b""))


def _ok(code: int = 0, out: bytes = b"", err: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=out, stderr=err)


_PLAN_ID = "01930000-0000-7000-8000-000000000003"


def _seed_plan(db_path: Path) -> None:
    with Database(db_path) as db:
        run_migrations(db)
        created = datetime.now(UTC)
        items = [{
            "name": "auditd",
            "action": "install",
            "packages": ["audit"],
            "expected_command": "pacman install audit",
            "config_dropin": None,
            "service_actions": ["systemctl enable --now auditd.service"],
            "permission_actions": [],
            "post_install_hooks": [],
        }]
        db.execute(
            "INSERT INTO pending_dep_plans (plan_id, created_at, created_by, distro, "
            "package_manager, items_json, estimated_disk_mb, expires_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [_PLAN_ID, created, "test", "arch", "pacman", json.dumps(items), 0,
             created + timedelta(hours=1), "pending"],
        )


def test_apply_plan_installs_and_drops_config(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_plan(db_path)
    sidecar_root = tmp_path / "etc" / "audit" / "rules.d"
    sidecar_root.mkdir(parents=True)
    runner = _Runner({
        ("pacman", "-Sy"): _ok(),
        ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(),
        ("systemctl", "enable", "--now", "auditd.service"): _ok(),
        ("systemctl", "is-active", "auditd.service"): _ok(out=b"active\n"),
    })
    backend = PacmanBackend(
        runner=runner,
        lock_path=tmp_path / "absent.lck",
        helper_command=["__in_process__"],
        db_path=db_path,
    )
    manifests = load_packaged_manifests()
    result = apply_plan(
        plan_id=_PLAN_ID,
        db_path=db_path,
        manifests=manifests,
        backend=backend,
        runner=runner,
        sidecar_dirs={"auditd": sidecar_root},
        chown=False,
    )
    assert isinstance(result, ApplierResult)
    assert result.ok is True
    assert (sidecar_root / "inspectord.rules").exists()
    assert ("systemctl", "enable", "--now", "auditd.service") in runner.calls


def test_apply_plan_records_audit_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_plan(db_path)
    sidecar_root = tmp_path / "etc" / "audit" / "rules.d"
    sidecar_root.mkdir(parents=True)
    runner = _Runner({
        ("pacman", "-Sy"): _ok(),
        ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(),
        ("systemctl", "enable", "--now", "auditd.service"): _ok(),
        ("systemctl", "is-active", "auditd.service"): _ok(out=b"active\n"),
    })
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck",
                            helper_command=["__in_process__"], db_path=db_path)
    apply_plan(
        plan_id=_PLAN_ID,
        db_path=db_path,
        manifests=load_packaged_manifests(),
        backend=backend,
        runner=runner,
        sidecar_dirs={"auditd": sidecar_root},
        chown=False,
    )
    with Database(db_path) as db:
        actions = {r[0] for r in db.query(
            "SELECT action FROM dep_audit WHERE plan_id = ?", [_PLAN_ID]
        ).fetchall()}
    assert "dropin_written" in actions
    assert "service_action" in actions
    assert "verify_pass" in actions or "verify_fail" in actions


def test_apply_plan_install_failure_skips_dropin(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_plan(db_path)
    sidecar_root = tmp_path / "etc" / "audit" / "rules.d"
    sidecar_root.mkdir(parents=True)
    runner = _Runner({
        ("pacman", "-Sy"): _ok(),
        ("pacman", "-S", "--noconfirm", "--needed", "audit"): _ok(code=1, err=b"boom"),
    })
    backend = PacmanBackend(runner=runner, lock_path=tmp_path / "absent.lck",
                            helper_command=["__in_process__"], db_path=db_path)
    result = apply_plan(
        plan_id=_PLAN_ID,
        db_path=db_path,
        manifests=load_packaged_manifests(),
        backend=backend,
        runner=runner,
        sidecar_dirs={"auditd": sidecar_root},
        chown=False,
    )
    assert result.ok is False
    assert not (sidecar_root / "inspectord.rules").exists()
```

- [ ] **Step 2: Implement**

Write `inspectord/dependencies/applier.py`:

```python
"""Applier — orchestrate install + config + verify for a persisted plan."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from inspectord.dependencies.audit import log_dep_action
from inspectord.dependencies.backend import PackageBackend
from inspectord.dependencies.probes import ProbeResult, run_probe
from inspectord.dependencies.schemas import DependencyManifest, DependencyPlanItem
from inspectord.dependencies.sidecar import SidecarError, write_sidecar
from inspectord.storage.db import Database


class _Runner(Protocol):
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]: ...


@dataclass
class ApplierResult:
    plan_id: str
    ok: bool
    failed_dep: str | None = None
    notes: list[str] = field(default_factory=list)


def _load_items(db_path: Path, plan_id: str) -> list[DependencyPlanItem]:
    with Database(db_path) as db:
        rows = db.query(
            "SELECT items_json FROM pending_dep_plans WHERE plan_id = ?",
            [plan_id],
        ).fetchall()
    if not rows:
        raise RuntimeError(f"plan not found: {plan_id}")
    return [DependencyPlanItem.model_validate(i) for i in json.loads(rows[0][0])]


def apply_plan(
    *,
    plan_id: str,
    db_path: Path,
    manifests: dict[str, DependencyManifest],
    backend: PackageBackend,
    runner: _Runner,
    sidecar_dirs: dict[str, Path] | None = None,
    chown: bool = True,
) -> ApplierResult:
    sidecar_dirs = dict(sidecar_dirs or {})
    items = _load_items(db_path, plan_id)
    notes: list[str] = []

    # 1. Install packages via the helper (one call, handles all install items).
    install_items = [i for i in items if i.action == "install" and i.packages]
    if install_items:
        all_pkgs = [pkg for i in install_items for pkg in i.packages]
        result = backend.install(all_pkgs, plan_id=plan_id)
        log_dep_action(
            db_path=db_path,
            actor="applier",
            action="install" if not result.failed else "install_failed",
            plan_id=plan_id,
            command=result.command,
            exit_code=result.exit_code,
            stderr_tail=result.stderr_tail,
        )
        if result.failed:
            return ApplierResult(plan_id=plan_id, ok=False, failed_dep="install", notes=[result.stderr_tail])

    # 2. Drop sidecar configs.
    for item in items:
        manifest = manifests.get(item.name)
        if manifest is None or manifest.config is None or manifest.config.dropin is None:
            continue
        include_dir = sidecar_dirs.get(item.name) or Path(manifest.config.include_dir or "/")
        try:
            target = write_sidecar(manifest, include_dir=include_dir, chown=chown)
        except SidecarError as exc:
            log_dep_action(
                db_path=db_path,
                actor="applier",
                action="dropin_failed",
                target=item.name,
                plan_id=plan_id,
                stderr_tail=str(exc),
            )
            return ApplierResult(plan_id=plan_id, ok=False, failed_dep=item.name, notes=[str(exc)])
        log_dep_action(
            db_path=db_path,
            actor="applier",
            action="dropin_written",
            target=item.name,
            plan_id=plan_id,
            command=str(target),
        )
        notes.append(f"wrote {target}")

    # 3. Service actions.
    for item in items:
        for action in item.service_actions:
            argv = action.split()
            result = runner.run(argv)
            log_dep_action(
                db_path=db_path,
                actor="applier",
                action="service_action" if result.returncode == 0 else "service_action_failed",
                target=item.name,
                plan_id=plan_id,
                command=action,
                exit_code=result.returncode,
                stderr_tail=result.stderr.decode("utf-8", "replace"),
            )

    # 4. Verify probes.
    for item in items:
        manifest = manifests.get(item.name)
        if manifest is None:
            continue
        probe: ProbeResult = run_probe(
            manifest.verify.health_probe,
            binary_paths=manifest.verify.binary_paths,
            version_cmd=manifest.verify.version_cmd,
            runner=runner,
        )
        log_dep_action(
            db_path=db_path,
            actor="applier",
            action="verify_pass" if probe.ok else "verify_fail",
            target=item.name,
            plan_id=plan_id,
            stderr_tail=probe.detail,
        )
        with Database(db_path) as db:
            installed_version = backend.installed_version(item.packages[0]) if item.packages else None
            dropin_present = item.config_dropin is not None
            now_ts = datetime.now(UTC)
            # DuckDB upsert syntax: ON CONFLICT (PK) DO UPDATE.
            db.execute(
                "INSERT INTO dep_state "
                "(name, installed, installed_version, dropin_present, dropin_sha256, "
                "last_verify_ts, last_verify_pass, last_verify_detail, updated_at) "
                "VALUES (?, TRUE, ?, ?, NULL, ?, ?, ?, ?) "
                "ON CONFLICT (name) DO UPDATE SET "
                "installed = excluded.installed, "
                "installed_version = excluded.installed_version, "
                "dropin_present = excluded.dropin_present, "
                "last_verify_ts = excluded.last_verify_ts, "
                "last_verify_pass = excluded.last_verify_pass, "
                "last_verify_detail = excluded.last_verify_detail, "
                "updated_at = excluded.updated_at",
                [
                    item.name,
                    installed_version,
                    dropin_present,
                    now_ts,
                    probe.ok,
                    probe.detail,
                    now_ts,
                ],
            )

    return ApplierResult(plan_id=plan_id, ok=True, notes=notes)
```

Note: `INSERT OR REPLACE` is DuckDB syntax — in DuckDB 1.x use `INSERT INTO ... ON CONFLICT DO UPDATE`. If the test fails, fall back to a manual delete+insert pattern. Adjust per the actual error.

Confirm tests pass; total ~129.

- [ ] **Step 3: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-15-deps-applier
git add inspectord/dependencies/applier.py tests/test_dependencies_applier.py
git commit -m "feat(deps): plan applier orchestrating install + sidecar + service + verify"
git push -u origin task-15-deps-applier
gh pr create --base main --head task-15-deps-applier \
  --title "feat(deps): plan applier" \
  --body "Orchestrates the full apply path: pkg-helper install → sidecar config drop → service enable/start → verify probe → audit + dep_state writes. Failure at install short-circuits before any sidecar writes."
```

---

## Task 16: dependency_manager worker

**Files:**
- Create: `inspectord/workers/dependency_manager/__init__.py`
- Create: `inspectord/workers/dependency_manager/__main__.py`
- Create: `tests/test_dependencies_worker.py`

**Branch:** `task-16-deps-worker`

The worker runs continuously as a child of the supervisor and re-verifies every declared dependency on a configurable cadence (spec §30.8). It does **not** plan or install — that happens on IPC request. Its job is the periodic health check and emitting `dep_*` events for state changes.

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_worker.py`:

```python
"""Tests for the dependency_manager worker."""

from __future__ import annotations

import io
import json
import subprocess
import threading
import time

from inspectord.workers.dependency_manager.__main__ import DependencyManagerWorker


class _Runner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self._scripts = scripts

    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return self._scripts.get(
            tuple(argv), subprocess.CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=b"")
        )


def test_worker_emits_state_events() -> None:
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    runner = _Runner({
        ("systemctl", "is-active", "auditd.service"): subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"active\n", stderr=b""
        ),
        ("systemctl", "is-active", "systemd-journald.service"): subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"active\n", stderr=b""
        ),
    })
    w = DependencyManagerWorker(
        name="dependency_manager",
        stdout=stdout,
        stderr=stderr,
        runner=runner,
        config={"interval_s": 0.05},
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.2)
    w.request_stop()
    t.join(timeout=2)

    lines = [
        json.loads(line)
        for line in stdout.getvalue().decode("utf-8").splitlines()
        if line.strip()
    ]
    assert lines
    actions = {ev["action"] for ev in lines}
    assert "dep_verified" in actions or "dep_state" in actions
    assert all(ev["module"] == "dependency_manager" for ev in lines)
```

- [ ] **Step 2: Implement**

Write `inspectord/workers/dependency_manager/__init__.py`:

```python
"""Dependency manager worker package."""
```

Write `inspectord/workers/dependency_manager/__main__.py`:

```python
"""dependency_manager worker (spec §30.8).

Runs continuously, periodically verifying every declared dependency. Emits
state events whose `action` carries the verify result. Does not plan or
install — that happens via IPC.
"""

from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from typing import Any, Protocol

from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.probes import ProbeResult, run_probe
from inspectord.ids import uuid7
from inspectord.schemas.versions import EVENT_SCHEMA_VERSION
from inspectord.workers.contract import Worker, read_config_from_stdin


class _Runner(Protocol):
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]: ...


class _DefaultRunner:
    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(argv, timeout=timeout, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class DependencyManagerWorker(Worker):
    def __init__(
        self,
        *,
        name: str,
        runner: _Runner | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(name=name, **kwargs)
        self._runner: _Runner = runner if runner is not None else _DefaultRunner()
        self._manifests = load_packaged_manifests()

    def step_interval_s(self) -> float:
        return float(self.config.get("interval_s", 300.0))

    def step(self) -> None:
        for name, manifest in sorted(self._manifests.items()):
            probe: ProbeResult = run_probe(
                manifest.verify.health_probe,
                binary_paths=manifest.verify.binary_paths,
                version_cmd=manifest.verify.version_cmd,
                runner=self._runner,
            )
            severity = "info" if probe.ok else "high"
            self.emit_event({
                "schema_version": EVENT_SCHEMA_VERSION,
                "ts": datetime.now(UTC).isoformat(),
                "event_id": str(uuid7()),
                "kind": "state",
                "category": ["host"],
                "type": ["info"] if probe.ok else ["change"],
                "action": "dep_verified" if probe.ok else "dep_misconfigured",
                "severity": severity,
                "module": "dependency_manager",
                "host": {"hostname": os.uname().nodename, "os": {"family": "linux"}},
                "labels": [f"dep:{name}"],
                "message": f"{name}: {probe.detail}",
            })


def main() -> None:
    cfg: dict[str, Any] = read_config_from_stdin()
    DependencyManagerWorker(name="dependency_manager", config=cfg).run()


if __name__ == "__main__":
    main()
```

Confirm tests pass; total ~130.

- [ ] **Step 3: Lint + commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-16-deps-worker
git add inspectord/workers/dependency_manager/ tests/test_dependencies_worker.py
git commit -m "feat(workers): add dependency_manager worker for periodic verify"
git push -u origin task-16-deps-worker
gh pr create --base main --head task-16-deps-worker \
  --title "feat(workers): dependency_manager worker" \
  --body "Periodic-verify worker; runs every interval_s (default 300s) and emits dep_verified / dep_misconfigured state events for each declared dep. Does not plan or install — that path lives in IPC."
```

---

## Task 17: Register worker in dev_config

**Files:**
- Modify: `inspectord/config.py` (add dependency_manager to dev_config workers)
- Modify: `tests/test_supervisor.py` (assert second worker came up)

**Branch:** `task-17-deps-register-worker`

- [ ] **Step 1: Update dev_config**

Open `/home/eli/Development/inspectord/inspectord/config.py` and replace the `workers` list inside `dev_config(base=...)` with:

```python
        "workers": [
            {
                "name": "healthcheck",
                "module": "inspectord.workers.healthcheck",
                "config": {"interval_s": 1.0},
            },
            {
                "name": "dependency_manager",
                "module": "inspectord.workers.dependency_manager",
                "config": {"interval_s": 30.0},
            },
        ],
```

- [ ] **Step 2: Add a supervisor test that confirms both workers come up**

Append to `tests/test_supervisor.py`:

```python
def test_supervisor_starts_dependency_manager_worker(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        deadline = time.monotonic() + 5.0
        modules: set[str] = set()

        def listener(ev: object) -> None:
            modules.add(getattr(ev, "module", ""))

        sup.attach_listener(listener)

        while time.monotonic() < deadline and "dependency_manager" not in modules:
            time.sleep(0.1)
        assert "dependency_manager" in modules
    finally:
        sup.stop(timeout=5.0)
```

- [ ] **Step 3: Run and confirm**

```bash
pytest tests/test_supervisor.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: all existing tests still pass plus the new one. Total goes up by 1.

- [ ] **Step 4: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-17-deps-register-worker
git add inspectord/config.py tests/test_supervisor.py
git commit -m "feat(config): register dependency_manager worker in dev_config"
git push -u origin task-17-deps-register-worker
gh pr create --base main --head task-17-deps-register-worker \
  --title "feat(config): register dependency_manager worker" \
  --body "dev_config() now spawns the dependency_manager worker alongside the healthcheck worker. Supervisor integration test asserts both workers emit events."
```

---

## Task 18: IPC methods — read paths

**Files:**
- Modify: `inspectord/__main__.py` (add dep IPC methods)
- Create: `inspectord/dependencies/ipc_handlers.py` (handlers, kept out of __main__)
- Create: `tests/test_dependencies_ipc.py`

**Branch:** `task-18-deps-ipc-read`

Adds the read-only deps IPC methods: `list_dependencies`, `get_dep_audit`, and `plan_dependency_install` (the latter creates a plan but doesn't apply it — that's `apply_dependency_plan` in Task 19).

- [ ] **Step 1: Failing tests**

Write `tests/test_dependencies_ipc.py`:

```python
"""Tests for deps IPC handlers."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from inspectord.dependencies.ipc_handlers import (
    handle_get_dep_audit,
    handle_list_dependencies,
    handle_plan_dependency_install,
)
from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.pacman_backend import PacmanBackend
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


class _Runner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self._scripts = scripts

    def run(self, argv: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return self._scripts.get(
            tuple(argv), subprocess.CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=b"")
        )


def _present(version: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        args=[], returncode=0, stdout=f"Name : x\nVersion : {version}\n".encode(), stderr=b""
    )


def _missing() -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout=b"", stderr=b"")


def test_handle_list_dependencies(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    runner = _Runner({
        ("pacman", "-Qi", "audit"): _present("3.1.5-1"),
        ("pacman", "-Qi", "aide"): _missing(),
        ("pacman", "-Qi", "yara"): _present("4.5.0-1"),
    })
    result = handle_list_dependencies(
        params={},
        manifests=load_packaged_manifests(),
        backend=PacmanBackend(runner=runner),
        db_path=db_path,
    )
    names = {d["name"] for d in result["dependencies"]}
    assert {"auditd", "aide", "yara"} <= names
    audit = next(d for d in result["dependencies"] if d["name"] == "auditd")
    assert audit["installed"] is True
    assert audit["installed_version"] == "3.1.5-1"


def test_handle_plan_returns_plan_id(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    runner = _Runner({
        ("pacman", "-Qi", "audit"): _missing(),
        ("pacman", "-Qi", "aide"): _missing(),
        ("pacman", "-Qi", "yara"): _missing(),
    })
    result = handle_plan_dependency_install(
        params={"profile": "minimal", "flags": [], "actor": "eli@local"},
        manifests=load_packaged_manifests(),
        backend=PacmanBackend(runner=runner),
        db_path=db_path,
    )
    assert "plan_id" in result
    with Database(db_path) as db:
        rows = db.query(
            "SELECT plan_id FROM pending_dep_plans WHERE plan_id = ?", [result["plan_id"]]
        ).fetchall()
    assert rows


def test_handle_get_dep_audit_empty(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    result = handle_get_dep_audit(params={"target": "auditd"}, db_path=db_path)
    assert result["entries"] == []
```

- [ ] **Step 2: Implement**

Write `inspectord/dependencies/ipc_handlers.py`:

```python
"""IPC handlers for the dependency_manager subsystem."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inspectord.dependencies.backend import PackageBackend
from inspectord.dependencies.distro import Distro, detect_distro
from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.planner import build_plan, persist_plan
from inspectord.dependencies.schemas import DependencyManifest
from inspectord.storage.db import Database


def handle_list_dependencies(
    *,
    params: dict[str, Any],
    manifests: dict[str, DependencyManifest],
    backend: PackageBackend,
    db_path: Path,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with Database(db_path) as db:
        state_rows = {
            r[0]: r
            for r in db.query(
                "SELECT name, installed, installed_version, dropin_present, "
                "last_verify_ts, last_verify_pass, last_verify_detail FROM dep_state"
            ).fetchall()
        }
    for name, manifest in sorted(manifests.items()):
        pkgs = manifest.distro_packages.get("arch", [])
        installed = all(backend.is_installed(p) for p in pkgs) if pkgs else None
        version = (
            backend.installed_version(pkgs[0]) if pkgs and installed else None
        )
        prior = state_rows.get(name)
        rows.append({
            "name": name,
            "description": manifest.description,
            "required_when_profiles": manifest.required_when.profiles,
            "packages_for_arch": pkgs,
            "installed": installed,
            "installed_version": version,
            "dropin_present": bool(prior[3]) if prior else False,
            "last_verify_ts": prior[4].isoformat() if prior and prior[4] else None,
            "last_verify_pass": prior[5] if prior else None,
            "last_verify_detail": prior[6] if prior else None,
        })
    return {"schema_version": "1.0.0", "dependencies": rows}


def handle_plan_dependency_install(
    *,
    params: dict[str, Any],
    manifests: dict[str, DependencyManifest],
    backend: PackageBackend,
    db_path: Path,
) -> dict[str, Any]:
    profile = str(params.get("profile", "standard"))
    flags = set(params.get("flags", []) or [])
    actor = str(params.get("actor", "ipc"))
    # Distro and package manager are independent: backend.name is "pacman", and the
    # distro is detected from /etc/os-release. The pkg-helper validates the pair later.
    distro = detect_distro()
    plan = build_plan(
        manifests=manifests,
        backend=backend,
        distro=distro,
        profile=profile,
        flags=flags,
        created_by=actor,
    )
    persist_plan(plan, db_path=db_path)
    return {
        "schema_version": "1.0.0",
        "plan_id": plan.plan_id,
        "distro": plan.distro,
        "package_manager": plan.package_manager,
        "items": [item.model_dump(mode="json") for item in plan.items],
        "expires_at": plan.expires_at.isoformat(),
    }


def handle_get_dep_audit(
    *,
    params: dict[str, Any],
    db_path: Path,
) -> dict[str, Any]:
    target = params.get("target")
    with Database(db_path) as db:
        if target:
            rows = db.query(
                "SELECT ts, actor, action, target, plan_id, command, exit_code, stderr_tail "
                "FROM dep_audit WHERE target = ? ORDER BY ts DESC LIMIT 200",
                [target],
            ).fetchall()
        else:
            rows = db.query(
                "SELECT ts, actor, action, target, plan_id, command, exit_code, stderr_tail "
                "FROM dep_audit ORDER BY ts DESC LIMIT 200"
            ).fetchall()
    return {
        "schema_version": "1.0.0",
        "entries": [
            {
                "ts": r[0].isoformat() if r[0] else None,
                "actor": r[1],
                "action": r[2],
                "target": r[3],
                "plan_id": r[4],
                "command": r[5],
                "exit_code": r[6],
                "stderr_tail": r[7],
            }
            for r in rows
        ],
    }
```

- [ ] **Step 3: Wire methods into `inspectord/__main__.py`**

In `_ipc_methods()`, replace the body so it also registers the deps handlers:

```python
def _ipc_methods(supervisor: Supervisor, cfg: DaemonConfig) -> list[Method]:
    from inspectord.dependencies.ipc_handlers import (
        handle_get_dep_audit,
        handle_list_dependencies,
        handle_plan_dependency_install,
    )
    from inspectord.dependencies.manifest import load_packaged_manifests
    from inspectord.dependencies.pacman_backend import PacmanBackend

    def get_health(_params: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "supervisor": "running",
            "workers": [{"name": w.name, "status": "up"} for w in cfg.workers],
        }

    manifests = load_packaged_manifests()
    backend = PacmanBackend()

    return [
        Method(name="get_health", handler=get_health, mutates=False),
        Method(
            name="list_dependencies",
            handler=lambda params: handle_list_dependencies(
                params=params, manifests=manifests, backend=backend,
                db_path=cfg.storage.db_path,
            ),
            mutates=False,
        ),
        Method(
            name="plan_dependency_install",
            handler=lambda params: handle_plan_dependency_install(
                params=params, manifests=manifests, backend=backend,
                db_path=cfg.storage.db_path,
            ),
            mutates=True,
        ),
        Method(
            name="get_dep_audit",
            handler=lambda params: handle_get_dep_audit(
                params=params, db_path=cfg.storage.db_path,
            ),
            mutates=False,
        ),
    ]
```

Update `main()` to pass `cfg` to `_ipc_methods`:

```python
    ipc = IpcServer(
        socket_path=cfg.ipc.socket_path,
        methods=_ipc_methods(sup, cfg),
        allowed_uids=cfg.ipc.allowed_uids,
    )
```

- [ ] **Step 4: Confirm tests pass**

```bash
pytest tests/test_dependencies_ipc.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 3 new tests pass; existing integration test still green.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-18-deps-ipc-read
git add inspectord/__main__.py inspectord/dependencies/ipc_handlers.py tests/test_dependencies_ipc.py
git commit -m "feat(ipc): add list_dependencies / plan_dependency_install / get_dep_audit"
git push -u origin task-18-deps-ipc-read
gh pr create --base main --head task-18-deps-ipc-read \
  --title "feat(ipc): deps read-path methods" \
  --body "Adds list_dependencies (status table), plan_dependency_install (creates + persists plan), get_dep_audit (audit log query). The apply path lands in Task 19."
```

---

## Task 19: IPC method — apply_dependency_plan

**Files:**
- Modify: `inspectord/dependencies/ipc_handlers.py`
- Modify: `inspectord/__main__.py` (register the method)
- Modify: `tests/test_dependencies_ipc.py`

**Branch:** `task-19-deps-ipc-apply`

- [ ] **Step 1: Failing tests**

Append to `tests/test_dependencies_ipc.py`:

```python
def test_handle_apply_dependency_plan_invokes_applier(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    runner = _Runner({
        ("pacman", "-Qi", "audit"): _missing(),
        ("pacman", "-Qi", "aide"): _missing(),
        ("pacman", "-Qi", "yara"): _missing(),
        ("pacman", "-Sy"): subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b""),
        ("pacman", "-S", "--noconfirm", "--needed", "audit", "aide", "yara"):
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b""),
        ("systemctl", "enable", "--now", "auditd.service"):
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b""),
        ("systemctl", "enable", "--now", "systemd-journald.service"):
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b""),
        ("systemctl", "is-active", "auditd.service"):
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"active\n", stderr=b""),
        ("systemctl", "is-active", "systemd-journald.service"):
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"active\n", stderr=b""),
        ("aide", "--version"):
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"Aide 0.18", stderr=b""),
        ("yara", "--version"):
            subprocess.CompletedProcess(args=[], returncode=0, stdout=b"4.5.0", stderr=b""),
    })
    backend = PacmanBackend(
        runner=runner,
        lock_path=tmp_path / "absent.lck",
        helper_command=["__in_process__"],
        db_path=db_path,
    )

    # Step 1: create plan.
    plan_result = handle_plan_dependency_install(
        params={"profile": "minimal", "flags": [], "actor": "eli@local"},
        manifests=load_packaged_manifests(),
        backend=backend,
        db_path=db_path,
    )

    # Step 2: apply.
    from inspectord.dependencies.ipc_handlers import handle_apply_dependency_plan

    apply_result = handle_apply_dependency_plan(
        params={"plan_id": plan_result["plan_id"]},
        manifests=load_packaged_manifests(),
        backend=backend,
        runner=runner,
        db_path=db_path,
        sidecar_dirs={
            "auditd": tmp_path / "etc" / "audit" / "rules.d",
            "journald": tmp_path / "etc" / "systemd" / "journald.conf.d",
        },
        chown=False,
    )
    assert apply_result["ok"] is True
```

Make the test setup create those sidecar dirs first; the applier requires them to exist.

- [ ] **Step 2: Implement**

Append to `inspectord/dependencies/ipc_handlers.py`:

```python
from inspectord.dependencies.applier import apply_plan


def handle_apply_dependency_plan(
    *,
    params: dict[str, Any],
    manifests: dict[str, DependencyManifest],
    backend: PackageBackend,
    runner: Any,
    db_path: Path,
    sidecar_dirs: dict[str, Path] | None = None,
    chown: bool = True,
) -> dict[str, Any]:
    plan_id = str(params.get("plan_id", ""))
    if not plan_id:
        raise ValueError("plan_id required")
    result = apply_plan(
        plan_id=plan_id,
        db_path=db_path,
        manifests=manifests,
        backend=backend,
        runner=runner,
        sidecar_dirs=sidecar_dirs,
        chown=chown,
    )
    return {
        "schema_version": "1.0.0",
        "plan_id": result.plan_id,
        "ok": result.ok,
        "failed_dep": result.failed_dep,
        "notes": result.notes,
    }
```

In `inspectord/__main__.py`, register the new method inside `_ipc_methods`:

```python
from inspectord.dependencies.ipc_handlers import handle_apply_dependency_plan
import subprocess as _subproc

def _backend_runner() -> _subproc.CompletedProcess:  # local helper
    pass  # not actually used; pacman backend creates its own default runner
```

And add a `Method` entry — use a thin lambda that constructs a real subprocess runner for the applier:

```python
        Method(
            name="apply_dependency_plan",
            handler=lambda params: handle_apply_dependency_plan(
                params=params,
                manifests=manifests,
                backend=backend,
                runner=backend._runner,    # reuse the backend's runner (DefaultRunner in prod)
                db_path=cfg.storage.db_path,
                sidecar_dirs=None,
                chown=True,
            ),
            mutates=True,
        ),
```

Confirm tests pass; total ~134.

- [ ] **Step 3: Commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-19-deps-ipc-apply
git add inspectord/dependencies/ipc_handlers.py inspectord/__main__.py tests/test_dependencies_ipc.py
git commit -m "feat(ipc): add apply_dependency_plan handler + method"
git push -u origin task-19-deps-ipc-apply
gh pr create --base main --head task-19-deps-ipc-apply \
  --title "feat(ipc): apply_dependency_plan" \
  --body "Wires the applier to IPC; CLI in the next task calls this method after the user reviews the plan."
```

---

## Task 20: CLI — `inspectorctl deps` subcommands

**Files:**
- Create: `inspectorctl/cli/deps.py`
- Modify: `inspectorctl/cli/app.py` (mount the deps subapp)
- Create: `tests/test_cli_deps.py`

**Branch:** `task-20-deps-cli`

Adds `inspectorctl deps status / plan / install / verify / audit`. These shell out to the IPC client.

- [ ] **Step 1: Implement the CLI**

Write `inspectorctl/cli/deps.py`:

```python
"""inspectorctl deps subcommands."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint
from rich.table import Table

from inspectorctl.ipc_client import IpcClient, IpcError


app = typer.Typer(no_args_is_help=True, add_completion=False, help="Dependency management commands.")


_DEFAULT_SOCKET = Path("var") / "inspectord.sock"


def _client(socket: Path) -> IpcClient:
    return IpcClient(socket_path=socket)


@app.command("status")
def status_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Show the status of every declared dependency."""
    try:
        result = _client(socket).call("list_dependencies")
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="Dependencies")
    table.add_column("Name")
    table.add_column("Installed")
    table.add_column("Version")
    table.add_column("Drop-in")
    table.add_column("Last verify")
    for d in result.get("dependencies", []):
        installed = "✓" if d.get("installed") else ("—" if d.get("installed") is None else "✗")
        verify = (
            "✓ pass" if d.get("last_verify_pass") is True
            else "✗ fail" if d.get("last_verify_pass") is False
            else "—"
        )
        table.add_row(
            d["name"],
            installed,
            d.get("installed_version") or "",
            "✓" if d.get("dropin_present") else "—",
            verify,
        )
    rprint(table)


@app.command("plan")
def plan_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    profile: Annotated[str, typer.Option("--profile")] = "standard",
    flag: Annotated[list[str], typer.Option("--flag")] = [],
) -> None:
    """Create an install plan; print it; do not apply."""
    try:
        result = _client(socket).call(
            "plan_dependency_install",
            {"profile": profile, "flags": flag, "actor": "cli@local"},
        )
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    rprint(f"[bold]Plan {result['plan_id']}[/bold]")
    rprint(f"distro: {result['distro']}, package_manager: {result['package_manager']}")
    rprint(f"expires_at: {result['expires_at']}")
    items = result.get("items", [])
    if not items:
        rprint("[green]Nothing to install — all required deps are already present.[/green]")
        return
    for item in items:
        rprint(
            f"  {item['name']}: install {item['packages']}; "
            f"service_actions={item['service_actions']}; "
            f"dropin={item.get('config_dropin') or '—'}"
        )
    rprint(
        "\n[dim]Run `inspectorctl deps install --plan-id "
        f"{result['plan_id']}` to apply.[/dim]"
    )


@app.command("install")
def install_cmd(
    plan_id: Annotated[str | None, typer.Option("--plan-id")] = None,
    profile: Annotated[str, typer.Option("--profile")] = "standard",
    flag: Annotated[list[str], typer.Option("--flag")] = [],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt.")] = False,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Apply an install plan; create one first if --plan-id not given."""
    client = _client(socket)
    if plan_id is None:
        plan_result = client.call(
            "plan_dependency_install",
            {"profile": profile, "flags": flag, "actor": "cli@local"},
        )
        plan_id = plan_result["plan_id"]
        if not plan_result["items"]:
            rprint("[green]Nothing to install.[/green]")
            return
        if not yes:
            rprint(f"[yellow]Plan {plan_id} created. Items:[/yellow]")
            for item in plan_result["items"]:
                rprint(f"  {item['name']}: install {item['packages']}")
            confirm = typer.confirm("Apply this plan?", default=False)
            if not confirm:
                raise typer.Exit(code=1)

    try:
        result = client.call("apply_dependency_plan", {"plan_id": plan_id})
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if result.get("ok"):
        rprint(f"[green]Plan {plan_id} applied successfully.[/green]")
        for note in result.get("notes", []):
            rprint(f"  {note}")
    else:
        rprint(f"[red]Plan {plan_id} failed at: {result.get('failed_dep')}[/red]")
        raise typer.Exit(code=1)


@app.command("audit")
def audit_cmd(
    target: Annotated[str | None, typer.Option("--target")] = None,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Show the deps audit log (optionally filtered by target dep)."""
    try:
        result = _client(socket).call("get_dep_audit", {"target": target})
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    for e in result.get("entries", []):
        rprint(f"{e['ts']}  {e['actor']:<12} {e['action']:<24} {e.get('target') or '—'}  {e.get('command') or ''}")
```

Modify `inspectorctl/cli/app.py` to mount the subapp:

```python
"""Top-level Typer app for inspectorctl."""

from __future__ import annotations

import typer

from inspectorctl.cli import deps, self_test, status, version

app = typer.Typer(no_args_is_help=True, add_completion=False)
app.command(name="status")(status.cmd)
app.command(name="self-test")(self_test.cmd)
app.command(name="version")(version.cmd)
app.add_typer(deps.app, name="deps")
```

- [ ] **Step 2: Tests**

Write `tests/test_cli_deps.py`:

```python
"""Tests for inspectorctl deps CLI."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from inspectord.ipc_server import IpcServer, Method
from inspectorctl.cli.app import app


runner = CliRunner()


def test_deps_status_renders(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def list_deps(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "dependencies": [
                {
                    "name": "auditd",
                    "installed": True,
                    "installed_version": "3.1.5-1",
                    "dropin_present": False,
                    "last_verify_pass": None,
                }
            ],
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="list_dependencies", handler=list_deps, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(app, ["deps", "status", "--socket", str(sock_path)])
        assert result.exit_code == 0
        assert "auditd" in result.stdout
    finally:
        server.stop()


def test_deps_plan_prints_items(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def plan_handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "plan_id": "01900000-0000-7000-8000-000000000000",
            "distro": "arch",
            "package_manager": "pacman",
            "items": [{
                "name": "auditd",
                "action": "install",
                "packages": ["audit"],
                "expected_command": "pacman install audit",
                "config_dropin": None,
                "service_actions": ["systemctl enable --now auditd.service"],
                "permission_actions": [],
                "post_install_hooks": [],
            }],
            "expires_at": "2026-05-24T16:00:00+00:00",
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="plan_dependency_install", handler=plan_handler, mutates=True)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(app, ["deps", "plan", "--socket", str(sock_path), "--profile", "minimal"])
        assert result.exit_code == 0
        assert "auditd" in result.stdout
        assert "audit" in result.stdout
    finally:
        server.stop()
```

Confirm tests pass; total ~136.

- [ ] **Step 3: Commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-20-deps-cli
git add inspectorctl/cli/deps.py inspectorctl/cli/app.py tests/test_cli_deps.py
git commit -m "feat(cli): add inspectorctl deps status/plan/install/audit"
git push -u origin task-20-deps-cli
gh pr create --base main --head task-20-deps-cli \
  --title "feat(cli): inspectorctl deps subcommands" \
  --body "Mounts a deps subapp under inspectorctl. status prints a table from list_dependencies. plan prints a fresh plan but does not apply. install asks for confirmation then calls apply_dependency_plan. audit dumps the dep_audit log (optionally filtered by --target)."
```

---

## Task 21: polkit action + helper-invocation docs

**Files:**
- Modify: `packaging/polkit/org.inspectord.policy.in` (add the deps.install action)
- Create: `packaging/scripts/pkg-helper.in` (wrapper script template installed to `/usr/libexec/inspectord/pkg-helper`)
- Create: `docs/manual-acceptance/deps-acceptance.md` (manual acceptance procedure)

**Branch:** `task-21-deps-polkit`

The polkit policy file template is added to the existing packaging tree but isn't installed in this plan (the installer script lands later). Defining the action now means the polkit XML is reviewed and shippable.

- [ ] **Step 1: Extend the polkit policy**

Open `/home/eli/Development/inspectord/packaging/polkit/org.inspectord.policy.in` and append a new `<action>` element inside `<policyconfig>` (above the closing tag):

```xml
  <action id="org.inspectord.deps.install">
    <description>Install dependencies for inspectord</description>
    <message>Authentication is required to install system packages on behalf of inspectord.</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/libexec/inspectord/pkg-helper</annotate>
    <annotate key="org.freedesktop.policykit.exec.argv1">--plan-id</annotate>
  </action>
```

- [ ] **Step 2: Add the helper wrapper script template**

Write `/home/eli/Development/inspectord/packaging/scripts/pkg-helper.in`:

```bash
#!/usr/bin/env bash
# inspectord pkg-helper wrapper — installed to /usr/libexec/inspectord/pkg-helper.
# Invoked by pkexec via the org.inspectord.deps.install polkit action.
# Templated: @PYTHON@ substituted at install time.
set -euo pipefail

# pkexec strips the environment; preserve only what we need.
exec @PYTHON@ -m inspectord.dependencies.pkg_helper "$@"
```

Set the file executable in git: the install script (later phase) will copy it to /usr/libexec/ with mode 0755 owned by root.

- [ ] **Step 3: Manual acceptance procedure**

Write `/home/eli/Development/inspectord/docs/manual-acceptance/deps-acceptance.md`:

```markdown
# Dependency Manager — Manual Acceptance

This procedure verifies the dep manager end-to-end on a **real Arch / CachyOS host**.
The automated test suite uses fake backends; only this manual run touches `pacman`.

## Preconditions

- Arch family host with sudo or root.
- inspectord built from source and installed in a venv (`pip install -e '.[dev]'`).
- The inspectord daemon is **not** running.

## Acceptance steps

### 1. Bring up the daemon

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
rm -rf var/
inspectord --dev &
sleep 2
```

### 2. Status (should list 6 deps; some installed, some missing)

```bash
inspectorctl deps status
```

Expected: a table with rows for `aide`, `auditd`, `ebpf_features`, `journald`, `libudev`, `yara`.
The `Installed` column reflects your current system. `libudev` and `journald` should always
appear installed (they're part of systemd).

### 3. Plan (should propose installing what's missing)

```bash
inspectorctl deps plan --profile minimal
```

Expected: a plan id, listed items for each missing dep. If everything is already
installed, you'll get `Nothing to install`.

### 4. Install (the privileged path)

If any deps were missing in step 3, run:

```bash
sudo -E env "PATH=$PATH" inspectorctl deps install --profile minimal
```

(We use `sudo` here in dev because polkit policy isn't installed yet. In a real
package install, `inspectorctl deps install` would call `pkexec
/usr/libexec/inspectord/pkg-helper --plan-id <uuid>` instead and prompt for
auth via the polkit agent.)

Confirm at the prompt. Expected: `pacman -Sy` runs, then `pacman -S
--noconfirm --needed <packages>`, sidecar configs land in `/etc/audit/rules.d/`
and `/etc/systemd/journald.conf.d/`, systemd services start, and the verify
probes report green.

### 5. Verify and re-status

```bash
inspectorctl deps status
```

All required deps should now show `Installed=✓`, `Drop-in=✓` (for those with
configs), `Last verify=✓ pass`.

### 6. Audit trail

```bash
inspectorctl deps audit --target auditd
```

Expected: a chronological list of every action the dep manager took for `auditd`:
`plan_created`, `metadata_refresh`, `install`, `dropin_written`, `service_action`,
`verify_pass`.

### 7. Stop the daemon

```bash
kill %1
wait %1 2>/dev/null || true
```

## Rollback (if the install needs to be undone)

For each dep with a drop-in, remove our config file (the upstream package keeps its own):

```bash
sudo rm /etc/audit/rules.d/inspectord.rules
sudo rm /etc/systemd/journald.conf.d/inspectord.conf
sudo augenrules --load    # re-apply audit rules
sudo systemctl restart auditd
sudo systemctl restart systemd-journald
```

Third-party packages we installed (audit, aide, yara) are left in place by
design (spec §30 — uninstall does not remove third-party packages, only our
drop-ins).
```

- [ ] **Step 4: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-21-deps-polkit
git add packaging/polkit/org.inspectord.policy.in \
        packaging/scripts/pkg-helper.in \
        docs/manual-acceptance/deps-acceptance.md
git commit -m "chore(packaging): add deps.install polkit action + pkg-helper wrapper template + acceptance docs"
git push -u origin task-21-deps-polkit
gh pr create --base main --head task-21-deps-polkit \
  --title "chore(packaging): polkit action + pkg-helper wrapper + acceptance docs" \
  --body "Adds org.inspectord.deps.install polkit action and a wrapper script template for /usr/libexec/inspectord/pkg-helper. Adds the manual acceptance procedure used to verify the dep manager against a real Arch system (outside the automated test suite)."
```

---

## Task 22: Worker integration test (synthetic verify cycle)

**Files:**
- Create: `tests/integration/test_deps_worker_e2e.py`

**Branch:** `task-22-deps-worker-e2e`

The Phase 0 acceptance test already proves the daemon + healthcheck pipeline. This new integration test proves the **dependency_manager** worker emits state events through the same pipeline and into DuckDB. It uses the real daemon via `--dev`, no mocks — the verify probes will run real `systemctl is-active` and similar but the *test does not depend on what they return*; it only requires that events flow through.

- [ ] **Step 1: Write the test**

Write `tests/integration/test_deps_worker_e2e.py`:

```python
"""End-to-end deps worker integration test."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from inspectord.storage.db import Database


@pytest.mark.integration
def test_dependency_manager_emits_state_events(daemon: dict[str, object]) -> None:
    """Wait until the dep_manager worker writes at least one verify event to DuckDB."""
    tmp_path = daemon["tmp_path"]
    proc = daemon["proc"]
    assert isinstance(tmp_path, Path)

    # The worker is configured with interval_s=30 in dev_config; give it ~5s plus
    # the immediate first tick. If it never fires, the test fails fast at the
    # 20s deadline. Stop the daemon first because DuckDB holds an exclusive
    # write lock while running (see Phase 0 acceptance test).
    deadline = time.monotonic() + 20.0
    found = False
    db_path = tmp_path / "var" / "inspectord.duckdb"
    # Force the worker to tick at least once by sleeping briefly.
    time.sleep(2.0)
    # Now SIGTERM the daemon so we can query DuckDB.
    import signal as _signal
    proc.send_signal(_signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except Exception:  # noqa: BLE001
        proc.kill()

    while time.monotonic() < deadline and not found:
        if db_path.exists():
            with Database(db_path) as db:
                rows = db.query(
                    "SELECT COUNT(*) FROM events_enriched "
                    "WHERE module = 'dependency_manager'"
                ).fetchall()
                if rows[0][0] >= 1:
                    found = True
                    break
        time.sleep(0.2)
    assert found, "dependency_manager worker never wrote any event"
```

This test depends on the `daemon` fixture already in `tests/conftest.py` (from Phase 0). It uses an **early SIGTERM** trick: send SIGTERM ourselves so DuckDB releases its lock before we query.

Quirk: `conftest.py`'s `daemon` fixture also sends SIGTERM in its `finally`. Calling `proc.send_signal` twice is harmless. The fixture's `proc.wait` will return immediately on the second call.

- [ ] **Step 2: Run**

```bash
pytest -m integration tests/integration/test_deps_worker_e2e.py -v
pytest tests/ -v
```

Expected: the new integration test passes, all 130+ tests still green.

- [ ] **Step 3: Commit + PR**

```bash
ruff check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-22-deps-worker-e2e
git add tests/integration/test_deps_worker_e2e.py
git commit -m "test(integration): dependency_manager worker emits events end-to-end"
git push -u origin task-22-deps-worker-e2e
gh pr create --base main --head task-22-deps-worker-e2e \
  --title "test(integration): dep_manager worker end-to-end" \
  --body "Proves the dep_manager worker, when spawned by the supervisor, emits state events that land in DuckDB through the router and journal. Probes themselves may or may not succeed on the CI runner — the assertion is only that the worker produced ≥1 enriched event row."
```

---

## Task 23: Final test sweep + lint + plan retrospective

**Files:** none (verification only)

**Branch:** none (run inline on `main` after Task 22 lands)

- [ ] **Step 1: Full sweep**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
git checkout main && git pull origin main
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: all tests pass (target ~135–140 total); ruff clean; mypy clean.

If anything fails, open a `task-23-deps-fixups` branch, fix, PR, merge. If everything is green, no commit needed.

- [ ] **Step 2: Update the spec changelog**

Open `/home/eli/Development/inspectord/docs/superpowers/specs/2026-05-24-local-inspection-design.md` and bump the changelog:

| Version | Date | Summary |
| --- | --- | --- |
| 0.1.0 | 2026-05-24 | Initial draft. |
| 0.2.0 | 2026-05-24 | Added Dependency Management subsystem (§30): ... |
| **0.2.1** | **2026-05-24** | **dependency_manager subsystem implemented for the PacmanBackend + minimal-profile v1 manifests. CLI: `inspectorctl deps {status\|plan\|install\|audit}`. Manual acceptance procedure documented under `docs/manual-acceptance/deps-acceptance.md`.** |

Also bump `Spec version` in the header to `0.2.1`. Commit as `docs(spec): mark §30 PacmanBackend portion implemented in spec v0.2.1`.

- [ ] **Step 3: Final manual acceptance**

On a real Arch/CachyOS box, run through `docs/manual-acceptance/deps-acceptance.md` start to finish. If any step fails, open a follow-up task. If it all works, you're done — Phase 1's dependency_manager subsystem is shipped.

---

## Acceptance criteria (this plan complete)

After Task 22 merges and Task 23 sweep is green:

```bash
$ pytest tests/                         → ~135–140 passed
$ ruff check / ruff format / mypy        → clean
$ inspectorctl deps status               → table with 6 v1 deps
$ inspectorctl deps plan                 → JSON-ish plan listing what's missing
$ sudo -E inspectorctl deps install      → installs missing deps via pkg-helper,
                                           drops sidecar configs, enables services,
                                           runs verify probes (manual acceptance)
$ inspectorctl deps audit                → full audit trail of every action
```

The `dependency_manager` worker runs on a 30-s cadence (default) inside the daemon and emits one `dep_verified` / `dep_misconfigured` state event per dep per cycle, persisted to `events_enriched` and the hash-chained journal.

## What this plan deliberately defers

* **AptBackend / DnfBackend / ZypperBackend** — spec §30.4 says Phase 4.
* **Manifests for Suricata / rkhunter / ClamAV / GeoLite2 / nftables** — they ship with their collector plans (Suricata with NIDS, rkhunter with scanners, etc.).
* **First-run wizard integration (§19.1 step 0)** — wizard UX is its own deliverable; this plan exposes the IPC + CLI surface the wizard will call.
* **Tamper detection on our drop-ins** (`dep_dropin_tampered` events) — spec §30.8 — implementation is straightforward (hash on write, re-hash on verify) but adds complexity; deferred to the runtime-monitoring polish pass in Phase 5.
* **Web dashboard "Dependencies" panel** — the dashboard plan handles all 28 panels at once.
* **edit-with-backup activation** — utility exists (Task 11) but no v1 manifest triggers it; the first user will be a collector that needs to edit rsyslog or similar.

## Next plan after this one

`log_tailer + fim_watcher + enrichment + log parsers` — the first real collector slice that consumes journald, the audit log, and the package-manager log. With `dependency_manager` in place, the wizard can guarantee these inputs exist before the collectors come up.
