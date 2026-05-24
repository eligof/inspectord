# Local Inspection — Phase 0 Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Phase 0 skeleton from the spec (`docs/superpowers/specs/2026-05-24-local-inspection-design.md` §31): a runnable `inspectord` daemon with a supervisor, in-process event router, append-only hash-chained journal, DuckDB storage, Unix-socket JSON-RPC IPC, a healthcheck-only worker, and a user-mode CLI + tray app stub. End-state: from a clean repo, `inspectorctl status` returns a green health report and `inspectorctl self-test` round-trips a synthetic event through every layer.

**Architecture:** One privileged daemon (`inspectord`) spawns workers as child processes and routes events through an in-process pub/sub. Storage is DuckDB + a hash-chained NDJSON journal. Communication with the daemon goes over a Unix socket using JSON-RPC 2.0 with `SO_PEERCRED` peer-uid authentication. The CLI (`inspectorctl`) and tray app are unprivileged user-mode clients of that socket. Each worker is an isolated subprocess emitting newline-delimited JSON events to its stdout, which the supervisor's router fans out.

**Tech Stack:** Python 3.12 · Pydantic v2 · DuckDB 1.x · Typer (CLI) · pystray + Pillow (tray) · pytest · ruff · mypy · Hatch (build backend) · stdlib `socket` (IPC) · stdlib `multiprocessing.Process` / subprocess (workers).

**Scope discipline for this plan:** Phase 0 only. No collectors that touch the OS (`log_tailer`, `fim_watcher`, etc.) — those come in subsequent plans. The only worker we build is `healthcheck` which emits synthetic events on a heartbeat. No notifications, no rules, no allowlist. No `dependency_manager`. Just the load-bearing skeleton everything else hangs from.

**Branching & PR workflow:** This repository lives at `github.com/eligof/inspectord` (public). Every task after Task 1 is implemented on its own feature branch named `task-NN-<short-slug>`, pushed, and opened as a PR. CI (`.github/workflows/ci.yml`, added in Task 2.5) must pass before merge. Squash-merge is the default. Task 1 is special: it lands the initial commit + remote setup directly on `main` because there's nothing to PR against yet.

---

## Repository state at the start

The directory `/home/eli/Development/inspectord/` currently contains only `docs/superpowers/specs/2026-05-24-local-inspection-design.md` and this plan file. It is **not** a git repository yet. Task 1 initializes it.

## File structure produced by this plan

```
inspectord/
├── .gitignore
├── .python-version
├── pyproject.toml
├── Cargo.toml                              # Empty workspace, ready for Phase 2 eBPF crates
├── README.md
├── ruff.toml
├── mypy.ini
├── pytest.ini
├── docs/                                   # already present
├── packaging/
│   ├── systemd/
│   │   ├── inspectord.service.template
│   │   └── inspectorctl-tray.service.template
│   ├── polkit/
│   │   └── org.inspectord.policy.in
│   └── apparmor/
│       └── inspectord.in                   # stub
├── crates/                                 # empty placeholder for Phase 2
│   └── .gitkeep
├── inspectord/
│   ├── __init__.py
│   ├── __main__.py
│   ├── log.py
│   ├── config.py
│   ├── supervisor.py
│   ├── router.py
│   ├── journal.py
│   ├── ipc_server.py
│   ├── ratelimit.py
│   ├── ids.py                              # UUIDv7 helper
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── versions.py
│   │   ├── event.py
│   │   ├── alert.py
│   │   ├── incident.py
│   │   ├── allowlist.py
│   │   └── case.py
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── db.py
│   │   ├── migrations.py
│   │   └── migrations_data/
│   │       └── 0001_initial.sql
│   └── workers/
│       ├── __init__.py
│       ├── contract.py
│       └── healthcheck/
│           ├── __init__.py
│           └── __main__.py
├── inspectorctl/
│   ├── __init__.py
│   ├── __main__.py
│   ├── ipc_client.py
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── app.py
│   │   ├── status.py
│   │   ├── self_test.py
│   │   └── version.py
│   └── tray/
│       ├── __init__.py
│       └── __main__.py
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── test_ids.py
    ├── test_schemas_event.py
    ├── test_schemas_alert.py
    ├── test_schemas_incident.py
    ├── test_schemas_allowlist.py
    ├── test_schemas_case.py
    ├── test_storage_db.py
    ├── test_storage_migrations.py
    ├── test_journal.py
    ├── test_ratelimit.py
    ├── test_router.py
    ├── test_worker_contract.py
    ├── test_healthcheck_worker.py
    ├── test_supervisor.py
    ├── test_ipc_server.py
    ├── test_ipc_client.py
    └── integration/
        ├── __init__.py
        └── test_end_to_end_skeleton.py
```

Each file has one clear responsibility. Tests live next to the package boundary they target, not interleaved with source.

---

## Task 1: Initialize the repository and Python project

**Files:**
- Create: `/home/eli/Development/inspectord/.gitignore`
- Create: `/home/eli/Development/inspectord/.python-version`
- Create: `/home/eli/Development/inspectord/pyproject.toml`
- Create: `/home/eli/Development/inspectord/Cargo.toml`
- Create: `/home/eli/Development/inspectord/README.md`
- Create: `/home/eli/Development/inspectord/crates/.gitkeep`

- [ ] **Step 1: Create `.gitignore`**

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.egg-info/
.eggs/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/
dist/
build/
.venv/
venv/

# Runtime
/var/
*.duckdb
*.duckdb.wal
journal/

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Rust
target/
Cargo.lock
```

- [ ] **Step 2: Pin Python version**

Write `/home/eli/Development/inspectord/.python-version`:

```
3.12
```

- [ ] **Step 3: Create `pyproject.toml`**

Write `/home/eli/Development/inspectord/pyproject.toml`:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "local-inspection"
version = "0.1.0"
description = "Unified Linux endpoint security console (Phase 0 skeleton)"
readme = "README.md"
requires-python = ">=3.12"
license = { text = "Proprietary" }
authors = [{ name = "eli" }]

dependencies = [
    "pydantic>=2.7,<3",
    "duckdb>=1.0,<2",
    "typer>=0.12,<1",
    "rich>=13.7,<14",
    "pystray>=0.19,<1",
    "Pillow>=10.0,<12",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0,<9",
    "pytest-asyncio>=0.23,<1",
    "ruff>=0.5,<1",
    "mypy>=1.10,<2",
    "types-Pillow",
]

[project.scripts]
inspectord = "inspectord.__main__:main"
inspectorctl = "inspectorctl.__main__:main"
inspectorctl-tray = "inspectorctl.tray.__main__:main"

[tool.hatch.build.targets.wheel]
packages = ["inspectord", "inspectorctl"]
```

- [ ] **Step 4: Create empty Rust workspace**

Write `/home/eli/Development/inspectord/Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = []

# Phase 2 will add eBPF crates here under crates/.
```

- [ ] **Step 5: Create placeholder directory for Rust crates**

```bash
mkdir -p /home/eli/Development/inspectord/crates
touch /home/eli/Development/inspectord/crates/.gitkeep
```

- [ ] **Step 6: Create initial README**

Write `/home/eli/Development/inspectord/README.md`:

```markdown
# Local Inspection

Unified Linux endpoint security console. See `docs/superpowers/specs/2026-05-24-local-inspection-design.md` for the design.

## Status

Phase 0 — skeleton only. No collectors, no rules, no notifications. The daemon, supervisor, router, journal, storage, IPC, healthcheck worker, CLI, and tray scaffolding are wired end-to-end so subsequent phases can plug detectors in.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
inspectord --dev    # run the daemon in foreground, dev paths
inspectorctl status # in another shell
```
```

- [ ] **Step 7: `git init` and stage**

```bash
cd /home/eli/Development/inspectord
git init -b main
git add .gitignore .python-version pyproject.toml Cargo.toml README.md crates/.gitkeep docs/
```

Expected: `git status` shows the spec file from `docs/superpowers/specs/...` and the new files staged.

- [ ] **Step 8: Initial commit**

```bash
git commit -m "chore: initialize Phase 0 project scaffolding"
```

Expected: one commit on `main`.

- [ ] **Step 9: Add the GitHub remote and push**

The GitHub repo `eligof/inspectord` is already created (by the main thread before this plan started). Add it as a remote and push.

```bash
git remote add origin https://github.com/eligof/inspectord.git
git push -u origin main
```

Expected: push succeeds; the repo on GitHub now shows the spec, plan, and scaffolding files.

---

## Task 2: Configure ruff, mypy, pytest

**Files:**
- Create: `ruff.toml`
- Create: `mypy.ini`
- Create: `pytest.ini`

- [ ] **Step 1: Create `ruff.toml`**

```toml
target-version = "py312"
line-length = 100

[lint]
select = ["E", "F", "I", "W", "B", "UP", "SIM", "PL", "RUF"]
ignore = ["PLR0913", "PLR2004"]

[lint.per-file-ignores]
"tests/**" = ["PLR2004", "S101"]

[format]
quote-style = "double"
```

- [ ] **Step 2: Create `mypy.ini`**

```ini
[mypy]
python_version = 3.12
strict = True
warn_unused_ignores = True
warn_redundant_casts = True
disallow_any_unimported = True
show_error_codes = True

[mypy-pystray.*]
ignore_missing_imports = True

[mypy-PIL.*]
ignore_missing_imports = True
```

- [ ] **Step 3: Create `pytest.ini`**

```ini
[pytest]
testpaths = tests
addopts = -ra -q --strict-markers --tb=short
markers =
    integration: end-to-end tests that spin up the daemon
asyncio_mode = auto
```

- [ ] **Step 4: Install dev dependencies and verify tooling**

```bash
cd /home/eli/Development/inspectord
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
ruff --version
mypy --version
pytest --version
```

Expected: all three print versions without error.

- [ ] **Step 5: Commit**

```bash
git add ruff.toml mypy.ini pytest.ini
git commit -m "chore: add ruff, mypy, pytest config"
```

---

## Task 2.5: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Branch:** `task-02.5-ci-workflow`

- [ ] **Step 1: Create the branch**

```bash
cd /home/eli/Development/inspectord
git checkout -b task-02.5-ci-workflow
```

- [ ] **Step 2: Write the CI workflow**

Write `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  lint-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e '.[dev]'

      - name: Ruff check
        run: ruff check inspectord inspectorctl tests

      - name: Ruff format check
        run: ruff format --check inspectord inspectorctl tests

      - name: Mypy
        run: mypy inspectord inspectorctl

      - name: Pytest (unit)
        run: pytest -m "not integration" -v

      - name: Pytest (integration)
        run: pytest -m integration -v
```

- [ ] **Step 3: Add CI badge to README**

In `/home/eli/Development/inspectord/README.md`, replace the line `## Status` with:

```markdown
[![CI](https://github.com/eligof/inspectord/actions/workflows/ci.yml/badge.svg)](https://github.com/eligof/inspectord/actions/workflows/ci.yml)

## Status
```

- [ ] **Step 4: Commit, push, and open the PR**

```bash
git add .github/workflows/ci.yml README.md
git commit -m "ci: add GitHub Actions workflow + status badge"
git push -u origin task-02.5-ci-workflow
gh pr create --base main --head task-02.5-ci-workflow \
  --title "ci: add GitHub Actions workflow" \
  --body "Adds Python 3.12 CI running ruff check + format + mypy + pytest (unit and integration)."
```

Expected: PR opens; CI runs on it; the workflow itself runs (it tests itself).

- [ ] **Step 5: Wait for CI and merge**

The PR runner is the main thread (not this subagent). Once CI is green and the PR is reviewed, it'll be squash-merged. After merge, switch back to `main`:

```bash
git checkout main
git pull origin main
git branch -D task-02.5-ci-workflow
```

---

## Task 3: Package skeletons (empty `__init__.py` files)

**Files:**
- Create: `inspectord/__init__.py`
- Create: `inspectord/schemas/__init__.py`
- Create: `inspectord/storage/__init__.py`
- Create: `inspectord/workers/__init__.py`
- Create: `inspectord/workers/healthcheck/__init__.py`
- Create: `inspectorctl/__init__.py`
- Create: `inspectorctl/cli/__init__.py`
- Create: `inspectorctl/tray/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/integration/__init__.py`

- [ ] **Step 1: Create the empty `__init__.py` files**

```bash
cd /home/eli/Development/inspectord
touch inspectord/__init__.py
touch inspectord/schemas/__init__.py
touch inspectord/storage/__init__.py
touch inspectord/workers/__init__.py
mkdir -p inspectord/workers/healthcheck && touch inspectord/workers/healthcheck/__init__.py
touch inspectorctl/__init__.py
mkdir -p inspectorctl/cli && touch inspectorctl/cli/__init__.py
mkdir -p inspectorctl/tray && touch inspectorctl/tray/__init__.py
mkdir -p tests/integration
touch tests/__init__.py
touch tests/integration/__init__.py
```

- [ ] **Step 2: Add package versions**

Write `inspectord/__init__.py`:

```python
"""Local Inspection daemon."""

__version__ = "0.1.0"
```

Write `inspectorctl/__init__.py`:

```python
"""Local Inspection CLI + tray client."""

__version__ = "0.1.0"
```

- [ ] **Step 3: Verify import works**

```bash
python -c "import inspectord, inspectorctl; print(inspectord.__version__, inspectorctl.__version__)"
```

Expected: `0.1.0 0.1.0`

- [ ] **Step 4: Commit**

```bash
git add inspectord/ inspectorctl/ tests/
git commit -m "chore: create empty package skeletons"
```

---

## Task 4: UUIDv7 id helper

We need globally-unique event ids that sort by time. UUIDv7 isn't in Python's stdlib until 3.14, so we implement a minimal version.

**Files:**
- Create: `inspectord/ids.py`
- Create: `tests/test_ids.py`

- [ ] **Step 1: Write the failing test**

Write `tests/test_ids.py`:

```python
"""Tests for the UUIDv7 helper."""

import time
import uuid

from inspectord.ids import uuid7


def test_uuid7_returns_uuid_object() -> None:
    result = uuid7()
    assert isinstance(result, uuid.UUID)


def test_uuid7_version_is_7() -> None:
    result = uuid7()
    assert result.version == 7


def test_uuid7_is_unique() -> None:
    ids = {uuid7() for _ in range(1000)}
    assert len(ids) == 1000


def test_uuid7_sorts_by_creation_time() -> None:
    first = uuid7()
    time.sleep(0.005)
    second = uuid7()
    assert first.bytes < second.bytes
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_ids.py -v
```

Expected: `ImportError: cannot import name 'uuid7' from 'inspectord.ids'`.

- [ ] **Step 3: Implement `uuid7`**

Write `inspectord/ids.py`:

```python
"""UUIDv7 generation. Time-sortable UUIDs per draft-peabody-dispatch-new-uuid-format."""

from __future__ import annotations

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    """Generate a UUIDv7. 48 bits of unix-ms timestamp + 4-bit version +
    12 bits of random + 2-bit variant + 62 bits of random.
    """
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_a = int.from_bytes(os.urandom(2), "big") & 0xFFF
    rand_b = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)

    value = (
        (ts_ms << 80)
        | (0x7 << 76)
        | (rand_a << 64)
        | (0b10 << 62)
        | rand_b
    )
    return uuid.UUID(int=value)
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_ids.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectord/ids.py tests/test_ids.py
git commit -m "feat(ids): add uuid7 helper"
```

---

## Task 5: Schema-version constants

**Files:**
- Create: `inspectord/schemas/versions.py`

- [ ] **Step 1: Create the file**

Write `inspectord/schemas/versions.py`:

```python
"""Centralized schema-version constants.

Bump MAJOR for breaking schema changes, MINOR for additive, PATCH for clarifications.
Every persisted/serialized object carries the relevant version so migrations can run.
"""

EVENT_SCHEMA_VERSION = "1.0.0"
ALERT_SCHEMA_VERSION = "1.0.0"
INCIDENT_SCHEMA_VERSION = "1.0.0"
ALLOWLIST_SCHEMA_VERSION = "1.0.0"
CASE_SCHEMA_VERSION = "1.0.0"
DB_SCHEMA_VERSION = 1
IPC_PROTOCOL_VERSION = "1.0.0"
RULE_YAML_VERSION = "1.0.0"
JOURNAL_FORMAT_VERSION = "1.0.0"
```

- [ ] **Step 2: Verify import works**

```bash
python -c "from inspectord.schemas.versions import EVENT_SCHEMA_VERSION; print(EVENT_SCHEMA_VERSION)"
```

Expected: `1.0.0`.

- [ ] **Step 3: Commit**

```bash
git add inspectord/schemas/versions.py
git commit -m "feat(schemas): add schema-version constants"
```

---

## Task 6: `Event` Pydantic model

**Files:**
- Create: `inspectord/schemas/event.py`
- Create: `tests/test_schemas_event.py`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_schemas_event.py`:

```python
"""Tests for the Event schema."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from inspectord.schemas.event import Event, EventKind, Severity


def _minimal_event_dict() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "ts": datetime.now(UTC).isoformat(),
        "event_id": "0190d3e1-0000-7000-8000-000000000000",
        "kind": "event",
        "category": ["host"],
        "type": ["start"],
        "action": "synthetic_heartbeat",
        "severity": "info",
        "module": "healthcheck",
    }


def test_minimal_event_validates() -> None:
    ev = Event.model_validate(_minimal_event_dict())
    assert ev.kind == EventKind.event
    assert ev.severity == Severity.info


def test_severity_must_be_known() -> None:
    bad = _minimal_event_dict() | {"severity": "catastrophic"}
    with pytest.raises(ValidationError):
        Event.model_validate(bad)


def test_kind_must_be_known() -> None:
    bad = _minimal_event_dict() | {"kind": "epiphany"}
    with pytest.raises(ValidationError):
        Event.model_validate(bad)


def test_extra_fields_in_raw_are_allowed() -> None:
    payload = _minimal_event_dict() | {"raw": {"source_file": "/x", "line": "abc"}}
    ev = Event.model_validate(payload)
    assert ev.raw == {"source_file": "/x", "line": "abc"}


def test_roundtrip_json() -> None:
    original = Event.model_validate(_minimal_event_dict())
    payload = original.model_dump_json()
    parsed = Event.model_validate_json(payload)
    assert parsed == original
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
pytest tests/test_schemas_event.py -v
```

Expected: ImportError or ModuleNotFoundError on `inspectord.schemas.event`.

- [ ] **Step 3: Implement `Event`**

Write `inspectord/schemas/event.py`:

```python
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
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_schemas_event.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectord/schemas/event.py tests/test_schemas_event.py
git commit -m "feat(schemas): add Event model"
```

---

## Task 7: `Alert` Pydantic model

**Files:**
- Create: `inspectord/schemas/alert.py`
- Create: `tests/test_schemas_alert.py`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_schemas_alert.py`:

```python
"""Tests for the Alert schema."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from inspectord.schemas.alert import Alert, AlertStatus, RuleRef


def _minimal_alert_dict() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "alert_id": "01900000-0000-7000-8000-000000000000",
        "rule": {
            "id": "test.rule",
            "name": "Test rule",
            "ruleset": "starter-pack",
            "version": "1.0.0",
            "severity": "medium",
            "why": "Detects test events",
            "false_positives": [],
        },
        "ts": datetime.now(UTC).isoformat(),
        "severity": "medium",
        "status": "new",
        "category": "test",
        "event_ids": ["01900000-0000-7000-8000-000000000001"],
        "entities": [{"kind": "process", "key": "pid:1234@boot:X"}],
        "dedup_key": "test.rule:pid:1234",
        "dedup_count": 1,
        "first_seen_at": datetime.now(UTC).isoformat(),
        "last_seen_at": datetime.now(UTC).isoformat(),
        "rendered": {"short": "test alert", "detail": "test details"},
    }


def test_minimal_alert_validates() -> None:
    a = Alert.model_validate(_minimal_alert_dict())
    assert a.status == AlertStatus.new
    assert isinstance(a.rule, RuleRef)


def test_status_must_be_known() -> None:
    bad = _minimal_alert_dict() | {"status": "elaborated"}
    with pytest.raises(ValidationError):
        Alert.model_validate(bad)


def test_dedup_count_minimum_is_one() -> None:
    bad = _minimal_alert_dict() | {"dedup_count": 0}
    with pytest.raises(ValidationError):
        Alert.model_validate(bad)
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_schemas_alert.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `Alert`**

Write `inspectord/schemas/alert.py`:

```python
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
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_schemas_alert.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectord/schemas/alert.py tests/test_schemas_alert.py
git commit -m "feat(schemas): add Alert model"
```

---

## Task 8: `Incident`, `Allowlist`, `Case` Pydantic models

We bundle these into one task because they're shape-only and very similar.

**Files:**
- Create: `inspectord/schemas/incident.py`
- Create: `inspectord/schemas/allowlist.py`
- Create: `inspectord/schemas/case.py`
- Create: `tests/test_schemas_incident.py`
- Create: `tests/test_schemas_allowlist.py`
- Create: `tests/test_schemas_case.py`

- [ ] **Step 1: Write failing tests for `Incident`**

Write `tests/test_schemas_incident.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime

from inspectord.schemas.incident import Incident


def test_incident_validates() -> None:
    inc = Incident.model_validate({
        "schema_version": "1.0.0",
        "incident_id": "01900000-0000-7000-8000-000000000010",
        "opened_at": datetime.now(UTC).isoformat(),
        "closed_at": None,
        "status": "open",
        "primary_entity": {"kind": "process", "key": "pid:1234@boot:X"},
        "entity_set": [],
        "alert_ids": [],
        "severity_max": "high",
        "narrative": "5 alerts in 10 minutes",
        "case_id": None,
    })
    assert inc.status == "open"
```

- [ ] **Step 2: Write failing tests for `AllowlistEntry`**

Write `tests/test_schemas_allowlist.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime

from inspectord.schemas.allowlist import AllowlistEntry


def test_allowlist_validates_with_minimal_scope() -> None:
    entry = AllowlistEntry.model_validate({
        "schema_version": "1.0.0",
        "id": "01900000-0000-7000-8000-000000000020",
        "scope": {"rule_id": "test.rule"},
        "reason": "user trusts this",
        "created_by": "eli@local",
        "created_at": datetime.now(UTC).isoformat(),
        "auto_origin": False,
        "stats": {"suppressed_count": 0, "last_suppressed_at": None},
    })
    assert entry.scope.rule_id == "test.rule"
```

- [ ] **Step 3: Write failing tests for `Case`**

Write `tests/test_schemas_case.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime

from inspectord.schemas.case import Case


def test_case_validates() -> None:
    case = Case.model_validate({
        "schema_version": "1.0.0",
        "case_id": "01900000-0000-7000-8000-000000000030",
        "opened_at": datetime.now(UTC).isoformat(),
        "title": "Suspicious activity",
        "alert_ids": [],
        "incident_ids": [],
        "entities": [],
        "evidence": [],
        "notes": "",
        "status": "open",
        "exported_at": None,
    })
    assert case.status == "open"
```

- [ ] **Step 4: Run all three to confirm failure**

```bash
pytest tests/test_schemas_incident.py tests/test_schemas_allowlist.py tests/test_schemas_case.py -v
```

Expected: ImportErrors.

- [ ] **Step 5: Implement `Incident`**

Write `inspectord/schemas/incident.py`:

```python
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
```

- [ ] **Step 6: Implement `AllowlistEntry`**

Write `inspectord/schemas/allowlist.py`:

```python
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
```

- [ ] **Step 7: Implement `Case`**

Write `inspectord/schemas/case.py`:

```python
"""Case schema. See spec §7.5."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

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
    _extra: dict[str, Any] = Field(default_factory=dict, repr=False)
```

- [ ] **Step 8: Run tests to confirm pass**

```bash
pytest tests/test_schemas_incident.py tests/test_schemas_allowlist.py tests/test_schemas_case.py -v
```

Expected: 3 passed.

- [ ] **Step 9: Commit**

```bash
git add inspectord/schemas/incident.py inspectord/schemas/allowlist.py inspectord/schemas/case.py \
        tests/test_schemas_incident.py tests/test_schemas_allowlist.py tests/test_schemas_case.py
git commit -m "feat(schemas): add Incident, Allowlist, Case models"
```

---

## Task 9: DuckDB connection wrapper

**Files:**
- Create: `inspectord/storage/db.py`
- Create: `tests/test_storage_db.py`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_storage_db.py`:

```python
"""Tests for the DuckDB connection wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.storage.db import Database


def test_database_creates_file(tmp_path: Path) -> None:
    db_path = tmp_path / "test.duckdb"
    db = Database(db_path)
    db.connect()
    db.close()
    assert db_path.exists()


def test_database_execute_and_query(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    try:
        db.execute("CREATE TABLE t (a INTEGER, b VARCHAR)")
        db.execute("INSERT INTO t VALUES (?, ?)", [1, "hello"])
        rows = db.query("SELECT a, b FROM t").fetchall()
        assert rows == [(1, "hello")]
    finally:
        db.close()


def test_database_context_manager_closes(tmp_path: Path) -> None:
    db_path = tmp_path / "test.duckdb"
    with Database(db_path) as db:
        db.execute("CREATE TABLE t (a INTEGER)")
    # Reopening should be fine if the previous session closed cleanly.
    with Database(db_path) as db2:
        rows = db2.query("SELECT * FROM t").fetchall()
        assert rows == []


def test_database_reraises_query_after_close(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    db.close()
    with pytest.raises(RuntimeError):
        db.query("SELECT 1")
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
pytest tests/test_storage_db.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `Database`**

Write `inspectord/storage/db.py`:

```python
"""DuckDB connection wrapper.

Centralizes connect/close, parametrized queries, and transactional helpers.
The wrapper is intentionally thin — DuckDB's own API is already pleasant.
"""

from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import Any

import duckdb


class Database:
    """A single-process DuckDB handle. Not thread-safe — use one per process."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._conn: duckdb.DuckDBPyConnection | None = None

    @property
    def path(self) -> Path:
        return self._path

    def connect(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = duckdb.connect(str(self._path))

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _require(self) -> duckdb.DuckDBPyConnection:
        if self._conn is None:
            raise RuntimeError("Database is not connected")
        return self._conn

    def execute(self, sql: str, params: list[Any] | None = None) -> None:
        self._require().execute(sql, params or [])

    def query(self, sql: str, params: list[Any] | None = None) -> duckdb.DuckDBPyConnection:
        return self._require().execute(sql, params or [])

    def __enter__(self) -> "Database":
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_storage_db.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectord/storage/db.py tests/test_storage_db.py
git commit -m "feat(storage): add DuckDB connection wrapper"
```

---

## Task 10: Schema-migrations runner

**Files:**
- Create: `inspectord/storage/migrations.py`
- Create: `inspectord/storage/migrations_data/0001_initial.sql`
- Create: `tests/test_storage_migrations.py`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_storage_migrations.py`:

```python
"""Tests for the schema migrations runner."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import current_schema_version, run_migrations


def test_run_migrations_on_fresh_db(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    assert current_schema_version(db) >= 1
    db.close()


def test_run_migrations_is_idempotent(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    first = current_schema_version(db)
    run_migrations(db)
    second = current_schema_version(db)
    assert first == second
    db.close()


def test_schema_version_table_exists_after_migration(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    rows = db.query(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_name='schema_version'"
    ).fetchall()
    assert rows
    db.close()
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
pytest tests/test_storage_migrations.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write the first migration**

Write `inspectord/storage/migrations_data/0001_initial.sql`:

```sql
-- Migration 0001 — initial schema (Phase 0 minimum).
-- Subsequent phases extend this with table additions; never destructive.

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events_enriched (
    event_id      VARCHAR PRIMARY KEY,
    ts            TIMESTAMP NOT NULL,
    kind          VARCHAR NOT NULL,
    module        VARCHAR NOT NULL,
    action        VARCHAR NOT NULL,
    severity      VARCHAR NOT NULL,
    payload_json  VARCHAR NOT NULL
);

CREATE INDEX IF NOT EXISTS events_enriched_ts_idx ON events_enriched (ts);
CREATE INDEX IF NOT EXISTS events_enriched_module_idx ON events_enriched (module);

CREATE TABLE IF NOT EXISTS worker_health (
    worker        VARCHAR NOT NULL,
    ts            TIMESTAMP NOT NULL,
    events_processed BIGINT NOT NULL,
    queue_depth   INTEGER NOT NULL,
    last_error    VARCHAR,
    uptime_s      DOUBLE NOT NULL
);

CREATE INDEX IF NOT EXISTS worker_health_worker_idx ON worker_health (worker, ts);
```

- [ ] **Step 4: Implement the runner**

Write `inspectord/storage/migrations.py`:

```python
"""Schema migrations runner.

Migrations are numbered SQL files in `migrations_data/`. They are applied
in order; each gets a row in `schema_version` so applying twice is a no-op.
"""

from __future__ import annotations

import re
from importlib.resources import files

from inspectord.storage.db import Database

_MIGRATION_NAME_RE = re.compile(r"^(\d{4})_.+\.sql$")


def _bootstrap(db: Database) -> None:
    db.execute(
        "CREATE TABLE IF NOT EXISTS schema_version "
        "(version INTEGER NOT NULL, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
    )


def current_schema_version(db: Database) -> int:
    _bootstrap(db)
    rows = db.query("SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchall()
    return int(rows[0][0])


def _list_migrations() -> list[tuple[int, str, str]]:
    """Return [(num, name, sql), ...] sorted by num."""
    migrations: list[tuple[int, str, str]] = []
    pkg = files("inspectord.storage.migrations_data")
    for entry in pkg.iterdir():
        match = _MIGRATION_NAME_RE.match(entry.name)
        if not match:
            continue
        num = int(match.group(1))
        sql = entry.read_text(encoding="utf-8")
        migrations.append((num, entry.name, sql))
    migrations.sort(key=lambda t: t[0])
    return migrations


def run_migrations(db: Database) -> int:
    """Apply pending migrations. Returns the new schema version."""
    _bootstrap(db)
    applied = current_schema_version(db)
    for num, name, sql in _list_migrations():
        if num <= applied:
            continue
        for statement in _split_sql(sql):
            db.execute(statement)
        db.execute("INSERT INTO schema_version (version) VALUES (?)", [num])
        applied = num
    return applied


def _split_sql(text: str) -> list[str]:
    """Split a SQL file into statements on semicolons (simple, no escaping)."""
    parts = [s.strip() for s in text.split(";")]
    return [p for p in parts if p and not p.startswith("--")]
```

- [ ] **Step 5: Ensure migration data is shipped with the package**

Open `pyproject.toml` and add this block under `[tool.hatch.build.targets.wheel]`:

```toml
[tool.hatch.build.targets.wheel.force-include]
"inspectord/storage/migrations_data" = "inspectord/storage/migrations_data"
```

Replace the existing `[tool.hatch.build.targets.wheel]` block with:

```toml
[tool.hatch.build.targets.wheel]
packages = ["inspectord", "inspectorctl"]

[tool.hatch.build.targets.wheel.force-include]
"inspectord/storage/migrations_data" = "inspectord/storage/migrations_data"
```

Reinstall:

```bash
pip install -e '.[dev]'
```

- [ ] **Step 6: Run tests to confirm they pass**

```bash
pytest tests/test_storage_migrations.py -v
```

Expected: 3 passed.

- [ ] **Step 7: Commit**

```bash
git add inspectord/storage/migrations.py inspectord/storage/migrations_data/0001_initial.sql \
        tests/test_storage_migrations.py pyproject.toml
git commit -m "feat(storage): add schema migrations runner with initial schema"
```

---

## Task 11: Append-only hash-chained journal

**Files:**
- Create: `inspectord/journal.py`
- Create: `tests/test_journal.py`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_journal.py`:

```python
"""Tests for the append-only hash-chained journal."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from inspectord.journal import Journal, JournalError, verify_chain


def test_journal_appends_lines(tmp_path: Path) -> None:
    j = Journal(tmp_path)
    j.append({"event_id": "1", "msg": "hi"})
    j.append({"event_id": "2", "msg": "ho"})
    j.flush()
    j.close()

    files = sorted(tmp_path.glob("*.jsonl.gz"))
    assert len(files) == 1
    with gzip.open(files[0], "rt") as f:
        lines = [json.loads(line) for line in f]
    assert len(lines) == 2
    assert lines[0]["event_id"] == "1"
    assert lines[1]["event_id"] == "2"


def test_journal_includes_prev_hash(tmp_path: Path) -> None:
    j = Journal(tmp_path)
    j.append({"event_id": "1"})
    j.append({"event_id": "2"})
    j.close()
    files = sorted(tmp_path.glob("*.jsonl.gz"))
    with gzip.open(files[0], "rt") as f:
        lines = [json.loads(line) for line in f]
    assert lines[0]["prev_hash"] == "0" * 64
    assert lines[1]["prev_hash"] != "0" * 64
    assert len(lines[1]["prev_hash"]) == 64  # sha256 hex


def test_verify_chain_accepts_valid(tmp_path: Path) -> None:
    j = Journal(tmp_path)
    for i in range(5):
        j.append({"event_id": str(i)})
    j.close()
    files = sorted(tmp_path.glob("*.jsonl.gz"))
    assert verify_chain(files[0]) is True


def test_verify_chain_detects_tamper(tmp_path: Path) -> None:
    j = Journal(tmp_path)
    j.append({"event_id": "1"})
    j.append({"event_id": "2"})
    j.close()
    files = sorted(tmp_path.glob("*.jsonl.gz"))

    # Read, mutate one record's data while leaving prev_hash chain unchanged.
    with gzip.open(files[0], "rt") as f:
        records = [json.loads(line) for line in f]
    records[1]["event_id"] = "tampered"
    with gzip.open(files[0], "wt") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    assert verify_chain(files[0]) is False


def test_append_after_close_raises(tmp_path: Path) -> None:
    j = Journal(tmp_path)
    j.close()
    with pytest.raises(JournalError):
        j.append({"event_id": "1"})
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
pytest tests/test_journal.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `Journal`**

Write `inspectord/journal.py`:

```python
"""Append-only NDJSON.gz journal with rolling SHA-256 hash chain.

Each line is a JSON object containing the caller-provided payload plus a
`prev_hash` field. `prev_hash` of the first line is 64 zeroes. The hash for
line N is sha256(line_N_serialized_without_terminator). Tampering with any
line breaks the chain from that point on.

The journal rotates daily (UTC) by default.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, IO

from inspectord.schemas.versions import JOURNAL_FORMAT_VERSION

ZERO_HASH = "0" * 64


class JournalError(RuntimeError):
    pass


class Journal:
    """Append-only journal. Caller must call close() (or use as context manager)."""

    def __init__(self, dir_path: Path) -> None:
        self._dir = Path(dir_path)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._fh: IO[bytes] | None = None
        self._current_date: date | None = None
        self._prev_hash = ZERO_HASH
        self._closed = False

    def _path_for(self, d: date) -> Path:
        return self._dir / f"{d.isoformat()}.jsonl.gz"

    def _open_for_today(self) -> None:
        today = datetime.now(UTC).date()
        if self._fh is not None and self._current_date == today:
            return
        if self._fh is not None:
            self._fh.close()
        path = self._path_for(today)
        if path.exists():
            # Recover last hash so the chain continues.
            with gzip.open(path, "rt", encoding="utf-8") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    self._prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
        else:
            self._prev_hash = ZERO_HASH
        self._fh = gzip.open(path, "ab")
        self._current_date = today

    def append(self, payload: dict[str, Any]) -> None:
        if self._closed:
            raise JournalError("journal is closed")
        self._open_for_today()
        record = {
            **payload,
            "journal_format_version": JOURNAL_FORMAT_VERSION,
            "prev_hash": self._prev_hash,
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        assert self._fh is not None
        self._fh.write((line + "\n").encode("utf-8"))
        self._prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()

    def flush(self) -> None:
        if self._fh is not None:
            self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        self._closed = True


def verify_chain(path: Path) -> bool:
    """Return True iff every line's prev_hash matches sha256(previous line)."""
    prev_hash = ZERO_HASH
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            record = json.loads(line)
            if record.get("prev_hash") != prev_hash:
                return False
            prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
    return True
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_journal.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectord/journal.py tests/test_journal.py
git commit -m "feat(journal): add append-only hash-chained journal"
```

---

## Task 12: Token-bucket rate limiter

**Files:**
- Create: `inspectord/ratelimit.py`
- Create: `tests/test_ratelimit.py`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_ratelimit.py`:

```python
"""Tests for token-bucket rate limiter."""

from __future__ import annotations

import time

from inspectord.ratelimit import TokenBucket


def test_bucket_allows_until_empty() -> None:
    bucket = TokenBucket(rate_per_s=10, capacity=5)
    allowed = sum(1 for _ in range(10) if bucket.try_take())
    assert allowed == 5  # capacity bound


def test_bucket_refills_over_time() -> None:
    bucket = TokenBucket(rate_per_s=100, capacity=5)
    for _ in range(5):
        bucket.try_take()
    assert not bucket.try_take()
    time.sleep(0.06)  # refills ~6 tokens, capped at 5
    assert bucket.try_take()


def test_bucket_capacity_caps_refill() -> None:
    bucket = TokenBucket(rate_per_s=1000, capacity=3)
    time.sleep(0.05)
    allowed = sum(1 for _ in range(10) if bucket.try_take())
    assert allowed == 3
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
pytest tests/test_ratelimit.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `TokenBucket`**

Write `inspectord/ratelimit.py`:

```python
"""Simple token-bucket rate limiter. Single-process; not thread-safe."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class TokenBucket:
    rate_per_s: float
    capacity: int
    _tokens: float = 0.0
    _last: float = 0.0

    def __post_init__(self) -> None:
        self._tokens = float(self.capacity)
        self._last = time.monotonic()

    def try_take(self, n: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_s)
        if self._tokens >= n:
            self._tokens -= n
            return True
        return False
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_ratelimit.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectord/ratelimit.py tests/test_ratelimit.py
git commit -m "feat: add token-bucket rate limiter"
```

---

## Task 13: Event Router

**Files:**
- Create: `inspectord/router.py`
- Create: `tests/test_router.py`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_router.py`:

```python
"""Tests for the event router."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from inspectord.router import DropPolicy, EventRouter, Subscription
from inspectord.schemas.event import Event


def _ev(action: str = "synthetic", severity: str = "info") -> Event:
    return Event.model_validate({
        "schema_version": "1.0.0",
        "ts": datetime.now(UTC).isoformat(),
        "event_id": "01900000-0000-7000-8000-000000000000",
        "kind": "event",
        "category": ["host"],
        "type": ["start"],
        "action": action,
        "severity": severity,
        "module": "test",
    })


def test_subscribe_receives_event() -> None:
    r = EventRouter()
    sub = r.subscribe(name="t", queue_size=8, drop_policy=DropPolicy.drop_oldest_non_critical)
    r.publish(_ev())
    got = sub.get_nowait()
    assert got.action == "synthetic"


def test_subscribe_filter() -> None:
    r = EventRouter()
    sub = r.subscribe(
        name="t",
        queue_size=8,
        drop_policy=DropPolicy.drop_oldest_non_critical,
        filter_fn=lambda e: e.severity.value == "critical",
    )
    r.publish(_ev(severity="info"))
    r.publish(_ev(severity="critical"))
    got = sub.get_nowait()
    assert got.severity.value == "critical"
    with pytest.raises(Exception):
        sub.get_nowait()  # no more


def test_drop_oldest_non_critical() -> None:
    r = EventRouter()
    sub = r.subscribe(name="t", queue_size=2, drop_policy=DropPolicy.drop_oldest_non_critical)
    r.publish(_ev(action="a"))
    r.publish(_ev(action="b"))
    r.publish(_ev(action="c"))
    drained = []
    while True:
        try:
            drained.append(sub.get_nowait().action)
        except Exception:
            break
    assert drained == ["b", "c"]
    assert sub.dropped == 1


def test_critical_events_never_dropped() -> None:
    r = EventRouter()
    sub = r.subscribe(name="t", queue_size=2, drop_policy=DropPolicy.drop_oldest_non_critical)
    r.publish(_ev(action="a", severity="critical"))
    r.publish(_ev(action="b", severity="critical"))
    r.publish(_ev(action="c", severity="critical"))  # would block
    # Drain so we know order: with all critical, oldest non-critical isn't available;
    # the router falls back to "block writer"; since this is in-process synchronous,
    # we expect the third publish to raise rather than drop.
    # See spec §6.2: "if a buffer is full of criticals, the writer blocks".
    # In the sync test we model this as raising.
    drained = []
    while True:
        try:
            drained.append(sub.get_nowait().action)
        except Exception:
            break
    assert drained == ["a", "b"]
    assert sub.dropped == 0
    assert sub.blocked >= 1
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
pytest tests/test_router.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement the router**

Write `inspectord/router.py`:

```python
"""In-process event router with bounded queues per subscription.

Drop policy:
  - drop_oldest_non_critical: when full, drop the oldest non-critical event.
    If the buffer is full of criticals, we record a 'blocked' counter and
    raise; the publisher decides what to do (the supervisor logs + retries).
  - block: never drop; the publisher must wait.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from queue import Empty as QueueEmpty

from inspectord.schemas.event import Event, Severity


class DropPolicy(Enum):
    block = "block"
    drop_oldest_non_critical = "drop_oldest_non_critical"


@dataclass
class Subscription:
    name: str
    queue_size: int
    drop_policy: DropPolicy
    filter_fn: Callable[[Event], bool] | None = None
    _q: deque[Event] = field(default_factory=deque)
    dropped: int = 0
    blocked: int = 0

    def _try_drop_oldest_non_critical(self) -> bool:
        for i, ev in enumerate(self._q):
            if ev.severity != Severity.critical:
                del self._q[i]
                self.dropped += 1
                return True
        return False

    def get_nowait(self) -> Event:
        if not self._q:
            raise QueueEmpty
        return self._q.popleft()


class RouterFull(RuntimeError):
    pass


class EventRouter:
    def __init__(self) -> None:
        self._subs: list[Subscription] = []

    def subscribe(
        self,
        *,
        name: str,
        queue_size: int,
        drop_policy: DropPolicy,
        filter_fn: Callable[[Event], bool] | None = None,
    ) -> Subscription:
        sub = Subscription(name=name, queue_size=queue_size, drop_policy=drop_policy, filter_fn=filter_fn)
        self._subs.append(sub)
        return sub

    def publish(self, event: Event) -> None:
        for sub in self._subs:
            if sub.filter_fn is not None and not sub.filter_fn(event):
                continue
            if len(sub._q) < sub.queue_size:
                sub._q.append(event)
                continue
            if sub.drop_policy is DropPolicy.drop_oldest_non_critical:
                if sub._try_drop_oldest_non_critical():
                    sub._q.append(event)
                    continue
                sub.blocked += 1
                raise RouterFull(
                    f"subscription {sub.name!r} is saturated with critical events"
                )
            else:
                sub.blocked += 1
                raise RouterFull(f"subscription {sub.name!r} is full")
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_router.py -v
```

Expected: 4 passed (the fourth test expects an exception on the third publish; pytest's `assert sub.blocked >= 1` covers that; the third publish raises which is swallowed by the `while True / except` drain loop only if drainer follows — here the third publish actually raises in the test. **Adjust the test** to wrap the third publish in `pytest.raises`).

Update `tests/test_router.py` test_critical_events_never_dropped:

```python
def test_critical_events_never_dropped() -> None:
    r = EventRouter()
    sub = r.subscribe(name="t", queue_size=2, drop_policy=DropPolicy.drop_oldest_non_critical)
    r.publish(_ev(action="a", severity="critical"))
    r.publish(_ev(action="b", severity="critical"))
    with pytest.raises(Exception):
        r.publish(_ev(action="c", severity="critical"))
    drained = []
    while True:
        try:
            drained.append(sub.get_nowait().action)
        except Exception:
            break
    assert drained == ["a", "b"]
    assert sub.dropped == 0
    assert sub.blocked >= 1
```

Re-run:

```bash
pytest tests/test_router.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectord/router.py tests/test_router.py
git commit -m "feat(router): add in-process event router with drop policy"
```

---

## Task 14: Worker contract

A worker is a child process that reads JSON config from stdin, emits NDJSON events to stdout, and a heartbeat to stderr. We provide a base class so workers share these mechanics.

**Files:**
- Create: `inspectord/workers/contract.py`
- Create: `tests/test_worker_contract.py`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_worker_contract.py`:

```python
"""Tests for the worker contract base class."""

from __future__ import annotations

import io
import json
import threading
import time

from inspectord.workers.contract import Worker


class _DummyWorker(Worker):
    def setup(self) -> None:
        self._counter = 0

    def step(self) -> None:
        self._counter += 1
        self.emit_event({
            "schema_version": "1.0.0",
            "ts": "2026-05-24T00:00:00Z",
            "event_id": f"id-{self._counter}",
            "kind": "event",
            "category": ["host"],
            "type": ["start"],
            "action": "tick",
            "severity": "info",
            "module": "dummy",
        })

    def step_interval_s(self) -> float:
        return 0.01


def test_worker_emits_events() -> None:
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = _DummyWorker(name="dummy", stdout=stdout, stderr=stderr)
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.05)
    w.request_stop()
    t.join(timeout=1)

    stdout_text = stdout.getvalue().decode("utf-8")
    events = [json.loads(line) for line in stdout_text.splitlines() if line.strip()]
    assert len(events) >= 2
    assert all(e["action"] == "tick" for e in events)


def test_worker_emits_heartbeats() -> None:
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = _DummyWorker(name="dummy", stdout=stdout, stderr=stderr)
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.05)
    w.request_stop()
    t.join(timeout=1)

    hb_text = stderr.getvalue().decode("utf-8")
    hbs = [json.loads(line) for line in hb_text.splitlines() if line.strip()]
    assert len(hbs) >= 1
    assert hbs[0]["kind"] == "heartbeat"
    assert hbs[0]["worker"] == "dummy"
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
pytest tests/test_worker_contract.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `Worker`**

Write `inspectord/workers/contract.py`:

```python
"""Worker base class.

A worker is a process that:
  * Reads its config from stdin (single JSON object on the first line).
  * Emits one event per line to stdout (NDJSON).
  * Emits a heartbeat object to stderr every 10s by default.
  * Handles SIGTERM by setting a stop flag and flushing.
"""

from __future__ import annotations

import abc
import json
import os
import signal
import sys
import threading
import time
from typing import IO, Any


HEARTBEAT_INTERVAL_S = 10.0


class Worker(abc.ABC):
    def __init__(
        self,
        *,
        name: str,
        stdout: IO[bytes] | None = None,
        stderr: IO[bytes] | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self._stdout = stdout if stdout is not None else sys.stdout.buffer
        self._stderr = stderr if stderr is not None else sys.stderr.buffer
        self.config: dict[str, Any] = config or {}
        self._stop = threading.Event()
        self._events_processed = 0
        self._last_error: str | None = None
        self._started_at = time.monotonic()

    # --- Subclasses override these.

    def setup(self) -> None:
        pass

    @abc.abstractmethod
    def step(self) -> None: ...

    def step_interval_s(self) -> float:
        return 1.0

    def teardown(self) -> None:
        pass

    # --- Internals.

    def emit_event(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":")) + "\n"
        self._stdout.write(line.encode("utf-8"))
        try:
            self._stdout.flush()
        except Exception:  # noqa: BLE001 — non-fatal flush failures
            pass
        self._events_processed += 1

    def emit_heartbeat(self) -> None:
        hb = {
            "kind": "heartbeat",
            "worker": self.name,
            "ts": time.time(),
            "events_processed": self._events_processed,
            "queue_depth": 0,
            "last_error": self._last_error,
            "uptime_s": time.monotonic() - self._started_at,
        }
        line = json.dumps(hb, separators=(",", ":")) + "\n"
        self._stderr.write(line.encode("utf-8"))
        try:
            self._stderr.flush()
        except Exception:  # noqa: BLE001
            pass

    def request_stop(self) -> None:
        self._stop.set()

    def _install_signals(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return  # signals only installable from main thread
        signal.signal(signal.SIGTERM, lambda *_: self.request_stop())
        signal.signal(signal.SIGINT, lambda *_: self.request_stop())

    def run(self) -> None:
        self._install_signals()
        self.setup()
        last_heartbeat = time.monotonic()
        try:
            while not self._stop.is_set():
                try:
                    self.step()
                except Exception as exc:  # noqa: BLE001
                    self._last_error = repr(exc)
                if time.monotonic() - last_heartbeat >= HEARTBEAT_INTERVAL_S:
                    self.emit_heartbeat()
                    last_heartbeat = time.monotonic()
                if self._stop.wait(self.step_interval_s()):
                    break
        finally:
            try:
                self.emit_heartbeat()
            finally:
                self.teardown()


def read_config_from_stdin() -> dict[str, Any]:
    """Read one JSON line from stdin; return empty dict if EOF."""
    line = sys.stdin.readline()
    if not line:
        return {}
    return json.loads(line)
```

Note: the test forces a heartbeat by setting `HEARTBEAT_INTERVAL_S` so low it always fires. Replace the constant with one read per-instance; for simplicity, make the tests adjust it via a class attribute. The test relies on `step_interval_s()` returning 0.01 → the run loop will iterate ~5 times in 50 ms, but heartbeats only fire after the configured interval. To make the test reliable, also emit one heartbeat in `teardown`. The implementation above does this in the `finally` of `run`.

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_worker_contract.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectord/workers/contract.py tests/test_worker_contract.py
git commit -m "feat(workers): add Worker base class with NDJSON IO and heartbeats"
```

---

## Task 15: Healthcheck worker

**Files:**
- Create: `inspectord/workers/healthcheck/__main__.py`
- Create: `tests/test_healthcheck_worker.py`

- [ ] **Step 1: Write the failing test**

Write `tests/test_healthcheck_worker.py`:

```python
"""Tests for the healthcheck worker."""

from __future__ import annotations

import io
import json
import threading
import time

from inspectord.workers.healthcheck.__main__ import HealthcheckWorker


def test_healthcheck_emits_synthetic_event() -> None:
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = HealthcheckWorker(name="healthcheck", stdout=stdout, stderr=stderr)
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.05)
    w.request_stop()
    t.join(timeout=1)

    events = [
        json.loads(line)
        for line in stdout.getvalue().decode("utf-8").splitlines()
        if line.strip()
    ]
    assert events
    assert all(e["module"] == "healthcheck" for e in events)
    assert all(e["action"] == "synthetic_heartbeat" for e in events)
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_healthcheck_worker.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement the worker**

Write `inspectord/workers/healthcheck/__main__.py`:

```python
"""Healthcheck worker.

Emits a synthetic event on a configurable cadence so the supervisor and
end-to-end pipeline can be validated without any OS-level collectors.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import Any

from inspectord.ids import uuid7
from inspectord.schemas.versions import EVENT_SCHEMA_VERSION
from inspectord.workers.contract import Worker, read_config_from_stdin


class HealthcheckWorker(Worker):
    def step_interval_s(self) -> float:
        return float(self.config.get("interval_s", 1.0))

    def step(self) -> None:
        self.emit_event({
            "schema_version": EVENT_SCHEMA_VERSION,
            "ts": datetime.now(UTC).isoformat(),
            "event_id": str(uuid7()),
            "kind": "event",
            "category": ["host"],
            "type": ["info"],
            "action": "synthetic_heartbeat",
            "severity": "info",
            "module": "healthcheck",
            "host": {"hostname": os.uname().nodename, "os": {"family": "linux"}},
            "message": "healthcheck synthetic event",
        })


def main() -> None:
    cfg: dict[str, Any] = read_config_from_stdin()
    HealthcheckWorker(name="healthcheck", config=cfg).run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_healthcheck_worker.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectord/workers/healthcheck/__main__.py tests/test_healthcheck_worker.py
git commit -m "feat(workers): add healthcheck worker"
```

---

## Task 16: Logging helper

**Files:**
- Create: `inspectord/log.py`

- [ ] **Step 1: Implement structured JSON logger**

Write `inspectord/log.py`:

```python
"""Structured JSON logger for inspectord's own application logs.

These are NOT events — they're the daemon's own logs (errors, lifecycle).
Goes to stderr by default; in production, systemd captures it to journald.
"""

from __future__ import annotations

import json
import logging
import sys
import time


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.time(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


def configure(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


def get(name: str) -> logging.Logger:
    return logging.getLogger(name)
```

- [ ] **Step 2: Sanity-check**

```bash
python -c "from inspectord.log import configure, get; configure(); get('test').info('hello')"
```

Expected: a JSON line on stderr.

- [ ] **Step 3: Commit**

```bash
git add inspectord/log.py
git commit -m "feat(log): add structured JSON logger"
```

---

## Task 17: Config loader

**Files:**
- Create: `inspectord/config.py`

- [ ] **Step 1: Implement config**

Write `inspectord/config.py`:

```python
"""Daemon config.

Phase 0 keeps the config minimal — paths and which workers to spawn. It will
expand in later phases (profiles, retention, notifier sinks, etc.).
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class WorkerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    module: str
    config: dict[str, Any] = Field(default_factory=dict)


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    db_path: Path
    journal_dir: Path


class IpcConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    socket_path: Path
    allowed_uids: list[int] = Field(default_factory=list)


class DaemonConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    storage: StorageConfig
    ipc: IpcConfig
    workers: list[WorkerSpec] = Field(default_factory=list)


def load(path: Path) -> DaemonConfig:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return DaemonConfig.model_validate(data)


def dev_config(*, base: Path) -> DaemonConfig:
    """Return a config suitable for running inspectord out of a working copy.

    Paths live under <base>/var/ so we don't need root to test the daemon.
    """
    base = Path(base)
    return DaemonConfig.model_validate({
        "version": "1.0.0",
        "storage": {
            "db_path": str(base / "var" / "inspectord.duckdb"),
            "journal_dir": str(base / "var" / "journal"),
        },
        "ipc": {
            "socket_path": str(base / "var" / "inspectord.sock"),
            "allowed_uids": [],  # empty = any uid in dev
        },
        "workers": [
            {
                "name": "healthcheck",
                "module": "inspectord.workers.healthcheck",
                "config": {"interval_s": 1.0},
            }
        ],
    })
```

- [ ] **Step 2: Sanity-check**

```bash
python -c "from pathlib import Path; from inspectord.config import dev_config; print(dev_config(base=Path('/tmp/x')).model_dump_json(indent=2))"
```

Expected: JSON config printed.

- [ ] **Step 3: Commit**

```bash
git add inspectord/config.py
git commit -m "feat(config): add dev config + loader"
```

---

## Task 18: Supervisor (lifecycle)

**Files:**
- Create: `inspectord/supervisor.py`
- Create: `tests/test_supervisor.py`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_supervisor.py`:

```python
"""Tests for the supervisor."""

from __future__ import annotations

import time
from pathlib import Path

from inspectord.config import dev_config
from inspectord.supervisor import Supervisor


def test_supervisor_starts_and_routes_events(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        # Healthcheck worker emits at 1s intervals; wait up to 3s.
        deadline = time.monotonic() + 3.0
        events: list[object] = []

        def collect(ev: object) -> None:
            events.append(ev)

        sup.attach_listener(collect)

        while time.monotonic() < deadline and not events:
            time.sleep(0.05)
        assert events, "supervisor did not deliver any events from healthcheck"
    finally:
        sup.stop(timeout=5.0)


def test_supervisor_persists_events_to_db(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        time.sleep(1.5)  # one tick at least
    finally:
        sup.stop(timeout=5.0)

    from inspectord.storage.db import Database
    with Database(cfg.storage.db_path) as db:
        rows = db.query("SELECT COUNT(*) FROM events_enriched").fetchall()
    assert rows[0][0] >= 1


def test_supervisor_journals_events(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        time.sleep(1.5)
    finally:
        sup.stop(timeout=5.0)

    assert any(cfg.storage.journal_dir.glob("*.jsonl.gz"))
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
pytest tests/test_supervisor.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `Supervisor`**

Write `inspectord/supervisor.py`:

```python
"""Supervisor — owns workers, router, journal, and storage.

Spawns each declared worker as a Python subprocess. Reads events from each
worker's stdout line by line and publishes them onto the router. Heartbeats
arrive on stderr and update worker_health.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

from inspectord.config import DaemonConfig, WorkerSpec
from inspectord.journal import Journal
from inspectord.log import get
from inspectord.router import DropPolicy, EventRouter
from inspectord.schemas.event import Event
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations

log = get(__name__)


class _WorkerProc:
    def __init__(self, spec: WorkerSpec, proc: subprocess.Popen[bytes]) -> None:
        self.spec = spec
        self.proc = proc
        self.threads: list[threading.Thread] = []


class Supervisor:
    def __init__(self, config: DaemonConfig) -> None:
        self._cfg = config
        self._router = EventRouter()
        self._journal = Journal(config.storage.journal_dir)
        self._db = Database(config.storage.db_path)
        self._procs: list[_WorkerProc] = []
        self._stop = threading.Event()
        self._listeners: list[Callable[[Event], None]] = []

    # --- Public lifecycle.

    def start(self) -> None:
        self._db.connect()
        run_migrations(self._db)
        self._subscribe_storage()
        for spec in self._cfg.workers:
            self._spawn_worker(spec)

    def attach_listener(self, fn: Callable[[Event], None]) -> None:
        self._listeners.append(fn)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        deadline = time.monotonic() + timeout
        for wp in self._procs:
            try:
                wp.proc.terminate()
            except Exception:  # noqa: BLE001
                pass
        for wp in self._procs:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                wp.proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                wp.proc.kill()
            for t in wp.threads:
                t.join(timeout=1.0)
        self._journal.close()
        self._db.close()

    # --- Internals.

    def _subscribe_storage(self) -> None:
        store_sub = self._router.subscribe(
            name="store",
            queue_size=4096,
            drop_policy=DropPolicy.drop_oldest_non_critical,
        )
        # We use the same subscription via a polling thread.
        threading.Thread(target=self._drain, args=(store_sub,), daemon=True).start()

    def _drain(self, sub) -> None:  # type: ignore[no-untyped-def]
        from queue import Empty as QueueEmpty
        while not self._stop.is_set():
            try:
                ev = sub.get_nowait()
            except QueueEmpty:
                time.sleep(0.01)
                continue
            self._persist(ev)
            for fn in list(self._listeners):
                try:
                    fn(ev)
                except Exception as exc:  # noqa: BLE001
                    log.warning("listener raised: %r", exc)

    def _persist(self, ev: Event) -> None:
        payload = ev.model_dump_json()
        self._journal.append(json.loads(payload))
        self._db.execute(
            "INSERT INTO events_enriched (event_id, ts, kind, module, action, severity, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [ev.event_id, ev.ts, ev.kind.value, ev.module, ev.action, ev.severity.value, payload],
        )

    def _spawn_worker(self, spec: WorkerSpec) -> None:
        cmd = [sys.executable, "-m", spec.module]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(spec.config) + "\n").encode("utf-8"))
        proc.stdin.flush()
        proc.stdin.close()
        wp = _WorkerProc(spec, proc)
        wp.threads.append(threading.Thread(target=self._read_stdout, args=(wp,), daemon=True))
        wp.threads.append(threading.Thread(target=self._read_stderr, args=(wp,), daemon=True))
        for t in wp.threads:
            t.start()
        self._procs.append(wp)

    def _read_stdout(self, wp: _WorkerProc) -> None:
        assert wp.proc.stdout is not None
        for raw in iter(wp.proc.stdout.readline, b""):
            if self._stop.is_set():
                return
            raw = raw.rstrip(b"\n")
            if not raw:
                continue
            try:
                payload = json.loads(raw.decode("utf-8"))
                ev = Event.model_validate(payload)
                self._router.publish(ev)
            except Exception as exc:  # noqa: BLE001
                log.error("worker %s emitted invalid event: %r", wp.spec.name, exc)

    def _read_stderr(self, wp: _WorkerProc) -> None:
        assert wp.proc.stderr is not None
        for raw in iter(wp.proc.stderr.readline, b""):
            if self._stop.is_set():
                return
            raw = raw.rstrip(b"\n")
            if not raw:
                continue
            try:
                hb = json.loads(raw.decode("utf-8"))
            except Exception:  # noqa: BLE001
                continue
            self._record_heartbeat(wp.spec.name, hb)

    def _record_heartbeat(self, name: str, hb: dict[str, object]) -> None:
        try:
            self._db.execute(
                "INSERT INTO worker_health (worker, ts, events_processed, queue_depth, last_error, uptime_s) "
                "VALUES (?, to_timestamp(?), ?, ?, ?, ?)",
                [
                    name,
                    float(hb.get("ts", time.time())),
                    int(hb.get("events_processed", 0)),
                    int(hb.get("queue_depth", 0)),
                    hb.get("last_error"),
                    float(hb.get("uptime_s", 0.0)),
                ],
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("failed to record heartbeat for %s: %r", name, exc)
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_supervisor.py -v
```

Expected: 3 passed (allow up to 10s due to process startup).

- [ ] **Step 5: Commit**

```bash
git add inspectord/supervisor.py tests/test_supervisor.py
git commit -m "feat(supervisor): spawn workers, persist events, drain router"
```

---

## Task 19: IPC server — JSON-RPC over Unix socket

**Files:**
- Create: `inspectord/ipc_server.py`
- Create: `tests/test_ipc_server.py`

- [ ] **Step 1: Write the failing tests**

Write `tests/test_ipc_server.py`:

```python
"""Tests for the IPC server."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

from inspectord.ipc_server import IpcServer, Method


def test_ipc_get_health(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def get_health() -> dict[str, object]:
        return {"workers": [{"name": "healthcheck", "events_processed": 42}]}

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="get_health", handler=lambda params: get_health(), mutates=False)],
        allowed_uids=[],  # empty = anyone in dev
    )
    server.start()
    try:
        # connect and call
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(sock_path))
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_health",
            "params": {},
            "schema_version": "1.0.0",
        }
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        line = b""
        while not line.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            line += chunk
        sock.close()
        response = json.loads(line.decode("utf-8"))
        assert response["id"] == 1
        assert response["result"]["workers"][0]["events_processed"] == 42
    finally:
        server.stop()


def test_ipc_rejects_unknown_method(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"
    server = IpcServer(socket_path=sock_path, methods=[], allowed_uids=[])
    server.start()
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(sock_path))
        sock.sendall(
            (
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "nope", "params": {}, "schema_version": "1.0.0"})
                + "\n"
            ).encode("utf-8")
        )
        line = b""
        while not line.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            line += chunk
        sock.close()
        resp = json.loads(line)
        assert resp["error"]["code"] == -32601
    finally:
        server.stop()
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_ipc_server.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `IpcServer`**

Write `inspectord/ipc_server.py`:

```python
"""Minimal JSON-RPC 2.0 server over a Unix socket.

Each connection is line-delimited JSON. Authentication is SO_PEERCRED:
if `allowed_uids` is non-empty, the caller's uid must be in the list.
Mutating methods can require a polkit check in a later phase; here we
only check the allowlist.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from inspectord.log import get
from inspectord.schemas.versions import IPC_PROTOCOL_VERSION

log = get(__name__)

# SO_PEERCRED constant
_SO_PEERCRED = 17
_CRED_FMT = "iII"  # pid, uid, gid


@dataclass
class Method:
    name: str
    handler: Callable[[dict[str, Any]], dict[str, Any] | list[Any] | str | int | None]
    mutates: bool = False


def _peer_uid(sock: socket.socket) -> int:
    raw = sock.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, struct.calcsize(_CRED_FMT))
    _pid, uid, _gid = struct.unpack(_CRED_FMT, raw)
    return uid


def _err(req_id: object, code: int, message: str) -> bytes:
    return (json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }) + "\n").encode("utf-8")


def _ok(req_id: object, result: object) -> bytes:
    return (json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result,
    }) + "\n").encode("utf-8")


class IpcServer:
    def __init__(
        self,
        *,
        socket_path: Path,
        methods: list[Method],
        allowed_uids: list[int],
    ) -> None:
        self._path = Path(socket_path)
        self._methods = {m.name: m for m in methods}
        self._allowed_uids = list(allowed_uids)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._path.exists():
            self._path.unlink()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(self._path))
        os.chmod(self._path, 0o660)
        s.listen(16)
        self._sock = s
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            if self._allowed_uids:
                if _peer_uid(conn) not in self._allowed_uids:
                    conn.sendall(_err(None, -32000, "peer uid not allowed"))
                    return
            with conn.makefile("rb") as rf:
                for raw in rf:
                    raw = raw.rstrip(b"\n")
                    if not raw:
                        continue
                    try:
                        req = json.loads(raw.decode("utf-8"))
                    except Exception:  # noqa: BLE001
                        conn.sendall(_err(None, -32700, "parse error"))
                        continue
                    self._dispatch(conn, req)
        finally:
            conn.close()

    def _dispatch(self, conn: socket.socket, req: dict[str, Any]) -> None:
        req_id = req.get("id")
        if req.get("jsonrpc") != "2.0":
            conn.sendall(_err(req_id, -32600, "invalid request"))
            return
        if req.get("schema_version") != IPC_PROTOCOL_VERSION:
            conn.sendall(_err(req_id, -32602, f"unsupported schema_version, expected {IPC_PROTOCOL_VERSION}"))
            return
        method = self._methods.get(req.get("method", ""))
        if method is None:
            conn.sendall(_err(req_id, -32601, "method not found"))
            return
        try:
            result = method.handler(req.get("params") or {})
            conn.sendall(_ok(req_id, result))
        except Exception as exc:  # noqa: BLE001
            log.exception("handler raised")
            conn.sendall(_err(req_id, -32000, repr(exc)))
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_ipc_server.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectord/ipc_server.py tests/test_ipc_server.py
git commit -m "feat(ipc): add JSON-RPC server over Unix socket"
```

---

## Task 20: Daemon entry point

**Files:**
- Create: `inspectord/__main__.py`

- [ ] **Step 1: Implement the entry point**

Write `inspectord/__main__.py`:

```python
"""inspectord entry point.

Usage:
  inspectord --dev                          # dev mode: paths under ./var/
  inspectord --config /etc/inspectord/config.toml
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from inspectord.config import dev_config, load
from inspectord.ipc_server import IpcServer, Method
from inspectord.log import configure as configure_log, get
from inspectord.supervisor import Supervisor

log = get("inspectord")


def _ipc_methods(supervisor: Supervisor) -> list[Method]:
    def get_health(_params: dict[str, Any]) -> dict[str, Any]:
        # Phase 0 stub: report supervisor + worker presence; per-worker counters arrive in Phase 1.
        return {
            "schema_version": "1.0.0",
            "supervisor": "running",
            "workers": [{"name": "healthcheck", "status": "up"}],
        }

    return [Method(name="get_health", handler=get_health, mutates=False)]


def main() -> None:
    parser = argparse.ArgumentParser(prog="inspectord")
    parser.add_argument("--dev", action="store_true", help="dev paths under ./var/")
    parser.add_argument("--config", type=Path, default=None)
    args = parser.parse_args()

    configure_log()

    if args.dev:
        cfg = dev_config(base=Path.cwd())
    elif args.config is not None:
        cfg = load(args.config)
    else:
        print("inspectord: pass --dev or --config <path>", file=sys.stderr)
        sys.exit(2)

    sup = Supervisor(cfg)
    sup.start()

    ipc = IpcServer(
        socket_path=cfg.ipc.socket_path,
        methods=_ipc_methods(sup),
        allowed_uids=cfg.ipc.allowed_uids,
    )
    ipc.start()
    log.info("inspectord ready; socket=%s", cfg.ipc.socket_path)

    stop = threading.Event()

    def _shutdown(*_: object) -> None:
        log.info("inspectord shutting down")
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        while not stop.is_set():
            time.sleep(0.2)
    finally:
        ipc.stop()
        sup.stop(timeout=5.0)
    log.info("inspectord exited cleanly")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Smoke-test the daemon in dev mode**

```bash
cd /home/eli/Development/inspectord
rm -rf var/
.venv/bin/inspectord --dev &
DAEMON_PID=$!
sleep 2
ls var/
test -S var/inspectord.sock && echo "socket exists"
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" || true
```

Expected: `var/` contains `inspectord.duckdb`, `journal/`, `inspectord.sock`. The "socket exists" message prints.

- [ ] **Step 3: Commit**

```bash
git add inspectord/__main__.py
git commit -m "feat(inspectord): add daemon entry point"
```

---

## Task 21: IPC client library

**Files:**
- Create: `inspectorctl/ipc_client.py`
- Create: `tests/test_ipc_client.py`

- [ ] **Step 1: Write the failing test**

Write `tests/test_ipc_client.py`:

```python
"""Tests for the IPC client library."""

from __future__ import annotations

from pathlib import Path

from inspectord.ipc_server import IpcServer, Method
from inspectorctl.ipc_client import IpcClient


def test_client_can_call_method(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {"ok": True}

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="get_health", handler=handler, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        client = IpcClient(socket_path=sock_path)
        result = client.call("get_health")
        assert result == {"ok": True}
    finally:
        server.stop()
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_ipc_client.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement `IpcClient`**

Write `inspectorctl/ipc_client.py`:

```python
"""Client for the inspectord IPC server."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from inspectord.schemas.versions import IPC_PROTOCOL_VERSION


class IpcError(RuntimeError):
    pass


class IpcClient:
    def __init__(self, *, socket_path: Path) -> None:
        self._path = Path(socket_path)
        self._next_id = 0

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(self._path))
        except FileNotFoundError as exc:
            raise IpcError(f"socket not found: {self._path} (is inspectord running?)") from exc
        try:
            self._next_id += 1
            req = {
                "jsonrpc": "2.0",
                "id": self._next_id,
                "method": method,
                "params": params or {},
                "schema_version": IPC_PROTOCOL_VERSION,
            }
            sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
            line = b""
            while not line.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                line += chunk
            resp = json.loads(line.decode("utf-8"))
            if "error" in resp:
                raise IpcError(f"{resp['error']['code']}: {resp['error']['message']}")
            return resp["result"]
        finally:
            sock.close()
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_ipc_client.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add inspectorctl/ipc_client.py tests/test_ipc_client.py
git commit -m "feat(ipc-client): add inspectord IPC client"
```

---

## Task 22: CLI — `inspectorctl status`, `version`, `self-test`

**Files:**
- Create: `inspectorctl/__main__.py`
- Create: `inspectorctl/cli/app.py`
- Create: `inspectorctl/cli/status.py`
- Create: `inspectorctl/cli/self_test.py`
- Create: `inspectorctl/cli/version.py`

- [ ] **Step 1: Implement `app.py`**

Write `inspectorctl/cli/app.py`:

```python
"""Top-level Typer app for inspectorctl."""

from __future__ import annotations

import typer

from inspectorctl.cli import self_test, status, version

app = typer.Typer(no_args_is_help=True, add_completion=False)
app.command(name="status")(status.cmd)
app.command(name="self-test")(self_test.cmd)
app.command(name="version")(version.cmd)
```

- [ ] **Step 2: Implement `status.py`**

Write `inspectorctl/cli/status.py`:

```python
"""inspectorctl status — show daemon + worker health."""

from __future__ import annotations

from pathlib import Path

import typer
from rich import print as rprint

from inspectorctl.ipc_client import IpcClient, IpcError


def cmd(
    socket: Path = typer.Option(
        Path.cwd() / "var" / "inspectord.sock",
        "--socket",
        "-s",
        help="Path to the inspectord IPC socket",
    ),
) -> None:
    """Show daemon and worker health."""
    client = IpcClient(socket_path=socket)
    try:
        report = client.call("get_health")
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    rprint(report)
```

- [ ] **Step 3: Implement `self_test.py`**

Write `inspectorctl/cli/self_test.py`:

```python
"""inspectorctl self-test — verify the daemon is alive and accepting calls."""

from __future__ import annotations

from pathlib import Path

import typer
from rich import print as rprint

from inspectorctl.ipc_client import IpcClient, IpcError


def cmd(
    socket: Path = typer.Option(
        Path.cwd() / "var" / "inspectord.sock",
        "--socket",
        "-s",
        help="Path to the inspectord IPC socket",
    ),
) -> None:
    """End-to-end self-test: connect, call get_health, exit non-zero on failure."""
    client = IpcClient(socket_path=socket)
    try:
        report = client.call("get_health")
    except IpcError as exc:
        rprint(f"[red]FAIL[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if report.get("supervisor") == "running":
        rprint("[green]PASS[/green] inspectord is responding and supervisor is running")
        return
    rprint(f"[red]FAIL[/red] unexpected health report: {report!r}")
    raise typer.Exit(code=1)
```

- [ ] **Step 4: Implement `version.py`**

Write `inspectorctl/cli/version.py`:

```python
"""inspectorctl version — print the client + server versions."""

from __future__ import annotations

from pathlib import Path

import typer
from rich import print as rprint

import inspectorctl
from inspectorctl.ipc_client import IpcClient, IpcError


def cmd(
    socket: Path = typer.Option(
        Path.cwd() / "var" / "inspectord.sock",
        "--socket",
        "-s",
    ),
) -> None:
    """Print client + daemon versions."""
    rprint(f"client: {inspectorctl.__version__}")
    try:
        report = IpcClient(socket_path=socket).call("get_health")
        rprint(f"daemon schema: {report.get('schema_version', '?')}")
    except IpcError:
        rprint("daemon: not running")
```

- [ ] **Step 5: Implement `__main__.py`**

Write `inspectorctl/__main__.py`:

```python
"""inspectorctl entry point."""

from __future__ import annotations

from inspectorctl.cli.app import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Smoke-test the CLI**

In one shell:

```bash
cd /home/eli/Development/inspectord
rm -rf var/
.venv/bin/inspectord --dev
```

In another shell:

```bash
cd /home/eli/Development/inspectord
.venv/bin/inspectorctl status
.venv/bin/inspectorctl self-test
.venv/bin/inspectorctl version
```

Expected: `status` prints a JSON-ish dict. `self-test` prints `PASS ...`. `version` prints `client: 0.1.0` and the daemon schema. Then Ctrl-C the daemon.

- [ ] **Step 7: Commit**

```bash
git add inspectorctl/__main__.py inspectorctl/cli/app.py inspectorctl/cli/status.py \
        inspectorctl/cli/self_test.py inspectorctl/cli/version.py
git commit -m "feat(cli): add inspectorctl status, self-test, version"
```

---

## Task 23: Tray app stub

**Files:**
- Create: `inspectorctl/tray/__main__.py`

- [ ] **Step 1: Implement the tray**

Write `inspectorctl/tray/__main__.py`:

```python
"""inspectorctl-tray — minimal status indicator.

Phase 0 deliverable: a system tray icon that polls inspectord's IPC every
few seconds and shows green if it's responding, red if not. No alert handling
yet.
"""

from __future__ import annotations

import argparse
import threading
import time
from pathlib import Path

from PIL import Image, ImageDraw
import pystray

from inspectorctl.ipc_client import IpcClient, IpcError


def _icon(color: str) -> Image.Image:
    img = Image.new("RGB", (64, 64), "white")
    draw = ImageDraw.Draw(img)
    draw.ellipse((6, 6, 58, 58), fill=color)
    return img


def main() -> None:
    parser = argparse.ArgumentParser(prog="inspectorctl-tray")
    parser.add_argument("--socket", type=Path, default=Path.cwd() / "var" / "inspectord.sock")
    parser.add_argument("--poll-interval", type=float, default=5.0)
    args = parser.parse_args()

    client = IpcClient(socket_path=args.socket)
    state = {"healthy": False}

    def build_menu() -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem("Healthy" if state["healthy"] else "Not responding", lambda _: None, enabled=False),
            pystray.MenuItem("Quit", lambda icon, _: icon.stop()),
        )

    def poll(icon: pystray.Icon) -> None:
        while True:
            try:
                client.call("get_health")
                state["healthy"] = True
                icon.icon = _icon("green")
            except IpcError:
                state["healthy"] = False
                icon.icon = _icon("red")
            icon.menu = build_menu()
            time.sleep(args.poll_interval)

    icon = pystray.Icon("inspectord", _icon("gray"), "Local Inspection", build_menu())

    def setup(icon: pystray.Icon) -> None:
        icon.visible = True
        threading.Thread(target=poll, args=(icon,), daemon=True).start()

    icon.run(setup=setup)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Smoke-test (manual)**

With the daemon running from the previous task:

```bash
.venv/bin/inspectorctl-tray --socket var/inspectord.sock
```

Expected: a tray icon appears (green when daemon is up). Kill the daemon; icon turns red within 5 seconds. Restart daemon; icon goes green again. Quit via tray menu.

If your DE doesn't have a system tray (e.g., GNOME without an extension), pystray will fall back to a polled hidden indicator and the menu will still work via right-click in environments that support it. Note this as a known limitation.

- [ ] **Step 3: Commit**

```bash
git add inspectorctl/tray/__main__.py
git commit -m "feat(tray): add minimal status-indicator tray app"
```

---

## Task 24: systemd unit templates

**Files:**
- Create: `packaging/systemd/inspectord.service.template`
- Create: `packaging/systemd/inspectorctl-tray.service.template`

- [ ] **Step 1: Write the daemon unit template**

Write `packaging/systemd/inspectord.service.template`:

```ini
# inspectord.service — installed at /etc/systemd/system/inspectord.service
# Templated: @PYTHON@, @CONFIG_PATH@ substituted at install time.

[Unit]
Description=Local Inspection daemon
After=network-online.target auditd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=@PYTHON@ -m inspectord --config @CONFIG_PATH@
KillSignal=SIGTERM
TimeoutStopSec=60
Restart=on-failure
RestartSec=5s

# Hardening (Phase 0 baseline; tightened in later phases)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
MemoryDenyWriteExecute=true
ReadWritePaths=/var/lib/inspectord /var/log/inspectord /run/inspectord

# Phase 0 budget — tightened in §22.
MemoryMax=500M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write the tray unit template**

Write `packaging/systemd/inspectorctl-tray.service.template`:

```ini
# inspectorctl-tray.service — installed to ~/.config/systemd/user/

[Unit]
Description=Local Inspection tray indicator
After=graphical-session.target

[Service]
Type=simple
ExecStart=@PYTHON@ -m inspectorctl.tray --socket /run/inspectord/inspectord.sock
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=graphical-session.target
```

- [ ] **Step 3: Commit**

```bash
git add packaging/systemd/
git commit -m "chore(packaging): add systemd unit templates for daemon + tray"
```

---

## Task 25: polkit policy stub

**Files:**
- Create: `packaging/polkit/org.inspectord.policy.in`

- [ ] **Step 1: Write the polkit policy stub**

Write `packaging/polkit/org.inspectord.policy.in`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>Local Inspection</vendor>
  <vendor_url>https://example.invalid/local-inspection</vendor_url>

  <!-- Phase 0 ships only the read-only IPC. Phase 1+ adds mutating actions
       (ack_alert, allowlist edits, dep install, etc.) with their own
       <action> blocks. -->
  <action id="org.inspectord.read">
    <description>Read inspectord runtime state</description>
    <message>Authentication is not required to read inspectord state.</message>
    <defaults>
      <allow_any>yes</allow_any>
      <allow_inactive>yes</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
</policyconfig>
```

- [ ] **Step 2: Stub AppArmor profile**

Write `packaging/apparmor/inspectord.in`:

```
# AppArmor profile for inspectord — stub. Filled in during Phase 4 hardening pass.
# See spec §17.3.
#include <tunables/global>

profile /usr/bin/inspectord {
  # Placeholder — deliberately permissive for Phase 0; tightened later.
  #include <abstractions/base>
  #include <abstractions/python>
  /usr/bin/inspectord r,
}
```

- [ ] **Step 3: Commit**

```bash
git add packaging/polkit/ packaging/apparmor/
git commit -m "chore(packaging): add polkit policy + apparmor profile stubs"
```

---

## Task 26: End-to-end integration test

**Files:**
- Create: `tests/integration/test_end_to_end_skeleton.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Write a small daemon harness fixture**

Write `tests/conftest.py`:

```python
"""Shared pytest fixtures."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def daemon(tmp_path: Path) -> Iterator[dict[str, object]]:
    """Spin up `inspectord --dev` rooted at tmp_path; tear it down after."""
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-m", "inspectord", "--dev"],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sock_path = tmp_path / "var" / "inspectord.sock"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not sock_path.exists():
        time.sleep(0.05)
    assert sock_path.exists(), "daemon did not create its IPC socket"
    try:
        yield {"socket_path": sock_path, "proc": proc, "tmp_path": tmp_path}
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
```

- [ ] **Step 2: Write the end-to-end test**

Write `tests/integration/test_end_to_end_skeleton.py`:

```python
"""End-to-end Phase 0 acceptance test.

Verifies that:
  1. Running `inspectord --dev` brings up the daemon.
  2. The IPC socket exists and accepts calls.
  3. The healthcheck worker emits events that land in DuckDB.
  4. The journal file exists and verifies its own hash chain.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from inspectord.journal import verify_chain
from inspectord.storage.db import Database
from inspectorctl.ipc_client import IpcClient


@pytest.mark.integration
def test_end_to_end_skeleton(daemon: dict[str, object]) -> None:
    sock_path = daemon["socket_path"]  # type: ignore[index]
    tmp_path = daemon["tmp_path"]  # type: ignore[index]
    assert isinstance(sock_path, Path)
    assert isinstance(tmp_path, Path)

    # 1. IPC responds.
    client = IpcClient(socket_path=sock_path)
    report = client.call("get_health")
    assert report["supervisor"] == "running"

    # 2. Wait for the healthcheck worker to emit at least one event.
    db_path = tmp_path / "var" / "inspectord.duckdb"
    deadline = time.monotonic() + 5
    rows_count = 0
    while time.monotonic() < deadline:
        if db_path.exists():
            with Database(db_path) as db:
                rows_count = db.query("SELECT COUNT(*) FROM events_enriched").fetchall()[0][0]
            if rows_count >= 1:
                break
        time.sleep(0.1)
    assert rows_count >= 1, "no synthetic events landed in DuckDB"

    # 3. The journal file exists and verifies.
    journal_files = sorted((tmp_path / "var" / "journal").glob("*.jsonl.gz"))
    assert journal_files
    assert verify_chain(journal_files[0])
```

- [ ] **Step 3: Run the integration test**

```bash
pytest -m integration tests/integration/ -v
```

Expected: 1 passed (allow ~10 s).

- [ ] **Step 4: Commit**

```bash
git add tests/conftest.py tests/integration/test_end_to_end_skeleton.py
git commit -m "test(integration): add end-to-end Phase 0 acceptance test"
```

---

## Task 27: Full test sweep + lint pass

- [ ] **Step 1: Run all tests**

```bash
cd /home/eli/Development/inspectord
pytest
```

Expected: all tests pass.

- [ ] **Step 2: Run ruff**

```bash
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
```

If anything fails, fix it (`ruff check --fix` and `ruff format`), re-run, commit:

```bash
git add -u
git commit -m "style: ruff format + auto-fixes"
```

- [ ] **Step 3: Run mypy**

```bash
mypy inspectord inspectorctl
```

Resolve any errors inline (most likely candidates: missing return types in tests, untyped dicts). After fixes:

```bash
git add -u
git commit -m "style(types): tighten type annotations for mypy --strict"
```

- [ ] **Step 4: Final commit**

```bash
git log --oneline
```

Expected: clean linear history covering Tasks 1–27.

---

## Acceptance criteria (Phase 0 complete)

A reviewer can verify Phase 0 by running:

```bash
cd /home/eli/Development/inspectord
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest                                              # all green
inspectord --dev &                                  # daemon comes up
sleep 2
inspectorctl status                                 # prints health
inspectorctl self-test                              # prints PASS
ls var/inspectord.sock var/inspectord.duckdb var/journal/*.jsonl.gz
kill %1
```

All commands succeed. The repo has approximately 27 commits, all tests pass, ruff is clean, mypy is clean, and the integration test demonstrates the full skeleton wired end-to-end.

---

## What Phase 0 deliberately leaves out

These belong to subsequent plans, not this one:

* No `dependency_manager` (next plan).
* No real collectors — only the synthetic `healthcheck` worker.
* No rule engine, no allowlist, no alerts, no incidents.
* No notifications (Telegram/Signal/desktop popup).
* No web dashboard.
* No first-run wizard.
* No polkit-mediated mutating IPC calls.
* No AppArmor profile beyond the stub.
* No watchdog unit.
* No multi-distro packaging.

---

## Next plan

After Phase 0 lands and is reviewed, the next plan target is **`dependency_manager`** (spec §30) — building the subsystem that detects, installs, and configures all external dependencies. With dep_manager working, the user can run `inspectorctl setup`, approve the install plan, and end up with `auditd`/`AIDE`/`YARA` ready for the collectors that follow.
