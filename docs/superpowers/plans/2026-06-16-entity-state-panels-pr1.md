# Entity-state projection — PR1 (projection core + Services panel) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the materialized entity-state projection foundation and the first consuming panel (Services, with baseline diff), end-to-end.

**Architecture:** A migration adds per-kind state tables + a generic baseline table. A `project(event, db)` function, hooked into the supervisor's single-threaded persist path, materializes service state from `services_monitor` events. Read-only IPC methods expose current service state with a new/removed/re-enabled diff against a captured baseline; a Services web panel renders it with a "Capture baseline" action.

**Tech Stack:** Python 3, DuckDB (`INSERT … ON CONFLICT`), FastAPI + Jinja2 + HTMX, pytest.

**Spec:** `docs/superpowers/specs/2026-06-16-entity-state-panels-design.md` (this is sub-project 1, PR1 of §9). PRs 2–5 (Devices, Processes, Network, File integrity) replicate this pattern and get their own plans.

**Scope note:** Migration `0004` creates **all** per-kind tables up front (additive, harmless when empty) so PRs 2–5 add no further migrations. PR1 wires the projector/IPC/panel for **Services only**; other tables stay empty until their PR.

**Conventions (from `CLAUDE.md`):** venv at `.venv`. Run unit tests with `.venv/bin/python -m pytest -m "not integration and not ebpf_load"`. Gates before any commit/PR (matching CI `ci.yml`): `.venv/bin/ruff check inspectord inspectorctl tests` · `.venv/bin/ruff format --check inspectord inspectorctl tests` · `.venv/bin/mypy inspectord inspectorctl`. `main` is PR-only — work on a feature branch (`feat/entity-state-services`), push, open PR, wait for `lint-and-test`, squash-merge.

---

## File structure

| File | Responsibility |
| --- | --- |
| `inspectord/storage/migrations_data/0004_entity_state.sql` | Create all per-kind state tables + `baseline_entry` |
| `inspectord/state/__init__.py` | New package marker |
| `inspectord/state/projector.py` | `project(event, db)` — dispatch + service transition |
| `inspectord/state/baseline.py` | `capture_baseline(kind, db)` |
| `inspectord/state/ipc_handlers.py` | `handle_list_services`, `handle_capture_baseline` |
| `inspectord/supervisor.py` (modify) | Call `project()` in `_persist`; boot-reconcile in `start()` |
| `inspectord/state/reconcile.py` | `current_boot_id()`, `reconcile_processes(db, boot_id)` |
| `inspectord/__main__.py` (modify) | Register `list_services` + `capture_baseline` methods |
| `inspectorctl/web/routes/services.py` | `/services`, `/services/feed`, `/services/capture-baseline` |
| `inspectorctl/web/templates/services.html` | Panel shell |
| `inspectorctl/web/templates/services_feed.html` | HTMX feed fragment |
| `inspectorctl/web/templates/base.html` (modify) | Add Services nav link |
| `inspectorctl/web/app.py` (modify) | Register the services router |
| `tests/state/__init__.py`, `tests/state/test_projector.py`, `tests/state/test_reconcile.py`, `tests/state/test_baseline.py`, `tests/state/test_ipc_handlers.py` | Unit tests |
| `tests/test_entity_state_migration.py` | Migration test |
| `tests/web/test_services.py` | Web panel tests |

---

## Task 1: Migration 0004 — entity-state tables

**Files:**
- Create: `inspectord/storage/migrations_data/0004_entity_state.sql`
- Test: `tests/test_entity_state_migration.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_entity_state_migration.py
"""Tests for migration 0004 — entity-state tables."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import current_schema_version, run_migrations

_TABLES = {
    "process_state",
    "connection_state",
    "listener_state",
    "service_state",
    "device_state",
    "file_state",
    "baseline_entry",
}


def test_migration_creates_entity_state_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    assert current_schema_version(db) >= 4
    rows = db.query("SELECT table_name FROM information_schema.tables").fetchall()
    present = {r[0] for r in rows}
    assert _TABLES <= present
    db.close()


def test_service_state_upsert_roundtrip(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    db.execute(
        "INSERT INTO service_state (unit, active_state, sub_state, load_state, "
        "first_seen, last_seen, last_event_id) VALUES "
        "('sshd.service', 'active', 'running', 'loaded', "
        "TIMESTAMP '2026-06-16 00:00:00', TIMESTAMP '2026-06-16 00:00:00', 'e1')"
    )
    rows = db.query("SELECT active_state FROM service_state WHERE unit='sshd.service'").fetchall()
    assert rows[0][0] == "active"
    db.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_entity_state_migration.py -v`
Expected: FAIL — schema version is 3 (migration file does not exist yet).

- [ ] **Step 3: Create the migration file**

```sql
-- inspectord/storage/migrations_data/0004_entity_state.sql
-- Migration 0004 — materialized entity-state tables + baseline store (spec
-- docs/superpowers/specs/2026-06-16-entity-state-panels-design.md §3).
-- Additive; never destructive. Keys follow design-spec §14.1.

-- kind=process — pid:<pid>@boot:<boot_id>
CREATE TABLE IF NOT EXISTS process_state (
    pid           INTEGER NOT NULL,
    boot_id       VARCHAR NOT NULL,
    ppid          INTEGER,
    comm          VARCHAR,
    exe_path      VARCHAR,
    exe_sha256    VARCHAR,
    uid           INTEGER,
    cmdline       VARCHAR,
    status        VARCHAR NOT NULL,
    exit_code     INTEGER,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR,
    PRIMARY KEY (pid, boot_id)
);

-- kind=connection
CREATE TABLE IF NOT EXISTS connection_state (
    conn_key      VARCHAR PRIMARY KEY,
    pid           INTEGER,
    comm          VARCHAR,
    saddr         VARCHAR,
    sport         INTEGER,
    daddr         VARCHAR,
    dport         INTEGER,
    proto         VARCHAR,
    family        VARCHAR,
    status        VARCHAR NOT NULL,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);

-- kind=listener — port:<addr>:<port>
CREATE TABLE IF NOT EXISTS listener_state (
    addr          VARCHAR NOT NULL,
    port          INTEGER NOT NULL,
    proto         VARCHAR NOT NULL,
    family        VARCHAR,
    pid           INTEGER,
    comm          VARCHAR,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    snapshot_gen  BIGINT NOT NULL,
    PRIMARY KEY (addr, port, proto)
);

-- kind=service — svc:<unit>
CREATE TABLE IF NOT EXISTS service_state (
    unit          VARCHAR PRIMARY KEY,
    active_state  VARCHAR,
    sub_state     VARCHAR,
    load_state    VARCHAR,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);

-- kind=device — dev:<vendor:product:serial>
CREATE TABLE IF NOT EXISTS device_state (
    dev_key       VARCHAR PRIMARY KEY,
    vendor        VARCHAR,
    product       VARCHAR,
    serial        VARCHAR,
    subsystem     VARCHAR,
    devnode       VARCHAR,
    status        VARCHAR NOT NULL,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);

-- kind=file — file:<path>
CREATE TABLE IF NOT EXISTS file_state (
    path          VARCHAR PRIMARY KEY,
    change_type   VARCHAR,
    sha256        VARCHAR,
    size          BIGINT,
    mode          INTEGER,
    uid           INTEGER,
    gid           INTEGER,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);

-- generic baseline store (reference data; uniform across kinds)
CREATE TABLE IF NOT EXISTS baseline_entry (
    kind          VARCHAR NOT NULL,
    key           VARCHAR NOT NULL,
    attrs_json    VARCHAR NOT NULL,
    captured_at   TIMESTAMP NOT NULL,
    PRIMARY KEY (kind, key)
);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_entity_state_migration.py -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add inspectord/storage/migrations_data/0004_entity_state.sql tests/test_entity_state_migration.py
git commit -m "feat(storage): migration 0004 — entity-state tables + baseline store"
```

---

## Task 2: Projector core + service transition

**Files:**
- Create: `inspectord/state/__init__.py` (empty)
- Create: `inspectord/state/projector.py`
- Create: `tests/state/__init__.py` (empty)
- Test: `tests/state/test_projector.py`

Reference — `services_monitor` builds events as `service={"name": unit, "state": active}` and
`raw={"source": "systemctl", "active": active, "sub": sub, "load": load}`, with actions
`service_added`, `service_state_changed`, `service_removed` (see
`inspectord/workers/services_monitor/__main__.py`).

- [ ] **Step 1: Write the failing test**

```python
# tests/state/test_projector.py
"""Tests for the entity-state projector."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inspectord.schemas.event import Event, EventKind, Severity
from inspectord.state.projector import project
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _service_event(action: str, unit: str, active: str, *, event_id: str) -> Event:
    return Event(
        ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event_id=event_id,
        kind=EventKind.event,
        category=["service"],
        type=["change"],
        action=action,
        severity=Severity.info,
        module="services_monitor",
        service={"name": unit, "state": active},
        raw={"source": "systemctl", "active": active, "sub": "running", "load": "loaded"},
    )


def test_service_added_inserts_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_service_event("service_added", "sshd.service", "active", event_id="e1"), db)
    rows = db.query(
        "SELECT active_state, sub_state, load_state, last_event_id FROM service_state "
        "WHERE unit='sshd.service'"
    ).fetchall()
    assert rows == [("active", "running", "loaded", "e1")]
    db.close()


def test_service_state_changed_updates_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_service_event("service_added", "sshd.service", "active", event_id="e1"), db)
    project(_service_event("service_state_changed", "sshd.service", "failed", event_id="e2"), db)
    rows = db.query(
        "SELECT active_state, first_seen, last_event_id FROM service_state WHERE unit='sshd.service'"
    ).fetchall()
    assert rows[0][0] == "failed"
    assert rows[0][2] == "e2"  # last_event_id advanced
    db.close()


def test_service_removed_deletes_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_service_event("service_added", "sshd.service", "active", event_id="e1"), db)
    project(_service_event("service_removed", "sshd.service", "active", event_id="e2"), db)
    rows = db.query("SELECT unit FROM service_state WHERE unit='sshd.service'").fetchall()
    assert rows == []
    db.close()


def test_unknown_module_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    ev = Event(
        ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event_id="e9",
        kind=EventKind.event,
        category=["x"],
        type=["x"],
        action="whatever",
        severity=Severity.info,
        module="some_future_collector",
    )
    project(ev, db)  # must not raise
    db.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/state/test_projector.py -v`
Expected: FAIL — `ModuleNotFoundError: inspectord.state.projector`.

- [ ] **Step 3: Write the projector**

```python
# inspectord/state/projector.py
"""Materialize current entity state from the event stream.

`project(event, db)` is invoked from the supervisor's single-threaded persist
path, so transitions apply in order with no locking. Unknown (module, action)
pairs are a no-op — adding collectors never breaks projection.
"""

from __future__ import annotations

from inspectord.schemas.event import Event
from inspectord.storage.db import Database


def project(event: Event, db: Database) -> None:
    if event.module == "services_monitor":
        _project_service(event, db)


def _project_service(event: Event, db: Database) -> None:
    unit = (event.service or {}).get("name")
    if not unit:
        return
    if event.action == "service_removed":
        db.execute("DELETE FROM service_state WHERE unit = ?", [unit])
        return
    raw = event.raw or {}
    db.execute(
        """
        INSERT INTO service_state
            (unit, active_state, sub_state, load_state, first_seen, last_seen, last_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (unit) DO UPDATE SET
            active_state  = excluded.active_state,
            sub_state     = excluded.sub_state,
            load_state    = excluded.load_state,
            last_seen     = excluded.last_seen,
            last_event_id = excluded.last_event_id
        """,
        [
            unit,
            raw.get("active"),
            raw.get("sub"),
            raw.get("load"),
            event.ts,
            event.ts,
            event.event_id,
        ],
    )
```

Also create the empty package markers:

```python
# inspectord/state/__init__.py
```
```python
# tests/state/__init__.py
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/state/test_projector.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add inspectord/state/__init__.py inspectord/state/projector.py tests/state/__init__.py tests/state/test_projector.py
git commit -m "feat(state): projector with services_monitor transition"
```

---

## Task 3: Boot reconciliation

**Files:**
- Create: `inspectord/state/reconcile.py`
- Test: `tests/state/test_reconcile.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/state/test_reconcile.py
"""Tests for process-state boot reconciliation."""

from __future__ import annotations

from pathlib import Path

from inspectord.state.reconcile import reconcile_processes
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _seed(db: Database, pid: int, boot_id: str, status: str) -> None:
    db.execute(
        "INSERT INTO process_state (pid, boot_id, status, first_seen, last_seen) "
        "VALUES (?, ?, ?, TIMESTAMP '2026-06-16 00:00:00', TIMESTAMP '2026-06-16 00:00:00')",
        [pid, boot_id, status],
    )


def test_reconcile_marks_stale_boot_processes_exited(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    _seed(db, 100, "old-boot", "running")
    _seed(db, 200, "current-boot", "running")
    reconcile_processes(db, "current-boot")
    rows = dict(
        db.query("SELECT boot_id, status FROM process_state ORDER BY boot_id").fetchall()
    )
    assert rows == {"current-boot": "running", "old-boot": "exited"}
    db.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/state/test_reconcile.py -v`
Expected: FAIL — `ModuleNotFoundError: inspectord.state.reconcile`.

- [ ] **Step 3: Write the module**

```python
# inspectord/state/reconcile.py
"""Boot-scoped reconciliation for process state.

A missed exit event leaves a stale 'running' row. Because the process entity
key is boot-scoped (spec §14.1), any 'running' row whose boot_id differs from
the current boot can be safely marked exited at startup.
"""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database

_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def current_boot_id() -> str:
    return _BOOT_ID_PATH.read_text(encoding="utf-8").strip()


def reconcile_processes(db: Database, boot_id: str) -> None:
    db.execute(
        "UPDATE process_state SET status='exited' WHERE boot_id <> ? AND status='running'",
        [boot_id],
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/state/test_reconcile.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/state/reconcile.py tests/state/test_reconcile.py
git commit -m "feat(state): boot reconciliation for stale process rows"
```

---

## Task 4: Hook projector + reconciliation into the supervisor

**Files:**
- Modify: `inspectord/supervisor.py` (imports; `start()` after `run_migrations`; `_persist`)
- Test: `tests/test_supervisor.py` (add one test; mirror existing style there)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_supervisor.py` (it already imports `Supervisor`, `dev_config`, `Database`).
`DaemonConfig.workers` is a mutable list, so `cfg.workers = []` skips spawning subprocesses, and
`Supervisor._inject_for_test` pushes an event through the real persist path:

```python
def test_supervisor_persist_projects_service_state(tmp_path) -> None:
    from datetime import UTC, datetime

    from inspectord.config import dev_config
    from inspectord.schemas.event import Event, EventKind, Severity
    from inspectord.storage.db import Database
    from inspectord.supervisor import Supervisor

    cfg = dev_config(base=tmp_path)
    cfg.workers = []  # no subprocesses; we inject directly
    sup = Supervisor(cfg)
    sup.start()
    try:
        ev = Event(
            ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
            event_id="svc-1",
            kind=EventKind.event,
            category=["service"],
            type=["change"],
            action="service_added",
            severity=Severity.info,
            module="services_monitor",
            service={"name": "cron.service", "state": "active"},
            raw={"source": "systemctl", "active": "active", "sub": "running", "load": "loaded"},
        )
        sup._inject_for_test(ev)
        # give the drain thread a moment to persist
        import time

        deadline = time.monotonic() + 2.0
        rows: list = []
        while time.monotonic() < deadline:
            with Database(cfg.storage.db_path) as db:
                rows = db.query(
                    "SELECT active_state FROM service_state WHERE unit='cron.service'"
                ).fetchall()
            if rows:
                break
            time.sleep(0.05)
        assert rows == [("active",)]
    finally:
        sup.stop(timeout=5.0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_supervisor.py::test_supervisor_persist_projects_service_state -v`
Expected: FAIL — `service_state` is empty (projector not wired into `_persist`).

- [ ] **Step 3: Wire the projector and reconciliation**

In `inspectord/supervisor.py`, add imports near the other `inspectord.*` imports:

```python
from inspectord.state.projector import project
from inspectord.state.reconcile import current_boot_id, reconcile_processes
```

In `start()`, immediately after `run_migrations(self._db)` and before `self._subscribe_storage()`:

```python
        run_migrations(self._db)
        with contextlib.suppress(OSError):
            reconcile_processes(self._db, current_boot_id())
        self._subscribe_storage()
```

(`contextlib` is already imported in this file. The `suppress(OSError)` guards hosts where
`/proc/sys/kernel/random/boot_id` is unreadable, e.g. some CI sandboxes.)

In `_persist()`, after the `events_enriched` insert, add the projection in the same write path:

```python
    def _persist(self, ev: Event) -> None:
        payload = ev.model_dump_json()
        self._journal.append(json.loads(payload))
        self._db.execute(
            "INSERT INTO events_enriched "
            "(event_id, ts, kind, module, action, severity, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [ev.event_id, ev.ts, ev.kind.value, ev.module, ev.action, ev.severity.value, payload],
        )
        project(ev, self._db)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_supervisor.py -v`
Expected: PASS (new test + existing supervisor tests still green).

- [ ] **Step 5: Commit**

```bash
git add inspectord/supervisor.py tests/test_supervisor.py
git commit -m "feat(supervisor): project entity state on persist; reconcile on start"
```

---

## Task 5: capture_baseline

**Files:**
- Create: `inspectord/state/baseline.py`
- Test: `tests/state/test_baseline.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/state/test_baseline.py
"""Tests for baseline capture."""

from __future__ import annotations

import json
from pathlib import Path

from inspectord.state.baseline import capture_baseline
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _seed_service(db: Database, unit: str, active: str) -> None:
    db.execute(
        "INSERT INTO service_state (unit, active_state, sub_state, load_state, "
        "first_seen, last_seen, last_event_id) VALUES "
        "(?, ?, 'running', 'loaded', TIMESTAMP '2026-06-16 00:00:00', "
        "TIMESTAMP '2026-06-16 00:00:00', 'e1')",
        [unit, active],
    )


def test_capture_service_baseline_snapshots_current_state(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_service(db, "sshd.service", "active")
    _seed_service(db, "cron.service", "inactive")
    count = capture_baseline("service", db)
    assert count == 2
    rows = db.query(
        "SELECT key, attrs_json FROM baseline_entry WHERE kind='service' ORDER BY key"
    ).fetchall()
    keys = [r[0] for r in rows]
    assert keys == ["svc:cron.service", "svc:sshd.service"]
    assert json.loads(rows[1][1])["active_state"] == "active"


def test_capture_baseline_replaces_previous(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_service(db, "sshd.service", "active")
    capture_baseline("service", db)
    db.execute("DELETE FROM service_state WHERE unit='sshd.service'")
    _seed_service(db, "nginx.service", "active")
    capture_baseline("service", db)
    rows = db.query("SELECT key FROM baseline_entry WHERE kind='service'").fetchall()
    assert {r[0] for r in rows} == {"svc:nginx.service"}


def test_capture_baseline_rejects_unknown_kind(tmp_path: Path) -> None:
    db = _db(tmp_path)
    try:
        capture_baseline("device", db)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/state/test_baseline.py -v`
Expected: FAIL — `ModuleNotFoundError: inspectord.state.baseline`.

- [ ] **Step 3: Write the module**

```python
# inspectord/state/baseline.py
"""Capture entity-state baselines (spec §19.3).

A baseline is a point-in-time snapshot of an entity set, stored in
`baseline_entry`, used to compute new/removed/re-enabled diffs. PR1 supports
the 'service' kind; other kinds reuse the same table later.
"""

from __future__ import annotations

import json

from inspectord.storage.db import Database

_SUPPORTED = {"service"}


def capture_baseline(kind: str, db: Database) -> int:
    if kind not in _SUPPORTED:
        raise ValueError(f"unsupported baseline kind: {kind!r}")
    db.execute("DELETE FROM baseline_entry WHERE kind = ?", [kind])
    rows = db.query(
        "SELECT unit, active_state, sub_state, load_state FROM service_state"
    ).fetchall()
    for unit, active, sub, load in rows:
        attrs = json.dumps({"active_state": active, "sub_state": sub, "load_state": load})
        db.execute(
            "INSERT INTO baseline_entry (kind, key, attrs_json, captured_at) "
            "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            [kind, f"svc:{unit}", attrs],
        )
    return len(rows)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/state/test_baseline.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add inspectord/state/baseline.py tests/state/test_baseline.py
git commit -m "feat(state): capture_baseline for services"
```

---

## Task 6: IPC handlers — list_services (with diff) + capture_baseline

**Files:**
- Create: `inspectord/state/ipc_handlers.py`
- Modify: `inspectord/__main__.py` (register two methods)
- Test: `tests/state/test_ipc_handlers.py`

Diff semantics (spec §5.1): **new** = unit not in baseline; **removed** = in baseline, not current
(emitted as a synthetic row); **re-enabled** = baseline active_state ∈ {inactive, failed, null} and
current active_state == "active"; **unchanged** otherwise.

- [ ] **Step 1: Write the failing test**

```python
# tests/state/test_ipc_handlers.py
"""Tests for entity-state IPC handlers."""

from __future__ import annotations

from pathlib import Path

from inspectord.state.baseline import capture_baseline
from inspectord.state.ipc_handlers import handle_capture_baseline, handle_list_services
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "test.duckdb"


def _seed_service(db_path: Path, unit: str, active: str) -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO service_state (unit, active_state, sub_state, load_state, "
            "first_seen, last_seen, last_event_id) VALUES "
            "(?, ?, 'running', 'loaded', TIMESTAMP '2026-06-16 00:00:00', "
            "TIMESTAMP '2026-06-16 00:00:00', 'e1') "
            "ON CONFLICT (unit) DO UPDATE SET active_state = excluded.active_state",
            [unit, active],
        )


def test_list_services_returns_rows(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    result = handle_list_services({}, db_path)
    units = [s["unit"] for s in result["services"]]
    assert units == ["sshd.service"]
    assert result["services"][0]["active_state"] == "active"


def test_list_services_no_diff_field_without_flag(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    result = handle_list_services({}, db_path)
    assert "diff_status" not in result["services"][0]


def test_diff_marks_new_when_no_baseline(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    result = handle_list_services({"diff": True}, db_path)
    assert result["services"][0]["diff_status"] == "new"


def test_diff_unchanged_and_reenabled_and_removed(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    _seed_service(db_path, "cron.service", "inactive")
    _seed_service(db_path, "ntp.service", "active")
    with Database(db_path) as db:
        capture_baseline("service", db)
    # mutate after baseline: cron re-enabled, ntp removed, new unit appears
    _seed_service(db_path, "cron.service", "active")
    with Database(db_path) as db:
        db.execute("DELETE FROM service_state WHERE unit='ntp.service'")
    _seed_service(db_path, "nginx.service", "active")

    result = handle_list_services({"diff": True}, db_path)
    by_unit = {s["unit"]: s["diff_status"] for s in result["services"]}
    assert by_unit["sshd.service"] == "unchanged"
    assert by_unit["cron.service"] == "re-enabled"
    assert by_unit["nginx.service"] == "new"
    assert by_unit["ntp.service"] == "removed"


def test_capture_baseline_handler(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    result = handle_capture_baseline({"kind": "service"}, db_path)
    assert result["captured"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/state/test_ipc_handlers.py -v`
Expected: FAIL — `ModuleNotFoundError: inspectord.state.ipc_handlers`.

- [ ] **Step 3: Write the handlers**

```python
# inspectord/state/ipc_handlers.py
"""IPC handlers for entity-state panels (spec §5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from inspectord.state.baseline import capture_baseline
from inspectord.storage.db import Database

_INACTIVE = {"inactive", "failed", None}


def _diff_status(key: str, current_active: str | None, baseline: dict[str, dict[str, Any]]) -> str:
    if key not in baseline:
        return "new"
    base_active = baseline[key].get("active_state")
    if base_active in _INACTIVE and current_active == "active":
        return "re-enabled"
    return "unchanged"


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def handle_list_services(params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    limit = int(params.get("limit", 200))
    want_diff = bool(params.get("diff", False))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT unit, active_state, sub_state, load_state, first_seen, last_seen "
            "FROM service_state ORDER BY unit LIMIT ?",
            [limit],
        ).fetchall()
        baseline: dict[str, dict[str, Any]] = {}
        if want_diff:
            brows = db.query(
                "SELECT key, attrs_json FROM baseline_entry WHERE kind='service'"
            ).fetchall()
            baseline = {k: json.loads(a) for k, a in brows}

    services: list[dict[str, Any]] = []
    current_keys: set[str] = set()
    for unit, active, sub, load, first_seen, last_seen in rows:
        key = f"svc:{unit}"
        current_keys.add(key)
        item: dict[str, Any] = {
            "unit": unit,
            "active_state": active,
            "sub_state": sub,
            "load_state": load,
            "first_seen": _iso(first_seen),
            "last_seen": _iso(last_seen),
        }
        if want_diff:
            item["diff_status"] = _diff_status(key, active, baseline)
        services.append(item)

    if want_diff:
        for key in baseline:
            if key not in current_keys:
                services.append(
                    {
                        "unit": key.removeprefix("svc:"),
                        "active_state": None,
                        "sub_state": None,
                        "load_state": None,
                        "first_seen": None,
                        "last_seen": None,
                        "diff_status": "removed",
                    }
                )

    return {"schema_version": "1.0.0", "services": services}


def handle_capture_baseline(params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    kind = str(params.get("kind", "service"))
    with Database(db_path) as db:
        count = capture_baseline(kind, db)
    return {"schema_version": "1.0.0", "captured": count}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/state/test_ipc_handlers.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Register the methods in `inspectord/__main__.py`**

Add the import near the other handler imports (after the `inspectord.dependencies.ipc_handlers`
import block):

```python
from inspectord.state.ipc_handlers import handle_capture_baseline, handle_list_services
```

Add two entries to the `return [...]` list in `_ipc_methods` (after the `suppress_alert` Method):

```python
        Method(
            name="list_services",
            handler=lambda params: handle_list_services(params, cfg.storage.db_path),
            mutates=False,
        ),
        Method(
            name="capture_baseline",
            handler=lambda params: handle_capture_baseline(params, cfg.storage.db_path),
            mutates=True,
        ),
```

- [ ] **Step 6: Run the full daemon test suite to confirm registration doesn't break startup**

Run: `.venv/bin/python -m pytest tests/test_ipc_server.py tests/state -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add inspectord/state/ipc_handlers.py inspectord/__main__.py tests/state/test_ipc_handlers.py
git commit -m "feat(ipc): list_services (with diff) + capture_baseline methods"
```

---

## Task 7: Services web panel

**Files:**
- Create: `inspectorctl/web/routes/services.py`
- Create: `inspectorctl/web/templates/services.html`
- Create: `inspectorctl/web/templates/services_feed.html`
- Modify: `inspectorctl/web/app.py` (import + `include_router`)
- Modify: `inspectorctl/web/templates/base.html` (nav link)
- Test: `tests/web/test_services.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/web/test_services.py
"""Tests for the /services panel."""

from __future__ import annotations

from inspectord.ipc_server import Method


def _list_services() -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "services": [
                {
                    "unit": "sshd.service",
                    "active_state": "active",
                    "sub_state": "running",
                    "load_state": "loaded",
                    "first_seen": "2026-06-16T00:00:00+00:00",
                    "last_seen": "2026-06-16T01:00:00+00:00",
                    "diff_status": "new",
                },
            ],
        }

    return Method(name="list_services", handler=handler, mutates=False)


def _capture_baseline(calls: list[dict]) -> Method:
    def handler(params: dict) -> dict:
        calls.append(params)
        return {"schema_version": "1.0.0", "captured": 1}

    return Method(name="capture_baseline", handler=handler, mutates=True)


def test_services_shell_renders(ipc_factory) -> None:
    client = ipc_factory([_list_services()])
    response = client.get("/services")
    assert response.status_code == 200
    assert "hx-get" in response.text
    assert "/services/feed" in response.text
    assert "services-feed" in response.text


def test_services_feed_renders_rows(ipc_factory) -> None:
    client = ipc_factory([_list_services()])
    response = client.get("/services/feed")
    assert response.status_code == 200
    assert "sshd.service" in response.text
    assert "new" in response.text
    assert "<nav>" not in response.text


def test_capture_baseline_button_posts(ipc_factory) -> None:
    calls: list[dict] = []
    client = ipc_factory([_list_services(), _capture_baseline(calls)])
    response = client.post("/services/capture-baseline", follow_redirects=False)
    assert response.status_code == 303
    assert any(c.get("kind") == "service" for c in calls)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/web/test_services.py -v`
Expected: FAIL — 404 for `/services` (route not registered).

- [ ] **Step 3: Write the route**

```python
# inspectorctl/web/routes/services.py
"""GET /services + /services/feed, POST /services/capture-baseline."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/services", response_class=HTMLResponse)
def services_shell(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "services.html",
        {
            "request": request,
            "title": "inspectord — Services",
            "current_path": "/services",
        },
    )


@router.get("/services/feed", response_class=HTMLResponse)
def services_feed(
    request: Request,
    limit: int = Query(default=300, ge=1, le=1000),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    services: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(socket_path, "list_services", {"diff": True, "limit": limit})
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        services = result.get("services", [])
    return templates.TemplateResponse(
        request,
        "services_feed.html",
        {"request": request, "services": services, "error": error},
    )


@router.post("/services/capture-baseline")
def services_capture_baseline(request: Request) -> RedirectResponse:
    try:
        call(request.app.state.socket_path, "capture_baseline", {"kind": "service"})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url="/services", status_code=303)
```

- [ ] **Step 4: Write the templates**

```html
{# inspectorctl/web/templates/services.html #}
{% extends "base.html" %}

{% block content %}
<h1>Services</h1>

<form method="post" action="/services/capture-baseline" class="filter-bar">
  <button type="submit">Capture baseline</button>
  <span class="muted">Snapshots current services as the diff reference.</span>
</form>

<div id="services-feed"
     hx-get="/services/feed"
     hx-target="#services-feed"
     hx-trigger="load, every 5s">
  <div class="empty">Loading…</div>
</div>
{% endblock %}
```

```html
{# inspectorctl/web/templates/services_feed.html #}
{%- from "_macros.html" import status_badge %}
{% if error %}
<div class="error">⚠ {{ error }}</div>
{% elif services %}
<table>
  <thead>
    <tr>
      <th>Unit</th>
      <th>Active</th>
      <th>Sub</th>
      <th>Load</th>
      <th>Diff</th>
      <th>Last seen</th>
    </tr>
  </thead>
  <tbody>
    {% for s in services %}
    <tr>
      <td class="mono">{{ s.unit }}</td>
      <td>{{ s.active_state or '' }}</td>
      <td class="mono muted">{{ s.sub_state or '' }}</td>
      <td class="mono muted">{{ s.load_state or '' }}</td>
      <td>{{ status_badge(s.diff_status) if s.diff_status else '' }}</td>
      <td class="mono muted">{{ s.last_seen or '' }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<div class="empty">No services observed yet. Capture a baseline once services appear.</div>
{% endif %}
```

- [ ] **Step 5: Register the router and nav link**

In `inspectorctl/web/app.py`, add `services` to the routes import and include it:

```python
from inspectorctl.web.routes import alerts, deps, events, health, services
```
```python
    app.include_router(alerts.router)
    app.include_router(services.router)
```

In `inspectorctl/web/templates/base.html`, add the nav link after the Dependencies link:

```html
    {{ nav_link("/deps", "Dependencies", current_path) }}
    {{ nav_link("/services", "Services", current_path) }}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/web/test_services.py -v`
Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
git add inspectorctl/web/routes/services.py inspectorctl/web/templates/services.html inspectorctl/web/templates/services_feed.html inspectorctl/web/app.py inspectorctl/web/templates/base.html tests/web/test_services.py
git commit -m "feat(web): Services panel with baseline diff + capture button"
```

---

## Task 8: Full gate run + PR

- [ ] **Step 1: Run the full unit suite**

Run: `.venv/bin/python -m pytest -m "not integration and not ebpf_load"`
Expected: PASS (all green, including the new `tests/state/*` and `tests/web/test_services.py`).

- [ ] **Step 2: Lint, format, types**

Run:
```bash
.venv/bin/ruff check inspectord inspectorctl tests
.venv/bin/ruff format --check inspectord inspectorctl tests
.venv/bin/mypy inspectord inspectorctl
```
Expected: no errors. If `ruff format --check` reports diffs, run `.venv/bin/ruff format inspectord inspectorctl tests` and re-stage.

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin feat/entity-state-services
gh pr create --fill --base main
```

- [ ] **Step 4: Wait for CI, then merge**

```bash
gh pr checks --watch
gh pr merge --squash --delete-branch
```
Expected: `lint-and-test`, CodeQL, cargo-audit, dependency-review all green before merge.

---

## Definition of done (PR1)

- Migration `0004` creates all seven entity-state/baseline tables.
- `services_monitor` events materialize into `service_state` via the supervisor persist path.
- Boot reconciliation marks stale-boot `running` process rows exited at startup.
- `list_services` returns current services and, with `diff=True`, a correct `diff_status`
  (new / removed / re-enabled / unchanged); `capture_baseline` snapshots services.
- The `/services` panel renders live rows with diff badges and a working "Capture baseline" button.
- All CI gates green; PR squash-merged to `main`.

## Follow-on (separate plans, per spec §9)

PR2 Devices · PR3 Processes (+ end-to-end boot-reconcile via real exec/exit events) · PR4 Network
(connections + listeners) · PR5 File integrity. Each adds its projector branch, `list_*` handler,
and panel following this exact pattern.
