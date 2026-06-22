# Cases store + IPC (PR8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. TDD throughout: write tests first, watch fail, implement, watch pass, run gates, commit per sub-task.

**Goal:** Build the manual-cases backend — migration `0006_cases.sql`, a standalone `inspectord/cases/` module (store + IPC handlers), and daemon registration of six methods (`open_case`, `attach_alert`, `add_note`, `close_case`, `list_cases`, `get_case`). No web (that's PR9).

**Architecture:** Cases are user-curated, NOT entity-state, so they live in their own `inspectord/cases/` package separate from the projector. `store.py` is pure DuckDB CRUD over a `Database` (mirrors `inspectord/state/baseline.py`); `ipc_handlers.py` wraps each store call in `with Database(db_path) as db:` (mirrors `handle_capture_baseline`). A single append-only `case_event` table is the activity/notes log (NOT tamper-evident chain-of-custody — that's deferred).

**Tech Stack:** Python 3.14, DuckDB via `inspectord.storage.db.Database`, `inspectord.ids.uuid7`, pytest.

**Spec:** `docs/superpowers/specs/2026-06-21-cases-panel-design.md` (concilium-reviewed). This PR = spec §7 "PR8". Read §1.1 (honesty note), §3 (schema), §4 (store ops — has the exact behaviours), §5 (IPC).

**Gates (run from repo root, all must pass before done):**
- `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- `.venv/bin/ruff check inspectord tests` · `.venv/bin/ruff format --check inspectord tests`
- `.venv/bin/mypy inspectord`

**Branch:** `feat/cases-store` (already checked out; spec + this plan ride along).

**Key codebase facts the implementer needs:**
- `Database` (`inspectord/storage/db.py`): `db.execute(sql, params)` returns `None`; `db.query(sql, params)` returns a cursor — use `.fetchall()`. Use `with Database(db_path) as db:` in handlers. DuckDB supports `db.execute("BEGIN TRANSACTION")` / `"COMMIT"` / `"ROLLBACK"`.
- `uuid7`: `from inspectord.ids import uuid7` → returns a `uuid.UUID`; use `str(uuid7())`.
- Idempotency/existence is decided by a pre-check `SELECT` (no rowcount exists), exactly like `inspectord/alerts/ipc_handlers.py::_transition` (`db.query("SELECT ... ").fetchall()`; empty → not found).
- The `alerts` table (migration 0003) has `alert_id, rule_id, ts, severity, status, rendered_short` among its columns.

---

## File structure
- Create: `inspectord/storage/migrations_data/0006_cases.sql`
- Create: `inspectord/cases/__init__.py` (empty), `inspectord/cases/store.py`, `inspectord/cases/ipc_handlers.py`
- Modify: `inspectord/__main__.py` (register six methods + import)
- Test: `tests/test_cases_migration.py`, `tests/cases/__init__.py` (empty), `tests/cases/test_store.py`, `tests/cases/test_ipc_handlers.py`

---

## Task 1: Migration `0006_cases.sql`

**Files:** Create `inspectord/storage/migrations_data/0006_cases.sql`; Test `tests/test_cases_migration.py`.

- [ ] **Step 1: Write the failing test** (mirror `tests/test_persistence_state_migration.py`):

```python
from pathlib import Path
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _cols(db: Database, table: str) -> set[str]:
    return {r[1] for r in db.query(f"PRAGMA table_info('{table}')").fetchall()}


def test_cases_tables_created(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    assert {"case_id", "title", "status", "opened_at", "closed_at"} <= _cols(db, "cases")
    assert {"case_id", "alert_id", "attached_at"} <= _cols(db, "case_alert")
    assert {"case_id", "ts", "seq", "kind", "text"} <= _cols(db, "case_event")
    db.close()
```

- [ ] **Step 2: Run it — expect failure** (tables don't exist). `pytest tests/test_cases_migration.py -v`
- [ ] **Step 3: Create the migration** (additive; auto-discovered by `\d{4}_*.sql`):

```sql
-- Cases (manual v1) — user-curated bundles of alerts + notes.
-- case_event is an append-only ACTIVITY/NOTES log, NOT a tamper-evident chain-of-custody
-- (parent spec §13.5/§20.4 audit_log is deferred). No foreign keys (consistent w/ schema).
CREATE TABLE IF NOT EXISTS cases (
    case_id     VARCHAR PRIMARY KEY,
    title       VARCHAR NOT NULL,
    status      VARCHAR NOT NULL DEFAULT 'open',
    opened_at   TIMESTAMP NOT NULL,
    closed_at   TIMESTAMP
);

CREATE TABLE IF NOT EXISTS case_alert (
    case_id     VARCHAR NOT NULL,
    alert_id    VARCHAR NOT NULL,
    attached_at TIMESTAMP NOT NULL,
    PRIMARY KEY (case_id, alert_id)
);

CREATE TABLE IF NOT EXISTS case_event (
    case_id     VARCHAR NOT NULL,
    ts          TIMESTAMP NOT NULL,
    seq         INTEGER NOT NULL,
    kind        VARCHAR NOT NULL,
    text        VARCHAR
);

CREATE INDEX IF NOT EXISTS case_alert_case_idx ON case_alert (case_id);
CREATE INDEX IF NOT EXISTS case_event_case_idx ON case_event (case_id, ts, seq);
```

- [ ] **Step 4: Run the test — expect pass.**
- [ ] **Step 5: Commit.** `feat(storage): migration 0006 — cases tables`.

---

## Task 2: `cases/store.py`

Pure DuckDB CRUD over a `Database`. Each mutating op captures one `datetime.now(tz=UTC)` and appends `case_event` row(s). `_MAX_TEXT = 16384` bounds note text and title. Build the module across three commits (TDD each); the full module may land in commit 2a since `get_case` is referenced by the open/attach tests, but each behaviour is exercised by its sub-task's tests.

**Files:** Create `inspectord/cases/__init__.py` (empty), `inspectord/cases/store.py`; Test `tests/cases/__init__.py` (empty), `tests/cases/test_store.py`.

**Helpers all tests use** (put at the top of `test_store.py`):

```python
from datetime import UTC, datetime
from pathlib import Path
from inspectord.cases import store
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _seed_alert(db: Database, alert_id: str, short: str = "sshd brute force") -> None:
    db.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
        "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, payload_json) "
        "VALUES (?, 'r1', TIMESTAMP '2026-06-20 00:00:00', 'high', 'new', 'auth', 'dk', 1, "
        "TIMESTAMP '2026-06-20 00:00:00', TIMESTAMP '2026-06-20 00:00:00', ?, 'detail', '{}')",
        [alert_id, short],
    )
```

### 2a — `open_case` + `attach_alert` + `_now`/`_bound`

- [ ] **Step 1: Write failing tests** in `tests/cases/test_store.py`:
  - `open_case` with a seeded alert: returns a `case_id` (str); a `cases` row exists with `status='open'`, `title == "sshd brute force"` (defaulted from `rendered_short`); a `case_alert` link exists; two `case_event` rows exist — `(kind='opened', seq=0)` then `(kind='alert_attached', seq=1)` sharing the same `ts`.
  - `open_case` with `title="custom"` overrides the default.
  - `open_case` with an alert_id NOT in `alerts` → title falls back to `f"Case {case_id[:8]}"`; still creates the case + link.
  - `attach_alert` is idempotent: open a case, `attach_alert` the SAME alert again → still exactly one `case_alert` row and exactly one `alert_attached` event (no duplicates).
  - `attach_alert` to a non-existent case → no-op (no rows created, no raise).

- [ ] **Step 2: Run — expect failure** (no `store` module).
- [ ] **Step 3: Implement** `inspectord/cases/store.py`:

```python
"""Manual cases store (spec §4) — user-curated bundles of alerts + notes.

case_event is an append-only activity/notes log, NOT a tamper-evident chain-of-custody
(spec §1.1); the daemon can mutate it. uuid7 ids match events/alerts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from inspectord.ids import uuid7
from inspectord.storage.db import Database

_MAX_TEXT = 16384


def _bound(text: str | None) -> str | None:
    if text is None:
        return None
    return text[:_MAX_TEXT]


def _append_event(db: Database, case_id: str, ts: datetime, seq: int, kind: str, text: str | None) -> None:
    db.execute(
        "INSERT INTO case_event (case_id, ts, seq, kind, text) VALUES (?, ?, ?, ?, ?)",
        [case_id, ts, seq, kind, _bound(text)],
    )


def _case_exists(db: Database, case_id: str) -> bool:
    return bool(db.query("SELECT 1 FROM cases WHERE case_id = ?", [case_id]).fetchall())


def _link_exists(db: Database, case_id: str, alert_id: str) -> bool:
    return bool(
        db.query(
            "SELECT 1 FROM case_alert WHERE case_id = ? AND alert_id = ?", [case_id, alert_id]
        ).fetchall()
    )


def _attach(db: Database, case_id: str, alert_id: str, ts: datetime, seq: int) -> bool:
    """Link alert→case if not already linked. Returns True if newly linked."""
    if _link_exists(db, case_id, alert_id):
        return False
    db.execute(
        "INSERT INTO case_alert (case_id, alert_id, attached_at) VALUES (?, ?, ?)",
        [case_id, alert_id, ts],
    )
    _append_event(db, case_id, ts, seq, "alert_attached", alert_id)
    return True


def open_case(db: Database, *, alert_id: str, title: str | None = None) -> str:
    case_id = str(uuid7())
    now = datetime.now(tz=UTC)
    if title is None:
        rows = db.query(
            "SELECT rendered_short FROM alerts WHERE alert_id = ?", [alert_id]
        ).fetchall()
        title = rows[0][0] if rows else f"Case {case_id[:8]}"
    db.execute("BEGIN TRANSACTION")
    try:
        db.execute(
            "INSERT INTO cases (case_id, title, status, opened_at, closed_at) "
            "VALUES (?, ?, 'open', ?, NULL)",
            [case_id, _bound(title), now],
        )
        _append_event(db, case_id, now, 0, "opened", None)
        _attach(db, case_id, alert_id, now, 1)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return case_id


def attach_alert(db: Database, *, case_id: str, alert_id: str) -> None:
    if not _case_exists(db, case_id):
        return
    _attach(db, case_id, alert_id, datetime.now(tz=UTC), 0)
```

- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit.** `feat(cases): store — open_case + attach_alert`.

### 2b — `add_note` + `close_case`

- [ ] **Step 1: Write failing tests**:
  - `add_note` appends a `note` event with the text; works on an OPEN case and (after `close_case`) on a CLOSED case (annotate-after-close).
  - `add_note` with text longer than 16384 chars stores a truncated value (length 16384).
  - `add_note`/`close_case` on a missing case → no-op, no raise.
  - `close_case` sets `status='closed'` + `closed_at` not null + appends a `closed` event; calling `close_case` again is a no-op (still one `closed` event, status stays closed).

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** (append to `store.py`):

```python
def add_note(db: Database, *, case_id: str, text: str) -> None:
    if not _case_exists(db, case_id):
        return
    _append_event(db, case_id, datetime.now(tz=UTC), 0, "note", text)


def close_case(db: Database, *, case_id: str) -> None:
    rows = db.query("SELECT status FROM cases WHERE case_id = ?", [case_id]).fetchall()
    if not rows or rows[0][0] == "closed":
        return
    now = datetime.now(tz=UTC)
    db.execute(
        "UPDATE cases SET status = 'closed', closed_at = ? WHERE case_id = ?", [now, case_id]
    )
    _append_event(db, case_id, now, 0, "closed", None)
```

- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit.** `feat(cases): store — add_note + close_case`.

### 2c — `list_cases` + `get_case`

- [ ] **Step 1: Write failing tests**:
  - `list_cases` returns each case with `alert_count` (= number of `case_alert` links) and fields; newest `opened_at` first (open two cases, assert order + counts).
  - `get_case` for a real case returns `{"case_id","title","status","opened_at","closed_at","alerts":[...],"timeline":[...]}`; `alerts` rows carry `alert_id, rule_id, severity, status, rendered_short, ts`; `timeline` is ordered by `(ts, seq)` so `opened` precedes `alert_attached`.
  - `get_case` for a case linking a PRUNED alert (link row exists but no `alerts` row) → that alert appears as a placeholder (`alert_id` set, `rendered_short`/`severity`/etc. `None`), so `len(case["alerts"]) == alert_count`.
  - `get_case` for a missing case_id → `None`.

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** (append to `store.py`):

```python
def list_cases(db: Database) -> list[dict[str, Any]]:
    rows = db.query(
        "SELECT c.case_id, c.title, c.status, c.opened_at, c.closed_at, "
        "  (SELECT COUNT(*) FROM case_alert a WHERE a.case_id = c.case_id) AS alert_count "
        "FROM cases c ORDER BY c.opened_at DESC"
    ).fetchall()
    return [
        {"case_id": r[0], "title": r[1], "status": r[2], "opened_at": r[3],
         "closed_at": r[4], "alert_count": r[5]}
        for r in rows
    ]


def get_case(db: Database, *, case_id: str) -> dict[str, Any] | None:
    crows = db.query(
        "SELECT case_id, title, status, opened_at, closed_at FROM cases WHERE case_id = ?",
        [case_id],
    ).fetchall()
    if not crows:
        return None
    c = crows[0]
    # LEFT JOIN so a pruned alert still appears (placeholder) and len(alerts) == alert_count.
    arows = db.query(
        "SELECT ca.alert_id, al.rule_id, al.severity, al.status, al.rendered_short, al.ts "
        "FROM case_alert ca LEFT JOIN alerts al ON al.alert_id = ca.alert_id "
        "WHERE ca.case_id = ? ORDER BY ca.attached_at",
        [case_id],
    ).fetchall()
    alerts = [
        {"alert_id": a[0], "rule_id": a[1], "severity": a[2], "status": a[3],
         "rendered_short": a[4], "ts": a[5]}
        for a in arows
    ]
    trows = db.query(
        "SELECT ts, seq, kind, text FROM case_event WHERE case_id = ? ORDER BY ts, seq",
        [case_id],
    ).fetchall()
    timeline = [{"ts": t[0], "seq": t[1], "kind": t[2], "text": t[3]} for t in trows]
    return {"case_id": c[0], "title": c[1], "status": c[2], "opened_at": c[3],
            "closed_at": c[4], "alerts": alerts, "timeline": timeline}
```

- [ ] **Step 4: Run — expect pass.** Run ruff + mypy on the new module.
- [ ] **Step 5: Commit.** `feat(cases): store — list_cases + get_case`.

---

## Task 3: `cases/ipc_handlers.py` + daemon wiring

Each handler wraps the store call in `with Database(db_path) as db:` (mirror `handle_capture_baseline`). Define a LOCAL `_iso` (copy, do not import from `state/ipc_handlers.py`). ISO-render timestamps in the read methods.

**Files:** Create `inspectord/cases/ipc_handlers.py`; Modify `inspectord/__main__.py`; Test `tests/cases/test_ipc_handlers.py`.

- [ ] **Step 1: Write failing tests** (`_fresh(tmp_path)` returns a migrated `db_path`, mirror `tests/state/test_ipc_handlers.py`; `_seed_alert` via a raw INSERT as in Task 2):
  - `handle_open_case(params={"alert_id": "a1"}, db_path=...)` returns `{"schema_version":"1.0.0","case_id": <str>}`.
  - `handle_add_note` / `handle_attach_alert` / `handle_close_case` return `{"schema_version":"1.0.0","ok": True}` (incl. unknown case_id → still `ok: True`, silent no-op).
  - `handle_list_cases` returns `{"schema_version":"1.0.0","cases":[...]}` with ISO `opened_at` strings.
  - `handle_get_case` returns the assembled case with ISO `opened_at`/alert `ts`/timeline `ts`; a missing case_id → `{"schema_version":"1.0.0","case": None}`.

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** `inspectord/cases/ipc_handlers.py`:

```python
"""IPC handlers for the Cases panel (spec §5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inspectord.cases import store
from inspectord.storage.db import Database


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def handle_open_case(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        case_id = store.open_case(
            db, alert_id=str(params["alert_id"]), title=params.get("title")
        )
    return {"schema_version": "1.0.0", "case_id": case_id}


def handle_attach_alert(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        store.attach_alert(db, case_id=str(params["case_id"]), alert_id=str(params["alert_id"]))
    return {"schema_version": "1.0.0", "ok": True}


def handle_add_note(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        store.add_note(db, case_id=str(params["case_id"]), text=str(params["text"]))
    return {"schema_version": "1.0.0", "ok": True}


def handle_close_case(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        store.close_case(db, case_id=str(params["case_id"]))
    return {"schema_version": "1.0.0", "ok": True}


def handle_list_cases(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        cases = store.list_cases(db)
    for c in cases:
        c["opened_at"] = _iso(c["opened_at"])
        c["closed_at"] = _iso(c["closed_at"])
    return {"schema_version": "1.0.0", "cases": cases}


def handle_get_case(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        case = store.get_case(db, case_id=str(params["case_id"]))
    if case is not None:
        case["opened_at"] = _iso(case["opened_at"])
        case["closed_at"] = _iso(case["closed_at"])
        for a in case["alerts"]:
            a["ts"] = _iso(a["ts"])
        for t in case["timeline"]:
            t["ts"] = _iso(t["ts"])
    return {"schema_version": "1.0.0", "case": case}
```

- [ ] **Step 4: Run tests — expect pass.**
- [ ] **Step 5: Wire `inspectord/__main__.py`.** Add the import and register all six methods alongside the existing list methods (find where `list_persistence`/`list_file_changes` are registered):

```python
from inspectord.cases.ipc_handlers import (
    handle_add_note,
    handle_attach_alert,
    handle_close_case,
    handle_get_case,
    handle_list_cases,
    handle_open_case,
)
```

```python
        Method(name="open_case",
               handler=lambda params: handle_open_case(params=params, db_path=cfg.storage.db_path),
               mutates=True),
        Method(name="attach_alert",
               handler=lambda params: handle_attach_alert(params=params, db_path=cfg.storage.db_path),
               mutates=True),
        Method(name="add_note",
               handler=lambda params: handle_add_note(params=params, db_path=cfg.storage.db_path),
               mutates=True),
        Method(name="close_case",
               handler=lambda params: handle_close_case(params=params, db_path=cfg.storage.db_path),
               mutates=True),
        Method(name="list_cases",
               handler=lambda params: handle_list_cases(params=params, db_path=cfg.storage.db_path),
               mutates=False),
        Method(name="get_case",
               handler=lambda params: handle_get_case(params=params, db_path=cfg.storage.db_path),
               mutates=False),
```

- [ ] **Step 6: Run all gates** (full pytest, ruff check + format, mypy). Confirm green.
- [ ] **Step 7: Commit.** `feat(cases): IPC handlers + daemon wiring for the six case methods`.

---

## Self-review checklist (before handoff)
- [ ] Spec coverage: §3 schema (Task 1), §4 store ops incl. atomic open_case / idempotent attach / LEFT-join get_case / `_MAX_TEXT` / reversible-close-with-add_note (Task 2), §5 six IPC methods + local `_iso` + unknown-case no-op (Task 3). ✓
- [ ] §1.1 honesty: migration comment + store docstring say case_event is NOT tamper-evident. ✓
- [ ] No web/inspectorctl changes (PR9). No evidence_collector / export (deferred §9).
- [ ] Signature consistency: `store.open_case(db, *, alert_id, title=None) -> str`; handlers wrap with `Database(db_path)`; `get_case` returns dict|None with `alerts`/`timeline` keys consumed identically by `handle_get_case`. ✓
- [ ] `mutates` flags: open/attach/add_note/close = True; list/get = False. ✓
