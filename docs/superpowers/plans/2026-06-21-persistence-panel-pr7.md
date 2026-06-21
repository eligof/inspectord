# Persistence projection + panel (PR7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. TDD throughout: write tests first, watch fail, implement, watch pass, run gates, commit.

**Goal:** Project `persistence_snapshotter` deltas into a materialized `persistence_state` table, wire baseline-diff for `kind='persistence'`, expose `list_persistence`, and ship the `/persistence` web panel — completing sub-project 2.

**Architecture:** Reuses the locked sub-project-1 projection architecture exactly. Mirrors the **Services** slice (single table + baseline-diff + Capture-baseline button), plus a new migration and projector branch. Removed entries are DELETEd (current set = all rows, like listeners); new/removed-vs-baseline is surfaced by baseline-diff.

**Tech Stack:** Python 3.14, DuckDB via `Database`, pydantic `Event`, FastAPI + Jinja2 + htmx, pytest.

**Spec:** `docs/superpowers/specs/2026-06-19-persistence-panel-design.md` (§4 storage, §5 projector, §6 IPC+baseline, §6.1 diff, §6.2 details bound, §7 panel). This PR = spec §8 "PR7". PR6 (collector) is merged; `persistence_snapshotter` emits `persistence_added`/`persistence_removed` Events carrying `event.persistence = {kind, name, source_path, details, key}`.

**Gates (run from repo root, all must pass before done):**
- `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- `.venv/bin/ruff check inspectord inspectorctl tests` · `.venv/bin/ruff format --check inspectord inspectorctl tests`
- `.venv/bin/mypy inspectord`

**Branch:** `feat/persistence-panel` (already checked out; spec + this plan ride along).

---

## Task 1 — migration + projector + baseline + `list_persistence` (TDD, backend)

**Files:**
- Create: `inspectord/storage/migrations_data/0005_persistence_state.sql`
- Modify: `inspectord/state/projector.py` (new branch + `_project_persistence`)
- Modify: `inspectord/state/baseline.py` (add `'persistence'` support)
- Modify: `inspectord/state/ipc_handlers.py` (`handle_list_persistence`)
- Modify: `inspectord/__main__.py` (register `list_persistence`)
- Test: `tests/test_persistence_state_migration.py`, and additions to `tests/state/test_projector.py`, `tests/state/test_baseline.py`, `tests/state/test_ipc_handlers.py`

### 1a — Migration `0005_persistence_state.sql`

- [ ] **Step 1: Write the failing test** `tests/test_persistence_state_migration.py` (mirror `tests/test_entity_state_migration.py`): run migrations on a fresh `Database`, assert a `persistence_state` table exists with the expected columns. Example:

```python
from pathlib import Path
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_persistence_state_table_created(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {r[0] for r in db.query("PRAGMA table_info('persistence_state')").fetchall()}
    assert {"persist_key", "kind", "name", "source_path", "details",
            "first_seen", "last_seen", "last_event_id"} <= cols
    db.close()
```

- [ ] **Step 2: Run it — expect failure** (no such table).
- [ ] **Step 3: Create the migration** (additive; migrations auto-discover by `\d{4}_*.sql` filename):

```sql
-- kind=persistence — persist:<kind>:<id>  (parent spec §14.1)
CREATE TABLE IF NOT EXISTS persistence_state (
    persist_key   VARCHAR PRIMARY KEY,
    kind          VARCHAR NOT NULL,
    name          VARCHAR,
    source_path   VARCHAR,
    details       VARCHAR,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    last_event_id VARCHAR
);
```

- [ ] **Step 4: Run the test — expect pass.**
- [ ] **Step 5: Commit.** `feat(storage): migration 0005 — persistence_state table`.

### 1b — Projector branch `_project_persistence`

Mirror `_project_listener` (upsert on add, delete on remove).

- [ ] **Step 1: Write failing tests** in `tests/state/test_projector.py` (add a `_persistence_event(action, *, key, kind="cron", name="j", source_path="/etc/crontab", details="d", event_id, ts=...)` helper that builds an `Event(module="persistence_snapshotter", action=action, persistence={...,"key":key}, ...)`):
  - `persistence_added` inserts a row (assert persist_key/kind/name/source_path/details/last_event_id).
  - `persistence_added` again on the same key preserves `first_seen`, advances `last_seen`/`last_event_id`/details.
  - `persistence_removed` DELETEs the row (assert gone).
  - an event with no `key` (`persistence={}` or `persistence=None`) is a no-op (no row, no raise).
  - Existing projector tests still pass.

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement.** In `project()` add (after the file branch):

```python
    elif event.module == "persistence_snapshotter":
        _project_persistence(event, db)
```

and the function (mirror `_project_listener`):

```python
def _project_persistence(event: Event, db: Database) -> None:
    p = event.persistence or {}
    key = p.get("key")
    if not key:
        return
    if event.action == "persistence_removed":
        db.execute("DELETE FROM persistence_state WHERE persist_key = ?", [key])
        return
    db.execute(
        """
        INSERT INTO persistence_state
            (persist_key, kind, name, source_path, details, first_seen, last_seen, last_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (persist_key) DO UPDATE SET
            kind          = excluded.kind,
            name          = excluded.name,
            source_path   = excluded.source_path,
            details       = excluded.details,
            last_seen     = excluded.last_seen,
            last_event_id = excluded.last_event_id
        """,
        [key, p.get("kind"), p.get("name"), p.get("source_path"), p.get("details"),
         event.ts, event.ts, event.event_id],
    )
```

- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit.** `feat(state): project persistence entity state`.

### 1c — `capture_baseline` persistence branch

`baseline.py` is currently per-kind with `_SUPPORTED = {"service"}`. Add persistence.

- [ ] **Step 1: Write failing tests** in `tests/state/test_baseline.py` (mirror the service test): seed two `persistence_state` rows, call `capture_baseline("persistence", db)`, assert it returns `2` and that `baseline_entry` has 2 rows with `kind='persistence'`, `key` = the persist_key, and `attrs_json` containing `{kind,name,source_path,details}`.

- [ ] **Step 2: Run — expect failure** (`unsupported baseline kind: 'persistence'`).
- [ ] **Step 3: Implement.** Add `"persistence"` to `_SUPPORTED`; branch on kind. Refactor minimally — keep the existing service path, add:

```python
    if kind == "persistence":
        rows = db.query(
            "SELECT persist_key, kind, name, source_path, details FROM persistence_state"
        ).fetchall()
        for pk, k, name, source_path, details in rows:
            attrs = json.dumps({"kind": k, "name": name,
                                "source_path": source_path, "details": details})
            db.execute(
                "INSERT INTO baseline_entry (kind, key, attrs_json, captured_at) "
                "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                ["persistence", pk, attrs],
            )
        return len(rows)
```

(Place the `DELETE FROM baseline_entry WHERE kind = ?` for the captured kind before the branch, as the service path does, so it applies to both kinds.)

- [ ] **Step 4: Run — expect pass.** (Service baseline tests must still pass.)
- [ ] **Step 5: Commit.** `feat(state): capture_baseline for persistence`.

### 1d — `handle_list_persistence` + daemon wiring

Mirror `handle_list_services` (with diff), but the persistence diff has **no "re-enabled"** — only new/removed/unchanged (spec §6.1).

- [ ] **Step 1: Write failing tests** in `tests/state/test_ipc_handlers.py` (add a `_seed_persistence(db_path, persist_key, kind, name)` helper):
  - `handle_list_persistence(params={}, db_path=...)` returns rows ordered by `kind, name`; result key is `"persistence"`; ISO `first_seen`/`last_seen`; no `diff_status` without the flag.
  - With `params={"diff": True}` and no baseline → every row `diff_status == "new"`.
  - Seed rows, `capture_baseline("persistence")`, then mutate (add one new key, delete one) → diff yields `new` for the added, `removed` (synthetic row) for the deleted, `unchanged` for the kept. Assert NO `"re-enabled"` ever appears.

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** `handle_list_persistence(*, params, db_path)` mirroring `handle_list_services`:
  - `limit = int(params.get("limit", 200))`, `want_diff = bool(params.get("diff", False))`.
  - `SELECT persist_key, kind, name, source_path, details, first_seen, last_seen FROM persistence_state ORDER BY kind, name LIMIT ?`.
  - If `want_diff`, load `baseline_entry` for `kind='persistence'` into `{key: attrs}`; per row `diff_status = "new" if persist_key not in baseline else "unchanged"`; track current keys; append synthetic `removed` rows for baseline keys absent from the current set (null name/kind/details, `diff_status="removed"`, `persist_key` = the baseline key).
  - Return `{"schema_version": "1.0.0", "persistence": [{persist_key, kind, name, source_path, details, first_seen(ISO), last_seen(ISO)[, diff_status]}]}`.
  - Use the existing `_iso` helper. Do NOT reuse `_diff_status` (that has service "re-enabled" logic); write the simpler new/removed/unchanged inline.
- [ ] **Step 4: Register the method.** In `inspectord/__main__.py`, add `handle_list_persistence` to the import and register `Method(name="list_persistence", handler=lambda params: handle_list_persistence(params=params, db_path=cfg.storage.db_path), mutates=False)` (alongside `list_file_changes` etc.). `capture_baseline` is already registered (now accepts `kind='persistence'`).
- [ ] **Step 5: Run all gates.** Commit. `feat(ipc): list_persistence (with diff) + persistence baseline wiring`.

---

## Task 2 — Persistence web panel (TDD, frontend)

Mirror the **Services** panel exactly (single table + Capture-baseline button + diff badge), substituting persistence.

**Files:**
- Create: `inspectorctl/web/routes/persistence.py`
- Create: `inspectorctl/web/templates/persistence.html`, `inspectorctl/web/templates/persistence_feed.html`
- Modify: `inspectorctl/web/app.py` (register router), `inspectorctl/web/templates/base.html` (nav link)
- Test: `tests/web/test_persistence.py`

- [ ] **Step 1: Write failing tests** `tests/web/test_persistence.py` (mirror `tests/web/test_services.py`), using `ipc_factory` + `from inspectord.ipc_server import Method`:
  - shell renders: `GET /persistence` 200, contains hx-get, `/persistence/feed`, `persistence-feed`.
  - feed renders rows: mock `list_persistence` returning one row `{"persist_key":"persist:cron:/etc/crontab:abc","kind":"cron","name":"backup","source_path":"/etc/crontab","details":"@daily root backup","first_seen":"2026-06-16T00:00:00","last_seen":"2026-06-16T01:00:00","diff_status":"new"}`; assert `cron`, `backup`, `/etc/crontab`, and the `new` badge appear; `<nav>` NOT in the fragment.
  - **escaping test (spec §7):** mock a row whose `details` is `"<script>alert(1)</script>"`; assert the raw `<script>` string is NOT present in `response.text` (it must be HTML-escaped, e.g. `&lt;script&gt;`). This pins the no-`| safe` requirement.
  - empty state: `No persistence entries observed`.
  - daemon-unreachable: `create_app(socket_path=tmp_path / "no.sock")` → `daemon unreachable`.
  - capture-baseline POST: `POST /persistence/capture-baseline` → 303; the mocked `capture_baseline` received `kind == "persistence"`.

- [ ] **Step 2: Run — expect failure** (404s).
- [ ] **Step 3: Implement** mirroring `inspectorctl/web/routes/services.py`:
  - `GET /persistence` → `persistence.html` (`title "inspectord — Persistence"`, `current_path "/persistence"`).
  - `GET /persistence/feed` → calls `list_persistence` with `{"diff": True, "limit": limit}` (limit `Query(default=300, ge=1, le=1000)`); on `WebIpcError` set the error string + empty list; reads `result.get("persistence", [])`; renders `persistence_feed.html`.
  - `POST /persistence/capture-baseline` → calls `capture_baseline` with `{"kind": "persistence"}`; on error `HTTPException(502)`; else `RedirectResponse("/persistence", 303)`.
  - `persistence.html` mirrors `services.html`: `<h1>Persistence</h1>`, the capture-baseline `<form method="post" action="/persistence/capture-baseline">` + button, and the hx-get polling block (`/persistence/feed`, `load, every 5s`, id `persistence-feed`).
  - `persistence_feed.html` mirrors `services_feed.html`: `{% from "_macros.html" import status_badge %}`, error block, table columns **Kind, Name, Source, Details, Diff, First seen** → `p.kind`, `p.name`, `p.source_path` (mono), `p.details` (mono muted), `status_badge(p.diff_status) if p.diff_status`, `p.first_seen` (mono muted). Empty-state `No persistence entries observed yet.` All of `name`/`source_path`/`details` render as plain autoescaped `{{ ... }}` — **no `| safe`**.
  - Register the router in `app.py`; add `nav_link("/persistence", "Persistence", current_path)` to `base.html` after File integrity.
- [ ] **Step 4: Run gates — expect pass.**
- [ ] **Step 5: Commit.** `feat(web): Persistence panel with baseline diff + capture button`.

---

## Self-review checklist (before handoff)
- [ ] Spec coverage: §4 migration (1a), §5 projector add/remove + no-key no-op (1b), §6 capture_baseline + list_persistence + §6.1 diff new/removed/unchanged-no-re-enabled (1c/1d), §6.2 — details already bounded at the collector (PR6); §7 panel + escaping test (Task 2). ✓
- [ ] Removed = DELETE (not retained), mirroring listeners. ✓
- [ ] `persistence` result key + `attrs` field names consistent with the collector's `event.persistence` block and the table columns. ✓
- [ ] No "re-enabled" in the persistence diff. ✓
- [ ] No placeholders; all code shown. ✓
- [ ] Out of scope (do NOT build): detection rules, extra mechanisms, per-entry enable/disable state.
