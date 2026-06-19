# PR5 — File integrity panel (entity-state sub-project 1, FINAL slice)

Spec: `docs/superpowers/specs/2026-06-16-entity-state-panels-design.md`
(§4 projection table line 184, §5 IPC 213, §6 panels 239, known-issue 253). Architecture
locked by PR1 (#99); mirrors the Services/Devices slices (single table, no baseline/diff).
`file_state` table already exists (migration 0004) — no migration. Simplest slice; closes
sub-project 1.

## Source data — what `fim_watcher` emits

`fim_watcher` (module `"fim_watcher"`), `action ∈ {file_created, file_modified,
file_deleted, file_attributes_changed, file_event}`, `event.file = {"path": "<path>"}`. Path
+ change type only — `fim_watcher` emits no hash/size/mode, so `file_state.sha256/size/mode/
uid/gid` stay NULL (spec §253 known issue).

This is a **recent-changes log** ("what changed"), not a "what currently exists" view: a
`file_deleted` event is **upserted** with `change_type='deleted'` (the row is KEPT), unlike
the listener projector which DELETEs. Newest `last_seen` leads.

## Tasks

### Task 1 — File projection + `list_file_changes` IPC (TDD, backend)

**Projector** (`inspectord/state/projector.py`) — add a `fim_watcher` branch →
`_project_file(event, db)` (mirror `_project_service`):
- `path = (event.file or {}).get("path")`; if no path → no-op.
- `change_type = event.action.removeprefix("file_")` → `"created"/"modified"/"deleted"/
  "attributes_changed"/"event"` (clean display value).
- upsert on `path`:
  `INSERT INTO file_state (path, change_type, first_seen, last_seen, last_event_id)
  VALUES (?, ?, ?, ?, ?) ON CONFLICT (path) DO UPDATE SET change_type=excluded.change_type,
  last_seen=excluded.last_seen, last_event_id=excluded.last_event_id` (preserve first_seen).
  sha256/size/mode/uid/gid omitted (default NULL). first_seen=last_seen=`event.ts`,
  last_event_id=`event.event_id`. **No DELETE branch** — `file_deleted` upserts
  `change_type='deleted'`.

**IPC handler** (`inspectord/state/ipc_handlers.py`) `handle_list_file_changes(*, params,
db_path)` (mirror `handle_list_devices`):
- params: `limit` default 200.
- `SELECT path, change_type, first_seen, last_seen FROM file_state ORDER BY last_seen DESC
  LIMIT ?` (newest first, spec §5).
- returns `{"schema_version": "1.0.0", "files": [{path, change_type, first_seen(ISO via
  _iso), last_seen(ISO)}]}`. No diff_status, no status filter.

**Daemon wiring** (`inspectord/__main__.py`): register `Method(name="list_file_changes",
handler=lambda params: handle_list_file_changes(...), mutates=False)` + import.

**Tests**:
- `tests/state/test_projector.py`: `_file_event(action, path, *, event_id, ts)` helper.
  Cover: file_created inserts a row with `change_type='created'`; file_modified on the same
  path updates change_type + advances last_seen, preserves first_seen; **file_deleted upserts
  `change_type='deleted'` and KEEPS the row** (assert the row still exists); a file event with
  no path → no-op. Existing projector tests still pass.
- `tests/state/test_ipc_handlers.py`: `_seed_file(...)`. `handle_list_file_changes` returns
  rows newest last_seen first; ISO first_seen/last_seen.

### Task 2 — File integrity web panel (TDD, frontend)

Mirror the Devices panel (single table, no baseline/diff). **Route paths use `/file-integrity`**:
- `inspectorctl/web/routes/file_integrity.py`: `GET /file-integrity` (shell
  `file_integrity.html`, title "inspectord — File integrity", current_path "/file-integrity")
  + `GET /file-integrity/feed` calls `list_file_changes` (limit `Query(default=300, ge=1,
  le=1000)`); WebIpcError → error string + empty list; reads `result.get("files", [])`.
- Templates `file_integrity.html` (hx-get `/file-integrity/feed`, every 5s, id
  `file-integrity-feed`) + `file_integrity_feed.html` (table: Path, Change, Last seen →
  `f.path`(mono), `f.change_type`, `f.last_seen`(mono muted); empty-state "No file changes
  observed yet."; error block like devices_feed).
- Register router in `app.py`; add `nav_link("/file-integrity", "File integrity",
  current_path)` to `base.html` after Devices (last in the panel group).
- Tests `tests/web/test_file_integrity.py` mirroring `test_devices.py`: shell renders; feed
  renders a row (assert a path like `/etc/passwd` and change_type `modified` appear, `<nav>`
  absent); empty state; daemon-unreachable.

## Out of scope
hash/size/mode capture (needs FIM extension — §253), AIDE-baseline diff, SUID inventory,
baseline/diff for files (Services-only), context cards, per-path filtering UI.

## Gates (all must pass before PR)
`.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` ·
`.venv/bin/ruff check inspectord inspectorctl tests` ·
`.venv/bin/ruff format --check inspectord inspectorctl tests` ·
`.venv/bin/mypy inspectord`
