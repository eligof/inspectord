# PR3 — Processes panel (entity-state sub-project 1)

Spec: `docs/superpowers/specs/2026-06-16-entity-state-panels-design.md`
(§4.1 projection table, §4.2 boot reconciliation, §5 IPC, §6 panels). Architecture locked
by PR1 (#99); mirrors the Services/Devices slices. `process_state` table + the
boot-reconciliation pass (`inspectord/state/reconcile.py`, wired in `Supervisor.start`)
already exist from PR1 — no migration, no new reconcile code; this PR adds the projector
branches + verifies reconcile end-to-end through real events.

## Source data — what the process collectors emit

- `process_collector` / `action="process_start"`: `event.process = {pid, name(=comm),
  command_line(=cmdline), parent:{pid}(=ppid, optional)}`, `event.user = {"id": "<uid str>"}`.
- `process_collector_exit` / `action="process_exit"`: `event.process = {pid, name(=comm),
  exit_code, exit_status?, killed_by_signal?}`. No user/ppid/cmdline on exit.
- **Neither event carries a boot_id.** The `process_state` PK is `(pid, boot_id)` (spec
  §14.1 key `pid:<pid>@boot:<boot_id>`). The projector must stamp the **current boot_id**,
  which the supervisor already reads at start via `current_boot_id()` (reconcile.py).
- `process_collector` does NOT emit exe_path → `exe_path`/`exe_sha256` stay NULL (acceptable;
  same "column null until the collector emits it" pattern as PR5's file sha256).

## Tasks

### Task 1 — Process projection + boot_id plumbing + `list_processes` (TDD, backend)

**Boot_id plumbing** — process events need the current boot_id at projection time:
- `inspectord/state/projector.py`: change signature to
  `project(event, db, *, boot_id: str | None = None)`. Add branches for module
  `process_collector` and `process_collector_exit` → `_project_process(event, db, boot_id)`,
  **only when `boot_id is not None`** (skip silently otherwise — mirrors the supervisor's
  `suppress(OSError)` around the boot_id read). The existing services/devices branches are
  unchanged and ignore boot_id.
- `inspectord/supervisor.py`: in `start()`, capture the boot id read inside the existing
  `suppress(OSError)` block into `self._boot_id` (init `self._boot_id: str | None = None` in
  `__init__`), then `reconcile_processes(self._db, self._boot_id)`. In `_persist`, call
  `project(ev, self._db, boot_id=self._boot_id)`.

**Projector `_project_process(event, db, boot_id)`** (mirror `_project_service`/`_project_device`):
- `pid = (event.process or {}).get("pid")`; if no pid → no-op.
- `process_start` → upsert `status='running'`: INSERT (pid, boot_id, ppid, comm, uid,
  cmdline, status='running', first_seen, last_seen, last_event_id) `ON CONFLICT (pid,
  boot_id) DO UPDATE SET` ppid/comm/uid/cmdline/last_seen/last_event_id + `status='running'`,
  preserving `first_seen`. ppid = `process.get("parent", {}).get("pid")`; comm =
  `process.get("name")`; cmdline = `process.get("command_line")`; uid = int of
  `(event.user or {}).get("id")` when present & digit-like else NULL (never raise on bad uid).
  exe_path/exe_sha256 left out of the INSERT (default NULL).
- `process_exit` → `INSERT (pid, boot_id, comm, status='exited', exit_code, first_seen,
  last_seen, last_event_id) ON CONFLICT (pid, boot_id) DO UPDATE SET status='exited',
  exit_code=excluded.exit_code, last_seen=excluded.last_seen,
  last_event_id=excluded.last_event_id`. This both flips an existing running row to exited
  **and** inserts an exited row when the exec was missed (spec §4.1). `first_seen` on the
  fresh-insert path = `event.ts`.

**IPC handler** `inspectord/state/ipc_handlers.py` `handle_list_processes(*, params, db_path)`
(mirror `handle_list_devices`):
- params: optional `status` filter, `limit` default 200.
- `SELECT pid, comm, ppid, uid, status, cmdline, first_seen FROM process_state
  [WHERE status=?] ORDER BY last_seen DESC LIMIT ?` (spec §5: newest last_seen first).
- returns `{"schema_version": "1.0.0", "processes": [{pid, comm, ppid, uid, status, cmdline,
  first_seen(ISO)}]}`. No diff_status.

**Daemon wiring** `inspectord/__main__.py`: register `Method(name="list_processes",
handler=lambda params: handle_list_processes(...), mutates=False)` + import.

**Tests**:
- `tests/state/test_projector.py`: `project(..., boot_id="b1")` — process_start inserts
  running row (pid/boot_id/ppid/comm/uid/cmdline); process_start with no pid is no-op; a
  process event with `boot_id=None` is a no-op (no row); process_exit flips an existing
  running row to exited + sets exit_code (first_seen preserved); process_exit with no prior
  row inserts an exited row (missed-exec path); bad/non-numeric uid → NULL, no raise. Add a
  `_process_event(...)` helper. Keep existing service/device tests passing (signature is
  backward-compatible — boot_id defaults to None).
- `tests/state/test_ipc_handlers.py`: `handle_list_processes` returns rows ordered newest
  last_seen first; `status` filter; first_seen ISO. Add `_seed_process(...)`.
- `tests/state/test_reconcile.py` (or test_supervisor): **end-to-end reconcile** — project a
  `process_start` with an OLD boot_id (`project(ev, db, boot_id="old-boot")`), then
  `reconcile_processes(db, "current-boot")`, assert the row flipped to `exited`; a row
  projected with the current boot stays `running`.
- `tests/test_supervisor.py`: extend the existing project-on-persist test (or add one) to
  inject a `process_start` via `_inject_for_test` and assert a `process_state` row appears
  with `status='running'` (uses the real current boot_id; gate on `process_state` non-empty,
  like the service test polls).

### Task 2 — Processes web panel (TDD, frontend)

Mirror `inspectorctl/web/routes/devices.py` (no baseline/diff):
- `inspectorctl/web/routes/processes.py`: `GET /processes` (shell) + `GET /processes/feed`
  (calls `list_processes`, limit `Query(default=300, ge=1, le=1000)`; WebIpcError → error
  string, empty list).
- Templates `processes.html` (hx-get `/processes/feed`, every 5s, id `processes-feed`) +
  `processes_feed.html` (table: PID, Comm, PPID, UID, Status, Cmdline, First seen → fields
  pid/comm/ppid/uid/status/cmdline/first_seen; `mono`/`muted` classes; empty-state "No
  processes observed yet."; error block like devices_feed).
- Register router in `inspectorctl/web/app.py`; add `nav_link("/processes", "Processes", …)`
  to `base.html` (place it first in the panel group — processes lead the §2.2 list).
- Tests `tests/web/test_processes.py` mirroring `test_devices.py`: shell renders, feed rows
  (assert pid/comm/status appear, `<nav>` absent), empty state, daemon-unreachable.

## Out of scope
Process-tree / open-files / threat-intel columns (need enrichment + anomaly_detector),
exe_path/sha256 capture, baseline/diff for processes, status-filter UI, mid-boot periodic
reconcile (§4.2 known gap).

## Gates (all must pass before PR)
`.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` ·
`.venv/bin/ruff check inspectord inspectorctl tests` ·
`.venv/bin/ruff format --check inspectord inspectorctl tests` ·
`.venv/bin/mypy inspectord`
