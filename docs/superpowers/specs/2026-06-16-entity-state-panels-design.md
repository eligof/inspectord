# Entity-state projection + System/Integrity dashboard panels — design

| Field | Value |
| --- | --- |
| Date | 2026-06-16 |
| Status | Approved (brainstorming) — ready for implementation plan |
| Spec section refs | §2.2 (panels), §14.1 (entities), §16 (IPC), §19 (baselines), §31 (roadmap, Phase 2) |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` |

## 1. Purpose & context

The design spec defines **28 dashboard panels** (§2.2); Phase 1 shipped 4 (Alerts, Live events,
Health, Dependencies). This program builds the remaining **7 System/Integrity panels**:
Processes, Network, Services, Devices, File integrity, Persistence, Cases.

Those 7 split unevenly by data source, so this is a **program decomposed into three sequential
sub-projects**, each its own spec → plan → implementation cycle:

1. **Entity-state projection + 5 data-backed panels** *(this document)* — Processes, Network,
   Services, Devices, File integrity. All backed by collectors already in `main`.
2. **Persistence** — net-new collector(s) for cron / systemd timers / `autostart` / shell-rc
   files, then its panel. (Separate spec.)
3. **Cases** — `evidence_collector` backend + forensic-bundle/export, then its panel.
   (Separate spec.)

**This spec covers sub-project 1 only.**

### Design decisions (locked during brainstorming)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Render model | **Reconstructed live state** | Panels show "what exists now," not just event history. |
| Projection architecture | **Materialized state tables + projector** | O(1) reads; foundation for `first_seen`/baselines/`anomaly_detector` later. |
| Schema shape | **Per-kind typed tables** | Typed columns per panel; clearer than a generic JSON blob. |
| Baseline diff | **Included now, wired to Services** | Spec §2.2 explicitly wants Services new/removed/re-enabled. |

## 2. Architecture (4 layers)

```
worker stdout ─► Supervisor._read_stdout ─► enrich ─► rule_engine ─► router.publish
                                                                          │
                                                  (single-threaded drain) ▼
                                              Supervisor._drain ─► Supervisor._persist
                                                                          │
                                       ┌──────────────────────────────────┼─────────────┐
                                       ▼                                   ▼             ▼
                              INSERT events_enriched              journal.append   project(event, db)   ◄── NEW
                                                                                          │
                                                                                  per-kind *_state upsert
                                                                                          │
        inspectorctl-web ─IPC─► list_processes / list_connections / list_listeners /      │
                                list_services / list_devices / list_file_changes  ◄────────┘
                                capture_baseline(kind)
```

1. **Storage** — migration `0004_entity_state.sql`: per-kind state tables + one generic
   `baseline_entry` table.
2. **Projector** — `inspectord/state/projector.py`: `project(event, db)`, called from
   `Supervisor._persist` inside the same DB write. The drain loop is single-threaded ⇒ events
   are applied in order with no locking or dual-write race. A startup **boot-reconciliation**
   pass marks stale process rows exited.
3. **IPC** — read-only snapshot methods + one mutating `capture_baseline`, registered in
   `inspectord/__main__.py` alongside the existing `list_events` / `get_health` methods.
4. **Web** — 5 panels following the established pattern exactly (shell template + HTMX-polled
   feed fragment + route in `inspectorctl/web/routes/`), plus nav links in `base.html`.

## 3. Storage schema (`0004_entity_state.sql`)

All timestamps stored UTC. `last_event_id` links a state row back to the event that last
mutated it (for the future context card, §14). Entity keys follow §14.1.

```sql
-- kind=process — pid:<pid>@boot:<boot_id>
CREATE TABLE IF NOT EXISTS process_state (
  pid           INTEGER NOT NULL,
  boot_id       TEXT    NOT NULL,
  ppid          INTEGER,
  comm          TEXT,
  exe_path      TEXT,
  exe_sha256    TEXT,
  uid           INTEGER,
  cmdline       TEXT,
  status        TEXT    NOT NULL,   -- 'running' | 'exited'
  exit_code     INTEGER,
  first_seen    TIMESTAMP NOT NULL,
  last_seen     TIMESTAMP NOT NULL,
  last_event_id TEXT,
  PRIMARY KEY (pid, boot_id)
);

-- kind=connection
CREATE TABLE IF NOT EXISTS connection_state (
  conn_key      TEXT PRIMARY KEY,   -- f"{pid}:{daddr}:{dport}:{proto}"
  pid           INTEGER,
  comm          TEXT,
  saddr         TEXT, sport INTEGER,
  daddr         TEXT, dport INTEGER,
  proto         TEXT, family TEXT,
  status        TEXT NOT NULL,      -- 'observed'
  first_seen    TIMESTAMP NOT NULL,
  last_seen     TIMESTAMP NOT NULL,
  last_event_id TEXT
);

-- kind=listener — port:<addr>:<port>
CREATE TABLE IF NOT EXISTS listener_state (
  addr          TEXT NOT NULL,
  port          INTEGER NOT NULL,
  proto         TEXT NOT NULL,
  family        TEXT,
  pid           INTEGER,
  comm          TEXT,
  first_seen    TIMESTAMP NOT NULL,
  last_seen     TIMESTAMP NOT NULL,
  snapshot_gen  BIGINT NOT NULL,    -- informational: generation at last sighting (removed rows are deleted, so current set = all rows)
  PRIMARY KEY (addr, port, proto)
);

-- kind=service — svc:<unit>
CREATE TABLE IF NOT EXISTS service_state (
  unit          TEXT PRIMARY KEY,
  active_state  TEXT,               -- active | inactive | failed | ...
  sub_state     TEXT,
  load_state    TEXT,               -- loaded | not-found | masked | ...
  first_seen    TIMESTAMP NOT NULL,
  last_seen     TIMESTAMP NOT NULL,
  last_event_id TEXT
);

-- kind=device — dev:<vendor:product:serial>
CREATE TABLE IF NOT EXISTS device_state (
  dev_key       TEXT PRIMARY KEY,   -- f"{vendor}:{product}:{serial}" (devpath fallback)
  vendor        TEXT, product TEXT, serial TEXT,
  subsystem     TEXT, devnode TEXT,
  status        TEXT NOT NULL,      -- 'present' | 'removed'
  first_seen    TIMESTAMP NOT NULL,
  last_seen     TIMESTAMP NOT NULL,
  last_event_id TEXT
);

-- kind=file — file:<path>
CREATE TABLE IF NOT EXISTS file_state (
  path          TEXT PRIMARY KEY,
  change_type   TEXT,               -- from fim action (created/modified/deleted/...)
  sha256        TEXT,               -- nullable: fim_watcher does not emit hashes today
  size          BIGINT,             -- nullable, future
  mode          INTEGER,            -- nullable, future
  uid           INTEGER,            -- nullable, future
  gid           INTEGER,            -- nullable, future
  first_seen    TIMESTAMP NOT NULL,
  last_seen     TIMESTAMP NOT NULL,
  last_event_id TEXT
);

-- generic baseline store (reference data; uniform across kinds)
CREATE TABLE IF NOT EXISTS baseline_entry (
  kind          TEXT NOT NULL,      -- 'service' (others reuse later)
  key           TEXT NOT NULL,      -- entity key, e.g. 'svc:sshd.service'
  attrs_json    TEXT NOT NULL,      -- captured snapshot attrs
  captured_at   TIMESTAMP NOT NULL,
  PRIMARY KEY (kind, key)
);
```

## 4. Projector (`inspectord/state/projector.py`)

`project(event: Event, db: Database) -> None` dispatches on `(module, action)` and performs the
per-kind upsert. Upserts use DuckDB `INSERT … ON CONFLICT (<pk>) DO UPDATE`. `first_seen` is set
only on insert; `last_seen` and `last_event_id` update every time. Unknown `(module, action)`
pairs are a no-op (so adding collectors never breaks projection).

| Collector event | Table | Transition |
| --- | --- | --- |
| `process_collector` / `process_start` | `process_state` | insert/upsert `status='running'`, comm/ppid/exe/uid/cmdline from `process.*`, `user.id` |
| `process_collector_exit` / *exit* | `process_state` | update `status='exited'`, `exit_code`, `last_seen` (insert exited row if exec was missed) |
| `outbound_connection_tracker(+6)` / `outbound_connection` | `connection_state` | upsert `status='observed'` from `source.*`/`destination.*`/`network.transport` |
| `listening_socket_snapshotter` / `listener_added` | `listener_state` | upsert with current `snapshot_gen` |
| `listening_socket_snapshotter` / `listener_removed` | `listener_state` | delete the (addr,port,proto) row |
| `services_monitor` / `service_added`,`service_state_changed` | `service_state` | upsert `active_state`/`sub_state`/`load_state` |
| `services_monitor` / `service_removed` | `service_state` | delete the unit row |
| `udev_monitor` / `device_added` | `device_state` | upsert `status='present'` |
| `udev_monitor` / `device_changed` | `device_state` | update attrs, keep `status='present'` |
| `udev_monitor` / `device_removed` | `device_state` | update `status='removed'` |
| `fim_watcher` / *change* | `file_state` | upsert `change_type`, `last_seen` (hash/size/mode null until fim emits them) |

### 4.1 Listener snapshot generation

`listening_socket_snapshotter` emits per-listener `listener_added` / `listener_removed`
deltas, so the projector simply upserts on `listener_added` and deletes on `listener_removed`;
the current listener set is therefore just all rows in `listener_state`. No full set-replacement
logic is required because the snapshotter already diffs and emits removals. `snapshot_gen` is an
informational counter (the generation at which a listener was last seen), not the set selector.

### 4.2 Boot reconciliation

On `Supervisor` start, before draining, run:
`UPDATE process_state SET status='exited' WHERE boot_id <> <current_boot_id> AND status='running'`.
The boot-scoped key (§14.1) makes this exact — a reused pid in a new boot is a different row.
Current boot id is read from `/proc/sys/kernel/random/boot_id`.

## 5. IPC methods (`inspectord/__main__.py`)

Mirror the existing `_list_events_handler` shape (params dict → JSON result with
`schema_version`). All read-only except `capture_baseline`.

| Method | Params | Returns |
| --- | --- | --- |
| `list_processes` | `status?`, `limit` | process rows; default newest `last_seen` first |
| `list_connections` | `active_within_s?`, `limit` | connection rows; `active` flag = `last_seen` within window |
| `list_listeners` | `limit` | current listener rows |
| `list_services` | `diff?` (bool), `limit` | service rows; when `diff`, each row carries `diff_status` ∈ {new, removed, re-enabled, unchanged} vs `baseline_entry` |
| `list_devices` | `status?`, `limit` | device rows |
| `list_file_changes` | `limit` | file rows, newest `last_seen` first |
| `capture_baseline` | `kind` (`'service'`) | **mutates**: replaces `baseline_entry` rows for `kind` with a fresh snapshot of the current `*_state`; returns count |

### 5.1 Services diff semantics

Computed in `list_services` by joining `service_state` against `baseline_entry WHERE kind='service'`:

- **new** — unit in `service_state`, not in baseline.
- **removed** — unit in baseline, not in `service_state` (surfaced as a synthetic row).
- **re-enabled** — unit in both, baseline `active_state` was inactive/failed but current is active.
- **unchanged** — otherwise.

Before the first `capture_baseline('service')`, baseline is empty ⇒ every unit reads **new**; the
panel shows a "No baseline captured — capture one" prompt.

## 6. Web panels (`inspectorctl/web/`)

Each panel = a route module + a shell template + an HTMX-polled feed fragment, identical in shape
to `routes/events.py` + `events.html` + `events_feed.html`. Nav links added to `base.html`.

| Panel | Route | IPC | Notable columns |
| --- | --- | --- | --- |
| Processes | `/processes` (+`/feed`) | `list_processes` | pid, comm, ppid, uid, status, cmdline, first_seen |
| Network | `/network` (+`/feed`) | `list_connections` + `list_listeners` | two tables: connections (pid/comm → daddr:dport, active flag) and listeners (addr:port, proto, pid/comm) |
| Services | `/services` (+`/feed`) | `list_services?diff=1` | unit, active/sub/load, diff badge; **"Capture baseline"** button → `capture_baseline` |
| Devices | `/devices` (+`/feed`) | `list_devices` | vendor/product/serial, subsystem, devnode, status, first_seen |
| File integrity | `/file-integrity` (+`/feed`) | `list_file_changes` | path, change_type, last_seen |

UI conventions reused from Phase 1: severity/status badge classes, mono columns, `muted`
timestamps, `empty`-state divs. Times rendered as stored (UTC) for now — local-TZ rendering is a
cross-cutting Phase-3 concern (§2.3) tracked separately.

## 7. Limitations (consequences of the chosen approach)

- **Zombie processes** — a missed exit leaves a `running` row; mitigated by boot reconciliation
  (§4.2). Mid-boot missed exits are a known gap; periodic reconcile deferred.
- **Connection liveness** — no close events from the tracker, so `active` is a
  `last_seen`-within-window heuristic, labelled as such in the UI.
- **Pre-daemon entities** — state reflects only what collectors observed since daemon start
  (inherent to event-sourcing).
- **File metadata** — `fim_watcher` emits path + change type only; `file_state.sha256/size/mode`
  stay null until FIM is extended (AIDE-baseline diff / SUID inventory are a later Integrity item).
- **Baseline diff** — wired to Services only; `baseline_entry` is generic so Listeners/Files
  diffs are cheap follow-ons.

## 8. Testing

- **Projector unit tests** — feed synthetic `Event`s through `project()` against an in-memory
  DuckDB; assert state-table contents after each transition (insert, update, delete, exit,
  device add→remove, listener add→remove). TDD: write these first.
- **Boot reconciliation test** — seed `running` rows with an old boot_id; assert they flip to
  `exited` on the reconcile pass; current-boot rows untouched.
- **IPC handler tests** — seed `*_state` rows; assert each `list_*` shape, filters, and the
  Services `diff_status` computation across all four statuses (incl. empty-baseline = all-new).
- **`capture_baseline` test** — capture, mutate `service_state`, re-list with `diff`, assert
  new/removed/re-enabled transitions.
- **Web route tests** — extend `tests/web/` (mirror `test_events.py`): panel shell renders, feed
  fragment renders rows from a stubbed IPC, daemon-unreachable shows the error banner.
- All CI gates green (`lint-and-test`, CodeQL, cargo-audit, dependency-review). No Rust changes in
  this sub-project (pure Python — projector + IPC + web).

## 9. PR breakdown

Pure-Python throughout (no eBPF), so each PR is a single PR per repo convention.

1. **Projection core + Services** — migration `0004` (all tables), `state/projector.py` + hook in
   `_persist`, boot reconciliation, `baseline_entry` + `capture_baseline`, `list_services` with
   diff, **Services panel**. (Establishes the pattern.)
2. **Devices** — device projection wiring + `list_devices` + **Devices panel**.
3. **Processes** — process/exit projection + boot-reconcile verified end-to-end + `list_processes`
   + **Processes panel**.
4. **Network** — connection + listener projection + `list_connections`/`list_listeners` +
   **Network panel**.
5. **File integrity** — file projection + `list_file_changes` + **File integrity panel**.

Built via `superpowers:subagent-driven-development` per repo `CLAUDE.md`.

## 10. Out of scope (this sub-project)

Persistence panel + collectors (sub-project 2); Cases + `evidence_collector` (sub-project 3);
baseline diff for non-service kinds; first-run-wizard baseline capture (§19.1); local-TZ / theme /
density UI cross-cutting work; context cards (§14); geo/ASN enrichment for Network; process tree
visualization / open-files / threat-intel columns (need enrichment + anomaly_detector).
