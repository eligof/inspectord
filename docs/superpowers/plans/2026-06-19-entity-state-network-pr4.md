# PR4 — Network panel (entity-state sub-project 1)

Spec: `docs/superpowers/specs/2026-06-16-entity-state-panels-design.md`
(§4 projection table lines 176-192, §5 IPC 209-210, §6 panels 236). Architecture locked by
PR1 (#99); mirrors the Services/Devices/Processes slices. `connection_state` +
`listener_state` tables already exist (migration 0004) — no migration. This is the most
complex slice: **two** entity kinds + **two** IPC handlers + a **two-table** panel.

## Source data

**Connections** — `outbound_connection_tracker` AND `outbound_connection_tracker6` (both
module names), `action="outbound_connection"`:
- `event.process = {pid, name(=comm)}`, `event.user = {"id": "<uid>"}` (uid unused here),
  `event.source = {ip(=saddr), port(=sport)}`, `event.destination = {ip(=daddr),
  port(=dport)}`, `event.network = {transport:"tcp", direction:"egress"}`.
- Both v4 and v6 set `transport:"tcp"` and carry no explicit family → derive family from the
  address: `"ipv6" if ":" in daddr else "ipv4"`.

**Listeners** — `listening_socket_snapshotter`, `action ∈ {listener_added,
listener_removed}`:
- `event.source = {ip(=addr), port}`, `event.network = {transport:"tcp"|"udp",
  direction:"ingress"}`. **No process/user** → listener `pid`/`comm` stay NULL.
- The snapshotter already diffs and emits per-listener add/remove deltas (spec §4.1), so the
  projector just upserts on `listener_added` and deletes on `listener_removed`; the current
  set is all rows in `listener_state`. No set-replacement logic.

## Tasks

### Task 1 — Connection + listener projection + two IPC handlers (TDD, backend)

**Projector** (`inspectord/state/projector.py`) — add two branches to `project()`:

- module in `("outbound_connection_tracker", "outbound_connection_tracker6")` →
  `_project_connection(event, db)`:
  - `pid = (process or {}).get("pid")`; `daddr = (destination or {}).get("ip")`; if either
    missing → no-op.
  - `proto = (network or {}).get("transport")` (e.g. `"tcp"`); `conn_key =
    f"{pid}:{daddr}:{dport}:{proto}"` (spec §4 key).
  - upsert `status='observed'`, `ON CONFLICT (conn_key) DO UPDATE` comm/saddr/sport/daddr/
    dport/proto/family/last_seen/last_event_id, preserve first_seen. comm = `process.get
    ("name")`; saddr/sport from `source`; daddr/dport from `destination`; family =
    `"ipv6" if ":" in daddr else "ipv4"`.

- module `"listening_socket_snapshotter"` → `_project_listener(event, db)`:
  - `addr = (source or {}).get("ip")`; `port = (source or {}).get("port")`; `proto =
    (network or {}).get("transport")`; if addr/port/proto missing → no-op.
  - `listener_removed` → `DELETE FROM listener_state WHERE addr=? AND port=? AND proto=?`
    (short-circuit, mirror `service_removed`).
  - `listener_added` → upsert `ON CONFLICT (addr, port, proto) DO UPDATE` family/last_seen/
    snapshot_gen, preserve first_seen. family = `"ipv6" if ":" in addr else "ipv4"`.
    `snapshot_gen = int(event.ts.timestamp())` (informational "generation at last sighting",
    NOT NULL — spec §4.1 says it's not the set selector). pid/comm omitted (NULL).

**IPC handlers** (`inspectord/state/ipc_handlers.py`):

- `handle_list_connections(*, params, db_path)`:
  - params: `active_within_s` (default 300), `limit` (default 200).
  - `SELECT conn_key, pid, comm, saddr, sport, daddr, dport, proto, family, status,
    first_seen, last_seen FROM connection_state ORDER BY last_seen DESC LIMIT ?`.
  - compute `active` per row: **TZ PITFALL** — DuckDB returns naive datetimes, so use
    `now = datetime.now(tz=UTC).replace(tzinfo=None)`; `active = last_seen is not None and
    (now - last_seen).total_seconds() <= active_within_s`. Never subtract aware−naive.
  - returns `{"schema_version": "1.0.0", "connections": [{... , first_seen(ISO),
    last_seen(ISO), active(bool)}]}`. No diff_status.

- `handle_list_listeners(*, params, db_path)`:
  - params: `limit` (default 200).
  - `SELECT addr, port, proto, family, pid, comm, first_seen FROM listener_state
    ORDER BY addr, port LIMIT ?`.
  - returns `{"schema_version": "1.0.0", "listeners": [{... , first_seen(ISO)}]}`.

**Daemon wiring** (`inspectord/__main__.py`): register `list_connections` and
`list_listeners` Methods (`mutates=False`) + imports.

**Tests**:
- `tests/state/test_projector.py`: `_connection_event(...)` + `_listener_event(...)` helpers.
  Connections: upsert inserts observed row w/ correct conn_key + family from daddr (v4 + a v6
  daddr containing `:`); re-observe preserves first_seen, advances last_seen; missing
  pid/daddr → no-op; v6 module routes through the same branch. Listeners: listener_added
  inserts row (family from addr, snapshot_gen set); listener_removed deletes the row; add
  then re-add preserves first_seen. Existing service/device/process tests still pass.
- `tests/state/test_ipc_handlers.py`: `_seed_connection(...)` + `_seed_listener(...)`.
  list_connections returns rows newest-first; `active` true for a row seeded with a
  near-now last_seen and false for one seeded with an old last_seen (assert the
  `active_within_s` window); first_seen/last_seen ISO. list_listeners returns rows ordered by
  addr,port; first_seen ISO.

### Task 2 — Network web panel (two tables) (TDD, frontend)

Mirror the Devices panel but render **two** tables from **two** IPC calls:
- `inspectorctl/web/routes/network.py`: `GET /network` (shell `network.html`, title
  "inspectord — Network", current_path "/network") + `GET /network/feed` calls BOTH
  `list_connections` and `list_listeners` (limit `Query(default=300, ge=1, le=1000)`),
  renders `network_feed.html` with `{connections, listeners, error}`. On `WebIpcError` (from
  either call) → `error = f"daemon unreachable: {exc}"`, both lists empty.
- Templates `network.html` (hx-get `/network/feed`, every 5s, id `network-feed`) +
  `network_feed.html`: error block like devices_feed, then a **Connections** section
  (`<h2>Connections</h2>` + table: PID, Comm, Source, Dest, Proto, Family, Active, Last seen
  → pid/comm/`{saddr}:{sport}`/`{daddr}:{dport}`/proto/family/active/last_seen; render active
  as e.g. `●`/`○` or `yes`/`no`) and a **Listeners** section (`<h2>Listeners</h2>` + table:
  Address, Port, Proto, Family, PID, Comm, First seen). Each section has its own empty-state
  ("No connections observed yet." / "No listeners observed yet.").
- Register router in `app.py`; add `nav_link("/network", "Network", current_path)` to
  `base.html` after Services (order: …, Processes, Services, **Network**, Devices — keep
  Network adjacent to the other system panels; place it right after Services).
- Tests `tests/web/test_network.py`: shell renders; feed renders both a connection row
  (assert daddr/dport/comm appear) and a listener row (assert addr/port appear), `<nav>`
  absent; both empty states; daemon-unreachable. Mock BOTH methods via `ipc_factory`.

## Out of scope
Geo/ASN enrichment, context cards, connection close-tracking (active is a heuristic — §
known issues), baseline/diff for connections/listeners (baseline is Services-only),
inbound-connection tracking, status-filter UI.

## Gates (all must pass before PR)
`.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` ·
`.venv/bin/ruff check inspectord inspectorctl tests` ·
`.venv/bin/ruff format --check inspectord inspectorctl tests` ·
`.venv/bin/mypy inspectord`
