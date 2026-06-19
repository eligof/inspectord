# PR2 — Devices panel (entity-state sub-project 1)

Spec: `docs/superpowers/specs/2026-06-16-entity-state-panels-design.md`
(§3 schema, §4 projection table, §5 IPC, §6 panels). Architecture is locked by PR1
(merged as #99). This PR adds the **Devices** kind end-to-end, mirroring the Services
slice — but **without** baseline/diff (spec §2.2 wires baseline-diff to Services only).

`device_state` table already exists (migration 0004 created all 7 tables up front). No
new migration.

## Source data — what `udev_monitor` emits

`udev_monitor` Events (`inspectord/workers/udev_monitor/__main__.py`) carry:
- `event.device` = `{name, kind, vendor, product, serial}`
- `event.action` ∈ `{device_added, device_removed, device_changed}`
- `event.raw` = full udev property dict + `source`, including `SUBSYSTEM`, `DEVNAME`,
  `DEVPATH` (every uevent carries these, including removes).

## Tasks

### Task 1 — Projector + IPC handler + daemon wiring (TDD, backend)

**Projector** (`inspectord/state/projector.py`): add a `udev_monitor` branch →
`_project_device(event, db)`:
- `dev_key` = `f"{vendor}:{product}:{serial}"`; **fallback** to `event.raw["DEVPATH"]`
  (then `name`) when vendor+product+serial are all empty/None — never key on `"::"`.
  If no usable key at all → no-op (mirror the `service`-with-no-unit guard).
- `device_added` → upsert `status='present'` (`ON CONFLICT (dev_key) DO UPDATE` attrs +
  `last_seen` + `last_event_id`, preserve `first_seen`).
- `device_changed` → same upsert, `status='present'`.
- `device_removed` → `UPDATE device_state SET status='removed', last_seen, last_event_id
  WHERE dev_key=?` (spec §4: removed devices are **kept** with `status='removed'`, NOT
  deleted — unlike services/listeners).
- Columns: `vendor, product, serial` from `event.device`; `subsystem` from
  `raw.get("SUBSYSTEM")`; `devnode` from `raw.get("DEVNAME")`.

**IPC handler** (`inspectord/state/ipc_handlers.py`): `handle_list_devices(*, params,
db_path)`:
- params: `status?` (filter `device_state.status` when present), `limit` (default 200).
- returns `{"schema_version": "1.0.0", "devices": [...]}` ordered by `dev_key`.
- each row: `dev_key, vendor, product, serial, subsystem, devnode, status, first_seen`
  (ISO via existing `_iso`). No diff_status.

**Daemon wiring** (`inspectord/__main__.py`): register `Method(name="list_devices",
handler=lambda params: handle_list_devices(...), mutates=False)`.

**Tests**: extend `tests/state/test_projector.py` (added/changed/removed/empty-key
fallback/no-key-noop) and `tests/state/test_ipc_handlers.py` (list returns rows; status
filter; first_seen ISO). Write tests first.

### Task 2 — Devices web panel (TDD, frontend)

Mirror `inspectorctl/web/routes/services.py` minus the capture-baseline POST:
- `inspectorctl/web/routes/devices.py`: `GET /devices` (shell) + `GET /devices/feed`
  (calls `list_devices`, default limit 300). No capture endpoint.
- Templates `devices.html` (hx-get `/devices/feed`, every 5s; no capture form) +
  `devices_feed.html` (table: vendor, product, serial, subsystem, devnode, status,
  first_seen; empty-state message).
- Register router in `inspectorctl/web/app.py`; add `nav_link("/devices", "Devices", …)`
  to `base.html` after Services.
- Tests `tests/web/test_devices.py` mirroring `test_services.py` (shell renders, feed
  renders rows, empty state, daemon-unreachable).

## Out of scope
Baseline/diff for devices, status filter UI controls, threat tags
(mass_storage_attached etc. — rule_engine's job), context cards.

## Gates (all must pass before PR)
`.venv/bin/python -m pytest -m "not integration and not ebpf_load"` ·
`.venv/bin/ruff check inspectord inspectorctl tests` ·
`.venv/bin/ruff format --check inspectord inspectorctl tests` ·
`.venv/bin/mypy inspectord`
