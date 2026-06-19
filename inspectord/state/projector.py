"""Materialize current entity state from the event stream.

`project(event, db)` is invoked from the supervisor's single-threaded persist
path, so transitions apply in order with no locking. Unknown (module, action)
pairs are a no-op — adding collectors never breaks projection.
"""

from __future__ import annotations

from inspectord.schemas.event import Event
from inspectord.storage.db import Database


def project(event: Event, db: Database, *, boot_id: str | None = None) -> None:
    if event.module == "services_monitor":
        _project_service(event, db)
    elif event.module == "udev_monitor":
        _project_device(event, db)
    elif event.module in ("process_collector", "process_collector_exit") and boot_id is not None:
        # Process rows are boot-scoped (spec §14.1). Without the current boot_id
        # we cannot form the (pid, boot_id) PK, so skip silently (boot_id is None)
        # — mirroring the supervisor's suppress(OSError) around the boot_id read.
        _project_process(event, db, boot_id)


def _project_service(event: Event, db: Database) -> None:
    unit = (event.service or {}).get("name")
    if not unit:
        return
    if event.action == "service_removed":
        # Removal short-circuits before the raw read: services_monitor's
        # service_removed events carry only previous_* keys in raw, no live state.
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


def _parse_uid(user: dict[str, object] | None) -> int | None:
    raw_uid = (user or {}).get("id")
    if isinstance(raw_uid, str) and raw_uid.isdigit():
        return int(raw_uid)
    if isinstance(raw_uid, int):
        return raw_uid
    return None


def _project_process(event: Event, db: Database, boot_id: str) -> None:
    process = event.process or {}
    pid = process.get("pid")
    if pid is None:
        return
    comm = process.get("name")
    if event.action == "process_exit":
        # One statement covers both the running→exited flip and the missed-exec
        # insert (an exit with no prior start row).
        db.execute(
            """
            INSERT INTO process_state
                (pid, boot_id, comm, status, exit_code,
                 first_seen, last_seen, last_event_id)
            VALUES (?, ?, ?, 'exited', ?, ?, ?, ?)
            ON CONFLICT (pid, boot_id) DO UPDATE SET
                status        = 'exited',
                exit_code     = excluded.exit_code,
                last_seen     = excluded.last_seen,
                last_event_id = excluded.last_event_id
            """,
            [
                pid,
                boot_id,
                comm,
                process.get("exit_code"),
                event.ts,
                event.ts,
                event.event_id,
            ],
        )
        return
    # process_start is the only other action these two modules emit, so the
    # fallthrough handles it: upsert a running row, preserving first_seen on conflict.
    ppid = (process.get("parent") or {}).get("pid")
    db.execute(
        """
        INSERT INTO process_state
            (pid, boot_id, ppid, comm, uid, cmdline, status,
             first_seen, last_seen, last_event_id)
        VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)
        ON CONFLICT (pid, boot_id) DO UPDATE SET
            ppid          = excluded.ppid,
            comm          = excluded.comm,
            uid           = excluded.uid,
            cmdline       = excluded.cmdline,
            last_seen     = excluded.last_seen,
            last_event_id = excluded.last_event_id,
            status        = 'running'
        """,
        [
            pid,
            boot_id,
            ppid,
            comm,
            _parse_uid(event.user),
            process.get("command_line"),
            event.ts,
            event.ts,
            event.event_id,
        ],
    )


def _device_key(event: Event) -> str | None:
    device = event.device or {}
    raw = event.raw or {}
    vendor = device.get("vendor")
    product = device.get("product")
    serial = device.get("serial")
    if vendor or product or serial:
        return f"{vendor or ''}:{product or ''}:{serial or ''}"
    # No vendor/product/serial: fall back to stable identifiers.
    return raw.get("DEVPATH") or device.get("name") or None


def _project_device(event: Event, db: Database) -> None:
    dev_key = _device_key(event)
    if not dev_key:
        return
    if event.action == "device_removed":
        # Removed devices are retained with status='removed' (spec §4) so the
        # panel can surface a disappearance rather than silently dropping it.
        db.execute(
            "UPDATE device_state SET status='removed', last_seen=?, last_event_id=? "
            "WHERE dev_key=?",
            [event.ts, event.event_id, dev_key],
        )
        return
    device = event.device or {}
    raw = event.raw or {}
    db.execute(
        """
        INSERT INTO device_state
            (dev_key, vendor, product, serial, subsystem, devnode,
             status, first_seen, last_seen, last_event_id)
        VALUES (?, ?, ?, ?, ?, ?, 'present', ?, ?, ?)
        ON CONFLICT (dev_key) DO UPDATE SET
            vendor        = excluded.vendor,
            product       = excluded.product,
            serial        = excluded.serial,
            subsystem     = excluded.subsystem,
            devnode       = excluded.devnode,
            status        = excluded.status,
            last_seen     = excluded.last_seen,
            last_event_id = excluded.last_event_id
        """,
        [
            dev_key,
            device.get("vendor"),
            device.get("product"),
            device.get("serial"),
            raw.get("SUBSYSTEM"),
            raw.get("DEVNAME"),
            event.ts,
            event.ts,
            event.event_id,
        ],
    )
