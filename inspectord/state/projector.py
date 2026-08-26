"""Materialize current entity state from the event stream.

`project(event, db)` is invoked from the supervisor's single-threaded persist
path, so transitions apply in order with no locking. Unknown (module, action)
pairs are a no-op — adding collectors never breaks projection.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

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
    elif event.module in ("outbound_connection_tracker", "outbound_connection_tracker6"):
        _project_connection(event, db)
    elif event.module == "listening_socket_snapshotter":
        _project_listener(event, db)
    elif event.module == "fim_watcher":
        _project_file(event, db)
    elif event.module == "persistence_snapshotter":
        _project_persistence(event, db)
    elif event.module == "scanner_runner":
        _project_scan_run(event, db)
    elif event.module == "vuln_scanner":
        _project_vulnerability(event, db)


def _family(addr: str) -> str:
    # The network workers emit canonical (ipaddress-normalized) address strings, so
    # a colon reliably distinguishes IPv6 from dotted-quad IPv4.
    return "ipv6" if ":" in addr else "ipv4"


def _project_connection(event: Event, db: Database) -> None:
    process = event.process or {}
    source = event.source or {}
    destination = event.destination or {}
    network = event.network or {}
    pid = process.get("pid")
    daddr = destination.get("ip")
    if pid is None or daddr is None:
        return
    proto = network.get("transport")
    dport = destination.get("port")
    conn_key = f"{pid}:{daddr}:{dport}:{proto}"
    family = _family(daddr)
    db.execute(
        """
        INSERT INTO connection_state
            (conn_key, pid, comm, saddr, sport, daddr, dport, proto, family,
             status, first_seen, last_seen, last_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'observed', ?, ?, ?)
        ON CONFLICT (conn_key) DO UPDATE SET
            comm          = excluded.comm,
            saddr         = excluded.saddr,
            sport         = excluded.sport,
            daddr         = excluded.daddr,
            dport         = excluded.dport,
            proto         = excluded.proto,
            family        = excluded.family,
            last_seen     = excluded.last_seen,
            last_event_id = excluded.last_event_id
        """,
        [
            conn_key,
            pid,
            process.get("name"),
            source.get("ip"),
            source.get("port"),
            daddr,
            dport,
            proto,
            family,
            event.ts,
            event.ts,
            event.event_id,
        ],
    )


def _project_listener(event: Event, db: Database) -> None:
    source = event.source or {}
    network = event.network or {}
    addr = source.get("ip")
    port = source.get("port")
    proto = network.get("transport")
    if addr is None or port is None or proto is None:
        return
    if event.action == "listener_removed":
        # The snapshotter emits per-listener deltas, so a removal deletes the
        # one (addr, port, proto) row (mirroring service_removed's short-circuit).
        db.execute(
            "DELETE FROM listener_state WHERE addr=? AND port=? AND proto=?",
            [addr, port, proto],
        )
        return
    family = _family(addr)
    snapshot_gen = int(event.ts.timestamp())
    db.execute(
        """
        INSERT INTO listener_state
            (addr, port, proto, family, first_seen, last_seen, snapshot_gen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (addr, port, proto) DO UPDATE SET
            family       = excluded.family,
            last_seen    = excluded.last_seen,
            snapshot_gen = excluded.snapshot_gen
        """,
        [addr, port, proto, family, event.ts, event.ts, snapshot_gen],
    )


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


def _project_file(event: Event, db: Database) -> None:
    path = (event.file or {}).get("path")
    if path is None:
        return
    # Recent-changes log ("what changed"), not "what exists now": a file_deleted
    # is upserted with change_type='deleted' and the row is KEPT — there is no
    # DELETE branch here (contrast _project_listener).
    change_type = event.action.removeprefix("file_")
    db.execute(
        """
        INSERT INTO file_state
            (path, change_type, first_seen, last_seen, last_event_id)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (path) DO UPDATE SET
            change_type   = excluded.change_type,
            last_seen     = excluded.last_seen,
            last_event_id = excluded.last_event_id
        """,
        [path, change_type, event.ts, event.ts, event.event_id],
    )


def _project_persistence(event: Event, db: Database) -> None:
    p = event.persistence or {}
    key = p.get("key")
    if not key:
        return
    if event.action == "persistence_removed":
        # The snapshotter emits per-mechanism deltas, so a removal deletes the one
        # persist_key row (current set = all rows, mirroring _project_listener).
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
        [
            key,
            p.get("kind"),
            p.get("name"),
            p.get("source_path"),
            p.get("details"),
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
    exe_path = process.get("executable")
    exe_sha256 = (process.get("hash") or {}).get("sha256")
    db.execute(
        """
        INSERT INTO process_state
            (pid, boot_id, ppid, comm, exe_path, exe_sha256, uid, cmdline, status,
             first_seen, last_seen, last_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)
        ON CONFLICT (pid, boot_id) DO UPDATE SET
            ppid          = excluded.ppid,
            comm          = excluded.comm,
            exe_path      = COALESCE(excluded.exe_path, process_state.exe_path),
            exe_sha256    = COALESCE(excluded.exe_sha256, process_state.exe_sha256),
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
            exe_path,
            exe_sha256,
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


def _project_scan_run(event: Event, db: Database) -> None:
    """Materialize scanner_runner's lifecycle events into `scan_run`.

    `scan_finding` is deliberately NOT projected: findings stay events (scanner
    design decision 6) and `scan_completed.finding_count` is the authoritative
    count, so counting finding events here would only risk double-counting.
    """
    raw = event.raw or {}
    scanner = raw.get("scanner")
    if not scanner:
        return
    if event.action == "scan_started":
        _project_scan_started(event, db, raw, str(scanner))
    elif event.action == "scan_completed":
        _project_scan_completed(event, db, raw, str(scanner))
    elif event.action == "scan_skipped":
        _project_scan_skipped(event, db, raw, str(scanner))


def _project_scan_started(event: Event, db: Database, raw: dict[str, Any], scanner: str) -> None:
    run_id = raw.get("run_id")
    if not run_id:
        return
    # ON CONFLICT deliberately leaves `status` and every completion column alone:
    # a scan_started that lands after its own scan_completed (out-of-order
    # replay) must not reopen a finished run as 'running' — that is exactly the
    # "running forever" state the panel must never show.
    db.execute(
        """
        INSERT INTO scan_run (run_id, scanner, status, started_at, last_event_id)
        VALUES (?, ?, 'running', ?, ?)
        ON CONFLICT (run_id) DO UPDATE SET
            scanner       = excluded.scanner,
            started_at    = excluded.started_at,
            last_event_id = excluded.last_event_id
        """,
        [str(run_id), scanner, event.ts, event.event_id],
    )


def _project_scan_completed(event: Event, db: Database, raw: dict[str, Any], scanner: str) -> None:
    run_id = raw.get("run_id")
    if not run_id:
        return
    duration_s = raw.get("duration_s")
    # `scan_outcome` is the runner's clean/findings/failure verdict; only
    # 'failure' is a failed run. clean-vs-findings stays readable off
    # finding_count, so the projected status needs no third value.
    status = "failure" if raw.get("scan_outcome") == "failure" else "success"
    # A completion whose scan_started was lost still needs a start time, so it is
    # derived from the run's own duration rather than left NULL.
    started_at = event.ts
    if isinstance(duration_s, int | float):
        started_at = event.ts - timedelta(seconds=float(duration_s))
    # ON CONFLICT updates everything EXCEPT started_at, so the real start time
    # recorded by scan_started survives.
    db.execute(
        """
        INSERT INTO scan_run
            (run_id, scanner, status, reason, exit_code, duration_s, finding_count,
             findings_dropped, truncated, output_truncated, output_excerpt,
             started_at, completed_at, last_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (run_id) DO UPDATE SET
            scanner          = excluded.scanner,
            status           = excluded.status,
            reason           = excluded.reason,
            exit_code        = excluded.exit_code,
            duration_s       = excluded.duration_s,
            finding_count    = excluded.finding_count,
            findings_dropped = excluded.findings_dropped,
            truncated        = excluded.truncated,
            output_truncated = excluded.output_truncated,
            output_excerpt   = excluded.output_excerpt,
            completed_at     = excluded.completed_at,
            last_event_id    = excluded.last_event_id
        """,
        [
            str(run_id),
            scanner,
            status,
            raw.get("reason"),
            raw.get("exit_code"),
            duration_s,
            raw.get("finding_count"),
            raw.get("findings_dropped"),
            bool(raw.get("truncated")),
            bool(raw.get("output_truncated")),
            raw.get("output_excerpt"),
            started_at,
            event.ts,
            event.event_id,
        ],
    )


def _project_scan_skipped(event: Event, db: Database, raw: dict[str, Any], scanner: str) -> None:
    # scan_skipped carries no run_id — nothing was spawned — so the key is
    # synthesized from the (uuid7) event id. Skips therefore never collide with
    # each other, and can never overwrite a real run. A skipped run has a row;
    # a scanner that never ran has none, which is how the two stay distinct.
    db.execute(
        """
        INSERT INTO scan_run
            (run_id, scanner, status, reason, started_at, completed_at, last_event_id)
        VALUES (?, ?, 'skipped', ?, ?, ?, ?)
        ON CONFLICT (run_id) DO NOTHING
        """,
        [
            f"skip:{event.event_id}",
            scanner,
            raw.get("reason"),
            event.ts,
            event.ts,
            event.event_id,
        ],
    )


def _project_vulnerability(event: Event, db: Database) -> None:
    """Materialize vuln_scanner's full-set emission into `vulnerabilities` (§5).

    Upserts never touch `first_seen_at`, `acked_at` or `acked_note` (an ack
    must survive every rescan), and always clear `resolved_at` (a reappearing
    match un-resolves its row). The `vuln_scan_completed` sweep is what makes
    resolution correct across daemon downtime: any unresolved row not
    re-emitted by this scan — and not owned by a skipped AVG — is resolved.
    Rows are never deleted.
    """
    if event.action == "vulnerability_found":
        _project_vulnerability_found(event, db)
    elif event.action == "vuln_scan_completed":
        _project_vulnerability_sweep(event, db)


def _project_vulnerability_found(event: Event, db: Database) -> None:
    v = event.vulnerability or {}
    avg_id = v.get("avg_id")
    cve_id = v.get("cve_id")
    package = v.get("package")
    if not avg_id or not cve_id or not package:
        return
    db.execute(
        """
        INSERT INTO vulnerabilities
            (avg_id, cve_id, package, installed_version, fixed_version, severity,
             status, fix_in_testing, first_seen_at, last_seen, last_event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (avg_id, cve_id, package) DO UPDATE SET
            installed_version = excluded.installed_version,
            fixed_version     = excluded.fixed_version,
            severity          = excluded.severity,
            status            = excluded.status,
            fix_in_testing    = excluded.fix_in_testing,
            last_seen         = excluded.last_seen,
            last_event_id     = excluded.last_event_id,
            resolved_at       = NULL
        """,
        [
            avg_id,
            cve_id,
            package,
            v.get("installed_version"),
            v.get("fixed_version"),
            v.get("severity"),
            v.get("status"),
            bool(v.get("fix_in_testing")),
            event.ts,
            event.ts,
            event.event_id,
        ],
    )


def _project_vulnerability_sweep(event: Event, db: Database) -> None:
    raw = event.raw or {}
    started_raw = raw.get("scan_started_at")
    if not isinstance(started_raw, str):
        return
    try:
        scan_started_at = datetime.fromisoformat(started_raw)
    except ValueError:
        return
    skipped = [s for s in (raw.get("skipped_avg_ids") or []) if isinstance(s, str)]
    # A malformed AVG must never silently resolve real CVEs: rows owned by a
    # skipped AVG are excluded from the sweep.
    sql = "UPDATE vulnerabilities SET resolved_at = ? WHERE resolved_at IS NULL AND last_seen < ?"
    params: list[Any] = [event.ts, scan_started_at]
    if skipped:
        placeholders = ", ".join("?" for _ in skipped)
        sql += f" AND avg_id NOT IN ({placeholders})"
        params.extend(skipped)
    db.execute(sql, params)
