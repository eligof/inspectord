"""Tests for the entity-state projector."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.schemas.event import Event, EventKind, Outcome, Severity
from inspectord.state.projector import project
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _service_event(
    action: str,
    unit: str,
    active: str,
    *,
    event_id: str,
    ts: datetime = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
) -> Event:
    return Event(
        ts=ts,
        event_id=event_id,
        kind=EventKind.event,
        category=["configuration"],
        type=["change"],
        action=action,
        severity=Severity.info,
        module="services_monitor",
        service={"name": unit, "state": active},
        raw={"source": "systemctl", "active": active, "sub": "running", "load": "loaded"},
    )


def _device_event(
    action: str,
    *,
    event_id: str,
    vendor: str = "1d6b",
    product: str = "0002",
    serial: str = "0000:00:14.0",
    name: str = "usb1",
    subsystem: str = "usb",
    devnode: str = "/dev/bus/usb/001/001",
    devpath: str = "/devices/pci0000:00/usb1",
    ts: datetime = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
) -> Event:
    return Event(
        ts=ts,
        event_id=event_id,
        kind=EventKind.event,
        category=["host"],
        type=["change"],
        action=action,
        severity=Severity.info,
        module="udev_monitor",
        device={
            "name": name,
            "kind": subsystem,
            "vendor": vendor,
            "product": product,
            "serial": serial,
        },
        raw={
            "source": "udevadm",
            "SUBSYSTEM": subsystem,
            "DEVNAME": devnode,
            "DEVPATH": devpath,
        },
    )


def _process_event(
    *,
    module: str = "process_collector",
    action: str = "process_start",
    event_id: str,
    pid: int | None = 1234,
    ppid: int | None = 1,
    name: str | None = "bash",
    cmdline: str | None = "bash -i",
    uid: str | None = "1000",
    exit_code: int | None = None,
    executable: str | None = None,
    sha256: str | None = None,
    ts: datetime = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
) -> Event:
    process: dict[str, object] = {}
    if pid is not None:
        process["pid"] = pid
    if name is not None:
        process["name"] = name
    if cmdline is not None:
        process["command_line"] = cmdline
    if executable is not None:
        process["executable"] = executable
    if sha256 is not None:
        process["hash"] = {"sha256": sha256}
    if ppid is not None:
        process["parent"] = {"pid": ppid}
    if exit_code is not None:
        process["exit_code"] = exit_code
    user = {"id": uid} if uid is not None else None
    return Event(
        ts=ts,
        event_id=event_id,
        kind=EventKind.event,
        category=["process"],
        type=["start"] if action == "process_start" else ["end"],
        action=action,
        severity=Severity.info,
        module=module,
        process=process or None,
        user=user,
        raw={"source": "ebpf"},
    )


def _connection_event(
    *,
    module: str = "outbound_connection_tracker",
    event_id: str,
    pid: int | None = 4321,
    comm: str | None = "curl",
    saddr: str | None = "192.168.1.10",
    sport: int | None = 54321,
    daddr: str | None = "93.184.216.34",
    dport: int | None = 443,
    transport: str = "tcp",
    ts: datetime = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
) -> Event:
    process: dict[str, object] = {}
    if pid is not None:
        process["pid"] = pid
    if comm is not None:
        process["name"] = comm
    source: dict[str, object] = {}
    if saddr is not None:
        source["ip"] = saddr
    if sport is not None:
        source["port"] = sport
    destination: dict[str, object] = {}
    if daddr is not None:
        destination["ip"] = daddr
    if dport is not None:
        destination["port"] = dport
    return Event(
        ts=ts,
        event_id=event_id,
        kind=EventKind.event,
        category=["network"],
        type=["connection", "start"],
        action="outbound_connection",
        severity=Severity.info,
        module=module,
        process=process or None,
        source=source or None,
        destination=destination or None,
        network={"transport": transport, "direction": "egress"},
        raw={"source": "ebpf:inet_sock_set_state"},
    )


def _listener_event(
    action: str,
    *,
    event_id: str,
    addr: str | None = "0.0.0.0",
    port: int | None = 22,
    transport: str | None = "tcp",
    ts: datetime = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
) -> Event:
    source: dict[str, object] = {}
    if addr is not None:
        source["ip"] = addr
    if port is not None:
        source["port"] = port
    network: dict[str, object] = {"direction": "ingress"}
    if transport is not None:
        network["transport"] = transport
    return Event(
        ts=ts,
        event_id=event_id,
        kind=EventKind.event,
        category=["network"],
        type=["start"] if action == "listener_added" else ["end"],
        action=action,
        severity=Severity.info,
        module="listening_socket_snapshotter",
        source=source or None,
        network=network,
        labels=["listener"],
        raw={"source": "/proc/net/tcp"},
    )


def _file_event(
    action: str,
    path: str | None,
    *,
    event_id: str,
    ts: datetime = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
) -> Event:
    return Event(
        ts=ts,
        event_id=event_id,
        kind=EventKind.event,
        category=["file"],
        type=["change"],
        action=action,
        severity=Severity.info,
        module="fim_watcher",
        file={"path": path} if path is not None else None,
        raw={"source": "inotify"},
    )


def _persistence_event(
    action: str,
    *,
    key: str,
    kind: str = "cron",
    name: str | None = "j",
    source_path: str | None = "/etc/crontab",
    details: str | None = "d",
    event_id: str,
    ts: datetime = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
) -> Event:
    return Event(
        ts=ts,
        event_id=event_id,
        kind=EventKind.event,
        category=["host"],
        type=["start"] if action == "persistence_added" else ["end"],
        action=action,
        severity=Severity.info,
        module="persistence_snapshotter",
        persistence={
            "kind": kind,
            "name": name,
            "source_path": source_path,
            "details": details,
            "key": key,
        },
        raw={"source": "persistence_snapshotter"},
    )


def test_persistence_added_inserts_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_persistence_event("persistence_added", key="persist:cron:abc", event_id="pp1"), db)
    rows = db.query(
        "SELECT persist_key, kind, name, source_path, details, last_event_id "
        "FROM persistence_state WHERE persist_key='persist:cron:abc'"
    ).fetchall()
    assert rows == [("persist:cron:abc", "cron", "j", "/etc/crontab", "d", "pp1")]
    db.close()


def test_persistence_readd_preserves_first_seen_advances_rest(tmp_path: Path) -> None:
    db = _db(tmp_path)
    first_ts = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    later_ts = datetime(2026, 6, 16, 12, 5, 0, tzinfo=UTC)
    project(
        _persistence_event(
            "persistence_added", key="persist:cron:abc", event_id="pp1", ts=first_ts
        ),
        db,
    )
    first_seen_before = db.query(
        "SELECT first_seen FROM persistence_state WHERE persist_key='persist:cron:abc'"
    ).fetchall()[0][0]
    project(
        _persistence_event(
            "persistence_added",
            key="persist:cron:abc",
            details="d2",
            event_id="pp2",
            ts=later_ts,
        ),
        db,
    )
    rows = db.query(
        "SELECT first_seen, last_seen, details, last_event_id FROM persistence_state "
        "WHERE persist_key='persist:cron:abc'"
    ).fetchall()
    assert rows[0][0] == first_seen_before  # first_seen preserved
    assert rows[0][1] != first_seen_before  # last_seen advanced
    assert rows[0][2] == "d2"  # details updated
    assert rows[0][3] == "pp2"  # last_event_id advanced
    db.close()


def test_persistence_removed_deletes_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_persistence_event("persistence_added", key="persist:cron:abc", event_id="pp1"), db)
    project(_persistence_event("persistence_removed", key="persist:cron:abc", event_id="pp2"), db)
    assert db.query("SELECT COUNT(*) FROM persistence_state").fetchall()[0][0] == 0
    db.close()


def test_persistence_event_with_no_key_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    ev = Event(
        ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event_id="pp9",
        kind=EventKind.event,
        category=["host"],
        type=["start"],
        action="persistence_added",
        severity=Severity.info,
        module="persistence_snapshotter",
        persistence={},
    )
    project(ev, db)  # must not raise
    assert db.query("SELECT COUNT(*) FROM persistence_state").fetchall()[0][0] == 0
    db.close()


def test_file_created_inserts_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_file_event("file_created", "/etc/passwd", event_id="f1"), db)
    rows = db.query(
        "SELECT path, change_type, last_event_id FROM file_state WHERE path='/etc/passwd'"
    ).fetchall()
    assert rows == [("/etc/passwd", "created", "f1")]
    db.close()


def test_file_modified_updates_preserves_first_seen(tmp_path: Path) -> None:
    db = _db(tmp_path)
    created_ts = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    modified_ts = datetime(2026, 6, 16, 13, 30, 0, tzinfo=UTC)
    project(_file_event("file_created", "/etc/passwd", event_id="f1", ts=created_ts), db)
    first_seen_before = db.query(
        "SELECT first_seen FROM file_state WHERE path='/etc/passwd'"
    ).fetchall()[0][0]
    project(_file_event("file_modified", "/etc/passwd", event_id="f2", ts=modified_ts), db)
    rows = db.query(
        "SELECT change_type, first_seen, last_seen, last_event_id FROM file_state "
        "WHERE path='/etc/passwd'"
    ).fetchall()
    assert rows[0][0] == "modified"
    assert rows[0][1] == first_seen_before  # first_seen preserved
    assert rows[0][2] != first_seen_before  # last_seen advanced
    assert rows[0][3] == "f2"
    db.close()


def test_file_deleted_upserts_deleted_and_keeps_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_file_event("file_created", "/tmp/scratch", event_id="f1"), db)
    project(_file_event("file_deleted", "/tmp/scratch", event_id="f2"), db)
    rows = db.query(
        "SELECT change_type, last_event_id FROM file_state WHERE path='/tmp/scratch'"
    ).fetchall()
    assert rows == [("deleted", "f2")]  # row KEPT with change_type='deleted', NOT removed
    db.close()


def test_file_attributes_changed_strips_only_file_prefix(tmp_path: Path) -> None:
    # "attributes_changed" still contains an underscore, so this pins removeprefix
    # (not a split on "_") as the change_type derivation.
    db = _db(tmp_path)
    project(_file_event("file_attributes_changed", "/etc/shadow", event_id="f1"), db)
    rows = db.query("SELECT change_type FROM file_state WHERE path='/etc/shadow'").fetchall()
    assert rows == [("attributes_changed",)]
    db.close()


def test_fim_event_with_no_path_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_file_event("file_created", None, event_id="f1"), db)  # must not raise
    assert db.query("SELECT COUNT(*) FROM file_state").fetchall()[0][0] == 0
    db.close()


def test_outbound_connection_inserts_observed_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_connection_event(event_id="c1"), db)
    rows = db.query(
        "SELECT conn_key, pid, comm, saddr, sport, daddr, dport, proto, family, "
        "status, last_event_id FROM connection_state"
    ).fetchall()
    assert rows == [
        (
            "4321:93.184.216.34:443:tcp",
            4321,
            "curl",
            "192.168.1.10",
            54321,
            "93.184.216.34",
            443,
            "tcp",
            "ipv4",
            "observed",
            "c1",
        )
    ]
    db.close()


def test_outbound_connection_v6_daddr_yields_ipv6_family(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_connection_event(event_id="c1", daddr="2606:2800:220:1:248:1893:25c8:1946"), db)
    rows = db.query("SELECT family FROM connection_state").fetchall()
    assert rows == [("ipv6",)]
    db.close()


def test_outbound_connection_tracker6_module_routes_through_same_branch(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(
        _connection_event(
            module="outbound_connection_tracker6",
            event_id="c1",
            daddr="2606:2800:220:1:248:1893:25c8:1946",
        ),
        db,
    )
    rows = db.query("SELECT family, status FROM connection_state").fetchall()
    assert rows == [("ipv6", "observed")]
    db.close()


def test_outbound_connection_reobserve_preserves_first_seen(tmp_path: Path) -> None:
    db = _db(tmp_path)
    first_ts = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    later_ts = datetime(2026, 6, 16, 12, 5, 0, tzinfo=UTC)
    project(_connection_event(event_id="c1", ts=first_ts), db)
    first_seen_before = db.query("SELECT first_seen FROM connection_state").fetchall()[0][0]
    project(_connection_event(event_id="c2", ts=later_ts), db)
    rows = db.query("SELECT first_seen, last_seen, last_event_id FROM connection_state").fetchall()
    assert rows[0][0] == first_seen_before  # first_seen preserved
    assert rows[0][1] != first_seen_before  # last_seen advanced
    assert rows[0][2] == "c2"
    db.close()


def test_outbound_connection_missing_pid_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_connection_event(event_id="c1", pid=None), db)
    assert db.query("SELECT COUNT(*) FROM connection_state").fetchall()[0][0] == 0
    db.close()


def test_outbound_connection_missing_daddr_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_connection_event(event_id="c1", daddr=None), db)
    assert db.query("SELECT COUNT(*) FROM connection_state").fetchall()[0][0] == 0
    db.close()


def test_listener_added_inserts_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_listener_event("listener_added", event_id="l1"), db)
    rows = db.query(
        "SELECT addr, port, proto, family, pid, comm, snapshot_gen FROM listener_state"
    ).fetchall()
    assert rows[0][0] == "0.0.0.0"
    assert rows[0][1] == 22
    assert rows[0][2] == "tcp"
    assert rows[0][3] == "ipv4"
    assert rows[0][4] is None  # pid stays NULL
    assert rows[0][5] is None  # comm stays NULL
    assert rows[0][6] is not None  # snapshot_gen populated
    db.close()


def test_listener_added_v6_addr_yields_ipv6_family(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_listener_event("listener_added", event_id="l1", addr="::"), db)
    rows = db.query("SELECT family FROM listener_state").fetchall()
    assert rows == [("ipv6",)]
    db.close()


def test_listener_removed_deletes_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_listener_event("listener_added", event_id="l1"), db)
    project(_listener_event("listener_removed", event_id="l2"), db)
    assert db.query("SELECT COUNT(*) FROM listener_state").fetchall()[0][0] == 0
    db.close()


def test_listener_readd_preserves_first_seen(tmp_path: Path) -> None:
    db = _db(tmp_path)
    first_ts = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    later_ts = datetime(2026, 6, 16, 12, 5, 0, tzinfo=UTC)
    project(_listener_event("listener_added", event_id="l1", ts=first_ts), db)
    first_seen_before = db.query("SELECT first_seen FROM listener_state").fetchall()[0][0]
    project(_listener_event("listener_added", event_id="l2", ts=later_ts), db)
    rows = db.query("SELECT first_seen, last_seen FROM listener_state").fetchall()
    assert rows[0][0] == first_seen_before  # first_seen preserved
    assert rows[0][1] != first_seen_before  # last_seen advanced
    db.close()


def test_listener_missing_proto_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_listener_event("listener_added", event_id="l1", transport=None), db)
    assert db.query("SELECT COUNT(*) FROM listener_state").fetchall()[0][0] == 0
    db.close()


def test_process_start_inserts_running_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_process_event(event_id="p1"), db, boot_id="b1")
    rows = db.query(
        "SELECT pid, boot_id, ppid, comm, uid, cmdline, status, last_event_id "
        "FROM process_state WHERE pid=1234 AND boot_id='b1'"
    ).fetchall()
    assert rows == [(1234, "b1", 1, "bash", 1000, "bash -i", "running", "p1")]
    db.close()


def test_process_start_no_pid_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_process_event(event_id="p1", pid=None), db, boot_id="b1")
    assert db.query("SELECT COUNT(*) FROM process_state").fetchall()[0][0] == 0
    db.close()


def test_process_event_with_no_boot_id_is_skipped(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_process_event(event_id="p1"), db)  # boot_id defaults to None
    assert db.query("SELECT COUNT(*) FROM process_state").fetchall()[0][0] == 0
    db.close()


def test_process_exit_flips_running_to_exited_preserves_first_seen(tmp_path: Path) -> None:
    db = _db(tmp_path)
    start_ts = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    exit_ts = datetime(2026, 6, 16, 12, 5, 0, tzinfo=UTC)
    project(_process_event(event_id="p1", ts=start_ts), db, boot_id="b1")
    first_seen_before = db.query(
        "SELECT first_seen FROM process_state WHERE pid=1234 AND boot_id='b1'"
    ).fetchall()[0][0]
    project(
        _process_event(
            module="process_collector_exit",
            action="process_exit",
            event_id="p2",
            exit_code=137,
            ts=exit_ts,
        ),
        db,
        boot_id="b1",
    )
    rows = db.query(
        "SELECT status, exit_code, first_seen, last_seen, last_event_id "
        "FROM process_state WHERE pid=1234 AND boot_id='b1'"
    ).fetchall()
    assert rows[0][0] == "exited"
    assert rows[0][1] == 137
    assert rows[0][2] == first_seen_before  # first_seen preserved
    assert rows[0][3] != first_seen_before  # last_seen advanced
    assert rows[0][4] == "p2"
    db.close()


def test_process_exit_without_prior_row_inserts_exited(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(
        _process_event(
            module="process_collector_exit",
            action="process_exit",
            event_id="p2",
            exit_code=0,
        ),
        db,
        boot_id="b1",
    )
    rows = db.query(
        "SELECT status, exit_code, comm FROM process_state WHERE pid=1234 AND boot_id='b1'"
    ).fetchall()
    assert rows == [("exited", 0, "bash")]
    db.close()


def test_process_start_non_numeric_uid_is_null(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_process_event(event_id="p1", uid="root"), db, boot_id="b1")  # must not raise
    rows = db.query("SELECT uid FROM process_state WHERE pid=1234 AND boot_id='b1'").fetchall()
    assert rows == [(None,)]
    db.close()


def test_process_start_missing_uid_is_null(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_process_event(event_id="p1", uid=None), db, boot_id="b1")
    rows = db.query("SELECT uid FROM process_state WHERE pid=1234 AND boot_id='b1'").fetchall()
    assert rows == [(None,)]
    db.close()


def test_process_start_writes_exe_fields(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(
        _process_event(
            event_id="p1",
            pid=4242,
            name="nc",
            cmdline="nc -l 4444",
            executable="/usr/bin/nc",
            sha256="ab" * 32,
        ),
        db,
        boot_id="b1",
    )
    rows = db.query(
        "SELECT exe_path, exe_sha256 FROM process_state WHERE pid=4242 AND boot_id='b1'"
    ).fetchall()
    assert rows == [("/usr/bin/nc", "ab" * 32)]
    db.close()


def test_process_start_without_hash_preserves_existing_exe_fields(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(
        _process_event(event_id="p1", pid=7, name="x", executable="/bin/x", sha256="cd" * 32),
        db,
        boot_id="b1",
    )
    # A later start event with no executable/hash (e.g. a short-lived exec the
    # enricher could not hash) must not wipe the previously captured fields.
    project(_process_event(event_id="p2", pid=7, name="x"), db, boot_id="b1")
    rows = db.query(
        "SELECT exe_path, exe_sha256 FROM process_state WHERE pid=7 AND boot_id='b1'"
    ).fetchall()
    assert rows == [("/bin/x", "cd" * 32)]
    db.close()


def test_device_added_inserts_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_device_event("device_added", event_id="d1"), db)
    rows = db.query(
        "SELECT vendor, product, serial, subsystem, devnode, status, last_event_id "
        "FROM device_state WHERE dev_key='1d6b:0002:0000:00:14.0'"
    ).fetchall()
    assert rows == [
        ("1d6b", "0002", "0000:00:14.0", "usb", "/dev/bus/usb/001/001", "present", "d1")
    ]
    db.close()


def test_device_changed_updates_attrs_preserves_first_seen(tmp_path: Path) -> None:
    db = _db(tmp_path)
    added_ts = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    changed_ts = datetime(2026, 6, 16, 13, 30, 0, tzinfo=UTC)
    project(_device_event("device_added", event_id="d1", ts=added_ts), db)
    first_seen_before = db.query(
        "SELECT first_seen FROM device_state WHERE dev_key='1d6b:0002:0000:00:14.0'"
    ).fetchall()[0][0]
    project(
        _device_event(
            "device_changed", event_id="d2", devnode="/dev/bus/usb/001/002", ts=changed_ts
        ),
        db,
    )
    rows = db.query(
        "SELECT devnode, status, first_seen, last_seen, last_event_id FROM device_state "
        "WHERE dev_key='1d6b:0002:0000:00:14.0'"
    ).fetchall()
    assert rows[0][0] == "/dev/bus/usb/001/002"
    assert rows[0][1] == "present"
    assert rows[0][2] == first_seen_before  # first_seen preserved
    assert rows[0][3] != first_seen_before  # last_seen advanced
    assert rows[0][4] == "d2"
    db.close()


def test_device_removed_keeps_row_with_removed_status(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_device_event("device_added", event_id="d1"), db)
    project(_device_event("device_removed", event_id="d2"), db)
    rows = db.query(
        "SELECT status, last_event_id FROM device_state WHERE dev_key='1d6b:0002:0000:00:14.0'"
    ).fetchall()
    assert rows == [("removed", "d2")]  # row kept, NOT deleted
    db.close()


def test_device_empty_ids_fall_back_to_devpath_key(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(
        _device_event(
            "device_added",
            event_id="d1",
            vendor="",
            product="",
            serial="",
            devpath="/devices/virtual/tty/tty0",
        ),
        db,
    )
    rows = db.query("SELECT dev_key, status FROM device_state").fetchall()
    assert rows == [("/devices/virtual/tty/tty0", "present")]
    db.close()


def test_device_with_no_usable_key_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    ev = Event(
        ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event_id="d9",
        kind=EventKind.event,
        category=["host"],
        type=["change"],
        action="device_added",
        severity=Severity.info,
        module="udev_monitor",
        device={"name": "", "kind": "", "vendor": "", "product": "", "serial": ""},
        raw={"source": "udevadm"},
    )
    project(ev, db)  # must not raise
    assert db.query("SELECT COUNT(*) FROM device_state").fetchall()[0][0] == 0
    db.close()


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
    added_ts = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    changed_ts = datetime(2026, 6, 16, 13, 30, 0, tzinfo=UTC)
    project(
        _service_event("service_added", "sshd.service", "active", event_id="e1", ts=added_ts), db
    )
    first_seen_before = db.query(
        "SELECT first_seen FROM service_state WHERE unit='sshd.service'"
    ).fetchall()[0][0]
    project(
        _service_event(
            "service_state_changed", "sshd.service", "failed", event_id="e2", ts=changed_ts
        ),
        db,
    )
    rows = db.query(
        "SELECT active_state, first_seen, last_seen, last_event_id FROM service_state"
        " WHERE unit='sshd.service'"
    ).fetchall()
    assert rows[0][0] == "failed"
    assert rows[0][1] == first_seen_before  # first_seen preserved across the update
    assert rows[0][2] != first_seen_before  # last_seen advanced to the change ts
    assert rows[0][3] == "e2"  # last_event_id advanced
    db.close()


def test_service_removed_deletes_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_service_event("service_added", "sshd.service", "active", event_id="e1"), db)
    project(_service_event("service_removed", "sshd.service", "active", event_id="e2"), db)
    rows = db.query("SELECT unit FROM service_state WHERE unit='sshd.service'").fetchall()
    assert rows == []
    db.close()


def test_services_monitor_event_with_no_service_field_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    ev = Event(
        ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event_id="e8",
        kind=EventKind.event,
        category=["configuration"],
        type=["change"],
        action="service_added",
        severity=Severity.info,
        module="services_monitor",
        service=None,
    )
    project(ev, db)  # must not raise
    assert db.query("SELECT COUNT(*) FROM service_state").fetchall()[0][0] == 0
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


# -- scanner_runner -> scan_run (plan 2026-08-20-scanner-panel §3) --------------

_SCAN_TS = datetime(2026, 8, 20, 2, 0, 0, tzinfo=UTC)


def _scan_event(
    action: str,
    *,
    event_id: str,
    scanner: str = "aide",
    ts: datetime = _SCAN_TS,
    outcome: Outcome | None = None,
    raw: dict[str, object] | None = None,
) -> Event:
    return Event(
        ts=ts,
        event_id=event_id,
        kind=EventKind.event,
        category=["process"],
        type=["info"],
        action=action,
        outcome=outcome,
        severity=Severity.info,
        module="scanner_runner",
        raw={"scanner": scanner, **(raw or {})},
    )


def _started(event_id: str, run_id: str, **kw: object) -> Event:
    return _scan_event("scan_started", event_id=event_id, raw={"run_id": run_id}, **kw)  # type: ignore[arg-type]


def _completed(
    event_id: str,
    run_id: str,
    *,
    scan_outcome: str = "clean",
    finding_count: int = 0,
    **extra: object,
) -> Event:
    failed = scan_outcome == "failure"
    return _scan_event(
        "scan_completed",
        event_id=event_id,
        ts=extra.pop("ts", _SCAN_TS + timedelta(seconds=30)),  # type: ignore[arg-type]
        outcome=Outcome.failure if failed else Outcome.success,
        raw={
            "run_id": run_id,
            "scan_outcome": scan_outcome,
            "duration_s": 30.0,
            "finding_count": finding_count,
            "findings_dropped": 0,
            "truncated": False,
            "output_dropped_bytes": 0,
            "output_truncated": False,
            **extra,
        },
    )


def _scan_row(db: Database, run_id: str) -> tuple:  # type: ignore[type-arg]
    return db.query(
        "SELECT scanner, status, reason, exit_code, duration_s, finding_count, "
        "findings_dropped, truncated, output_truncated, output_excerpt, "
        "started_at, completed_at, last_event_id FROM scan_run WHERE run_id = ?",
        [run_id],
    ).fetchall()[0]


def test_scan_started_creates_a_running_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_started("e1", "run-1"), db)
    row = _scan_row(db, "run-1")
    assert row[0] == "aide"
    assert row[1] == "running"
    assert row[10] == _SCAN_TS.replace(tzinfo=None)
    assert row[11] is None
    assert row[12] == "e1"
    db.close()


def test_complete_run_projects_success(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_started("e1", "run-1"), db)
    project(_completed("e2", "run-1", scan_outcome="findings", finding_count=3), db)
    row = _scan_row(db, "run-1")
    assert row[1] == "success"
    assert row[4] == 30.0
    assert row[5] == 3
    # started_at is preserved from scan_started, not overwritten by the completion.
    assert row[10] == _SCAN_TS.replace(tzinfo=None)
    assert row[11] == (_SCAN_TS + timedelta(seconds=30)).replace(tzinfo=None)
    assert row[12] == "e2"
    # Exactly one row per run — the pair does not create two.
    assert db.query("SELECT COUNT(*) FROM scan_run").fetchall()[0][0] == 1
    db.close()


def test_failed_run_projects_reason_and_output_excerpt(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_started("e1", "run-1"), db)
    project(
        _completed(
            "e2",
            "run-1",
            scan_outcome="failure",
            reason="timeout",
            exit_code=None,
            output_excerpt="aide: cannot open database",
        ),
        db,
    )
    row = _scan_row(db, "run-1")
    assert row[1] == "failure"
    assert row[2] == "timeout"
    assert row[9] == "aide: cannot open database"
    db.close()


def test_truncated_run_records_both_truncation_flags(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_started("e1", "run-1"), db)
    project(
        _completed(
            "e2",
            "run-1",
            scan_outcome="findings",
            finding_count=500,
            findings_dropped=12,
            truncated=True,
            output_truncated=True,
        ),
        db,
    )
    row = _scan_row(db, "run-1")
    assert (row[6], row[7], row[8]) == (12, True, True)
    db.close()


def test_skipped_run_gets_its_own_row_keyed_on_event_id(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(
        _scan_event(
            "scan_skipped",
            event_id="e1",
            raw={"reason": "binary_not_found", "binary": "aide"},
        ),
        db,
    )
    rows = db.query(
        "SELECT run_id, scanner, status, reason, started_at, completed_at FROM scan_run"
    ).fetchall()
    assert len(rows) == 1
    run_id, scanner, status, reason, started_at, completed_at = rows[0]
    # scan_skipped carries no run_id (nothing was spawned), so the key is synthesized
    # from the event id — it can never collide with, or overwrite, a real run.
    assert run_id == "skip:e1"
    assert (scanner, status, reason) == ("aide", "skipped", "binary_not_found")
    assert started_at == _SCAN_TS.replace(tzinfo=None)
    assert completed_at == _SCAN_TS.replace(tzinfo=None)
    db.close()


def test_two_skips_do_not_overwrite_each_other(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_scan_event("scan_skipped", event_id="e1", raw={"reason": "binary_not_found"}), db)
    project(_scan_event("scan_skipped", event_id="e2", raw={"reason": "config_missing"}), db)
    assert db.query("SELECT COUNT(*) FROM scan_run").fetchall()[0][0] == 2
    db.close()


def test_run_that_never_completed_stays_running(tmp_path: Path) -> None:
    db = _db(tmp_path)
    # A daemon restart mid-scan: scan_started with no scan_completed, ever.
    project(_started("e1", "run-1"), db)
    row = _scan_row(db, "run-1")
    assert row[1] == "running"
    # It must never look like a finished run: no outcome, no duration, no count.
    assert (row[2], row[4], row[5], row[11]) == (None, None, None, None)
    db.close()


def test_completed_without_started_backfills_the_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    # The scan_started event was lost (queue drop, restart between the two).
    project(_completed("e2", "run-1", scan_outcome="clean"), db)
    row = _scan_row(db, "run-1")
    assert row[1] == "success"
    # started_at is derived from the completion minus its duration, not left null.
    assert row[10] == _SCAN_TS.replace(tzinfo=None)
    db.close()


def test_started_arriving_after_completed_cannot_resurrect_the_run(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_completed("e2", "run-1", scan_outcome="clean"), db)
    project(_started("e1", "run-1"), db)
    row = _scan_row(db, "run-1")
    # Projection is order-independent: a late scan_started never reopens a
    # finished run (it would otherwise read as "running forever").
    assert row[1] == "success"
    assert row[11] is not None
    db.close()


def test_scan_finding_is_not_projected(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_started("e1", "run-1"), db)
    project(
        _scan_event("scan_finding", event_id="e3", raw={"run_id": "run-1", "line": "x"}),
        db,
    )
    # Findings stay events (scanner design decision 6); scan_completed's
    # finding_count is the authoritative count.
    assert db.query("SELECT COUNT(*) FROM scan_run").fetchall()[0][0] == 1
    assert _scan_row(db, "run-1")[5] is None
    db.close()


def test_scan_event_without_scanner_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    ev = Event(
        ts=_SCAN_TS,
        event_id="e1",
        kind=EventKind.event,
        category=["process"],
        type=["info"],
        action="scan_started",
        severity=Severity.info,
        module="scanner_runner",
        raw={"run_id": "run-1"},
    )
    project(ev, db)  # must not raise
    assert db.query("SELECT COUNT(*) FROM scan_run").fetchall()[0][0] == 0
    db.close()


def test_scan_started_without_run_id_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_scan_event("scan_started", event_id="e1"), db)
    assert db.query("SELECT COUNT(*) FROM scan_run").fetchall()[0][0] == 0
    db.close()
