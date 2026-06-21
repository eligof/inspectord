"""Tests for entity-state IPC handlers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inspectord.state.baseline import capture_baseline
from inspectord.state.ipc_handlers import (
    handle_capture_baseline,
    handle_list_connections,
    handle_list_devices,
    handle_list_file_changes,
    handle_list_listeners,
    handle_list_persistence,
    handle_list_processes,
    handle_list_services,
)
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "test.duckdb"


def _seed_service(db_path: Path, unit: str, active: str) -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO service_state (unit, active_state, sub_state, load_state, "
            "first_seen, last_seen, last_event_id) VALUES "
            "(?, ?, 'running', 'loaded', TIMESTAMP '2026-06-16 00:00:00', "
            "TIMESTAMP '2026-06-16 00:00:00', 'e1') "
            "ON CONFLICT (unit) DO UPDATE SET active_state = excluded.active_state",
            [unit, active],
        )


def _seed_device(db_path: Path, dev_key: str, status: str) -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO device_state (dev_key, vendor, product, serial, subsystem, devnode, "
            "status, first_seen, last_seen, last_event_id) VALUES "
            "(?, '1d6b', '0002', 'ser', 'usb', '/dev/usb1', ?, "
            "TIMESTAMP '2026-06-16 00:00:00', TIMESTAMP '2026-06-16 00:00:00', 'd1') "
            "ON CONFLICT (dev_key) DO UPDATE SET status = excluded.status",
            [dev_key, status],
        )


def _seed_process(
    db_path: Path,
    pid: int,
    *,
    boot_id: str = "b1",
    comm: str = "bash",
    ppid: int = 1,
    uid: int = 1000,
    status: str = "running",
    cmdline: str = "bash -i",
    last_seen: str = "2026-06-16 00:00:00",
) -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO process_state (pid, boot_id, ppid, comm, uid, cmdline, status, "
            "first_seen, last_seen, last_event_id) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, TIMESTAMP '2026-06-16 00:00:00', "
            f"TIMESTAMP '{last_seen}', 'p1')",
            [pid, boot_id, ppid, comm, uid, cmdline, status],
        )


def _seed_connection(
    db_path: Path,
    conn_key: str,
    *,
    pid: int = 4321,
    comm: str = "curl",
    saddr: str = "192.168.1.10",
    sport: int = 54321,
    daddr: str = "93.184.216.34",
    dport: int = 443,
    proto: str = "tcp",
    family: str = "ipv4",
    status: str = "observed",
    last_seen: str | None = "2026-06-16 00:00:00",
    last_seen_dt: datetime | None = None,
) -> None:
    with Database(db_path) as db:
        if last_seen_dt is not None:
            db.execute(
                "INSERT INTO connection_state (conn_key, pid, comm, saddr, sport, daddr, dport, "
                "proto, family, status, first_seen, last_seen, last_event_id) VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TIMESTAMP '2026-06-16 00:00:00', ?, 'c1')",
                [
                    conn_key,
                    pid,
                    comm,
                    saddr,
                    sport,
                    daddr,
                    dport,
                    proto,
                    family,
                    status,
                    last_seen_dt,
                ],
            )
        else:
            db.execute(
                "INSERT INTO connection_state (conn_key, pid, comm, saddr, sport, daddr, dport, "
                "proto, family, status, first_seen, last_seen, last_event_id) VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TIMESTAMP '2026-06-16 00:00:00', "
                f"TIMESTAMP '{last_seen}', 'c1')",
                [conn_key, pid, comm, saddr, sport, daddr, dport, proto, family, status],
            )


def _seed_listener(
    db_path: Path,
    addr: str,
    port: int,
    *,
    proto: str = "tcp",
    family: str = "ipv4",
) -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO listener_state (addr, port, proto, family, first_seen, last_seen, "
            "snapshot_gen) VALUES "
            "(?, ?, ?, ?, TIMESTAMP '2026-06-16 00:00:00', TIMESTAMP '2026-06-16 00:00:00', 17)",
            [addr, port, proto, family],
        )


def _seed_file(
    db_path: Path,
    path: str,
    *,
    change_type: str = "modified",
    last_seen: str = "2026-06-16 00:00:00",
) -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO file_state (path, change_type, first_seen, last_seen, last_event_id) "
            "VALUES (?, ?, TIMESTAMP '2026-06-16 00:00:00', "
            f"TIMESTAMP '{last_seen}', 'f1')",
            [path, change_type],
        )


def test_list_file_changes_returns_rows_newest_last_seen_first(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_file(db_path, "/a", last_seen="2026-06-16 00:00:00")
    _seed_file(db_path, "/b", last_seen="2026-06-16 02:00:00")
    _seed_file(db_path, "/c", last_seen="2026-06-16 01:00:00")
    result = handle_list_file_changes(params={}, db_path=db_path)
    paths = [f["path"] for f in result["files"]]
    assert paths == ["/b", "/c", "/a"]
    row = result["files"][0]
    assert row["change_type"] == "modified"
    assert "diff_status" not in row


def test_list_file_changes_iso_timestamps(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_file(db_path, "/a")
    result = handle_list_file_changes(params={}, db_path=db_path)
    row = result["files"][0]
    assert row["first_seen"] == "2026-06-16T00:00:00"
    assert row["last_seen"] == "2026-06-16T00:00:00"


def test_list_connections_returns_rows_newest_last_seen_first(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_connection(db_path, "1:a:1:tcp", last_seen="2026-06-16 00:00:00")
    _seed_connection(db_path, "2:b:2:tcp", last_seen="2026-06-16 02:00:00")
    _seed_connection(db_path, "3:c:3:tcp", last_seen="2026-06-16 01:00:00")
    result = handle_list_connections(params={}, db_path=db_path)
    keys = [c["conn_key"] for c in result["connections"]]
    assert keys == ["2:b:2:tcp", "3:c:3:tcp", "1:a:1:tcp"]
    row = result["connections"][0]
    assert row["pid"] == 4321
    assert row["comm"] == "curl"
    assert row["saddr"] == "192.168.1.10"
    assert row["sport"] == 54321
    assert row["daddr"] == "93.184.216.34"
    assert row["dport"] == 443
    assert row["proto"] == "tcp"
    assert row["family"] == "ipv4"
    assert row["status"] == "observed"
    assert "diff_status" not in row


def test_list_connections_iso_timestamps(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_connection(db_path, "1:a:1:tcp")
    result = handle_list_connections(params={}, db_path=db_path)
    row = result["connections"][0]
    assert row["first_seen"] == "2026-06-16T00:00:00"
    assert row["last_seen"] == "2026-06-16T00:00:00"


def test_list_connections_active_flag(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    now = datetime.now(tz=UTC).replace(tzinfo=None)
    _seed_connection(db_path, "fresh:a:1:tcp", last_seen_dt=now)
    _seed_connection(db_path, "stale:b:2:tcp", last_seen="2020-01-01 00:00:00")
    result = handle_list_connections(params={}, db_path=db_path)
    by_key = {c["conn_key"]: c["active"] for c in result["connections"]}
    assert by_key["fresh:a:1:tcp"] is True
    assert by_key["stale:b:2:tcp"] is False


def test_list_listeners_returns_rows_ordered_by_addr_port(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_listener(db_path, "0.0.0.0", 443)
    _seed_listener(db_path, "0.0.0.0", 22)
    _seed_listener(db_path, "127.0.0.1", 53, proto="udp")
    result = handle_list_listeners(params={}, db_path=db_path)
    pairs = [(item["addr"], item["port"]) for item in result["listeners"]]
    assert pairs == [("0.0.0.0", 22), ("0.0.0.0", 443), ("127.0.0.1", 53)]
    row = result["listeners"][0]
    assert row["proto"] == "tcp"
    assert row["family"] == "ipv4"
    assert row["pid"] is None
    assert row["comm"] is None


def test_list_listeners_first_seen_is_iso_string(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_listener(db_path, "0.0.0.0", 22)
    result = handle_list_listeners(params={}, db_path=db_path)
    assert result["listeners"][0]["first_seen"] == "2026-06-16T00:00:00"


def test_list_processes_returns_rows_newest_last_seen_first(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_process(db_path, 100, last_seen="2026-06-16 00:00:00")
    _seed_process(db_path, 200, last_seen="2026-06-16 02:00:00")
    _seed_process(db_path, 300, last_seen="2026-06-16 01:00:00")
    result = handle_list_processes(params={}, db_path=db_path)
    pids = [p["pid"] for p in result["processes"]]
    assert pids == [200, 300, 100]
    row = result["processes"][0]
    assert row["comm"] == "bash"
    assert row["ppid"] == 1
    assert row["uid"] == 1000
    assert row["status"] == "running"
    assert row["cmdline"] == "bash -i"
    assert "diff_status" not in row


def test_list_processes_status_filter(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_process(db_path, 100, status="running")
    _seed_process(db_path, 200, status="exited")
    result = handle_list_processes(params={"status": "exited"}, db_path=db_path)
    pids = [p["pid"] for p in result["processes"]]
    assert pids == [200]


def test_list_processes_first_seen_is_iso_string(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_process(db_path, 100)
    result = handle_list_processes(params={}, db_path=db_path)
    assert result["processes"][0]["first_seen"] == "2026-06-16T00:00:00"


def test_list_devices_returns_rows(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_device(db_path, "1d6b:0002:ser", "present")
    result = handle_list_devices(params={}, db_path=db_path)
    keys = [d["dev_key"] for d in result["devices"]]
    assert keys == ["1d6b:0002:ser"]
    row = result["devices"][0]
    assert row["vendor"] == "1d6b"
    assert row["product"] == "0002"
    assert row["serial"] == "ser"
    assert row["subsystem"] == "usb"
    assert row["devnode"] == "/dev/usb1"
    assert row["status"] == "present"
    assert "diff_status" not in row


def test_list_devices_status_filter(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_device(db_path, "a:b:c", "present")
    _seed_device(db_path, "d:e:f", "removed")
    result = handle_list_devices(params={"status": "removed"}, db_path=db_path)
    keys = [d["dev_key"] for d in result["devices"]]
    assert keys == ["d:e:f"]


def test_list_devices_first_seen_is_iso_string(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_device(db_path, "a:b:c", "present")
    result = handle_list_devices(params={}, db_path=db_path)
    assert result["devices"][0]["first_seen"] == "2026-06-16T00:00:00"


def test_list_services_returns_rows(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    result = handle_list_services(params={}, db_path=db_path)
    units = [s["unit"] for s in result["services"]]
    assert units == ["sshd.service"]
    assert result["services"][0]["active_state"] == "active"


def test_list_services_no_diff_field_without_flag(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    result = handle_list_services(params={}, db_path=db_path)
    assert "diff_status" not in result["services"][0]


def test_diff_marks_new_when_no_baseline(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    result = handle_list_services(params={"diff": True}, db_path=db_path)
    assert result["services"][0]["diff_status"] == "new"


def test_diff_unchanged_and_reenabled_and_removed(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    _seed_service(db_path, "cron.service", "inactive")
    _seed_service(db_path, "ntp.service", "active")
    with Database(db_path) as db:
        capture_baseline("service", db)
    # mutate after baseline: cron re-enabled, ntp removed, new unit appears
    _seed_service(db_path, "cron.service", "active")
    with Database(db_path) as db:
        db.execute("DELETE FROM service_state WHERE unit='ntp.service'")
    _seed_service(db_path, "nginx.service", "active")

    result = handle_list_services(params={"diff": True}, db_path=db_path)
    by_unit = {s["unit"]: s["diff_status"] for s in result["services"]}
    assert by_unit["sshd.service"] == "unchanged"
    assert by_unit["cron.service"] == "re-enabled"
    assert by_unit["nginx.service"] == "new"
    assert by_unit["ntp.service"] == "removed"


def test_diff_marks_all_removed_when_services_gone(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    _seed_service(db_path, "cron.service", "active")
    with Database(db_path) as db:
        capture_baseline("service", db)
        db.execute("DELETE FROM service_state")
    result = handle_list_services(params={"diff": True}, db_path=db_path)
    by_unit = {s["unit"]: s["diff_status"] for s in result["services"]}
    assert by_unit == {"sshd.service": "removed", "cron.service": "removed"}
    # synthetic rows carry null state fields
    assert all(s["active_state"] is None for s in result["services"])


def _seed_persistence(db_path: Path, persist_key: str, kind: str, name: str) -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO persistence_state (persist_key, kind, name, source_path, details, "
            "first_seen, last_seen, last_event_id) VALUES "
            "(?, ?, ?, '/etc/crontab', 'd', TIMESTAMP '2026-06-16 00:00:00', "
            "TIMESTAMP '2026-06-16 00:00:00', 'pp1') "
            "ON CONFLICT (persist_key) DO UPDATE SET name = excluded.name",
            [persist_key, kind, name],
        )


def test_list_persistence_returns_rows_ordered_by_kind_name(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_persistence(db_path, "persist:systemd:1", "systemd", "zeta")
    _seed_persistence(db_path, "persist:cron:1", "cron", "beta")
    _seed_persistence(db_path, "persist:cron:2", "cron", "alpha")
    result = handle_list_persistence(params={}, db_path=db_path)
    pairs = [(p["kind"], p["name"]) for p in result["persistence"]]
    assert pairs == [("cron", "alpha"), ("cron", "beta"), ("systemd", "zeta")]
    row = result["persistence"][0]
    assert row["persist_key"] == "persist:cron:2"
    assert row["source_path"] == "/etc/crontab"
    assert row["details"] == "d"
    assert "diff_status" not in row


def test_list_persistence_iso_timestamps(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_persistence(db_path, "persist:cron:1", "cron", "a")
    result = handle_list_persistence(params={}, db_path=db_path)
    row = result["persistence"][0]
    assert row["first_seen"] == "2026-06-16T00:00:00"
    assert row["last_seen"] == "2026-06-16T00:00:00"


def test_list_persistence_diff_marks_new_when_no_baseline(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_persistence(db_path, "persist:cron:1", "cron", "a")
    _seed_persistence(db_path, "persist:cron:2", "cron", "b")
    result = handle_list_persistence(params={"diff": True}, db_path=db_path)
    assert all(p["diff_status"] == "new" for p in result["persistence"])


def test_list_persistence_diff_new_removed_unchanged_no_reenabled(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_persistence(db_path, "persist:cron:keep", "cron", "keep")
    _seed_persistence(db_path, "persist:cron:gone", "cron", "gone")
    with Database(db_path) as db:
        capture_baseline("persistence", db)
    # mutate after baseline: add one, delete one, keep one
    _seed_persistence(db_path, "persist:cron:added", "cron", "added")
    with Database(db_path) as db:
        db.execute("DELETE FROM persistence_state WHERE persist_key='persist:cron:gone'")

    result = handle_list_persistence(params={"diff": True}, db_path=db_path)
    by_key = {p["persist_key"]: p["diff_status"] for p in result["persistence"]}
    assert by_key["persist:cron:keep"] == "unchanged"
    assert by_key["persist:cron:added"] == "new"
    assert by_key["persist:cron:gone"] == "removed"
    assert "re-enabled" not in by_key.values()
    # synthetic removed row carries null fields
    gone = next(p for p in result["persistence"] if p["persist_key"] == "persist:cron:gone")
    assert gone["kind"] is None
    assert gone["name"] is None
    assert gone["first_seen"] is None


def test_capture_baseline_handler(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    result = handle_capture_baseline(params={"kind": "service"}, db_path=db_path)
    assert result["captured"] == 1
