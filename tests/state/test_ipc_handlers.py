"""Tests for entity-state IPC handlers."""

from __future__ import annotations

from pathlib import Path

from inspectord.state.baseline import capture_baseline
from inspectord.state.ipc_handlers import (
    handle_capture_baseline,
    handle_list_devices,
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


def test_capture_baseline_handler(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_service(db_path, "sshd.service", "active")
    result = handle_capture_baseline(params={"kind": "service"}, db_path=db_path)
    assert result["captured"] == 1
