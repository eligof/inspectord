"""Tests for entity-state IPC handlers."""

from __future__ import annotations

from pathlib import Path

from inspectord.state.baseline import capture_baseline
from inspectord.state.ipc_handlers import handle_capture_baseline, handle_list_services
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
