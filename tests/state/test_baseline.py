"""Tests for baseline capture."""

from __future__ import annotations

import json
from pathlib import Path

from inspectord.state.baseline import capture_baseline
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _seed_service(db: Database, unit: str, active: str) -> None:
    db.execute(
        "INSERT INTO service_state (unit, active_state, sub_state, load_state, "
        "first_seen, last_seen, last_event_id) VALUES "
        "(?, ?, 'running', 'loaded', TIMESTAMP '2026-06-16 00:00:00', "
        "TIMESTAMP '2026-06-16 00:00:00', 'e1')",
        [unit, active],
    )


def test_capture_service_baseline_snapshots_current_state(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_service(db, "sshd.service", "active")
    _seed_service(db, "cron.service", "inactive")
    count = capture_baseline("service", db)
    assert count == 2
    rows = db.query(
        "SELECT key, attrs_json FROM baseline_entry WHERE kind='service' ORDER BY key"
    ).fetchall()
    keys = [r[0] for r in rows]
    assert keys == ["svc:cron.service", "svc:sshd.service"]
    assert json.loads(rows[1][1])["active_state"] == "active"


def test_capture_baseline_replaces_previous(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_service(db, "sshd.service", "active")
    capture_baseline("service", db)
    db.execute("DELETE FROM service_state WHERE unit='sshd.service'")
    _seed_service(db, "nginx.service", "active")
    capture_baseline("service", db)
    rows = db.query("SELECT key FROM baseline_entry WHERE kind='service'").fetchall()
    assert {r[0] for r in rows} == {"svc:nginx.service"}


def test_capture_baseline_rejects_unknown_kind(tmp_path: Path) -> None:
    db = _db(tmp_path)
    try:
        capture_baseline("device", db)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
