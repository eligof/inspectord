"""Tests for the alerts IPC handlers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from inspectord.alerts.ipc_handlers import (
    handle_ack_alert,
    handle_get_alert,
    handle_list_alerts,
    handle_resolve_alert,
    handle_suppress_alert,
)
from inspectord.alerts.lifecycle import InvalidTransitionError
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _seed_alert(
    db_path: Path,
    *,
    alert_id: str = "01900000-0000-7000-8000-000000000001",
    rule_id: str = "lolbin.bash_dev_tcp",
    severity: str = "critical",
    status: str = "new",
) -> None:
    now = datetime.now(UTC)
    payload = {
        "schema_version": "1.0.0",
        "alert_id": alert_id,
        "rule": {
            "id": rule_id,
            "name": rule_id,
            "ruleset": "starter-pack",
            "version": "1.0.0",
            "severity": severity,
            "why": "",
            "false_positives": [],
        },
        "ts": now.isoformat(),
        "severity": severity,
        "status": status,
        "category": "intrusion_detection",
        "event_ids": ["e1"],
        "entities": [{"kind": "process", "key": "pid:1234"}],
        "dedup_key": f"{rule_id}:pid:1234",
        "dedup_count": 1,
        "first_seen_at": now.isoformat(),
        "last_seen_at": now.isoformat(),
        "rendered": {"short": "short", "detail": "detail"},
        "notes": [],
        "labels": [],
    }
    with Database(db_path) as db:
        run_migrations(db)
        db.execute(
            "INSERT INTO alerts "
            "(alert_id, rule_id, ts, severity, status, category, dedup_key, "
            "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, "
            "payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                alert_id,
                rule_id,
                now,
                severity,
                status,
                "intrusion_detection",
                f"{rule_id}:pid:1234",
                1,
                now,
                now,
                "short",
                "detail",
                json.dumps(payload),
            ],
        )


def test_list_alerts_returns_seeded_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path)
    result = handle_list_alerts(params={"limit": 10}, db_path=db_path)
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["rule_id"] == "lolbin.bash_dev_tcp"


def test_list_alerts_filters_by_status(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1", status="new")
    _seed_alert(db_path, alert_id="a2", status="resolved")
    result = handle_list_alerts(params={"status": "new"}, db_path=db_path)
    ids = [a["alert_id"] for a in result["alerts"]]
    assert ids == ["a1"]


def test_get_alert_returns_full_payload(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1")
    result = handle_get_alert(params={"alert_id": "a1"}, db_path=db_path)
    assert result["alert"]["alert_id"] == "a1"
    assert result["alert"]["rule"]["id"] == "lolbin.bash_dev_tcp"


def test_get_alert_missing_returns_none(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    result = handle_get_alert(params={"alert_id": "absent"}, db_path=db_path)
    assert result["alert"] is None


def test_ack_alert_transitions_status(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1")
    handle_ack_alert(params={"alert_id": "a1", "note": "looking"}, db_path=db_path)
    with Database(db_path) as db:
        row = db.query("SELECT status FROM alerts WHERE alert_id = ?", ["a1"]).fetchall()[0][0]
    assert row == "acknowledged"


def test_resolve_alert_from_new(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1")
    handle_resolve_alert(params={"alert_id": "a1"}, db_path=db_path)
    with Database(db_path) as db:
        row = db.query("SELECT status FROM alerts WHERE alert_id = ?", ["a1"]).fetchall()[0][0]
    assert row == "resolved"


def test_suppress_alert(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1")
    handle_suppress_alert(params={"alert_id": "a1"}, db_path=db_path)
    with Database(db_path) as db:
        row = db.query("SELECT status FROM alerts WHERE alert_id = ?", ["a1"]).fetchall()[0][0]
    assert row == "suppressed"


def test_invalid_transition_raises(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    _seed_alert(db_path, alert_id="a1", status="resolved")
    with pytest.raises(InvalidTransitionError):
        handle_ack_alert(params={"alert_id": "a1"}, db_path=db_path)
