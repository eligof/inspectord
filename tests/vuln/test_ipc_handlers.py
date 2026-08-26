"""Tests for the vulnerability IPC handlers (vuln-scanner design §7)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from inspectord.__main__ import _ipc_methods
from inspectord.audit.log import reset_for_tests
from inspectord.config import dev_config
from inspectord.schemas.event import Event, EventKind, Severity
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
from inspectord.storage.migrations import run_migrations
from inspectord.vuln.ipc_handlers import handle_ack_vulnerability, handle_list_vulnerabilities

_T0 = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)


def setup_function(_fn) -> None:
    reset_for_tests()  # drop the audit module connection + counters between tests


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


def _insert_vuln(
    db_path: Path,
    *,
    avg_id: str = "AVG-1",
    cve_id: str = "CVE-2026-0001",
    package: str = "openssl",
    severity: str = "Critical",
    first_seen_at: datetime = _T0,
    resolved_at: datetime | None = None,
    acked_at: datetime | None = None,
    acked_note: str | None = None,
    fix_in_testing: bool = False,
) -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO vulnerabilities (avg_id, cve_id, package, installed_version,"
            " fixed_version, severity, status, fix_in_testing, first_seen_at, last_seen,"
            " last_event_id, resolved_at, acked_at, acked_note)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                avg_id,
                cve_id,
                package,
                "1.0-1",
                "1.1-1",
                severity,
                "Fixed",
                fix_in_testing,
                first_seen_at.replace(tzinfo=None),
                first_seen_at.replace(tzinfo=None),
                "e1",
                resolved_at.replace(tzinfo=None) if resolved_at else None,
                acked_at.replace(tzinfo=None) if acked_at else None,
                acked_note,
            ],
        )


def _scan_event(
    db_path: Path,
    *,
    event_id: str,
    ts: datetime,
    action: str,
    raw: dict[str, Any],
) -> None:
    event = Event(
        ts=ts,
        event_id=event_id,
        kind=EventKind.event,
        category=["package"],
        type=["end"],
        action=action,
        severity=Severity.info,
        module="vuln_scanner",
        raw=raw,
    )
    with Database(db_path) as db:
        insert_event(db, event, event.model_dump_json(exclude_none=True))


def _completed_raw(**overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "scan_started_at": _T0.isoformat(),
        "advisories": 12,
        "matched": 3,
        "new": 1,
        "warnings": 0,
        "skipped_avg_ids": [],
        "advisory_mtime": _T0.isoformat(),
        "duration_ms": 42,
    }
    raw.update(overrides)
    return raw


# --------------------------------------------------------------------------
# list_vulnerabilities
# --------------------------------------------------------------------------


def test_list_empty(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    out = handle_list_vulnerabilities(params={}, db_path=db_path)
    assert out["ok"] is True
    assert out["schema_version"] == "1.0.0"
    assert out["rows"] == []
    assert out["last_scan"] is None


def test_list_shape_and_order(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _insert_vuln(db_path, avg_id="AVG-1", first_seen_at=_T0)
    _insert_vuln(db_path, avg_id="AVG-2", first_seen_at=_T0 + timedelta(hours=1))
    out = handle_list_vulnerabilities(params={}, db_path=db_path)
    assert [r["avg_id"] for r in out["rows"]] == ["AVG-2", "AVG-1"]  # newest first
    row = out["rows"][1]
    assert row["cve_id"] == "CVE-2026-0001"
    assert row["package"] == "openssl"
    assert row["installed_version"] == "1.0-1"
    assert row["fixed_version"] == "1.1-1"
    assert row["severity"] == "Critical"
    assert row["status"] == "Fixed"
    assert row["fix_in_testing"] is False
    assert row["first_seen_at"] == "2026-08-26T12:00:00"  # ISO
    assert row["last_seen"] == "2026-08-26T12:00:00"
    assert row["last_event_id"] == "e1"
    assert row["resolved_at"] is None
    assert row["acked_at"] is None
    assert row["acked_note"] is None


def test_list_limit_clamped(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    for i in range(3):
        _insert_vuln(db_path, avg_id=f"AVG-{i}", first_seen_at=_T0 + timedelta(minutes=i))
    assert len(handle_list_vulnerabilities(params={"limit": 1}, db_path=db_path)["rows"]) == 1
    # 0 clamps up to 1, not an error and never unbounded
    assert len(handle_list_vulnerabilities(params={"limit": 0}, db_path=db_path)["rows"]) == 1
    # over-cap clamps to 500 — with 3 rows that means all of them
    assert len(handle_list_vulnerabilities(params={"limit": 9999}, db_path=db_path)["rows"]) == 3
    # garbage falls back to the default
    assert len(handle_list_vulnerabilities(params={"limit": "x"}, db_path=db_path)["rows"]) == 3


def test_list_severity_filter_exact_match(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _insert_vuln(db_path, avg_id="AVG-1", severity="Critical")
    _insert_vuln(db_path, avg_id="AVG-2", severity="High")
    out = handle_list_vulnerabilities(params={"severity": "High"}, db_path=db_path)
    assert [r["avg_id"] for r in out["rows"]] == ["AVG-2"]


def test_list_acked_included_by_default_excluded_on_request(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _insert_vuln(db_path, avg_id="AVG-1")
    _insert_vuln(db_path, avg_id="AVG-2", acked_at=_T0, acked_note="known")
    assert len(handle_list_vulnerabilities(params={}, db_path=db_path)["rows"]) == 2
    out = handle_list_vulnerabilities(params={"include_acked": False}, db_path=db_path)
    assert [r["avg_id"] for r in out["rows"]] == ["AVG-1"]


def test_list_resolved_excluded_by_default_included_on_request(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _insert_vuln(db_path, avg_id="AVG-1")
    _insert_vuln(db_path, avg_id="AVG-2", resolved_at=_T0)
    out = handle_list_vulnerabilities(params={}, db_path=db_path)
    assert [r["avg_id"] for r in out["rows"]] == ["AVG-1"]
    out = handle_list_vulnerabilities(params={"include_resolved": True}, db_path=db_path)
    assert {r["avg_id"] for r in out["rows"]} == {"AVG-1", "AVG-2"}


def test_last_scan_completed(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _scan_event(
        db_path,
        event_id="s1",
        ts=_T0,
        action="vuln_scan_completed",
        raw=_completed_raw(),
    )
    last = handle_list_vulnerabilities(params={}, db_path=db_path)["last_scan"]
    assert last is not None
    assert last["action"] == "vuln_scan_completed"
    assert last["ts"] == "2026-08-26T12:00:00"
    assert last["advisory_mtime"] == _T0.isoformat()
    assert last["counts"] == {"advisories": 12, "matched": 3, "new": 1, "warnings": 0}
    assert "reason" not in last


def test_last_scan_failed_newest_wins(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _scan_event(
        db_path,
        event_id="s1",
        ts=_T0,
        action="vuln_scan_completed",
        raw=_completed_raw(),
    )
    _scan_event(
        db_path,
        event_id="s2",
        ts=_T0 + timedelta(hours=1),
        action="vuln_scan_failed",
        raw={"reason": "pacman_db_locked"},
    )
    last = handle_list_vulnerabilities(params={}, db_path=db_path)["last_scan"]
    assert last is not None
    assert last["action"] == "vuln_scan_failed"
    assert last["ts"] == "2026-08-26T13:00:00"
    assert last["reason"] == "pacman_db_locked"
    assert "counts" not in last


# --------------------------------------------------------------------------
# ack_vulnerability
# --------------------------------------------------------------------------


def _newest_audit(db_path: Path) -> dict[str, Any] | None:
    with Database(db_path) as db:
        row = db.query(
            "SELECT actor, action, target, details_json FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    return {
        "actor": row[0],
        "action": row[1],
        "target": row[2],
        "details": json.loads(row[3]),
    }


def _audit_count(db_path: Path) -> int:
    with Database(db_path) as db:
        return db.query(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'vulnerability_acked'"
        ).fetchone()[0]


def _ack_params(**overrides: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "avg_id": "AVG-1",
        "cve_id": "CVE-2026-0001",
        "package": "openssl",
    }
    params.update(overrides)
    return params


def test_ack_sets_fields_and_writes_audit_row(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _insert_vuln(db_path)
    out = handle_ack_vulnerability(params=_ack_params(note="reviewed"), db_path=db_path)
    assert out["ok"] is True
    rows = handle_list_vulnerabilities(params={}, db_path=db_path)["rows"]
    assert rows[0]["acked_at"] is not None
    assert rows[0]["acked_note"] == "reviewed"
    audit = _newest_audit(db_path)
    assert audit is not None
    assert audit["actor"] == "user:local"
    assert audit["action"] == "vulnerability_acked"
    assert audit["target"] == "vuln:AVG-1/CVE-2026-0001/openssl"
    assert audit["details"] == {"note": "reviewed"}


def test_ack_without_note_writes_empty_details(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _insert_vuln(db_path)
    out = handle_ack_vulnerability(params=_ack_params(), db_path=db_path)
    assert out["ok"] is True
    audit = _newest_audit(db_path)
    assert audit is not None
    assert audit["details"] == {}


def test_ack_idempotent_no_second_audit_row(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _insert_vuln(db_path)
    assert handle_ack_vulnerability(params=_ack_params(), db_path=db_path)["ok"] is True
    assert _audit_count(db_path) == 1
    # Re-ack is allowed (idempotent) but must not fabricate a second audit row.
    assert handle_ack_vulnerability(params=_ack_params(note="again"), db_path=db_path)["ok"] is True
    assert _audit_count(db_path) == 1


def test_ack_missing_row_not_found(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    out = handle_ack_vulnerability(params=_ack_params(), db_path=db_path)
    assert out["ok"] is False
    assert out["error"] == "not_found"
    assert _audit_count(db_path) == 0


# --------------------------------------------------------------------------
# registration
# --------------------------------------------------------------------------


def test_methods_registered(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    mutates = {m.name: m.mutates for m in _ipc_methods(None, cfg)}  # type: ignore[arg-type]
    assert mutates["list_vulnerabilities"] is False
    assert mutates["ack_vulnerability"] is True
