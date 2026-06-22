"""Tests for the manual cases store (spec §4)."""

from __future__ import annotations

from pathlib import Path

from inspectord.cases import store
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _seed_alert(db: Database, alert_id: str, short: str = "sshd brute force") -> None:
    db.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
        "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, payload_json) "
        "VALUES (?, 'r1', TIMESTAMP '2026-06-20 00:00:00', 'high', 'new', 'auth', 'dk', 1, "
        "TIMESTAMP '2026-06-20 00:00:00', TIMESTAMP '2026-06-20 00:00:00', ?, 'detail', '{}')",
        [alert_id, short],
    )


# --- 2a: open_case + attach_alert ---


def test_open_case_defaults_title_from_alert(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    assert isinstance(case_id, str)

    crow = db.query("SELECT title, status FROM cases WHERE case_id = ?", [case_id]).fetchall()
    assert crow[0][0] == "sshd brute force"
    assert crow[0][1] == "open"

    links = db.query("SELECT alert_id FROM case_alert WHERE case_id = ?", [case_id]).fetchall()
    assert [r[0] for r in links] == ["a1"]

    events = db.query(
        "SELECT kind, seq, ts FROM case_event WHERE case_id = ? ORDER BY seq", [case_id]
    ).fetchall()
    assert [(e[0], e[1]) for e in events] == [("opened", 0), ("alert_attached", 1)]
    # opened + alert_attached share the same ts.
    assert events[0][2] == events[1][2]


def test_open_case_title_override(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1", title="custom")
    crow = db.query("SELECT title FROM cases WHERE case_id = ?", [case_id]).fetchall()
    assert crow[0][0] == "custom"


def test_open_case_title_fallback_when_alert_absent(tmp_path: Path) -> None:
    db = _db(tmp_path)
    case_id = store.open_case(db, alert_id="ghost")
    crow = db.query("SELECT title FROM cases WHERE case_id = ?", [case_id]).fetchall()
    assert crow[0][0] == f"Case {case_id[:8]}"
    # The link is still created even though the alert is absent.
    links = db.query("SELECT alert_id FROM case_alert WHERE case_id = ?", [case_id]).fetchall()
    assert [r[0] for r in links] == ["ghost"]


def test_attach_alert_idempotent(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    store.attach_alert(db, case_id=case_id, alert_id="a1")
    links = db.query(
        "SELECT alert_id FROM case_alert WHERE case_id = ? AND alert_id = 'a1'", [case_id]
    ).fetchall()
    assert len(links) == 1
    events = db.query(
        "SELECT kind FROM case_event WHERE case_id = ? AND kind = 'alert_attached'", [case_id]
    ).fetchall()
    assert len(events) == 1


def test_attach_alert_missing_case_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    store.attach_alert(db, case_id="nope", alert_id="a1")
    links = db.query("SELECT alert_id FROM case_alert").fetchall()
    assert links == []
    events = db.query("SELECT kind FROM case_event").fetchall()
    assert events == []
