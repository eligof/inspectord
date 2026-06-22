"""Tests for the manual cases store (spec §4)."""

from __future__ import annotations

import contextlib
from pathlib import Path

import pytest

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


def test_open_case_truncates_long_title(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1", short="x" * 20000)
    case_id = store.open_case(db, alert_id="a1")
    title = db.query("SELECT title FROM cases WHERE case_id = ?", [case_id]).fetchall()[0][0]
    assert len(title) == 16384


def test_open_case_is_atomic_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A mid-op failure must roll back the whole case (no case row, link, or events left behind).
    db = _db(tmp_path)
    _seed_alert(db, "a1")

    def _boom(*args: object, **kwargs: object) -> bool:
        raise RuntimeError("attach failed")

    monkeypatch.setattr(store, "_attach", _boom)
    with contextlib.suppress(RuntimeError):
        store.open_case(db, alert_id="a1")
    assert db.query("SELECT COUNT(*) FROM cases").fetchall()[0][0] == 0
    assert db.query("SELECT COUNT(*) FROM case_event").fetchall()[0][0] == 0
    assert db.query("SELECT COUNT(*) FROM case_alert").fetchall()[0][0] == 0


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


# --- 2b: add_note + close_case ---


def test_add_note_appends_note_event(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    store.add_note(db, case_id=case_id, text="looks malicious")
    notes = db.query(
        "SELECT text FROM case_event WHERE case_id = ? AND kind = 'note'", [case_id]
    ).fetchall()
    assert [n[0] for n in notes] == ["looks malicious"]


def test_add_note_works_on_closed_case(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    store.close_case(db, case_id=case_id)
    store.add_note(db, case_id=case_id, text="after close")
    notes = db.query(
        "SELECT text FROM case_event WHERE case_id = ? AND kind = 'note'", [case_id]
    ).fetchall()
    assert [n[0] for n in notes] == ["after close"]


def test_add_note_truncates_long_text(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    store.add_note(db, case_id=case_id, text="x" * 20000)
    notes = db.query(
        "SELECT text FROM case_event WHERE case_id = ? AND kind = 'note'", [case_id]
    ).fetchall()
    assert len(notes[0][0]) == 16384


def test_add_note_missing_case_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    store.add_note(db, case_id="nope", text="hi")
    events = db.query("SELECT kind FROM case_event").fetchall()
    assert events == []


def test_close_case_sets_status_and_appends_event(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    store.close_case(db, case_id=case_id)
    crow = db.query("SELECT status, closed_at FROM cases WHERE case_id = ?", [case_id]).fetchall()
    assert crow[0][0] == "closed"
    assert crow[0][1] is not None
    closed = db.query(
        "SELECT kind FROM case_event WHERE case_id = ? AND kind = 'closed'", [case_id]
    ).fetchall()
    assert len(closed) == 1


def test_close_case_idempotent(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    store.close_case(db, case_id=case_id)
    store.close_case(db, case_id=case_id)
    crow = db.query("SELECT status FROM cases WHERE case_id = ?", [case_id]).fetchall()
    assert crow[0][0] == "closed"
    closed = db.query(
        "SELECT kind FROM case_event WHERE case_id = ? AND kind = 'closed'", [case_id]
    ).fetchall()
    assert len(closed) == 1


def test_close_case_missing_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    store.close_case(db, case_id="nope")
    events = db.query("SELECT kind FROM case_event").fetchall()
    assert events == []


# --- 2c: list_cases + get_case ---


def test_list_cases_counts_and_orders_newest_first(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    _seed_alert(db, "a2")
    first = store.open_case(db, alert_id="a1", title="first")
    store.attach_alert(db, case_id=first, alert_id="a2")
    second = store.open_case(db, alert_id="a2", title="second")
    cases = store.list_cases(db)
    # Newest opened_at first.
    assert [c["case_id"] for c in cases] == [second, first]
    by_id = {c["case_id"]: c for c in cases}
    assert by_id[first]["alert_count"] == 2
    assert by_id[second]["alert_count"] == 1
    assert by_id[first]["title"] == "first"
    assert by_id[first]["status"] == "open"


def test_get_case_returns_alerts_and_timeline(tmp_path: Path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    case = store.get_case(db, case_id=case_id)
    assert case is not None
    assert set(case.keys()) == {
        "case_id",
        "title",
        "status",
        "opened_at",
        "closed_at",
        "alerts",
        "timeline",
    }
    assert len(case["alerts"]) == 1
    a = case["alerts"][0]
    assert a["alert_id"] == "a1"
    assert a["rule_id"] == "r1"
    assert a["severity"] == "high"
    assert a["status"] == "new"
    assert a["rendered_short"] == "sshd brute force"
    assert a["ts"] is not None
    kinds = [t["kind"] for t in case["timeline"]]
    assert kinds == ["opened", "alert_attached"]


def test_get_case_pruned_alert_is_placeholder(tmp_path: Path) -> None:
    db = _db(tmp_path)
    case_id = store.open_case(db, alert_id="ghost")
    case = store.get_case(db, case_id=case_id)
    assert case is not None
    assert len(case["alerts"]) == 1
    a = case["alerts"][0]
    assert a["alert_id"] == "ghost"
    assert a["rule_id"] is None
    assert a["severity"] is None
    assert a["status"] is None
    assert a["rendered_short"] is None
    assert a["ts"] is None


def test_get_case_missing_returns_none(tmp_path: Path) -> None:
    db = _db(tmp_path)
    assert store.get_case(db, case_id="nope") is None
