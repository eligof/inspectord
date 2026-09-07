"""Tests for the dedup engine."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.alerts.builder import build_alert
from inspectord.alerts.dedup import DedupEngine
from inspectord.parsers.base import build_event
from inspectord.rules.base import Match
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations

NOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)


def _ev(ts: datetime | None = None):
    return build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1234, "name": "bash"},
        ts=ts,
    )


def _match(short: str = "short", detail: str = "detail") -> Match:
    return Match(
        rule_id="lolbin.bash_dev_tcp",
        severity="critical",
        category="intrusion_detection",
        dedup_key="lolbin.bash_dev_tcp:pid:1234",
        primary_entity_kind="process",
        primary_entity_key="pid:1234",
        short=short,
        detail=detail,
    )


def _fresh_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    return db_path


def test_first_alert_inserts_new_row(tmp_path: Path) -> None:
    db_path = _fresh_db(tmp_path)
    engine = DedupEngine(db_path=db_path, window_s=60.0)
    a = build_alert(match=_match(), event=_ev())
    written, was_new, notifiable = engine.persist(a)
    assert was_new is True
    assert notifiable is True
    assert written.dedup_count == 1
    with Database(db_path) as db:
        rows = db.query("SELECT alert_id, dedup_count FROM alerts").fetchall()
    assert len(rows) == 1
    assert rows[0][1] == 1


def test_second_same_key_updates_existing(tmp_path: Path) -> None:
    db_path = _fresh_db(tmp_path)
    engine = DedupEngine(db_path=db_path, window_s=60.0)
    a1 = build_alert(match=_match(), event=_ev())
    engine.persist(a1)
    a2 = build_alert(match=_match(), event=_ev())
    a2_out, was_new, notifiable = engine.persist(a2)
    assert was_new is False
    assert notifiable is True
    assert a2_out.dedup_count == 2
    with Database(db_path) as db:
        rows = db.query("SELECT alert_id, dedup_count FROM alerts").fetchall()
    assert len(rows) == 1
    assert rows[0][1] == 2


def test_old_window_creates_new_alert(tmp_path: Path) -> None:
    db_path = _fresh_db(tmp_path)
    engine = DedupEngine(db_path=db_path, window_s=0.05)
    a1 = build_alert(match=_match(), event=_ev())
    engine.persist(a1)
    time.sleep(0.1)
    a2 = build_alert(match=_match(), event=_ev())
    _, was_new, _ = engine.persist(a2)
    assert was_new is True
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 2


# --------------------------------------------------------------------------
# per-call window override (hunt-followups design §4.5)
# --------------------------------------------------------------------------


def test_window_override_merges_beyond_the_default_window(tmp_path: Path) -> None:
    db_path = _fresh_db(tmp_path)
    engine = DedupEngine(db_path=db_path, window_s=600.0)
    a1 = build_alert(match=_match(), event=_ev(ts=NOW))
    engine.persist(a1)
    # 2 h later: far outside the 600 s default, inside a one-day override.
    a2 = build_alert(match=_match(), event=_ev(ts=NOW + timedelta(hours=2)))
    out, was_new, notifiable = engine.persist(a2, window_s=86400.0)
    assert was_new is False
    assert notifiable is True
    assert out.dedup_count == 2
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 1


def test_none_override_keeps_the_engine_default(tmp_path: Path) -> None:
    db_path = _fresh_db(tmp_path)
    engine = DedupEngine(db_path=db_path, window_s=600.0)
    engine.persist(build_alert(match=_match(), event=_ev(ts=NOW)))
    a2 = build_alert(match=_match(), event=_ev(ts=NOW + timedelta(hours=2)))
    _, was_new, _ = engine.persist(a2, window_s=None)
    assert was_new is True
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 2


# --------------------------------------------------------------------------
# non-open bump semantics (hunt-followups design §4.5)
# --------------------------------------------------------------------------


def test_bump_of_acknowledged_alert_is_quiet_and_preserves_text(tmp_path: Path) -> None:
    db_path = _fresh_db(tmp_path)
    engine = DedupEngine(db_path=db_path, window_s=600.0)
    a1 = build_alert(
        match=_match(short="original short", detail="original detail"), event=_ev(ts=NOW)
    )
    engine.persist(a1)
    with Database(db_path) as db:
        db.execute("UPDATE alerts SET status = 'acknowledged'")
        original_payload = db.query("SELECT payload_json FROM alerts").fetchall()[0][0]

    a2 = build_alert(
        match=_match(short="rewritten short", detail="rewritten detail"),
        event=_ev(ts=NOW + timedelta(seconds=60)),
    )
    out, was_new, notifiable = engine.persist(a2)

    assert was_new is False
    assert notifiable is False
    assert out.dedup_count == 2
    with Database(db_path) as db:
        rows = db.query(
            "SELECT dedup_count, last_seen_at, rendered_short, rendered_detail, payload_json "
            "FROM alerts"
        ).fetchall()
    assert len(rows) == 1
    count, last_seen, short, detail, payload = rows[0]
    # The bump only advances the counters — never the acked alert's text.
    assert count == 2
    assert last_seen.replace(tzinfo=UTC) == a2.last_seen_at
    assert short == "original short"
    assert detail == "original detail"
    assert payload == original_payload


def test_bump_of_open_alert_stays_notifiable_and_rewrites_text(tmp_path: Path) -> None:
    db_path = _fresh_db(tmp_path)
    engine = DedupEngine(db_path=db_path, window_s=600.0)
    engine.persist(build_alert(match=_match(short="original short"), event=_ev(ts=NOW)))

    a2 = build_alert(
        match=_match(short="rewritten short"), event=_ev(ts=NOW + timedelta(seconds=60))
    )
    _, was_new, notifiable = engine.persist(a2)

    assert was_new is False
    assert notifiable is True
    with Database(db_path) as db:
        short = db.query("SELECT rendered_short FROM alerts").fetchall()[0][0]
    assert short == "rewritten short"
