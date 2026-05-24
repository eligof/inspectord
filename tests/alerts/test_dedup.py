"""Tests for the dedup engine."""

from __future__ import annotations

import time
from pathlib import Path

from inspectord.alerts.builder import build_alert
from inspectord.alerts.dedup import DedupEngine
from inspectord.parsers.base import build_event
from inspectord.rules.base import Match
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _ev():
    return build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1234, "name": "bash"},
    )


def _match() -> Match:
    return Match(
        rule_id="lolbin.bash_dev_tcp",
        severity="critical",
        category="intrusion_detection",
        dedup_key="lolbin.bash_dev_tcp:pid:1234",
        primary_entity_kind="process",
        primary_entity_key="pid:1234",
        short="short",
        detail="detail",
    )


def test_first_alert_inserts_new_row(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    engine = DedupEngine(db_path=db_path, window_s=60.0)
    a = build_alert(match=_match(), event=_ev())
    written, was_new = engine.persist(a)
    assert was_new is True
    assert written.dedup_count == 1
    with Database(db_path) as db:
        rows = db.query("SELECT alert_id, dedup_count FROM alerts").fetchall()
    assert len(rows) == 1
    assert rows[0][1] == 1


def test_second_same_key_updates_existing(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    engine = DedupEngine(db_path=db_path, window_s=60.0)
    a1 = build_alert(match=_match(), event=_ev())
    engine.persist(a1)
    a2 = build_alert(match=_match(), event=_ev())
    a2_out, was_new = engine.persist(a2)
    assert was_new is False
    assert a2_out.dedup_count == 2
    with Database(db_path) as db:
        rows = db.query("SELECT alert_id, dedup_count FROM alerts").fetchall()
    assert len(rows) == 1
    assert rows[0][1] == 2


def test_old_window_creates_new_alert(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    engine = DedupEngine(db_path=db_path, window_s=0.05)
    a1 = build_alert(match=_match(), event=_ev())
    engine.persist(a1)
    time.sleep(0.1)
    a2 = build_alert(match=_match(), event=_ev())
    _, was_new = engine.persist(a2)
    assert was_new is True
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 2
