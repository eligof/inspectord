"""Tests for the rule_engine library."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from inspectord.parsers.base import build_event
from inspectord.rule_engine import RuleEngine
from inspectord.rules.base import EvalContext, Match
from inspectord.rules.registry import Registry
from inspectord.rules.starter_pack.ssh_brute_force import RULE as SSH_BRUTE_FORCE_RULE
from inspectord.schemas.allowlist import AllowlistEntry, AllowlistScope, AllowlistStats
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


class _AlwaysFireOnce:
    rule_id = "test.always"
    severity = "info"
    category = "test"

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        return [
            Match(
                rule_id=self.rule_id,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:event:{ctx.event.event_id}",
                primary_entity_kind="event",
                primary_entity_key=ctx.event.event_id,
                short=f"fire {ctx.event.event_id}",
                detail="d",
            )
        ]


def test_rule_engine_persists_alert(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    reg = Registry(yaml_rules=[], python_rules=[_AlwaysFireOnce()])
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=[])
    ev = build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    out = engine.process(ev)
    assert len(out) == 1
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 1


def test_rule_engine_respects_allowlist(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    reg = Registry(yaml_rules=[], python_rules=[_AlwaysFireOnce()])
    entries = [
        AllowlistEntry(
            id="x",
            scope=AllowlistScope(rule_id="test.always"),
            reason="muted",
            created_by="eli@local",
            created_at=datetime.now(UTC),
            auto_origin=False,
            stats=AllowlistStats(),
        )
    ]
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=entries)
    ev = build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    out = engine.process(ev)
    assert out == []
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 0


def test_rule_engine_drops_first_seen_events(tmp_path: Path) -> None:
    """A first_seen baseline event is dropped before rule evaluation."""
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    reg = Registry(yaml_rules=[], python_rules=[_AlwaysFireOnce()])
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=[])
    ev = build_event(
        module="m",
        action="a",
        category=["c"],
        type_=["t"],
        severity="info",
        first_seen=True,
    )
    out = engine.process(ev)
    assert out == []
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 0


def test_rule_engine_first_seen_does_not_enter_history(tmp_path: Path) -> None:
    """A dropped first_seen event must not pollute correlation history.

    A normal (first_seen=False) event matching the same rule still alerts.
    """
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    reg = Registry(yaml_rules=[], python_rules=[_AlwaysFireOnce()])
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=[])

    baseline = build_event(
        module="m",
        action="a",
        category=["c"],
        type_=["t"],
        severity="info",
        first_seen=True,
    )
    assert engine.process(baseline) == []

    normal = build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    out = engine.process(normal)
    assert len(out) == 1


class _FixedKeyRule:
    """Fires on every event with one stable dedup key (a standing detection)."""

    rule_id = "test.standing"
    severity = "medium"
    category = "test"

    def __init__(self, dedup_window_s: float | None = None) -> None:
        self._dedup_window_s = dedup_window_s

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        return [
            Match(
                rule_id=self.rule_id,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:hunt:q1",
                primary_entity_kind="hunt",
                primary_entity_key="q1",
                short="s",
                detail="d",
                dedup_window_s=self._dedup_window_s,
            )
        ]


def test_rule_engine_does_not_return_non_open_bumps(tmp_path: Path) -> None:
    """§4.5: a dedup bump of a non-open alert must not reach the supervisor's
    fan-out (notifier, evidence collector) — process() simply omits it."""
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    reg = Registry(yaml_rules=[], python_rules=[_FixedKeyRule()])
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=[])

    first = engine.process(
        build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    )
    assert len(first) == 1

    with Database(db_path) as db:
        db.execute("UPDATE alerts SET status = 'acknowledged'")

    bumped = engine.process(
        build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    )
    assert bumped == []
    with Database(db_path) as db:
        rows = db.query("SELECT COUNT(*), MAX(dedup_count) FROM alerts").fetchall()
    # The bump itself still landed — it just did not fan out.
    assert rows[0][0] == 1
    assert rows[0][1] == 2


def test_rule_engine_returns_open_bumps(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    reg = Registry(yaml_rules=[], python_rules=[_FixedKeyRule()])
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=[])
    ev = build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    assert len(engine.process(ev)) == 1
    out = engine.process(
        build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    )
    assert len(out) == 1
    assert out[0].dedup_count == 2


def test_rule_engine_honors_per_rule_dedup_window(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    reg = Registry(yaml_rules=[], python_rules=[_FixedKeyRule(dedup_window_s=86400.0)])
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=[])
    now = datetime.now(UTC)

    ev1 = build_event(module="m", action="a", category=["c"], type_=["t"], severity="info", ts=now)
    assert len(engine.process(ev1)) == 1
    # 2 h later: outside the 600 s engine default, inside the rule's window.
    ev2 = build_event(
        module="m",
        action="a",
        category=["c"],
        type_=["t"],
        severity="info",
        ts=now + timedelta(hours=2),
    )
    out = engine.process(ev2)
    assert len(out) == 1
    assert out[0].dedup_count == 2
    with Database(db_path) as db:
        n = db.query("SELECT COUNT(*) FROM alerts").fetchall()[0][0]
    assert n == 1


def test_rule_engine_passes_history_to_correlation_rules(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    reg = Registry(yaml_rules=[], python_rules=[SSH_BRUTE_FORCE_RULE])
    engine = RuleEngine(registry=reg, db_path=db_path, allowlist_entries=[])
    now = datetime.now(UTC)
    ip = "1.2.3.5"
    for i in range(4):
        ev = build_event(
            module="log_tailer",
            action="ssh_login_failed",
            category=["authentication"],
            type_=["end"],
            severity="medium",
            outcome="failure",
            source={"ip": ip, "port": 51234},
        ).model_copy(update={"ts": now - timedelta(seconds=10 - i)})
        assert engine.process(ev) == []
    fifth = build_event(
        module="log_tailer",
        action="ssh_login_failed",
        category=["authentication"],
        type_=["end"],
        severity="medium",
        outcome="failure",
        source={"ip": ip, "port": 51234},
    )
    out = engine.process(fifth)
    assert len(out) == 1
    assert out[0].rule.id == "auth.ssh_brute_force"
