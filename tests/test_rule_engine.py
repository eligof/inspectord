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
