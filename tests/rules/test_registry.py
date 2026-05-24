"""Tests for the Rule Registry."""

from __future__ import annotations

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext, Match
from inspectord.rules.registry import Registry


class _AlwaysFire:
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
                short="fired",
                detail="fired",
            )
        ]


def test_registry_aggregates_matches() -> None:
    reg = Registry(yaml_rules=[], python_rules=[_AlwaysFire(), _AlwaysFire()])
    ev = build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    matches = reg.evaluate(EvalContext(event=ev, history=[]))
    assert len(matches) == 2


def test_registry_empty() -> None:
    reg = Registry(yaml_rules=[], python_rules=[])
    ev = build_event(module="m", action="a", category=["c"], type_=["t"], severity="info")
    assert reg.evaluate(EvalContext(event=ev, history=[])) == []


def test_registry_rule_ids() -> None:
    reg = Registry(yaml_rules=[], python_rules=[_AlwaysFire()])
    assert reg.rule_ids() == ["test.always"]
