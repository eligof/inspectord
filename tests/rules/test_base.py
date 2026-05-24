"""Tests for the rule framework."""

from __future__ import annotations

from datetime import UTC, datetime

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext, Match, Rule


def _event(action: str = "test"):
    return build_event(
        module="log_tailer",
        action=action,
        category=["host"],
        type_=["info"],
        severity="info",
    )


def test_match_dataclass() -> None:
    m = Match(
        rule_id="x.y",
        severity="medium",
        category="test",
        dedup_key="x.y:foo",
        primary_entity_kind="process",
        primary_entity_key="pid:1234",
        short="short msg",
        detail="detail msg",
    )
    assert m.rule_id == "x.y"
    assert m.severity == "medium"


def test_eval_context_carries_event_and_history() -> None:
    ctx = EvalContext(event=_event(), history=[_event("a"), _event("b")])
    assert len(ctx.history) == 2
    assert ctx.event.action == "test"


def test_eval_context_recent_filter() -> None:
    older = _event("old")
    older = older.model_copy(update={"ts": datetime(2020, 1, 1, tzinfo=UTC)})
    newer = _event("new")
    ctx = EvalContext(event=newer, history=[older, newer])
    recent = ctx.recent_events(window_s=60.0)
    assert newer in recent
    assert older not in recent


class _AlwaysFireRule:
    rule_id = "test.always"
    severity = "info"
    category = "test"

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        return [
            Match(
                rule_id=self.rule_id,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:{ctx.event.action}",
                primary_entity_kind="event",
                primary_entity_key=ctx.event.event_id,
                short=f"fired on {ctx.event.action}",
                detail="long-form detail",
            )
        ]


def test_protocol_compatible_class() -> None:
    rule: Rule = _AlwaysFireRule()
    matches = rule.evaluate(EvalContext(event=_event(), history=[]))
    assert len(matches) == 1
    assert matches[0].rule_id == "test.always"
