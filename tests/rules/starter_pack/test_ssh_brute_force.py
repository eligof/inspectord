"""Tests for the sshd brute-force rule."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.starter_pack.ssh_brute_force import RULE


def _failed_event(when: datetime, ip: str = "1.2.3.5"):
    ev = build_event(
        module="log_tailer",
        action="ssh_login_failed",
        category=["authentication"],
        type_=["end"],
        severity="medium",
        outcome="failure",
        source={"ip": ip, "port": 51234},
    )
    return ev.model_copy(update={"ts": when})


def test_does_not_fire_below_threshold() -> None:
    now = datetime.now(UTC)
    history = [_failed_event(now - timedelta(seconds=5 * i)) for i in range(3)]
    matches = RULE.evaluate(EvalContext(event=history[0], history=history))
    assert matches == []


def test_fires_at_threshold() -> None:
    now = datetime.now(UTC)
    history = [_failed_event(now - timedelta(seconds=5 * i)) for i in range(5)]
    matches = RULE.evaluate(EvalContext(event=history[0], history=history))
    assert len(matches) == 1
    assert matches[0].severity == "high"
    assert matches[0].rule_id == "auth.ssh_brute_force"
    assert "1.2.3.5" in matches[0].short


def test_window_resets_outside_60s() -> None:
    now = datetime.now(UTC)
    history = [_failed_event(now)]
    history += [_failed_event(now - timedelta(minutes=10)) for _ in range(4)]
    matches = RULE.evaluate(EvalContext(event=history[0], history=history))
    assert matches == []


def test_does_not_count_other_ips() -> None:
    now = datetime.now(UTC)
    history = [_failed_event(now - timedelta(seconds=i), ip=f"1.2.3.{i}") for i in range(5)]
    matches = RULE.evaluate(EvalContext(event=history[0], history=history))
    assert matches == []
