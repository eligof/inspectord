"""Tests for YAML rule loader + evaluator."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext, Match
from inspectord.rules.yaml_loader import (
    YamlRule,
    YamlRuleError,
    evaluate_yaml_rule,
    load_yaml_rule,
)


def test_load_minimal_yaml(tmp_path: Path) -> None:
    p = tmp_path / "r.yaml"
    p.write_text(
        """
version: 1.0.0
id: test.always
name: "Always fire"
severity: info
category: test
why: "test"
detect:
  any_of:
    - event.action == "tick"
short: "tick"
detail: "tick happened"
""".lstrip()
    )
    rule = load_yaml_rule(p)
    assert isinstance(rule, YamlRule)
    assert rule.rule_id == "test.always"
    assert rule.severity == "info"


def test_evaluate_simple_equality() -> None:
    rule = YamlRule(
        rule_id="x",
        name="x",
        severity="info",
        category="test",
        why="",
        false_positives=[],
        detect_any_of=['event.action == "tick"'],
        short_tpl="t",
        detail_tpl="d",
    )
    ev = build_event(module="m", action="tick", category=["c"], type_=["t"], severity="info")
    matches = evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))
    assert len(matches) == 1
    assert isinstance(matches[0], Match)
    assert matches[0].rule_id == "x"


def test_evaluate_string_predicates() -> None:
    rule = YamlRule(
        rule_id="x",
        name="x",
        severity="info",
        category="test",
        why="",
        false_positives=[],
        detect_any_of=['file.path STARTSWITH "/etc/sudoers"'],
        short_tpl="m {file.path}",
        detail_tpl="d {file.path}",
    )
    ev = build_event(
        module="fim_watcher",
        action="file_modified",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/etc/sudoers.d/extra"},
    )
    matches = evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))
    assert matches
    assert matches[0].short == "m /etc/sudoers.d/extra"


def test_no_match_returns_empty() -> None:
    rule = YamlRule(
        rule_id="x",
        name="x",
        severity="info",
        category="test",
        why="",
        false_positives=[],
        detect_any_of=['event.action == "ping"'],
        short_tpl="t",
        detail_tpl="d",
    )
    ev = build_event(module="m", action="pong", category=["c"], type_=["t"], severity="info")
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[])) == []


def test_and_combiner() -> None:
    rule = YamlRule(
        rule_id="x",
        name="x",
        severity="info",
        category="test",
        why="",
        false_positives=[],
        detect_any_of=[
            'event.module == "fim_watcher" AND event.action == "file_modified"',
        ],
        short_tpl="t",
        detail_tpl="d",
    )
    matching = build_event(
        module="fim_watcher",
        action="file_modified",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/etc/x"},
    )
    nonmatching = build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/etc/x"},
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=matching, history=[]))
    assert evaluate_yaml_rule(rule, EvalContext(event=nonmatching, history=[])) == []


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("name: : :")
    with pytest.raises(YamlRuleError):
        load_yaml_rule(p)


def test_missing_required_field_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("version: 1.0.0\nid: x\n")
    with pytest.raises(YamlRuleError):
        load_yaml_rule(p)
