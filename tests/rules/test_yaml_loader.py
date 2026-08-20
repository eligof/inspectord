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
    load_yaml_rule_from_dict,
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


def _proc_event(name: str):
    return build_event(
        module="process_collector_module_load",
        action="module_load_attempt",
        category=["driver"],
        type_=["installation"],
        severity="info",
        process={"pid": 1, "name": name},
    )


@pytest.mark.parametrize(
    ("expr", "comm", "expected"),
    [
        # `path NOT IN [...]` is advertised by the leaf grammar, so it must be
        # reachable: the boolean tokenizer must not split the leading NOT off
        # as a unary operator and leave a bare `IN [...]` behind.
        ('process.name NOT IN ["modprobe", "insmod"]', "curl", True),
        ('process.name NOT IN ["modprobe", "insmod"]', "modprobe", False),
        # ...including as the tail of an AND chain, which is how rules use it.
        (
            'event.action == "module_load_attempt" AND process.name NOT IN ["modprobe"]',
            "curl",
            True,
        ),
        (
            'event.action == "module_load_attempt" AND process.name NOT IN ["modprobe"]',
            "modprobe",
            False,
        ),
        # The unary `NOT <leaf>` prefix form must keep working.
        ('NOT process.name IN ["modprobe"]', "curl", True),
        ('NOT process.name IN ["modprobe"]', "modprobe", False),
        ('NOT process.name == "modprobe"', "curl", True),
        # And plain IN is unaffected.
        ('process.name IN ["modprobe", "insmod"]', "modprobe", True),
        ('process.name IN ["modprobe", "insmod"]', "curl", False),
    ],
)
def test_not_in_leaf_operator(expr: str, comm: str, expected: bool) -> None:
    rule = _rule_from_expr(expr)
    fired = bool(evaluate_yaml_rule(rule, EvalContext(event=_proc_event(comm), history=[])))
    assert fired is expected, expr


def test_pidless_process_event_gets_stable_name_dedup_key() -> None:
    # Anomaly signals stamp process={"name": ...} with no pid; without a name
    # fallback these fell through to the per-event key and never deduped.
    rule = _rule_from_expr('event.action == "tick"')
    ev1 = build_event(
        module="anomaly_detector",
        action="tick",
        category=["anomaly"],
        type_=["info"],
        severity="info",
        process={"name": "curl"},
    )
    ev2 = build_event(
        module="anomaly_detector",
        action="tick",
        category=["anomaly"],
        type_=["info"],
        severity="info",
        process={"name": "curl"},
    )
    m1 = evaluate_yaml_rule(rule, EvalContext(event=ev1, history=[]))
    m2 = evaluate_yaml_rule(rule, EvalContext(event=ev2, history=[]))
    assert m1[0].primary_entity_kind == "process"
    assert m1[0].primary_entity_key == "name:curl"
    assert m1[0].dedup_key == m2[0].dedup_key


def _rule_from_expr(expr: str) -> YamlRule:
    return load_yaml_rule_from_dict(
        {
            "version": "1.0.0",
            "id": "test.expr",
            "name": "expr",
            "severity": "info",
            "category": "test",
            "why": "test",
            "detect": {"any_of": [expr]},
            "short": "s",
            "detail": "d",
        },
        source="test.yaml",
    )
