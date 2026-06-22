"""Tests for the persistence-detection rules (one per persistence kind)."""

from __future__ import annotations

from importlib.resources import files

import yaml as _yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict


def _rule(filename: str):
    pkg = files("inspectord.rules.starter_pack")
    path = pkg / filename
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")),
        source=path.name,
    )


def _event(kind: str, *, action: str = "persistence_added", type_=None):
    return build_event(
        module="persistence_snapshotter",
        action=action,
        category=["host"],
        type_=type_ or ["start"],
        severity="low",
        persistence={
            "kind": kind,
            "name": "n",
            "source_path": "/p",
            "details": "d",
            "key": "k",
        },
    )


# persistence.new_cron -------------------------------------------------------


def test_new_cron_fires_on_cron_added() -> None:
    rule = _rule("persistence_new_cron.yaml")
    matches = evaluate_yaml_rule(rule, EvalContext(event=_event("cron"), history=[]))
    assert matches
    assert matches[0].severity == "medium"


def test_new_cron_ignores_other_kind() -> None:
    rule = _rule("persistence_new_cron.yaml")
    assert evaluate_yaml_rule(rule, EvalContext(event=_event("timer"), history=[])) == []


def test_new_cron_ignores_removed() -> None:
    rule = _rule("persistence_new_cron.yaml")
    ev = _event("cron", action="persistence_removed", type_=["end"])
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[])) == []


# persistence.new_systemd_timer ----------------------------------------------


def test_new_timer_fires_on_timer_added() -> None:
    rule = _rule("persistence_new_systemd_timer.yaml")
    matches = evaluate_yaml_rule(rule, EvalContext(event=_event("timer"), history=[]))
    assert matches
    assert matches[0].severity == "medium"


def test_new_timer_ignores_other_kind() -> None:
    rule = _rule("persistence_new_systemd_timer.yaml")
    assert evaluate_yaml_rule(rule, EvalContext(event=_event("cron"), history=[])) == []


def test_new_timer_ignores_removed() -> None:
    rule = _rule("persistence_new_systemd_timer.yaml")
    ev = _event("timer", action="persistence_removed", type_=["end"])
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[])) == []


# persistence.autostart_changed ----------------------------------------------


def test_autostart_fires_on_autostart_added() -> None:
    rule = _rule("persistence_autostart_changed.yaml")
    matches = evaluate_yaml_rule(rule, EvalContext(event=_event("autostart"), history=[]))
    assert matches
    assert matches[0].severity == "medium"


def test_autostart_ignores_other_kind() -> None:
    rule = _rule("persistence_autostart_changed.yaml")
    assert evaluate_yaml_rule(rule, EvalContext(event=_event("cron"), history=[])) == []


def test_autostart_ignores_removed() -> None:
    rule = _rule("persistence_autostart_changed.yaml")
    ev = _event("autostart", action="persistence_removed", type_=["end"])
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[])) == []


# persistence.authorized_keys_changed ----------------------------------------


def test_authorized_keys_fires_on_authorized_key_added() -> None:
    rule = _rule("persistence_authorized_keys_changed.yaml")
    matches = evaluate_yaml_rule(rule, EvalContext(event=_event("authorized_key"), history=[]))
    assert matches
    assert matches[0].severity == "high"


def test_authorized_keys_ignores_other_kind() -> None:
    rule = _rule("persistence_authorized_keys_changed.yaml")
    assert evaluate_yaml_rule(rule, EvalContext(event=_event("cron"), history=[])) == []


def test_authorized_keys_ignores_removed() -> None:
    rule = _rule("persistence_authorized_keys_changed.yaml")
    ev = _event("authorized_key", action="persistence_removed", type_=["end"])
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[])) == []
