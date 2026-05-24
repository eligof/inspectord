"""Tests for the new-SUID rule."""

from __future__ import annotations

from importlib.resources import files

import yaml as _yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict


def _rule():
    pkg = files("inspectord.rules.starter_pack")
    path = pkg / "persistence_new_suid.yaml"
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")),
        source=path.name,
    )


def test_fires_on_setuid_file_create() -> None:
    rule = _rule()
    ev = build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/tmp/x", "setuid": True, "owner": 1000, "hash": {"sha256": "abc"}},
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[]))


def test_does_not_fire_on_setuid_false() -> None:
    rule = _rule()
    ev = build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": "/tmp/x", "setuid": False},
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev, history=[])) == []
