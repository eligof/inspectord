"""Tests for the proc.ptrace_injection rule (attach family only)."""

from __future__ import annotations

from importlib.resources import files

import yaml as _yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict


def _rule():
    pkg = files("inspectord.rules.starter_pack")
    path = pkg / "proc_ptrace_injection.yaml"
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")),
        source=path.name,
    )


def _event(
    request_name: str,
    *,
    module: str = "process_collector_ptrace",
    action: str = "ptrace_call",
):
    return build_event(
        module=module,
        action=action,
        category=["process"],
        type_=["access"],
        severity="info",
        user={"id": "1000"},
        process={
            "pid": 1234,
            "name": "gdb",
            "ptrace_request": request_name,
            "target_pid": 5678,
            "target": {"pid": 5678},
        },
        raw={"source": "ebpf:sys_enter_ptrace", "request": 16},
    )


def test_fires_on_attach() -> None:
    matches = evaluate_yaml_rule(_rule(), EvalContext(event=_event("PTRACE_ATTACH"), history=[]))
    assert matches
    assert matches[0].severity == "medium"


def test_fires_on_seize() -> None:
    matches = evaluate_yaml_rule(_rule(), EvalContext(event=_event("PTRACE_SEIZE"), history=[]))
    assert matches
    assert matches[0].severity == "medium"


def test_does_not_fire_on_poketext() -> None:
    assert (
        evaluate_yaml_rule(_rule(), EvalContext(event=_event("PTRACE_POKETEXT"), history=[])) == []
    )


def test_does_not_fire_on_setregset() -> None:
    assert (
        evaluate_yaml_rule(_rule(), EvalContext(event=_event("PTRACE_SETREGSET"), history=[])) == []
    )


def test_does_not_fire_on_other_module() -> None:
    ev = _event("PTRACE_ATTACH", module="process_collector")
    assert evaluate_yaml_rule(_rule(), EvalContext(event=ev, history=[])) == []


def test_does_not_fire_on_other_action() -> None:
    ev = _event("PTRACE_ATTACH", action="process_start")
    assert evaluate_yaml_rule(_rule(), EvalContext(event=ev, history=[])) == []
