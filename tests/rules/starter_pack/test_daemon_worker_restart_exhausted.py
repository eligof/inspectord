"""Tests for daemon.worker_restart_exhausted (spec section 3.2).

The rule fires on the one supervisor event that means a collector is
permanently down: the supervisor gave up restarting it. worker_died and
worker_restarted are transient by comparison and must not alert here.
"""

from __future__ import annotations

from importlib.resources import files

import pytest
import yaml as _yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict


def _rule():
    path = files("inspectord.rules.starter_pack") / "daemon_worker_restart_exhausted.yaml"
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")),
        source=path.name,
    )


def _event(action: str, *, module: str = "supervisor", worker: str = "fim_watcher"):
    return build_event(
        module=module,
        action=action,
        category=["process"],
        type_=["error"],
        severity="high",
        message=f"worker {worker} stayed down after 8 restarts",
        raw={"worker": worker, "attempts": 8},
    )


def _fires(event) -> bool:
    return bool(evaluate_yaml_rule(_rule(), EvalContext(event=event, history=[])))


def test_fires_on_worker_restart_exhausted() -> None:
    matches = evaluate_yaml_rule(
        _rule(), EvalContext(event=_event("worker_restart_exhausted"), history=[])
    )
    assert matches
    assert matches[0].rule_id == "daemon.worker_restart_exhausted"
    assert matches[0].severity == "high"


def test_alert_text_names_the_dead_worker() -> None:
    matches = evaluate_yaml_rule(
        _rule(),
        EvalContext(event=_event("worker_restart_exhausted", worker="log_tailer"), history=[]),
    )
    assert "log_tailer" in matches[0].short
    assert "log_tailer" in matches[0].detail
    assert "8" in matches[0].detail


@pytest.mark.parametrize("action", ["worker_died", "worker_restarted"])
def test_does_not_fire_on_transient_worker_events(action: str) -> None:
    assert not _fires(_event(action))


def test_does_not_fire_for_another_module() -> None:
    assert not _fires(_event("worker_restart_exhausted", module="services_monitor"))


def test_rule_documents_why_and_false_positives() -> None:
    rule = _rule()
    assert rule.why.strip()
    assert len(rule.false_positives) >= 2
