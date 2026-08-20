"""Statistical anomaly.* starter rules match metric_anomaly signals."""

from __future__ import annotations

from importlib.resources import files

import yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict


def _rule(name: str):
    text = files("inspectord.rules.starter_pack").joinpath(name).read_text(encoding="utf-8")
    return load_yaml_rule_from_dict(yaml.safe_load(text), source=name)


def _signal(metric_kind: str, **entity):
    ev = build_event(
        module="anomaly_detector",
        action="metric_anomaly",
        category=["anomaly"],
        type_=["info"],
        severity="info",
        kind="signal",
        **entity,
    )
    ev.baseline = {
        "metric_kind": metric_kind,
        "entity_key": "x",
        "window": "1h",
        "observed": 100.0,
        "mean": 1.0,
        "stddev": 0.5,
        "deviation": 42.0,
    }
    return ev


CASES = [
    (
        "anomaly_egress_volume_spike.yaml",
        "anomaly.process_egress_volume_spike",
        "egress_bytes_per_min",
        "medium",
        {"process": {"name": "curl"}},
    ),
    (
        "anomaly_event_rate_spike.yaml",
        "anomaly.process_event_rate_spike",
        "events_per_min",
        "low",
        {"process": {"name": "curl"}},
    ),
    (
        "anomaly_sudo_rate_spike.yaml",
        "anomaly.sudo_rate_spike",
        "sudo_per_min",
        "medium",
        {"user": {"name": "eli"}},
    ),
    (
        "anomaly_login_rate_spike.yaml",
        "anomaly.login_rate_spike",
        "logins_per_min",
        "low",
        {"user": {"name": "eli"}},
    ),
]


def test_each_rule_fires_on_its_metric_only() -> None:
    for fname, rule_id, metric, severity, entity in CASES:
        rule = _rule(fname)
        assert rule.severity == severity, fname
        matches = evaluate_yaml_rule(rule, EvalContext(event=_signal(metric, **entity)))
        assert len(matches) == 1, fname
        assert matches[0].rule_id == rule_id
        assert matches[0].category == "anomaly"
        # Wrong metric on an otherwise identical signal: no match.
        other = "sudo_per_min" if metric != "sudo_per_min" else "events_per_min"
        assert not evaluate_yaml_rule(rule, EvalContext(event=_signal(other, **entity))), fname


def test_non_signal_event_with_stamped_metric_kind_does_not_fire() -> None:
    # A hostile or buggy worker cannot forge a statistical alert by writing
    # baseline.metric_kind: the module gate pins these rules to the detector.
    ev = build_event(
        module="log_tailer",
        action="metric_anomaly",
        category=["anomaly"],
        type_=["info"],
        severity="info",
        process={"name": "curl"},
    )
    ev.baseline = {"metric_kind": "sudo_per_min", "deviation": 99.0}
    for fname, *_ in CASES:
        assert not evaluate_yaml_rule(_rule(fname), EvalContext(event=ev)), fname


def test_wrong_action_from_detector_module_does_not_fire() -> None:
    # Pins the action clause: module and metric_kind alone must not match.
    ev = _signal("sudo_per_min", user={"name": "eli"})
    ev.action = "something_else"
    for fname, *_ in CASES:
        assert not evaluate_yaml_rule(_rule(fname), EvalContext(event=ev)), fname
