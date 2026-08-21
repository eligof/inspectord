"""The anomaly.beacon_signature starter rule matches beacon signals only."""

from __future__ import annotations

from importlib.resources import files

import yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict

_FILENAME = "anomaly_beacon_signature.yaml"


def _rule():
    text = files("inspectord.rules.starter_pack").joinpath(_FILENAME).read_text(encoding="utf-8")
    return load_yaml_rule_from_dict(yaml.safe_load(text), source=_FILENAME)


def _beacon_signal():
    ev = build_event(
        module="anomaly_detector",
        action="beacon_signature",
        category=["anomaly"],
        type_=["info"],
        severity="info",
        kind="signal",
        process={"name": "curl"},
        destination={"ip": "203.0.113.9", "port": 443},
    )
    ev.baseline = {
        "metric_kind": "beacon",
        "entity_key": "curl->203.0.113.9:443",
        "count": 12,
        "interval_mean_s": 60.0,
        "interval_stddev_s": 1.2,
        "cv": 0.02,
    }
    return ev


def test_beacon_rule_fires_on_beacon_signal() -> None:
    rule = _rule()
    assert rule.severity == "medium"
    matches = evaluate_yaml_rule(rule, EvalContext(event=_beacon_signal()))
    assert len(matches) == 1
    assert matches[0].rule_id == "anomaly.beacon_signature"
    assert matches[0].category == "anomaly"
    assert "{" not in matches[0].short
    assert "{" not in matches[0].detail
    assert "203.0.113.9:443" in matches[0].short
    assert "60.0" in matches[0].detail


def test_beacon_rule_ignores_statistical_signals() -> None:
    ev = _beacon_signal()
    ev.action = "metric_anomaly"
    assert evaluate_yaml_rule(_rule(), EvalContext(event=ev)) == []


def test_beacon_rule_ignores_other_modules() -> None:
    ev = _beacon_signal()
    ev.module = "outbound_connection_tracker"
    assert evaluate_yaml_rule(_rule(), EvalContext(event=ev)) == []
