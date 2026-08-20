"""First-sighting starter rules (anomaly.first_*)."""

from __future__ import annotations

from importlib.resources import files

import yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict


def _rule(name: str):
    text = files("inspectord.rules.starter_pack").joinpath(name).read_text(encoding="utf-8")
    return load_yaml_rule_from_dict(yaml.safe_load(text), source=name)


def _stamped(ev):
    ev.baseline = {**(ev.baseline or {}), "first_sighting": True}
    return ev


def _proc_start():
    return build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1, "name": "xz", "executable": "/usr/bin/xz"},
    )


def test_first_binary_execution_fires_only_when_stamped() -> None:
    rule = _rule("anomaly_first_binary_execution.yaml")
    assert rule.severity == "low"
    assert not evaluate_yaml_rule(rule, EvalContext(event=_proc_start()))
    matches = evaluate_yaml_rule(rule, EvalContext(event=_stamped(_proc_start())))
    assert len(matches) == 1
    assert matches[0].rule_id == "anomaly.first_binary_execution"
    assert matches[0].category == "anomaly"


def test_first_outbound_dest_fires() -> None:
    rule = _rule("anomaly_first_outbound_dest.yaml")
    assert rule.severity == "low"
    ev = _stamped(
        build_event(
            module="outbound_connection_tracker",
            action="outbound_connection",
            category=["network"],
            type_=["connection", "start"],
            severity="info",
            process={"pid": 2, "name": "curl"},
            destination={"ip": "203.0.113.9", "port": 443},
        )
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev))


def test_first_login_ip_fires() -> None:
    rule = _rule("anomaly_first_login_ip.yaml")
    assert rule.severity == "low"
    ev = _stamped(
        build_event(
            module="log_tailer",
            action="ssh_login_succeeded",
            category=["authentication"],
            type_=["start"],
            severity="info",
            outcome="success",
            user={"name": "eli"},
            source={"ip": "198.51.100.7"},
        )
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev))


def test_first_kmod_load_fires_at_medium() -> None:
    rule = _rule("anomaly_first_kmod_load.yaml")
    assert rule.severity == "medium"
    ev = _stamped(
        build_event(
            module="kmod_watcher",
            action="kmod_loaded",
            category=["driver"],
            type_=["installation"],
            severity="info",
            raw={"module_name": "nft_ct"},
        )
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev))


def test_first_suid_file_fires_at_medium() -> None:
    rule = _rule("anomaly_first_suid_file.yaml")
    assert rule.severity == "medium"
    ev = _stamped(
        build_event(
            module="fim_watcher",
            action="file_created",
            category=["file"],
            type_=["creation"],
            severity="info",
            file={"path": "/usr/local/bin/backdoor", "setuid": True},
        )
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev))
    # setuid gate: a stamped fim event without the bit must not fire.
    plain = _stamped(
        build_event(
            module="fim_watcher",
            action="file_created",
            category=["file"],
            type_=["creation"],
            severity="info",
            file={"path": "/tmp/x", "setuid": False},
        )
    )
    assert not evaluate_yaml_rule(rule, EvalContext(event=plain))


def test_unstamped_events_never_fire_any_rule() -> None:
    names = [
        "anomaly_first_binary_execution.yaml",
        "anomaly_first_outbound_dest.yaml",
        "anomaly_first_login_ip.yaml",
        "anomaly_first_kmod_load.yaml",
        "anomaly_first_suid_file.yaml",
    ]
    ev = _proc_start()
    for name in names:
        assert not evaluate_yaml_rule(_rule(name), EvalContext(event=ev)), name
