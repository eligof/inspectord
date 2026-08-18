"""Tests for the raw-socket creation rule (spec section 5).

proc.raw_socket_unprivileged keys off the caller's uid, which is only a
*proxy* for CAP_NET_RAW -- the sys_enter_socket tracepoint carries no outcome
and no capability. The "does not fire for uid 0" test below encodes the
accepted v1 blind spot deliberately: a root-run sniffer produces an event but
no alert, and changing that must be a decision, not a drift.
"""

from __future__ import annotations

from importlib.resources import files

import yaml as _yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict

AF_PACKET = 17
AF_INET = 2
SOCK_RAW = 3


def _rule():
    path = files("inspectord.rules.starter_pack") / "proc_raw_socket_unprivileged.yaml"
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")),
        source=path.name,
    )


def _event(
    *,
    uid: str = "1000",
    family: int = AF_PACKET,
    family_name: str = "AF_PACKET",
    comm: str = "tcpdump",
    protocol: int = 768,
    module: str = "process_collector_raw_socket",
    action: str = "raw_socket_created",
):
    type_value = SOCK_RAW | 0o2000000  # SOCK_RAW | SOCK_CLOEXEC
    return build_event(
        module=module,
        action=action,
        category=["network"],
        type_=["start"],
        severity="info",
        user={"id": uid},
        process={"pid": 1234, "name": comm},
        network={
            "socket_family": family_name,
            "socket_type": type_value,
            "socket_protocol": protocol,
        },
        raw={
            "source": "ebpf:sys_enter_socket",
            "family": family,
            "type": type_value,
            "protocol": protocol,
        },
    )


def _fires(event) -> bool:
    return bool(evaluate_yaml_rule(_rule(), EvalContext(event=event, history=[])))


def test_fires_for_a_non_root_uid() -> None:
    matches = evaluate_yaml_rule(_rule(), EvalContext(event=_event(uid="1000"), history=[]))
    assert matches
    assert matches[0].severity == "medium"
    assert matches[0].rule_id == "proc.raw_socket_unprivileged"


def test_fires_for_an_af_inet_raw_socket_too() -> None:
    # The family is evidence, not a condition: AF_INET/SOCK_RAW is as much a
    # packet-crafting primitive as AF_PACKET.
    assert _fires(
        _event(uid="1000", family=AF_INET, family_name="AF_INET", comm="ping", protocol=1)
    )


def test_does_not_fire_for_root() -> None:
    # Accepted v1 blind spot (spec section 5): a root-run sniffer is recorded
    # as an event but never alerts through this rule.
    assert not _fires(_event(uid="0"))


def test_does_not_fire_on_other_module() -> None:
    assert not _fires(_event(uid="1000", module="outbound_connection_tracker"))


def test_does_not_fire_on_other_action() -> None:
    assert not _fires(_event(uid="1000", action="outbound_connection"))
