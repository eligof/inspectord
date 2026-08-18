"""Tests for the two kernel-module load rules (spec section 4).

proc.kernel_module_from_memory keys off the init_module variant;
proc.kernel_module_loaded_unknown keys off a finit_module call from a caller
outside the known-loader list. Both key off the *loader*, never a module name
-- this collector deliberately does not resolve one.
"""

from __future__ import annotations

from importlib.resources import files

import pytest
import yaml as _yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict

KNOWN_LOADERS = [
    "modprobe",
    "insmod",
    "kmod",
    "systemd-udevd",
    "systemd",
    "dracut",
    "mkinitcpio",
]


def _rule(filename: str):
    path = files("inspectord.rules.starter_pack") / filename
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")),
        source=path.name,
    )


def _from_memory_rule():
    return _rule("proc_kernel_module_from_memory.yaml")


def _loaded_unknown_rule():
    return _rule("proc_kernel_module_loaded_unknown.yaml")


def _event(
    variant_name: str,
    *,
    comm: str = "curl",
    module: str = "process_collector_module_load",
    action: str = "module_load_attempt",
):
    fd = 7 if variant_name == "finit_module" else -1
    return build_event(
        module=module,
        action=action,
        category=["driver"],
        type_=["installation"],
        severity="info",
        user={"id": "0"},
        process={
            "pid": 1234,
            "name": comm,
            "module_load_variant": variant_name,
            "module_load_fd": fd,
            "module_load_flags": 0,
        },
        raw={
            "source": f"ebpf:sys_enter_{variant_name}",
            "variant": 0 if variant_name == "finit_module" else 1,
            "fd": fd,
            "flags": 0,
        },
    )


def _fires(rule, event) -> bool:
    return bool(evaluate_yaml_rule(rule, EvalContext(event=event, history=[])))


def test_from_memory_fires_on_init_module() -> None:
    matches = evaluate_yaml_rule(
        _from_memory_rule(), EvalContext(event=_event("init_module"), history=[])
    )
    assert matches
    assert matches[0].severity == "high"
    assert matches[0].rule_id == "proc.kernel_module_from_memory"


def test_from_memory_fires_even_for_a_known_loader_name() -> None:
    # The rule keys off the syscall variant only: modprobe has no business
    # calling init_module(2) either, so the loader name must not exempt it.
    assert _fires(_from_memory_rule(), _event("init_module", comm="modprobe"))


def test_from_memory_does_not_fire_on_finit_module() -> None:
    assert not _fires(_from_memory_rule(), _event("finit_module"))


def test_from_memory_does_not_fire_on_other_module() -> None:
    ev = _event("init_module", module="kmod_watcher")
    assert not _fires(_from_memory_rule(), ev)


def test_from_memory_does_not_fire_on_other_action() -> None:
    ev = _event("init_module", action="kmod_loaded")
    assert not _fires(_from_memory_rule(), ev)


def test_loaded_unknown_fires_for_an_unknown_loader() -> None:
    matches = evaluate_yaml_rule(
        _loaded_unknown_rule(),
        EvalContext(event=_event("finit_module", comm="curl"), history=[]),
    )
    assert matches
    assert matches[0].severity == "medium"
    assert matches[0].rule_id == "proc.kernel_module_loaded_unknown"


@pytest.mark.parametrize("comm", KNOWN_LOADERS)
def test_loaded_unknown_does_not_fire_for_known_loaders(comm: str) -> None:
    assert not _fires(_loaded_unknown_rule(), _event("finit_module", comm=comm))


def test_loaded_unknown_does_not_fire_on_init_module() -> None:
    # init_module from an unknown loader is proc.kernel_module_from_memory's
    # business; this rule must not double-alert on it.
    assert not _fires(_loaded_unknown_rule(), _event("init_module", comm="curl"))


def test_loaded_unknown_does_not_fire_on_other_module() -> None:
    ev = _event("finit_module", comm="curl", module="kmod_watcher")
    assert not _fires(_loaded_unknown_rule(), ev)


def test_loaded_unknown_does_not_fire_on_other_action() -> None:
    ev = _event("finit_module", comm="curl", action="kmod_loaded")
    assert not _fires(_loaded_unknown_rule(), ev)
