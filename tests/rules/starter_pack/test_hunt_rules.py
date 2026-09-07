"""Tests for the hunt.scheduled_* starter rules + the hunt dedup entity branch."""

from __future__ import annotations

import re
from importlib.resources import files
from typing import Any

import yaml as _yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext, Match
from inspectord.rules.yaml_loader import (
    YamlRule,
    _primary_entity_for,
    evaluate_yaml_rule,
    load_yaml_rule_from_dict,
)
from inspectord.schemas.event import Event

TIER_RULES = {
    "high": "hunt_scheduled_match_high.yaml",
    "medium": "hunt_scheduled_match.yaml",
    "low": "hunt_scheduled_match_low.yaml",
}
ALL_RULES = (*TIER_RULES.values(), "hunt_scheduled_run_failed.yaml")


def _rule(filename: str) -> YamlRule:
    pkg = files("inspectord.rules.starter_pack")
    path = pkg / filename
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")),
        source=path.name,
    )


def _match_event(
    *,
    module: str = "hunt_scheduler",
    severity: str = "medium",
    name: str = "q1",
) -> Event:
    hunt: dict[str, Any] = {
        "name": name,
        "severity": severity,
        "match_count": 3,
        "sample_event_ids": ["a", "b", "c"],
        "window_upper_seq": 42,
        "run_duration_s": 0.05,
        "truncated": False,
        "pruned_gap": False,
    }
    return build_event(
        module=module,
        action="hunt_match",
        category=["hunt"],
        type_=["info"],
        severity=severity,
        kind="signal",
        hunt=hunt,
    )


def _failed_event(*, module: str = "hunt_scheduler", name: str = "q1") -> Event:
    return build_event(
        module=module,
        action="hunt_run_failed",
        category=["hunt"],
        type_=["error"],
        severity="medium",
        kind="signal",
        hunt={"name": name, "severity": "medium", "error_kind": "execution"},
    )


def _matches(filename: str, event: Event) -> list[Match]:
    return evaluate_yaml_rule(_rule(filename), EvalContext(event=event, history=[]))


# -- the three severity tiers ------------------------------------------------


def test_each_tier_fires_only_for_its_severity() -> None:
    for tier, filename in TIER_RULES.items():
        for severity in ("low", "medium", "high"):
            got = _matches(filename, _match_event(severity=severity))
            if severity == tier:
                assert got, f"{filename} must fire for hunt.severity={severity}"
                assert got[0].severity == tier
            else:
                assert got == [], f"{filename} must not fire for hunt.severity={severity}"


def test_tier_rules_are_module_pinned_against_forgery() -> None:
    for tier, filename in TIER_RULES.items():
        forged = _match_event(module="synthetic_emitter", severity=tier)
        assert _matches(filename, forged) == []


def test_tier_rules_do_not_fire_on_run_failed() -> None:
    for filename in TIER_RULES.values():
        assert _matches(filename, _failed_event()) == []


# -- hunt.scheduled_run_failed -----------------------------------------------


def test_run_failed_rule_fires() -> None:
    got = _matches("hunt_scheduled_run_failed.yaml", _failed_event())
    assert got
    assert got[0].severity == "medium"
    assert "q1" in got[0].short
    assert "execution" in got[0].short


def test_run_failed_rule_is_module_pinned() -> None:
    assert (
        _matches("hunt_scheduled_run_failed.yaml", _failed_event(module="synthetic_emitter")) == []
    )


def test_run_failed_rule_ignores_hunt_match() -> None:
    assert _matches("hunt_scheduled_run_failed.yaml", _match_event()) == []


# -- dedup entity ------------------------------------------------------------


def test_hunt_match_dedups_on_the_query_name() -> None:
    m1 = _matches("hunt_scheduled_match.yaml", _match_event())[0]
    m2 = _matches("hunt_scheduled_match.yaml", _match_event())[0]
    assert m1.primary_entity_kind == "hunt"
    assert m1.primary_entity_key == "q1"
    assert m1.dedup_key == m2.dedup_key


def test_hunt_branch_precedes_the_process_branch() -> None:
    event = build_event(
        module="hunt_scheduler",
        action="hunt_match",
        category=["hunt"],
        type_=["info"],
        severity="medium",
        kind="signal",
        hunt={"name": "q1", "severity": "medium", "match_count": 1},
        process={"pid": 1234, "name": "bash"},
    )
    kind, key = _primary_entity_for(event)
    assert (kind, key) == ("hunt", "q1")


def test_hunt_entity_is_module_pinned() -> None:
    # The same payload from another module must not steal the hunt identity.
    event = build_event(
        module="synthetic_emitter",
        action="hunt_match",
        category=["hunt"],
        type_=["info"],
        severity="medium",
        kind="signal",
        hunt={"name": "q1", "severity": "medium", "match_count": 1},
    )
    kind, _key = _primary_entity_for(event)
    assert kind != "hunt"


# -- rendering safety (§4.4) -------------------------------------------------


def test_templates_interpolate_only_safe_hunt_fields() -> None:
    """The expression never rides in the payload, and the templates must not
    reach for anything beyond the charset-validated name and the counters."""
    allowed = {"hunt.name", "hunt.match_count", "hunt.error_kind"}
    for filename in ALL_RULES:
        rule = _rule(filename)
        fields = set(re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_.]*)\}", rule.short_tpl + rule.detail_tpl))
        assert fields <= allowed, f"{filename} interpolates {fields - allowed}"


def test_rendered_messages_contain_no_escape_byte() -> None:
    for filename in TIER_RULES.values():
        tier = next(t for t, f in TIER_RULES.items() if f == filename)
        got = _matches(filename, _match_event(severity=tier, name="totally-benign-name"))
        assert got
        assert "\x1b" not in got[0].short
        assert "\x1b" not in got[0].detail


# -- schedule-friendly dedup window (§4.5) -----------------------------------


def test_all_four_rules_carry_a_one_day_dedup_window() -> None:
    for filename in ALL_RULES:
        assert _rule(filename).dedup_window_s == 86400.0, filename
