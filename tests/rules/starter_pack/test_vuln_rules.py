"""Tests for vuln.new_critical / vuln.new_high + the vulnerability entity branch."""

from __future__ import annotations

from importlib.resources import files
from typing import Any

import yaml as _yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import YamlRule, evaluate_yaml_rule, load_yaml_rule_from_dict
from inspectord.schemas.event import Event


def _rule(filename: str) -> YamlRule:
    pkg = files("inspectord.rules.starter_pack")
    path = pkg / filename
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")),
        source=path.name,
    )


def _event(
    *,
    severity: str = "Critical",
    new: bool = True,
    status: str = "Fixed",
    first_seen: bool = False,
    avg_id: str = "AVG-1",
    package: str = "openssl",
) -> Event:
    vulnerability: dict[str, Any] = {
        "avg_id": avg_id,
        "cve_id": "CVE-2026-1234",
        "package": package,
        "installed_version": "1.0-1",
        "fixed_version": "1.1-1",
        "severity": severity,
        "status": status,
        "fix_in_testing": False,
        "new": new,
        "advisory_url": f"https://security.archlinux.org/{avg_id}",
    }
    return build_event(
        module="vuln_scanner",
        action="vulnerability_found",
        category=["package"],
        type_=["info"],
        severity="low",
        kind="state",
        vulnerability=vulnerability,
        first_seen=first_seen,
    )


def _matches(filename: str, event: Event) -> list[Any]:
    return evaluate_yaml_rule(_rule(filename), EvalContext(event=event, history=[]))


# -- vuln.new_critical -------------------------------------------------------


def test_new_critical_fires_high() -> None:
    matches = _matches("vuln_new_critical.yaml", _event(severity="Critical"))
    assert matches
    assert matches[0].severity == "high"


def test_new_critical_ignores_high_severity() -> None:
    assert _matches("vuln_new_critical.yaml", _event(severity="High")) == []


def test_new_critical_ignores_not_new() -> None:
    assert _matches("vuln_new_critical.yaml", _event(new=False)) == []


def test_new_critical_ignores_unknown_status() -> None:
    # §4: an Unknown-status advisory gets a row and an event, never an alert.
    assert _matches("vuln_new_critical.yaml", _event(status="Unknown")) == []


def test_new_critical_ignores_other_actions() -> None:
    ev = build_event(
        module="vuln_scanner",
        action="vuln_scan_completed",
        category=["package"],
        type_=["end"],
        severity="info",
        raw={"matched": 3},
    )
    assert _matches("vuln_new_critical.yaml", ev) == []


# -- vuln.new_high -----------------------------------------------------------


def test_new_high_fires_medium() -> None:
    matches = _matches("vuln_new_high.yaml", _event(severity="High"))
    assert matches
    assert matches[0].severity == "medium"


def test_new_high_ignores_critical() -> None:
    assert _matches("vuln_new_high.yaml", _event(severity="Critical")) == []


def test_medium_and_unknown_severity_alert_nowhere() -> None:
    for severity in ("Medium", "Low", "Unknown"):
        for filename in ("vuln_new_critical.yaml", "vuln_new_high.yaml"):
            assert _matches(filename, _event(severity=severity)) == []


def test_new_high_ignores_not_new() -> None:
    assert _matches("vuln_new_high.yaml", _event(new=False)) == []


# -- dedup / primary entity --------------------------------------------------


def test_dedup_key_is_per_advisory_per_package_not_per_cve() -> None:
    m1 = _matches("vuln_new_critical.yaml", _event())
    ev2 = _event()
    assert ev2.vulnerability is not None
    ev2.vulnerability["cve_id"] = "CVE-2026-9999"
    m2 = _matches("vuln_new_critical.yaml", ev2)
    assert m1[0].primary_entity_kind == "package"
    assert m1[0].primary_entity_key == "AVG-1/openssl"
    assert m1[0].dedup_key == m2[0].dedup_key


def test_different_package_different_dedup_key() -> None:
    m1 = _matches("vuln_new_critical.yaml", _event(package="openssl"))
    m2 = _matches("vuln_new_critical.yaml", _event(package="bash"))
    assert m1[0].dedup_key != m2[0].dedup_key
