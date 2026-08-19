"""Tests for the two YAML `av.*` scanner rules.

Both key on **structural** fields — `event.module`, `event.action` and
`threat.indicator.source`, all of which the runner sets from its own state and
no scanner parser can influence. The YARA rule additionally reads
`threat.indicator.severity`, which *is* scanner-supplied; that is the one place
these rules trust parser output, and it is documented in the rule file rather
than hidden here.

`_finding_event` mirrors `ScannerRunnerWorker._emit_finding` exactly, so a
change to the emitted shape breaks these tests instead of silently
un-triggering the rules.
"""

from __future__ import annotations

from importlib.resources import files
from typing import Any

import pytest
import yaml as _yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import YamlRule, evaluate_yaml_rule, load_yaml_rule_from_dict
from inspectord.schemas.event import Event


def _rule(filename: str) -> YamlRule:
    path = files("inspectord.rules.starter_pack") / filename
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")),
        source=path.name,
    )


def _rkhunter_rule() -> YamlRule:
    return _rule("av_rkhunter_warning_or_worse.yaml")


def _yara_rule() -> YamlRule:
    return _rule("av_yara_high_confidence_hit.yaml")


def _finding_event(
    *,
    scanner: str,
    indicator_type: str,
    indicator_value: str,
    scanner_severity: str | None = None,
    path: str | None = None,
    message: str | None = None,
    category: str = "file",
    module: str = "scanner_runner",
    action: str = "scan_finding",
) -> Event:
    """A `scan_finding` event shaped exactly like `runner._emit_finding` builds it."""
    indicator: dict[str, Any] = {
        "type": indicator_type,
        "value": indicator_value,
        "source": scanner,
    }
    # The runner omits the key entirely when the scanner declared no severity.
    if scanner_severity is not None:
        indicator["severity"] = scanner_severity
    file_block = {"path": path} if path is not None else None
    return build_event(
        module=module,
        action=action,
        category=[category],
        type_=["info"],
        severity="low",
        host={"name": "testhost"},
        message=message,
        labels=["scanner", f"scanner:{scanner}"],
        file=file_block,
        threat={"indicator": indicator},
        raw={"scanner": scanner, "run_id": "0198f000-0000-7000-8000-000000000000", "line": "x"},
    )


def _rkhunter_event(**kwargs: Any) -> Event:
    kwargs.setdefault("indicator_value", "Checking for prerequisites")
    kwargs.setdefault("message", "Checking for prerequisites [ Warning ] rkhunter.dat is missing")
    kwargs.setdefault("category", "process")
    return _finding_event(scanner="rkhunter", indicator_type="rkhunter_test", **kwargs)


def _yara_event(**kwargs: Any) -> Event:
    kwargs.setdefault("indicator_value", "SUSP_Example_Rule")
    kwargs.setdefault("path", "/home/eli/Downloads/dropper.bin")
    kwargs.setdefault("message", "YARA: SUSP_Example_Rule matched /home/eli/Downloads/dropper.bin")
    return _finding_event(scanner="yara", indicator_type="yara_rule", **kwargs)


def _aide_event(**kwargs: Any) -> Event:
    kwargs.setdefault("indicator_value", "changed")
    kwargs.setdefault("path", "/usr/bin/sudo")
    kwargs.setdefault("message", "AIDE: changed /usr/bin/sudo")
    return _finding_event(scanner="aide", indicator_type="aide_change", **kwargs)


def _fires(rule: YamlRule, event: Event) -> bool:
    return bool(evaluate_yaml_rule(rule, EvalContext(event=event, history=[])))


# --------------------------------------------------------------------------
# av.rkhunter_warning_or_worse
# --------------------------------------------------------------------------


def test_rkhunter_rule_fires_on_an_rkhunter_finding() -> None:
    matches = evaluate_yaml_rule(_rkhunter_rule(), EvalContext(event=_rkhunter_event(), history=[]))
    assert matches
    assert matches[0].rule_id == "av.rkhunter_warning_or_worse"
    # Measured: five warnings on a healthy Arch host, so `high` would cry wolf.
    assert matches[0].severity == "medium"
    assert matches[0].false_positives


def test_rkhunter_rule_renders_the_check_name_and_the_warning_text() -> None:
    matches = evaluate_yaml_rule(_rkhunter_rule(), EvalContext(event=_rkhunter_event(), history=[]))
    assert "Checking for prerequisites" in matches[0].short
    assert "rkhunter.dat is missing" in matches[0].detail


def test_rkhunter_rule_fires_on_a_file_scoped_warning_too() -> None:
    # `The command '/usr/bin/egrep' has been replaced by a script` — the shape
    # that carries a path, so category is "file" rather than "process".
    event = _rkhunter_event(
        indicator_value="The command '/usr/bin/egrep' has been replaced by a script",
        path="/usr/bin/egrep",
        category="file",
    )
    assert _fires(_rkhunter_rule(), event)


def test_rkhunter_rule_does_not_fire_on_an_aide_finding() -> None:
    assert not _fires(_rkhunter_rule(), _aide_event())


def test_rkhunter_rule_does_not_fire_on_a_yara_finding() -> None:
    assert not _fires(_rkhunter_rule(), _yara_event(scanner_severity="critical"))


def test_rkhunter_rule_does_not_fire_on_another_module() -> None:
    assert not _fires(_rkhunter_rule(), _rkhunter_event(module="fim_watcher"))


@pytest.mark.parametrize("action", ["scan_started", "scan_completed", "scan_skipped"])
def test_rkhunter_rule_does_not_fire_on_a_lifecycle_action(action: str) -> None:
    assert not _fires(_rkhunter_rule(), _rkhunter_event(action=action))


# --------------------------------------------------------------------------
# av.yara_high_confidence_hit
# --------------------------------------------------------------------------


@pytest.mark.parametrize("declared", ["high", "critical"])
def test_yara_rule_fires_for_a_high_confidence_hit(declared: str) -> None:
    matches = evaluate_yaml_rule(
        _yara_rule(),
        EvalContext(event=_yara_event(scanner_severity=declared), history=[]),
    )
    assert matches
    assert matches[0].rule_id == "av.yara_high_confidence_hit"
    assert matches[0].severity == "high"
    assert matches[0].false_positives


@pytest.mark.parametrize("declared", ["High", "CRITICAL", "Critical"])
def test_yara_rule_is_case_insensitive_about_the_meta_value(declared: str) -> None:
    # No rulesets ship yet and imported third-party rules capitalise freely; a
    # case-sensitive comparison would silently never fire on half of them.
    assert _fires(_yara_rule(), _yara_event(scanner_severity=declared))


@pytest.mark.parametrize("declared", ["low", "medium", "informational", "none"])
def test_yara_rule_does_not_fire_for_a_low_confidence_hit(declared: str) -> None:
    assert not _fires(_yara_rule(), _yara_event(scanner_severity=declared))


def test_yara_rule_does_not_fire_when_the_rule_declares_no_severity_meta() -> None:
    """The documented behaviour, pinned so it cannot change silently.

    A YARA rule with no `severity` meta produces a finding with no
    `threat.indicator.severity` key at all, and this rule stays silent: "high
    confidence" cannot be asserted about a rule that asserts nothing. The hit is
    still recorded as a `scan_finding` event — only the alert is withheld.
    """
    event = _yara_event(scanner_severity=None)
    assert "severity" not in (event.threat or {})["indicator"]
    assert not _fires(_yara_rule(), event)


def test_yara_rule_does_not_fire_for_a_numeric_severity_meta() -> None:
    # yara prints integer meta as `severity =3`; the adapter preserves "3".
    # Documented as unrecognised, not a bug — this rule knows string labels only.
    assert not _fires(_yara_rule(), _yara_event(scanner_severity="3"))


def test_yara_rule_does_not_fire_for_a_substring_of_a_label() -> None:
    # The comparison is anchored: "highly-unlikely" must not read as "high".
    assert not _fires(_yara_rule(), _yara_event(scanner_severity="highly-unlikely"))


def test_yara_rule_does_not_fire_on_an_rkhunter_finding_claiming_high() -> None:
    # Source is set by the runner from which adapter ran; it is the structural
    # discriminator and no scanner output can forge it.
    assert not _fires(_yara_rule(), _rkhunter_event(scanner_severity="high"))


def test_yara_rule_does_not_fire_on_an_aide_finding_claiming_high() -> None:
    assert not _fires(_yara_rule(), _aide_event(scanner_severity="high"))


def test_yara_rule_does_not_fire_on_another_module() -> None:
    assert not _fires(_yara_rule(), _yara_event(scanner_severity="high", module="fim_watcher"))


@pytest.mark.parametrize("action", ["scan_started", "scan_completed", "scan_skipped"])
def test_yara_rule_does_not_fire_on_a_lifecycle_action(action: str) -> None:
    assert not _fires(_yara_rule(), _yara_event(scanner_severity="high", action=action))
