"""Tests for `av.aide_change_outside_pkgmgr`.

The rule is Python, not YAML, because it needs a time window and the YAML
grammar has none. Everything structural is asserted the same way the two YAML
`av.*` rules assert it — module, action, `threat.indicator.source` — and the
window is tested on **both** sides of its boundary, since an off-by-one there
is the difference between suppressing every post-upgrade alert and suppressing
none.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from inspectord import rule_engine
from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.starter_pack.av_aide_change_outside_pkgmgr import (
    PKGMGR_ACTIONS,
    PKGMGR_WINDOW_S,
    RULE,
)
from inspectord.schemas.event import Event

NOW = datetime(2026, 8, 19, 3, 0, 0, tzinfo=UTC)


def _scan_finding(
    *,
    when: datetime = NOW,
    scanner: str = "aide",
    indicator_type: str = "aide_change",
    indicator_value: str = "changed",
    path: str | None = "/usr/bin/sudo",
    module: str = "scanner_runner",
    action: str = "scan_finding",
) -> Event:
    """A `scan_finding` shaped exactly like `runner._emit_finding` builds it."""
    indicator: dict[str, Any] = {
        "type": indicator_type,
        "value": indicator_value,
        "source": scanner,
    }
    event = build_event(
        module=module,
        action=action,
        category=["file"],
        type_=["info"],
        severity="low",
        host={"name": "testhost"},
        message=f"AIDE: {indicator_value} {path}",
        labels=["scanner", f"scanner:{scanner}"],
        file={"path": path} if path is not None else None,
        threat={"indicator": indicator},
        raw={"scanner": scanner, "run_id": "0198f000-0000-7000-8000-000000000000", "line": "x"},
    )
    return event.model_copy(update={"ts": when})


def _pkg_event(*, when: datetime, action: str = "package_upgraded") -> Event:
    """A `log_tailer` package event, as `parsers/pacman.py` emits one.

    Its `ts` is pacman's own timestamp from the log line, not the moment the
    tailer read it — which is the clock this rule wants.
    """
    event = build_event(
        module="log_tailer",
        action=action,
        category=["package"],
        type_=["change"],
        severity="info",
        message="upgraded openssl 3.5.0-1 -> 3.5.1-1",
        package={
            "name": "openssl",
            "version": "3.5.1-1",
            "previous_version": "3.5.0-1",
            "action": action.removeprefix("package_"),
        },
        raw={"source_file": "/var/log/pacman.log", "line": "x", "fields": {}},
    )
    return event.model_copy(update={"ts": when})


def _evaluate(event: Event, history: list[Event]) -> list[Any]:
    return RULE.evaluate(EvalContext(event=event, history=[*history, event]))


# --------------------------------------------------------------------------
# firing
# --------------------------------------------------------------------------


def test_fires_with_an_empty_history() -> None:
    """Nothing to correlate against is the common case: AIDE runs nightly and
    the engine's history is usually empty of package events."""
    event = _scan_finding()
    matches = RULE.evaluate(EvalContext(event=event, history=[]))
    assert len(matches) == 1
    assert matches[0].rule_id == "av.aide_change_outside_pkgmgr"
    assert matches[0].severity == "medium"
    assert matches[0].why
    assert matches[0].false_positives


def test_fires_when_the_nearest_transaction_is_outside_the_window() -> None:
    history = [_pkg_event(when=NOW - timedelta(seconds=PKGMGR_WINDOW_S + 1))]
    assert _evaluate(_scan_finding(), history)


def test_the_match_points_at_the_reported_file() -> None:
    matches = _evaluate(_scan_finding(path="/etc/sudoers"), [])
    assert matches[0].primary_entity_kind == "file"
    assert matches[0].primary_entity_key == "/etc/sudoers"
    assert matches[0].dedup_key == "av.aide_change_outside_pkgmgr:file:/etc/sudoers"
    assert "/etc/sudoers" in matches[0].short


def test_a_pathless_finding_still_alerts_keyed_on_the_event() -> None:
    matches = _evaluate(_scan_finding(path=None), [])
    assert len(matches) == 1
    assert matches[0].primary_entity_kind == "event"


@pytest.mark.parametrize("change", ["added", "removed", "changed"])
def test_fires_for_every_aide_change_kind(change: str) -> None:
    assert _evaluate(_scan_finding(indicator_value=change), [])


# --------------------------------------------------------------------------
# suppression
# --------------------------------------------------------------------------


@pytest.mark.parametrize("pkg_action", sorted(PKGMGR_ACTIONS))
def test_does_not_fire_when_a_transaction_sits_inside_the_window(pkg_action: str) -> None:
    history = [_pkg_event(when=NOW - timedelta(seconds=30), action=pkg_action)]
    assert _evaluate(_scan_finding(), history) == []


@pytest.mark.parametrize("pkg_action", sorted(PKGMGR_ACTIONS))
def test_window_boundary_inclusive_side(pkg_action: str) -> None:
    """Exactly `PKGMGR_WINDOW_S` old still counts — `recent_events` uses `>=`."""
    history = [_pkg_event(when=NOW - timedelta(seconds=PKGMGR_WINDOW_S), action=pkg_action)]
    assert _evaluate(_scan_finding(), history) == []


@pytest.mark.parametrize("pkg_action", sorted(PKGMGR_ACTIONS))
def test_window_boundary_exclusive_side(pkg_action: str) -> None:
    """One second past the window, the transaction no longer explains anything."""
    history = [_pkg_event(when=NOW - timedelta(seconds=PKGMGR_WINDOW_S + 1), action=pkg_action)]
    assert len(_evaluate(_scan_finding(), history)) == 1


def test_a_transaction_timestamped_just_after_the_finding_also_suppresses() -> None:
    """`recent_events` sets a lower bound only, and that is right here.

    A finding's `ts` is set when the runner emits it, at the *end* of a scan
    that took minutes. A pacman line timestamped a few seconds later is still
    concurrent with the scan that produced the finding, so it explains it just
    as well as one from a few seconds earlier.
    """
    history = [_pkg_event(when=NOW + timedelta(seconds=30))]
    assert _evaluate(_scan_finding(), history) == []


def test_an_unrelated_event_inside_the_window_does_not_suppress() -> None:
    unrelated = build_event(
        module="log_tailer",
        action="ssh_login_failed",
        category=["authentication"],
        type_=["end"],
        severity="medium",
        source={"ip": "1.2.3.4"},
    ).model_copy(update={"ts": NOW - timedelta(seconds=10)})
    assert len(_evaluate(_scan_finding(), [unrelated])) == 1


# --------------------------------------------------------------------------
# structural non-firing
# --------------------------------------------------------------------------


@pytest.mark.parametrize("scanner", ["rkhunter", "yara"])
def test_does_not_fire_for_another_scanner(scanner: str) -> None:
    event = _scan_finding(scanner=scanner, indicator_type="yara_rule", indicator_value="Evil_Rule")
    assert _evaluate(event, []) == []


def test_does_not_fire_on_another_module() -> None:
    assert _evaluate(_scan_finding(module="fim_watcher"), []) == []


@pytest.mark.parametrize("action", ["scan_started", "scan_completed", "scan_skipped"])
def test_does_not_fire_on_a_lifecycle_action(action: str) -> None:
    assert _evaluate(_scan_finding(action=action), []) == []


def test_does_not_fire_when_the_event_carries_no_threat_block() -> None:
    event = build_event(
        module="scanner_runner",
        action="scan_finding",
        category=["file"],
        type_=["info"],
        severity="low",
    )
    assert _evaluate(event, []) == []


# --------------------------------------------------------------------------
# the window cannot outgrow what the engine can answer
# --------------------------------------------------------------------------


def test_window_fits_inside_the_engines_correlation_history() -> None:
    """The rule may not promise a correlation the engine cannot perform.

    `RuleEngine` trims its history to `_HISTORY_WINDOW` on every event, so a
    window wider than that would silently behave as `_HISTORY_WINDOW` while
    reading like a longer guarantee.
    """
    assert rule_engine._HISTORY_WINDOW.total_seconds() >= PKGMGR_WINDOW_S


def test_reinstall_is_a_suppressing_transaction() -> None:
    # `parsers/pacman.py` emits `package_reinstalled` and a reinstall rewrites
    # files exactly like an upgrade; leaving it out would alert on every
    # `pacman -S <already-installed>`.
    assert "package_reinstalled" in PKGMGR_ACTIONS
