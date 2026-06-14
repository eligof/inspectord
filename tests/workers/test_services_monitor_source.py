"""Tests for the services_monitor service state diff source.

All tests inject ``runner`` or ``capture`` callables so they never invoke
real subprocesses or require any special privileges.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

import pytest

from inspectord.workers.services_monitor.source import (
    ServicesSource,
    _capture_units,
    diff_units,
    parse_units,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_SAMPLE_JSON = (
    '[{"unit":"sshd.service","load":"loaded","active":"active","sub":"running",'
    '"description":"OpenSSH Daemon"},'
    '{"unit":"cronie.service","load":"loaded","active":"inactive","sub":"dead",'
    '"description":"Periodic Command Scheduler"}]'
)

_SSHD_INFO: dict[str, Any] = {"active": "active", "sub": "running", "load": "loaded"}
_CRONIE_INFO: dict[str, Any] = {"active": "inactive", "sub": "dead", "load": "loaded"}


def _ok(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout)


def _fail(stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout=stdout)


def _make_runner(
    outcome: subprocess.CompletedProcess[str] | BaseException,
) -> Callable[..., subprocess.CompletedProcess[str]]:
    """Return a fake runner that always produces *outcome* (or raises it).

    Pass a ``CompletedProcess`` to simulate a successful/failed subprocess, or
    an exception *instance* to simulate a raise.
    """

    def runner(
        _cmd: list[str],
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return runner


def _make_capture(*snapshots: str) -> Callable[[], str]:
    """Return a callable that yields each text snapshot in turn, then repeats
    the last one indefinitely."""
    seq = list(snapshots)
    idx = 0

    def capture() -> str:
        nonlocal idx
        val = seq[idx]
        idx = min(idx + 1, len(seq) - 1)
        return val

    return capture


# ---------------------------------------------------------------------------
# _capture_units
# ---------------------------------------------------------------------------


def test_capture_units_success_returns_stdout() -> None:
    runner = _make_runner(_ok(_SAMPLE_JSON))
    assert _capture_units(runner=runner) == _SAMPLE_JSON


def test_capture_units_nonzero_returncode_returns_empty() -> None:
    runner = _make_runner(_fail("error: something"))
    assert _capture_units(runner=runner) == ""


def test_capture_units_file_not_found_returns_empty() -> None:
    runner = _make_runner(FileNotFoundError("systemctl not found"))
    assert _capture_units(runner=runner) == ""


def test_capture_units_timeout_returns_empty() -> None:
    runner = _make_runner(subprocess.TimeoutExpired(cmd=["systemctl"], timeout=10))
    assert _capture_units(runner=runner) == ""


def test_capture_units_subprocess_error_returns_empty() -> None:
    runner = _make_runner(subprocess.SubprocessError("generic error"))
    assert _capture_units(runner=runner) == ""


# ---------------------------------------------------------------------------
# parse_units
# ---------------------------------------------------------------------------


def test_parse_units_realistic_json() -> None:
    result = parse_units(_SAMPLE_JSON)
    assert result == {
        "sshd.service": _SSHD_INFO,
        "cronie.service": _CRONIE_INFO,
    }


def test_parse_units_blank_text_returns_empty() -> None:
    assert parse_units("") == {}
    assert parse_units("   ") == {}


def test_parse_units_invalid_json_returns_empty() -> None:
    assert parse_units("not json at all") == {}
    assert parse_units("{bad}") == {}


def test_parse_units_element_missing_unit_key_skipped() -> None:
    text = '[{"load":"loaded","active":"active","sub":"running"}]'
    assert parse_units(text) == {}


def test_parse_units_missing_active_defaults_to_empty_string() -> None:
    text = '[{"unit":"foo.service","load":"loaded","sub":"running"}]'
    result = parse_units(text)
    assert result["foo.service"]["active"] == ""


def test_parse_units_missing_sub_defaults_to_empty_string() -> None:
    text = '[{"unit":"foo.service","load":"loaded","active":"active"}]'
    result = parse_units(text)
    assert result["foo.service"]["sub"] == ""


def test_parse_units_missing_load_defaults_to_empty_string() -> None:
    text = '[{"unit":"foo.service","active":"active","sub":"running"}]'
    result = parse_units(text)
    assert result["foo.service"]["load"] == ""


def test_parse_units_non_dict_element_skipped() -> None:
    text = (
        '["just-a-string",'
        ' {"unit":"foo.service","active":"active","sub":"running","load":"loaded"}]'
    )
    result = parse_units(text)
    assert list(result.keys()) == ["foo.service"]


# ---------------------------------------------------------------------------
# diff_units
# ---------------------------------------------------------------------------

_PREV: dict[str, dict[str, Any]] = {
    "sshd.service": {"active": "active", "sub": "running", "load": "loaded"},
    "cronie.service": {"active": "inactive", "sub": "dead", "load": "loaded"},
}


def test_diff_units_service_added() -> None:
    curr = {
        **_PREV,
        "newapp.service": {"active": "active", "sub": "running", "load": "loaded"},
    }
    records = diff_units(_PREV, curr)
    added = [r for r in records if r["action"] == "service_added"]
    assert len(added) == 1
    assert added[0]["unit"] == "newapp.service"
    assert added[0]["active"] == "active"
    assert added[0]["sub"] == "running"
    assert added[0]["load"] == "loaded"


def test_diff_units_service_removed() -> None:
    curr = {"sshd.service": _PREV["sshd.service"]}
    records = diff_units(_PREV, curr)
    removed = [r for r in records if r["action"] == "service_removed"]
    assert len(removed) == 1
    assert removed[0]["unit"] == "cronie.service"
    assert removed[0]["previous_active"] == "inactive"
    assert removed[0]["previous_sub"] == "dead"
    assert removed[0]["previous_load"] == "loaded"


def test_diff_units_service_state_changed_active() -> None:
    curr = {
        "sshd.service": {"active": "inactive", "sub": "dead", "load": "loaded"},
        "cronie.service": _PREV["cronie.service"],
    }
    records = diff_units(_PREV, curr)
    changed = [r for r in records if r["action"] == "service_state_changed"]
    assert len(changed) == 1
    rec = changed[0]
    assert rec["unit"] == "sshd.service"
    assert rec["active"] == "inactive"
    assert rec["sub"] == "dead"
    assert rec["load"] == "loaded"
    assert rec["previous_active"] == "active"
    assert rec["previous_sub"] == "running"
    assert rec["previous_load"] == "loaded"


def test_diff_units_service_state_changed_sub_only() -> None:
    """A change in the sub-state alone (active unchanged) is detected."""
    curr = {
        "sshd.service": {"active": "active", "sub": "exited", "load": "loaded"},
        "cronie.service": _PREV["cronie.service"],
    }
    records = diff_units(_PREV, curr)
    changed = [r for r in records if r["action"] == "service_state_changed"]
    assert len(changed) == 1
    rec = changed[0]
    assert rec["unit"] == "sshd.service"
    assert rec["sub"] == "exited"
    assert rec["previous_sub"] == "running"
    assert rec["load"] == "loaded"
    assert rec["previous_load"] == "loaded"


def test_diff_units_service_state_changed_load_only() -> None:
    """A change in load alone (active and sub unchanged) is detected.

    A ``"loaded"`` → ``"masked"`` transition is a persistence/evasion indicator
    and must not be silently dropped.
    """
    curr = {
        "sshd.service": {"active": "active", "sub": "running", "load": "masked"},
        "cronie.service": _PREV["cronie.service"],
    }
    records = diff_units(_PREV, curr)
    changed = [r for r in records if r["action"] == "service_state_changed"]
    assert len(changed) == 1
    rec = changed[0]
    assert rec["unit"] == "sshd.service"
    assert rec["load"] == "masked"
    assert rec["previous_load"] == "loaded"
    # active and sub are unchanged
    assert rec["active"] == "active"
    assert rec["sub"] == "running"
    assert rec["previous_active"] == "active"
    assert rec["previous_sub"] == "running"


def test_diff_units_identical_returns_empty() -> None:
    assert diff_units(_PREV, _PREV) == []


def test_diff_units_result_is_sorted() -> None:
    """Results must be sorted deterministically by (action, unit)."""
    curr = {
        "zzz.service": {"active": "active", "sub": "running", "load": "loaded"},
        "aaa.service": {"active": "active", "sub": "running", "load": "loaded"},
    }
    prev = {
        "mmm.service": {"active": "active", "sub": "running", "load": "loaded"},
    }
    records = diff_units(prev, curr)
    sort_keys = [(r["action"], r["unit"]) for r in records]
    assert sort_keys == sorted(sort_keys)


# ---------------------------------------------------------------------------
# ServicesSource
# ---------------------------------------------------------------------------


def test_source_baseline_not_emitted_on_first_poll() -> None:
    """Services present at construction must NOT appear on the first poll."""
    capture = _make_capture(_SAMPLE_JSON, _SAMPLE_JSON)
    src = ServicesSource(capture=capture)
    result = src.poll(timeout_ms=0)
    assert result == []


def test_source_service_added() -> None:
    added_json = (
        '[{"unit":"sshd.service","load":"loaded","active":"active","sub":"running",'
        '"description":"OpenSSH Daemon"},'
        '{"unit":"cronie.service","load":"loaded","active":"inactive","sub":"dead",'
        '"description":"Periodic Command Scheduler"},'
        '{"unit":"newapp.service","load":"loaded","active":"active","sub":"running",'
        '"description":"New App"}]'
    )
    capture = _make_capture(_SAMPLE_JSON, added_json)
    src = ServicesSource(capture=capture)
    result = src.poll(timeout_ms=0)
    assert len(result) == 1
    assert result[0]["action"] == "service_added"
    assert result[0]["unit"] == "newapp.service"


def test_source_service_removed() -> None:
    removed_json = (
        '[{"unit":"sshd.service","load":"loaded","active":"active","sub":"running",'
        '"description":"OpenSSH Daemon"}]'
    )
    capture = _make_capture(_SAMPLE_JSON, removed_json)
    src = ServicesSource(capture=capture)
    result = src.poll(timeout_ms=0)
    assert len(result) == 1
    assert result[0]["action"] == "service_removed"
    assert result[0]["unit"] == "cronie.service"
    assert result[0]["previous_active"] == "inactive"
    assert result[0]["previous_sub"] == "dead"
    assert result[0]["previous_load"] == "loaded"


def test_source_service_state_changed() -> None:
    changed_json = (
        '[{"unit":"sshd.service","load":"loaded","active":"inactive","sub":"dead",'
        '"description":"OpenSSH Daemon"},'
        '{"unit":"cronie.service","load":"loaded","active":"inactive","sub":"dead",'
        '"description":"Periodic Command Scheduler"}]'
    )
    capture = _make_capture(_SAMPLE_JSON, changed_json)
    src = ServicesSource(capture=capture)
    result = src.poll(timeout_ms=0)
    assert len(result) == 1
    rec = result[0]
    assert rec["action"] == "service_state_changed"
    assert rec["unit"] == "sshd.service"
    assert rec["active"] == "inactive"
    assert rec["sub"] == "dead"
    assert rec["load"] == "loaded"
    assert rec["previous_active"] == "active"
    assert rec["previous_sub"] == "running"
    assert rec["previous_load"] == "loaded"


def test_source_transient_failure_preserves_baseline() -> None:
    """capture() returning '' must return [] and NOT update the baseline.

    A subsequent successful poll must diff against the ORIGINAL baseline, not
    the empty set — so no spurious ``service_removed`` flood, and a real change
    after the failure is still detected.
    """
    changed_json = (
        '[{"unit":"sshd.service","load":"loaded","active":"inactive","sub":"dead",'
        '"description":"OpenSSH Daemon"},'
        '{"unit":"cronie.service","load":"loaded","active":"inactive","sub":"dead",'
        '"description":"Periodic Command Scheduler"}]'
    )
    # seq: baseline, transient failure, real change
    capture = _make_capture(_SAMPLE_JSON, "", changed_json)
    src = ServicesSource(capture=capture)

    # Poll 1: transient failure
    result1 = src.poll(timeout_ms=0)
    assert result1 == []

    # Poll 2: real change detected against original baseline (not the empty set)
    result2 = src.poll(timeout_ms=0)
    service_removed = [r for r in result2 if r["action"] == "service_removed"]
    # Only sshd changed state; cronie still inactive/dead — no removes at all
    assert service_removed == []
    state_changed = [r for r in result2 if r["action"] == "service_state_changed"]
    assert len(state_changed) == 1
    assert state_changed[0]["unit"] == "sshd.service"


def test_source_empty_list_preserves_baseline() -> None:
    """A poll whose capture() returns '[]' (valid empty array) must return []
    AND must NOT wipe the baseline.

    A subsequent normal poll must diff against the original snapshot — i.e. no
    spurious ``service_removed`` flood, and real changes are still detected.
    """
    changed_json = (
        '[{"unit":"sshd.service","load":"loaded","active":"inactive","sub":"dead",'
        '"description":"OpenSSH Daemon"},'
        '{"unit":"cronie.service","load":"loaded","active":"inactive","sub":"dead",'
        '"description":"Periodic Command Scheduler"}]'
    )
    # seq: baseline, empty-list guard trigger, real change
    capture = _make_capture(_SAMPLE_JSON, "[]", changed_json)
    src = ServicesSource(capture=capture)

    # Poll 1: empty-list parse — guard fires, baseline preserved
    result1 = src.poll(timeout_ms=0)
    assert result1 == []

    # Poll 2: real change detected against ORIGINAL baseline, not the empty set
    result2 = src.poll(timeout_ms=0)
    service_removed = [r for r in result2 if r["action"] == "service_removed"]
    assert service_removed == []  # no spurious removes
    state_changed = [r for r in result2 if r["action"] == "service_state_changed"]
    assert len(state_changed) == 1
    assert state_changed[0]["unit"] == "sshd.service"


def test_source_first_capture_failed_then_readable_adopts_silently() -> None:
    """If the initial capture failed (empty baseline), the first successful poll
    must adopt the snapshot silently — no ``service_added`` flood.

    A third poll with a mutated snapshot proves the adopted baseline is actually
    stored and used for diffing (i.e. self._units was set correctly).
    """
    # sshd changes active→inactive/dead; cronie added; baseline is _SAMPLE_JSON
    mutated_json = (
        '[{"unit":"sshd.service","load":"loaded","active":"inactive","sub":"dead",'
        '"description":"OpenSSH Daemon"},'
        '{"unit":"cronie.service","load":"loaded","active":"inactive","sub":"dead",'
        '"description":"Periodic Command Scheduler"},'
        '{"unit":"newapp.service","load":"loaded","active":"active","sub":"running",'
        '"description":"New App"}]'
    )
    capture = _make_capture("", _SAMPLE_JSON, _SAMPLE_JSON, mutated_json)
    src = ServicesSource(capture=capture)

    # Poll 1: baseline was empty; adopt silently
    result1 = src.poll(timeout_ms=0)
    assert result1 == []

    # Poll 2: same snapshot as adopted — no changes
    result2 = src.poll(timeout_ms=0)
    assert result2 == []

    # Poll 3: mutated snapshot — diffs against the adopted baseline (_SAMPLE_JSON)
    result3 = src.poll(timeout_ms=0)
    actions = {r["action"] for r in result3}
    # sshd changed state AND newapp was added; NO spurious service_removed
    assert "service_state_changed" in actions
    assert "service_added" in actions
    assert "service_removed" not in actions
    state_changed = [r for r in result3 if r["action"] == "service_state_changed"]
    assert len(state_changed) == 1
    assert state_changed[0]["unit"] == "sshd.service"
    added = [r for r in result3 if r["action"] == "service_added"]
    assert len(added) == 1
    assert added[0]["unit"] == "newapp.service"


def test_source_close_is_idempotent() -> None:
    capture = _make_capture(_SAMPLE_JSON)
    src = ServicesSource(capture=capture)
    src.close()
    src.close()  # must not raise


def test_source_poll_raises_after_close() -> None:
    capture = _make_capture(_SAMPLE_JSON, _SAMPLE_JSON)
    src = ServicesSource(capture=capture)
    src.close()
    with pytest.raises(RuntimeError, match="closed"):
        src.poll(timeout_ms=0)
