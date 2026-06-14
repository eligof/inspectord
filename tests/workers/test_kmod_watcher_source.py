"""Tests for the kmod_watcher /proc/modules diff source.

All tests inject a ``reader`` callable so they never touch the real filesystem.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from inspectord.workers.kmod_watcher.source import (
    ProcModulesSource,
    diff_modules,
    parse_proc_modules,
)

# ---------------------------------------------------------------------------
# parse_proc_modules
# ---------------------------------------------------------------------------

_SAMPLE = """\
nf_tables 360448 1 - Live 0x0000000000000000
videodev 372736 4 uvcvideo,videobuf2_v4l2 Live 0x0000000000000000
overlay 188416 0 - Live 0x0000000000000000
"""


def test_parse_proc_modules_basic() -> None:
    result = parse_proc_modules(_SAMPLE)
    assert set(result.keys()) == {"nf_tables", "videodev", "overlay"}
    assert result["nf_tables"] == {"size": 360448, "refcount": 1}
    assert result["videodev"] == {"size": 372736, "refcount": 4}
    assert result["overlay"] == {"size": 188416, "refcount": 0}


def test_parse_proc_modules_blank_and_malformed_lines() -> None:
    text = "\n\nnf_tables 360448 1 - Live 0x0\n\nbad_line\npartial 1234\n"
    result = parse_proc_modules(text)
    # Only the valid line should appear
    assert set(result.keys()) == {"nf_tables"}
    assert result["nf_tables"]["size"] == 360448


def test_parse_proc_modules_non_integer_fields_skipped() -> None:
    text = "bad_mod NOTANINT 1 - Live 0x0\n"
    result = parse_proc_modules(text)
    assert result == {}


# ---------------------------------------------------------------------------
# diff_modules
# ---------------------------------------------------------------------------


def test_diff_modules_loaded() -> None:
    prev: dict[str, dict[str, Any]] = {}
    curr = {"ext4": {"size": 900000, "refcount": 2}}
    result = diff_modules(prev, curr)
    assert result == [{"action": "loaded", "name": "ext4", "size": 900000, "refcount": 2}]


def test_diff_modules_unloaded() -> None:
    prev = {"ext4": {"size": 900000, "refcount": 0}}
    curr: dict[str, dict[str, Any]] = {}
    result = diff_modules(prev, curr)
    assert result == [{"action": "unloaded", "name": "ext4"}]


def test_diff_modules_identical_returns_empty() -> None:
    snap = {"nf_tables": {"size": 360448, "refcount": 1}}
    assert diff_modules(snap, snap) == []


def test_diff_modules_action_name_sort_order() -> None:
    prev = {"b_mod": {"size": 1, "refcount": 0}}
    curr = {"a_mod": {"size": 2, "refcount": 1}}
    result = diff_modules(prev, curr)
    # "loaded" a_mod comes before "unloaded" b_mod (sorted by (action, name))
    assert result[0]["action"] == "loaded"
    assert result[0]["name"] == "a_mod"
    assert result[1]["action"] == "unloaded"
    assert result[1]["name"] == "b_mod"


# ---------------------------------------------------------------------------
# ProcModulesSource
# ---------------------------------------------------------------------------


def _make_reader(*snapshots: str) -> Callable[[], str]:
    """Return a callable that yields each snapshot in turn."""
    seq = list(snapshots)
    idx = 0

    def reader() -> str:
        nonlocal idx
        val = seq[idx]
        idx = min(idx + 1, len(seq) - 1)
        return val

    return reader


_SNAP_A = "nf_tables 360448 1 - Live 0x0\n"
_SNAP_B = "nf_tables 360448 1 - Live 0x0\noverlay 188416 0 - Live 0x0\n"
_SNAP_C = "overlay 188416 0 - Live 0x0\n"  # nf_tables gone


def test_source_baseline_not_emitted() -> None:
    """Modules present at construction must NOT appear in the first poll."""
    reader = _make_reader(_SNAP_A, _SNAP_A)
    src = ProcModulesSource(reader=reader)
    result = src.poll(timeout_ms=0)
    assert result == []


def test_source_new_module_emitted_as_loaded() -> None:
    """A module that appears after baseline is emitted as 'loaded'."""
    reader = _make_reader(_SNAP_A, _SNAP_B)
    src = ProcModulesSource(reader=reader)
    result = src.poll(timeout_ms=0)
    assert len(result) == 1
    assert result[0]["action"] == "loaded"
    assert result[0]["name"] == "overlay"
    assert result[0]["size"] == 188416
    assert result[0]["refcount"] == 0


def test_source_removed_module_emitted_as_unloaded() -> None:
    """A module that disappears after baseline is emitted as 'unloaded'."""
    reader = _make_reader(_SNAP_B, _SNAP_C)
    src = ProcModulesSource(reader=reader)
    result = src.poll(timeout_ms=0)
    assert len(result) == 1
    assert result[0]["action"] == "unloaded"
    assert result[0]["name"] == "nf_tables"


def test_source_close_sets_flag_and_is_idempotent() -> None:
    reader = _make_reader(_SNAP_A)
    src = ProcModulesSource(reader=reader)
    assert src._closed is False
    src.close()
    assert src._closed is True
    src.close()  # must not raise
    assert src._closed is True


def test_source_poll_raises_after_close() -> None:
    """poll() must raise RuntimeError after close() has been called."""
    reader = _make_reader(_SNAP_A, _SNAP_A)
    src = ProcModulesSource(reader=reader)
    src.close()
    try:
        src.poll(timeout_ms=0)
        raise AssertionError("expected RuntimeError")
    except RuntimeError as exc:
        assert "closed" in str(exc)


def test_source_two_consecutive_polls() -> None:
    """Each poll advances the internal snapshot so diffs are relative to the previous call."""
    # baseline=A, poll1 reads B (overlay loaded), poll2 reads C (nf_tables unloaded)
    reader = _make_reader(_SNAP_A, _SNAP_B, _SNAP_C)
    src = ProcModulesSource(reader=reader)

    result1 = src.poll(timeout_ms=0)
    assert len(result1) == 1
    assert result1[0]["action"] == "loaded"
    assert result1[0]["name"] == "overlay"

    result2 = src.poll(timeout_ms=0)
    assert len(result2) == 1
    assert result2[0]["action"] == "unloaded"
    assert result2[0]["name"] == "nf_tables"
