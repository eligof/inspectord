"""Tests for the symlink/TOCTOU-safe capture reader (spec §3.3, §11)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from inspectord.evidence import capture
from inspectord.evidence.capture import read_capture


def test_reads_regular_file(tmp_path: Path) -> None:
    p = tmp_path / "f"
    p.write_bytes(b"data")
    assert read_capture(str(p)) == b"data"


def test_truncates_at_max_bytes(tmp_path: Path) -> None:
    p = tmp_path / "big"
    p.write_bytes(b"abcdefghij")
    assert read_capture(str(p), max_bytes=4) == b"abcd"


def test_truncates_at_patched_constant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "big"
    p.write_bytes(b"abcdefghij")
    monkeypatch.setattr(capture, "_MAX_FILE_BYTES", 3)
    # default arg is bound at def time, so call without override exercises the cap path too
    assert read_capture(str(p), max_bytes=capture._MAX_FILE_BYTES) == b"abc"


def test_fifo_does_not_hang(tmp_path: Path) -> None:
    p = tmp_path / "fifo"
    os.mkfifo(p)
    assert read_capture(str(p)) is None  # must return, not block


def test_symlink_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_bytes(b"x")
    link = tmp_path / "link"
    os.symlink(real, link)
    assert read_capture(str(link)) is None


def test_rejects_relative_dotdot_and_denylist(tmp_path: Path) -> None:
    assert read_capture("relative/path") is None
    assert read_capture(str(tmp_path / ".." / "x")) is None
    assert read_capture("/proc/self/cmdline") is None
    assert read_capture(str(tmp_path / "nope")) is None
