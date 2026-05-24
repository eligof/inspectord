"""Tests for TailingFileSource."""

from __future__ import annotations

import os
import time
from pathlib import Path

from inspectord.sources.file_tail import TailingFileSource


def test_reads_lines_appended_after_open(tmp_path: Path) -> None:
    f = tmp_path / "log"
    f.write_text("line1\n")
    src = TailingFileSource(f, from_start=True)
    src.open()
    try:
        lines: list[str] = []
        for _ in range(10):
            ln = src.read_one(timeout=0.05)
            if ln is None:
                break
            lines.append(ln)
        assert lines == ["line1"]

        with f.open("a") as fh:
            fh.write("line2\nline3\n")
            fh.flush()
        time.sleep(0.05)

        more: list[str] = []
        for _ in range(10):
            ln = src.read_one(timeout=0.05)
            if ln is None:
                break
            more.append(ln)
        assert more == ["line2", "line3"]
    finally:
        src.close()


def test_skips_existing_lines_when_from_start_false(tmp_path: Path) -> None:
    f = tmp_path / "log"
    f.write_text("old\n")
    src = TailingFileSource(f, from_start=False)
    src.open()
    try:
        assert src.read_one(timeout=0.05) is None
        with f.open("a") as fh:
            fh.write("new\n")
            fh.flush()
        time.sleep(0.05)
        assert src.read_one(timeout=0.2) == "new"
    finally:
        src.close()


def test_handles_rotation_by_inode_change(tmp_path: Path) -> None:
    f = tmp_path / "log"
    f.write_text("first\n")
    src = TailingFileSource(f, from_start=True)
    src.open()
    try:
        assert src.read_one(timeout=0.05) == "first"

        rotated = tmp_path / "log.1"
        os.rename(f, rotated)
        f.write_text("after_rotate\n")
        time.sleep(0.05)

        got: list[str] = []
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline and len(got) < 1:
            ln = src.read_one(timeout=0.1)
            if ln is not None:
                got.append(ln)
        assert got == ["after_rotate"]
    finally:
        src.close()


def test_missing_file_returns_none_then_picks_up_when_created(tmp_path: Path) -> None:
    f = tmp_path / "later"
    src = TailingFileSource(f, from_start=True)
    src.open()
    try:
        assert src.read_one(timeout=0.05) is None
        f.write_text("appeared\n")
        time.sleep(0.05)
        deadline = time.monotonic() + 0.5
        got = None
        while time.monotonic() < deadline and got is None:
            got = src.read_one(timeout=0.1)
        assert got == "appeared"
    finally:
        src.close()
