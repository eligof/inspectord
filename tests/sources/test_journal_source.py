"""Tests for JournalSource."""

from __future__ import annotations

import io
import json
import threading
import time

from inspectord.sources.journal_source import JournalSource


class _FakeProc:
    def __init__(self, lines: list[bytes]) -> None:
        self.stdout = io.BytesIO(b"".join(lines))
        self.stderr = io.BytesIO(b"")
        self.returncode: int | None = None
        self._terminated = threading.Event()

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 0
        self._terminated.set()

    def kill(self) -> None:
        self.returncode = -9
        self._terminated.set()

    def wait(self, timeout: float | None = None) -> int:
        self._terminated.wait(timeout)
        return self.returncode if self.returncode is not None else 0


def test_journal_source_yields_parsed_entries() -> None:
    entries = [
        {"__REALTIME_TIMESTAMP": "1", "MESSAGE": "first"},
        {"__REALTIME_TIMESTAMP": "2", "MESSAGE": "second"},
    ]
    lines = [(json.dumps(e) + "\n").encode("utf-8") for e in entries]
    fake = _FakeProc(lines)

    def spawn(_argv: list[str]) -> _FakeProc:
        return fake

    src = JournalSource(spawn=spawn)
    src.open()
    try:
        got = []
        deadline = time.monotonic() + 1.0
        while len(got) < 2 and time.monotonic() < deadline:
            entry = src.read_one(timeout=0.05)
            if entry is not None:
                got.append(entry)
        assert got == entries
    finally:
        src.close()


def test_journal_source_silently_drops_invalid_json_lines() -> None:
    lines = [
        b"not json\n",
        json.dumps({"MESSAGE": "ok"}).encode("utf-8") + b"\n",
    ]
    fake = _FakeProc(lines)
    src = JournalSource(spawn=lambda _argv: fake)
    src.open()
    try:
        deadline = time.monotonic() + 1.0
        entry = None
        while entry is None and time.monotonic() < deadline:
            entry = src.read_one(timeout=0.1)
        assert entry == {"MESSAGE": "ok"}
    finally:
        src.close()


def test_journal_source_close_terminates_subprocess() -> None:
    fake = _FakeProc([])
    src = JournalSource(spawn=lambda _argv: fake)
    src.open()
    src.close()
    assert fake.returncode is not None
