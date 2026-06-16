"""Tests for the udev_monitor streaming source and event-block parser.

All tests inject a fake ``spawn`` callable (or monkeypatch ``subprocess.Popen``)
so they never invoke real ``udevadm`` or require any special privileges.  Where
``select.select`` needs a real file descriptor, the tests use ``os.pipe()``.
"""

from __future__ import annotations

import os
import subprocess
import threading
from typing import IO, Any

import pytest

from inspectord.workers.udev_monitor.source import (
    _MAX_LINEBUF_CHARS,
    UdevMonitorSource,
    _default_spawn,
    parse_event_block,
)

# ---------------------------------------------------------------------------
# Sample event blocks (header line + KEY=VALUE lines, no trailing blank line)
# ---------------------------------------------------------------------------

_ADD_BLOCK = [
    "UDEV  [12345.678901] add      /devices/pci0000:00/usb1/1-1 (usb)",
    "ACTION=add",
    "DEVPATH=/devices/pci0000:00/usb1/1-1",
    "SUBSYSTEM=usb",
    "DEVTYPE=usb_device",
    "PRODUCT=45e/800/944",
    "BUSNUM=001",
    "DEVNUM=002",
    "ID_VENDOR_ID=045e",
    "ID_MODEL_ID=0800",
    "ID_VENDOR=Microsoft",
    "ID_MODEL=Microsoft_Nano_Transceiver",
    "ID_SERIAL_SHORT=abc123",
]

_REMOVE_BLOCK = [
    "UDEV  [12346.000000] remove   /devices/pci0000:00/usb1/1-1 (usb)",
    "ACTION=remove",
    "DEVPATH=/devices/pci0000:00/usb1/1-1",
    "SUBSYSTEM=usb",
    "DEVTYPE=usb_device",
    "ID_VENDOR_ID=045e",
    "ID_MODEL_ID=0800",
]

_CHANGE_BLOCK = [
    "UDEV  [12347.000000] change   /devices/virtual/block/dm-0 (block)",
    "ACTION=change",
    "DEVPATH=/devices/virtual/block/dm-0",
    "SUBSYSTEM=block",
    "DEVTYPE=disk",
]


def _block_text(lines: list[str]) -> str:
    """Render a block as raw text terminated by a blank line."""
    return "".join(line + "\n" for line in lines) + "\n"


# ---------------------------------------------------------------------------
# Fake process / spawn injection
# ---------------------------------------------------------------------------


class _FakeProc:
    """Minimal Popen-like object backed by a file object (the read end of a pipe)."""

    def __init__(self, stdout: IO[str]) -> None:
        self.stdout = stdout
        self._alive = True
        self.terminate_called = 0
        self.kill_called = 0

    def poll(self) -> int | None:
        return None if self._alive else 0

    def terminate(self) -> None:
        self.terminate_called += 1
        self._alive = False

    def kill(self) -> None:
        self.kill_called += 1
        self._alive = False


def _make_source_with_pipe() -> tuple[UdevMonitorSource, int, _FakeProc]:
    """Create a source reading from an os.pipe; return (source, write_fd, proc)."""
    r, w = os.pipe()
    read_obj = os.fdopen(r, "r")
    proc = _FakeProc(read_obj)
    src = UdevMonitorSource(spawn=lambda: proc)
    return src, w, proc


# ---------------------------------------------------------------------------
# parse_event_block
# ---------------------------------------------------------------------------


def test_parse_add_block_fields() -> None:
    rec = parse_event_block(_ADD_BLOCK)
    assert rec is not None
    assert rec["action"] == "add"
    assert rec["subsystem"] == "usb"
    assert rec["devtype"] == "usb_device"
    assert rec["devpath"] == "/devices/pci0000:00/usb1/1-1"
    assert rec["vendor"] == "045e"  # ID_VENDOR_ID preferred
    assert rec["product"] == "0800"  # ID_MODEL_ID preferred
    assert rec["serial"] == "abc123"  # ID_SERIAL_SHORT preferred
    assert rec["name"] == "Microsoft_Nano_Transceiver"  # ID_MODEL preferred


def test_parse_remove_block() -> None:
    rec = parse_event_block(_REMOVE_BLOCK)
    assert rec is not None
    assert rec["action"] == "remove"
    assert rec["subsystem"] == "usb"
    assert rec["vendor"] == "045e"
    assert rec["product"] == "0800"


def test_parse_change_block() -> None:
    rec = parse_event_block(_CHANGE_BLOCK)
    assert rec is not None
    assert rec["action"] == "change"
    assert rec["subsystem"] == "block"
    assert rec["devtype"] == "disk"


def test_parse_missing_action_returns_none() -> None:
    block = [
        "UDEV  [1.0] add /devices/foo (usb)",
        "SUBSYSTEM=usb",
        "DEVPATH=/devices/foo",
    ]
    assert parse_event_block(block) is None


def test_parse_empty_action_returns_none() -> None:
    block = ["ACTION=", "SUBSYSTEM=usb"]
    assert parse_event_block(block) is None


def test_parse_serial_fallback_to_id_serial() -> None:
    block = [
        "ACTION=add",
        "SUBSYSTEM=usb",
        "ID_SERIAL=full-serial-string",
    ]
    rec = parse_event_block(block)
    assert rec is not None
    assert rec["serial"] == "full-serial-string"


def test_parse_serial_defaults_empty_when_absent() -> None:
    rec = parse_event_block(["ACTION=add", "SUBSYSTEM=usb"])
    assert rec is not None
    assert rec["serial"] == ""


def test_parse_vendor_fallback_to_id_vendor() -> None:
    block = ["ACTION=add", "ID_VENDOR=SomeVendor"]
    rec = parse_event_block(block)
    assert rec is not None
    assert rec["vendor"] == "SomeVendor"


def test_parse_product_fallback_to_id_model() -> None:
    block = ["ACTION=add", "ID_MODEL=SomeModel"]
    rec = parse_event_block(block)
    assert rec is not None
    assert rec["product"] == "SomeModel"


def test_parse_name_fallback_to_vendor_then_basename() -> None:
    # No ID_MODEL, but ID_VENDOR present → name = ID_VENDOR
    rec = parse_event_block(["ACTION=add", "ID_VENDOR=VendorOnly"])
    assert rec is not None
    assert rec["name"] == "VendorOnly"

    # No model, no vendor → name = basename of devpath
    rec2 = parse_event_block(["ACTION=add", "DEVPATH=/devices/pci/usb1/1-3"])
    assert rec2 is not None
    assert rec2["name"] == "1-3"

    # Nothing useful → name == ""
    rec3 = parse_event_block(["ACTION=add"])
    assert rec3 is not None
    assert rec3["name"] == ""


def test_parse_line_without_equals_ignored() -> None:
    block = [
        "UDEV  [1.0] add /devices/foo (usb)",  # header, no '='
        "ACTION=add",
        "this line has no equals sign",
        "SUBSYSTEM=usb",
    ]
    rec = parse_event_block(block)
    assert rec is not None
    assert rec["action"] == "add"
    assert rec["subsystem"] == "usb"
    assert "this line has no equals sign" not in rec["properties"]


def test_parse_value_with_equals_keeps_full_value() -> None:
    block = ["ACTION=add", "ID_MODEL=foo=bar=baz"]
    rec = parse_event_block(block)
    assert rec is not None
    assert rec["properties"]["ID_MODEL"] == "foo=bar=baz"
    assert rec["product"] == "foo=bar=baz"


def test_parse_garbage_non_ascii_does_not_raise() -> None:
    block = [
        "ACTION=add",
        "ID_MODEL=你好\U0001f600\x00garbage",
        "SUBSYSTEM=ÿþ",
        "=leading-equals-empty-key",
        "   ",  # whitespace-only line
    ]
    rec = parse_event_block(block)
    assert rec is not None
    assert rec["action"] == "add"


def test_parse_properties_holds_full_map() -> None:
    rec = parse_event_block(_ADD_BLOCK)
    assert rec is not None
    props = rec["properties"]
    assert props["ACTION"] == "add"
    assert props["BUSNUM"] == "001"
    assert props["DEVNUM"] == "002"
    assert props["PRODUCT"] == "45e/800/944"
    # header line (no '=') is not in the map
    assert all("UDEV" not in k for k in props)


def test_parse_whitespace_only_lines_skipped() -> None:
    block = ["ACTION=add", "", "   ", "\t", "SUBSYSTEM=usb"]
    rec = parse_event_block(block)
    assert rec is not None
    assert rec["subsystem"] == "usb"


# ---------------------------------------------------------------------------
# UdevMonitorSource
# ---------------------------------------------------------------------------


def test_source_emits_record_on_complete_block() -> None:
    src, w, _proc = _make_source_with_pipe()
    try:
        os.write(w, _block_text(_ADD_BLOCK).encode())
        records = src.poll(timeout_ms=200)
        assert len(records) == 1
        assert records[0]["action"] == "add"
        assert records[0]["vendor"] == "045e"
    finally:
        os.close(w)
        src.close()


def test_source_partial_block_across_polls() -> None:
    """A block split across two poll() calls emits only after the blank line."""
    src, w, _proc = _make_source_with_pipe()
    try:
        # First half: header + a few props, NO terminating blank line.
        first_half = "".join(line + "\n" for line in _ADD_BLOCK[:5])
        os.write(w, first_half.encode())
        records = src.poll(timeout_ms=200)
        assert records == []  # not terminated yet

        # Second half + blank terminator.
        second_half = "".join(line + "\n" for line in _ADD_BLOCK[5:]) + "\n"
        os.write(w, second_half.encode())
        records = src.poll(timeout_ms=200)
        assert len(records) == 1
        assert records[0]["action"] == "add"
    finally:
        os.close(w)
        src.close()


def test_source_two_blocks_one_poll() -> None:
    src, w, _proc = _make_source_with_pipe()
    try:
        os.write(w, (_block_text(_ADD_BLOCK) + _block_text(_REMOVE_BLOCK)).encode())
        records = src.poll(timeout_ms=200)
        assert [r["action"] for r in records] == ["add", "remove"]
    finally:
        os.close(w)
        src.close()


def test_source_timeout_returns_empty() -> None:
    src, w, _proc = _make_source_with_pipe()
    try:
        # Nothing written → select times out → []
        records = src.poll(timeout_ms=50)
        assert records == []
    finally:
        os.close(w)
        src.close()


def test_source_eof_raises_runtime_error() -> None:
    src, w, _proc = _make_source_with_pipe()
    # Close the write end → read end hits EOF.
    os.close(w)
    with pytest.raises(RuntimeError, match="udevadm monitor exited"):
        src.poll(timeout_ms=200)
    src.close()


def test_source_close_terminates_process() -> None:
    src, w, proc = _make_source_with_pipe()
    try:
        src.close()
        assert proc.terminate_called >= 1
    finally:
        os.close(w)


def test_source_close_idempotent() -> None:
    src, w, _proc = _make_source_with_pipe()
    try:
        src.close()
        src.close()  # must not raise
    finally:
        os.close(w)


def test_source_close_survives_dead_process() -> None:
    """close() must not raise even if terminate/kill raise (already-dead proc)."""
    r, w = os.pipe()

    class _ExplodingProc:
        def __init__(self) -> None:
            self.stdout = os.fdopen(r, "r")

        def poll(self) -> int | None:
            return 0

        def terminate(self) -> None:
            raise ProcessLookupError("already dead")

        def kill(self) -> None:
            raise ProcessLookupError("already dead")

    src = UdevMonitorSource(spawn=_ExplodingProc)
    try:
        src.close()  # must swallow the exceptions
    finally:
        os.close(w)


def test_source_newline_free_flood_is_bounded_and_resyncs() -> None:
    """A huge newline-free flood is dropped (bounded memory), then parsing resyncs."""
    src, w, _proc = _make_source_with_pipe()
    try:
        # Flood with no newline at all → split() yields no complete lines, so the
        # block-line cap never trips; the linebuf ceiling must bound it instead.
        # The flood exceeds the OS pipe buffer, so write from a background thread
        # while the reader drains it across multiple poll() calls.
        flood = b"A" * (_MAX_LINEBUF_CHARS + (1 << 18))
        writer = threading.Thread(target=os.write, args=(w, flood))
        writer.start()
        # Poll until the writer has delivered everything and been drained; the
        # internal buffer must stay bounded the entire time.
        deadline = 50
        while writer.is_alive() or src._linebuf:
            records = src.poll(timeout_ms=100)
            assert records == []
            assert len(src._linebuf) <= _MAX_LINEBUF_CHARS
            deadline -= 1
            if deadline <= 0:
                break
        writer.join(timeout=5)
        assert not writer.is_alive()
        assert len(src._linebuf) <= _MAX_LINEBUF_CHARS
        assert src._block == []

        # A normal complete block afterward must still parse (resync).
        os.write(w, _block_text(_ADD_BLOCK).encode())
        records = []
        for _ in range(10):
            records = src.poll(timeout_ms=200)
            if records:
                break
        assert len(records) == 1
        assert records[0]["action"] == "add"
    finally:
        os.close(w)
        src.close()


def test_source_multibyte_char_split_across_reads_is_reassembled() -> None:
    """A UTF-8 multibyte sequence split across os.read boundaries decodes correctly."""
    src, w, _proc = _make_source_with_pipe()
    try:
        # "café" — the é is two UTF-8 bytes (0xC3 0xA9).  Write the block up to
        # and including the first byte of é, poll, then write the rest.
        line = "ID_MODEL=café\n"
        full = "ACTION=add\n" + line + "\n"
        data = full.encode("utf-8")
        # Find the split point inside the é byte sequence.
        prefix = ("ACTION=add\n" + "ID_MODEL=caf").encode("utf-8")
        split = len(prefix) + 1  # prefix + first byte (0xC3) of é
        os.write(w, data[:split])
        records = src.poll(timeout_ms=200)
        assert records == []  # block not terminated yet
        os.write(w, data[split:])
        records = src.poll(timeout_ms=200)
        assert len(records) == 1
        # The é must be the real character, NOT U+FFFD (replacement).
        assert records[0]["properties"]["ID_MODEL"] == "café"
        assert "�" not in records[0]["properties"]["ID_MODEL"]
    finally:
        os.close(w)
        src.close()


def test_source_close_reaps_child() -> None:
    """close() waits on the child after terminate to avoid leaving a zombie."""

    class _WaitProc:
        def __init__(self) -> None:
            r, _w = os.pipe()
            self._w = _w
            self.stdout = os.fdopen(r, "r")
            self._alive = True
            self.wait_called = 0

        def poll(self) -> int | None:
            return None if self._alive else 0

        def terminate(self) -> None:
            self._alive = False

        def kill(self) -> None:
            self._alive = False

        def wait(self, timeout: float | None = None) -> int:
            self.wait_called += 1
            return 0

    proc = _WaitProc()
    src = UdevMonitorSource(spawn=lambda: proc)
    try:
        src.close()
        assert proc.wait_called >= 1
    finally:
        os.close(proc._w)


def test_source_close_survives_wait_timeout() -> None:
    """close() must not raise if wait() times out (escalates to kill)."""

    class _HangingProc:
        def __init__(self) -> None:
            r, _w = os.pipe()
            self._w = _w
            self.stdout = os.fdopen(r, "r")
            self.kill_called = 0

        def poll(self) -> int | None:
            return None

        def terminate(self) -> None:
            pass

        def kill(self) -> None:
            self.kill_called += 1

        def wait(self, timeout: float | None = None) -> int:
            if timeout is not None:
                raise subprocess.TimeoutExpired(cmd="udevadm", timeout=timeout)
            return 0

    proc = _HangingProc()
    src = UdevMonitorSource(spawn=lambda: proc)
    try:
        src.close()  # must not raise
        assert proc.kill_called >= 1
    finally:
        os.close(proc._w)


def test_source_raises_when_stdout_is_none() -> None:
    """__init__ must raise a clear RuntimeError if the proc has no stdout pipe."""

    class _NoStdoutProc:
        stdout = None

        def poll(self) -> int | None:
            return None

    with pytest.raises(RuntimeError, match="no stdout pipe"):
        UdevMonitorSource(spawn=_NoStdoutProc)


# ---------------------------------------------------------------------------
# _default_spawn argv builder
# ---------------------------------------------------------------------------


def test_default_spawn_argv_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _DummyPopen:
        def __init__(self, argv: list[str], **kwargs: Any) -> None:
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            self.stdout = None

    monkeypatch.setattr(subprocess, "Popen", _DummyPopen)
    _default_spawn()

    argv = captured["argv"]
    kwargs = captured["kwargs"]
    assert argv[0] == "udevadm"
    assert "monitor" in argv
    assert "--property" in argv
    assert "--udev" in argv
    assert "--subsystem-match=usb" in argv
    # Must NOT use the privileged kernel socket or sudo.
    assert "--kernel" not in argv
    assert "sudo" not in argv
    assert all("sudo" not in a for a in argv)
    # shell must never be True.
    assert kwargs.get("shell", False) is False
    assert isinstance(argv, list)  # argv list, never a shell string
