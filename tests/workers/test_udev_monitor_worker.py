"""Tests for UdevMonitorWorker, independent of the real UdevMonitorSource.

The worker is parameterised with a stream_factory so tests inject a FakeStream
that yields a fixed sequence of records without shelling out to udevadm.
"""

from __future__ import annotations

import json
import shutil
import signal
import subprocess
import sys
import threading
import time
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from inspectord.workers.udev_monitor.__main__ import (
    UdevMonitorWorker,
    _install_stop_handlers,
)


class FakeStream:
    """Stand-in for UdevMonitorSource."""

    def __init__(self, batches: list[list[dict[str, Any]]]) -> None:
        self._batches = batches
        self._closed = False

    def poll(self, timeout_ms: int) -> list[dict[str, Any]]:
        if not self._batches:
            return []
        return self._batches.pop(0)

    def close(self) -> None:
        self._closed = True


def _read_events(buf: BytesIO) -> list[dict[str, Any]]:
    buf.seek(0)
    return [json.loads(line) for line in buf.read().splitlines() if line]


def _record(
    *,
    action: str = "add",
    subsystem: str = "usb",
    devtype: str = "usb_device",
    devpath: str = "/devices/pci0000:00/usb1/1-1",
    vendor: str = "0bda",
    product: str = "8153",
    serial: str = "000123",
    name: str = "USB 10/100/1000 LAN",
    properties: dict[str, str] | None = None,
) -> dict[str, Any]:
    props = properties if properties is not None else {"ACTION": action, "SUBSYSTEM": subsystem}
    return {
        "action": action,
        "subsystem": subsystem,
        "devtype": devtype,
        "devpath": devpath,
        "vendor": vendor,
        "product": product,
        "serial": serial,
        "name": name,
        "properties": props,
    }


def test_worker_emits_device_added_event() -> None:
    sink = BytesIO()
    record = _record(action="add")
    stream = FakeStream([[record]])
    worker = UdevMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 1, events
    ev = events[0]

    assert ev["module"] == "udev_monitor"
    assert ev["action"] == "device_added"
    assert ev["kind"] == "event"
    assert ev["category"] == ["host"]
    assert ev["type"] == ["installation"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert ev["labels"] == ["device"]

    # device ECS field
    assert ev["device"]["name"] == "USB 10/100/1000 LAN"
    assert ev["device"]["kind"] == "usb_device"
    assert ev["device"]["vendor"] == "0bda"
    assert ev["device"]["product"] == "8153"
    assert ev["device"]["serial"] == "000123"

    # message contains the device name
    assert "USB 10/100/1000 LAN" in ev["message"]

    # raw fields
    assert ev["raw"]["source"] == "udevadm"
    assert ev["raw"]["ACTION"] == "add"
    assert ev["raw"]["SUBSYSTEM"] == "usb"


def test_worker_emits_device_removed_event() -> None:
    sink = BytesIO()
    record = _record(action="remove")
    stream = FakeStream([[record]])
    worker = UdevMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 1, events
    ev = events[0]

    assert ev["module"] == "udev_monitor"
    assert ev["action"] == "device_removed"
    assert ev["type"] == ["deletion"]
    assert ev["category"] == ["host"]
    assert ev["severity"] == "info"
    assert ev["labels"] == ["device"]
    assert ev["device"]["name"] == "USB 10/100/1000 LAN"
    assert "USB 10/100/1000 LAN" in ev["message"]
    assert ev["raw"]["source"] == "udevadm"


@pytest.mark.parametrize("action", ["change", "bind", "unbind", "move"])
def test_worker_emits_device_changed_event(action: str) -> None:
    sink = BytesIO()
    record = _record(action=action)
    stream = FakeStream([[record]])
    worker = UdevMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 1, events
    ev = events[0]

    assert ev["module"] == "udev_monitor"
    assert ev["action"] == "device_changed"
    assert ev["type"] == ["change"]
    assert ev["category"] == ["host"]
    assert ev["labels"] == ["device"]


def test_worker_handles_empty_fields_without_crashing() -> None:
    sink = BytesIO()
    record = _record(
        action="add",
        devtype="",
        devpath="",
        vendor="",
        product="",
        serial="",
        name="",
    )
    stream = FakeStream([[record]])
    worker = UdevMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 1, events
    ev = events[0]
    assert ev["action"] == "device_added"
    # kind falls back to subsystem when devtype is empty
    assert ev["device"]["kind"] == "usb"
    # message renders (even if empty fields produce a sparse string)
    assert isinstance(ev["message"], str)


def test_worker_kind_falls_back_to_subsystem() -> None:
    sink = BytesIO()
    record = _record(action="add", devtype="", subsystem="block")
    stream = FakeStream([[record]])
    worker = UdevMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    ev = _read_events(sink)[0]
    assert ev["device"]["kind"] == "block"


def test_worker_step_before_start_raises() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = UdevMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    with pytest.raises(RuntimeError, match="worker not started"):
        worker.step(poll_timeout_ms=10)


def test_worker_emits_multiple_events_in_one_poll() -> None:
    sink = BytesIO()
    records = [
        _record(action="add", name="dev-a"),
        _record(action="remove", name="dev-b"),
        _record(action="change", name="dev-c"),
    ]
    stream = FakeStream([records])
    worker = UdevMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 3, events
    assert events[0]["action"] == "device_added"
    assert events[1]["action"] == "device_removed"
    assert events[2]["action"] == "device_changed"


def test_worker_flushes_each_record() -> None:
    flush_calls: list[int] = []

    class CountingSink(BytesIO):
        def flush(self) -> None:
            flush_calls.append(1)
            super().flush()

    sink = CountingSink()
    records = [_record(action="add"), _record(action="remove")]
    stream = FakeStream([records])
    worker = UdevMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    assert len(flush_calls) == 2


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = UdevMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=1)
    worker.stop()
    assert _read_events(sink) == []


def test_worker_closes_stream_on_stop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = UdevMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True


# ---------------------------------------------------------------------------
# SIGTERM teardown: the supervisor stops workers with SIGTERM, and this worker
# owns a long-lived ``udevadm monitor`` grandchild that must go with it.
# ---------------------------------------------------------------------------


def test_install_stop_handlers_sets_the_flag_on_sigterm_and_sigint() -> None:
    """SIGTERM/SIGINT must set the stop flag rather than kill the interpreter.

    Python's default SIGTERM disposition terminates the process outright, so
    main()'s ``finally: worker.stop()`` never runs and the udevadm grandchild
    is orphaned (reparented to init, alive forever).
    """
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            stop = threading.Event()
            _install_stop_handlers(stop)
            assert not stop.is_set()
            signal.raise_signal(sig)
            assert stop.is_set(), f"{sig!r} did not request a graceful stop"
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@pytest.mark.skipif(shutil.which("udevadm") is None, reason="needs udevadm")
def test_sigterm_leaves_no_orphaned_udevadm() -> None:
    """End to end: SIGTERM the worker exactly as the supervisor does; no leak.

    ``udevadm monitor --udev`` is the unprivileged libudev broadcast socket, so
    this needs no root.
    """
    proc = subprocess.Popen(
        [sys.executable, "-m", "inspectord.workers.udev_monitor"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        # Wait for the grandchild to actually exist before signalling.
        deadline = time.monotonic() + 15.0
        children: list[str] = []
        while time.monotonic() < deadline and not children:
            children = subprocess.run(
                ["pgrep", "-P", str(proc.pid)], capture_output=True, text=True, check=False
            ).stdout.split()
            if not children:
                time.sleep(0.05)
        assert children, "the worker never spawned its udevadm child"

        proc.terminate()
        assert proc.wait(timeout=15) == 0, "SIGTERM killed the worker before it could tear down"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=15)
        if proc.stdout is not None:
            proc.stdout.close()

    # The grandchildren must be gone -- not merely reparented away from us.
    deadline = time.monotonic() + 5.0
    alive = children
    while time.monotonic() < deadline and alive:
        alive = [pid for pid in children if Path(f"/proc/{pid}").exists()]
        if alive:
            time.sleep(0.05)
    assert not alive, f"orphaned udevadm processes survived the worker: {alive}"
