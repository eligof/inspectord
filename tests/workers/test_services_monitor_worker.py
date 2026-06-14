"""Tests for ServicesMonitorWorker, independent of the real ServicesSource.

The worker is parameterised with a stream_factory so tests inject a FakeStream
that yields a fixed sequence of records without shelling out to systemctl.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

import pytest

from inspectord.workers.services_monitor.__main__ import ServicesMonitorWorker


class FakeStream:
    """Stand-in for ServicesSource."""

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


def _added_record(
    *,
    unit: str = "sshd.service",
    active: str = "active",
    sub: str = "running",
    load: str = "loaded",
) -> dict[str, Any]:
    return {
        "action": "service_added",
        "unit": unit,
        "active": active,
        "sub": sub,
        "load": load,
    }


def _removed_record(
    *,
    unit: str = "cups.service",
    previous_active: str = "inactive",
    previous_sub: str = "dead",
    previous_load: str = "loaded",
) -> dict[str, Any]:
    return {
        "action": "service_removed",
        "unit": unit,
        "previous_active": previous_active,
        "previous_sub": previous_sub,
        "previous_load": previous_load,
    }


def _changed_record(
    *,
    unit: str = "nginx.service",
    active: str = "failed",
    sub: str = "failed",
    load: str = "loaded",
    previous_active: str = "active",
    previous_sub: str = "running",
    previous_load: str = "loaded",
) -> dict[str, Any]:
    return {
        "action": "service_state_changed",
        "unit": unit,
        "active": active,
        "sub": sub,
        "load": load,
        "previous_active": previous_active,
        "previous_sub": previous_sub,
        "previous_load": previous_load,
    }


def test_worker_emits_service_added_event() -> None:
    sink = BytesIO()
    record = _added_record(
        unit="sshd.service",
        active="active",
        sub="running",
        load="loaded",
    )
    stream = FakeStream([[record]])
    worker = ServicesMonitorWorker(
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

    assert ev["module"] == "services_monitor"
    assert ev["action"] == "service_added"
    assert ev["kind"] == "event"
    assert ev["category"] == ["configuration"]
    assert ev["type"] == ["installation"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert ev["labels"] == ["service"]

    # service ECS field
    assert ev["service"]["name"] == "sshd.service"
    assert ev["service"]["state"] == "active"

    # message contains the unit name
    assert "sshd.service" in ev["message"]

    # raw fields
    assert ev["raw"]["source"] == "systemctl"
    assert ev["raw"]["active"] == "active"
    assert ev["raw"]["sub"] == "running"
    assert ev["raw"]["load"] == "loaded"


def test_worker_emits_service_removed_event() -> None:
    sink = BytesIO()
    record = _removed_record(
        unit="cups.service",
        previous_active="inactive",
        previous_sub="dead",
        previous_load="loaded",
    )
    stream = FakeStream([[record]])
    worker = ServicesMonitorWorker(
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

    assert ev["module"] == "services_monitor"
    assert ev["action"] == "service_removed"
    assert ev["kind"] == "event"
    assert ev["category"] == ["configuration"]
    assert ev["type"] == ["deletion"]
    assert ev["severity"] == "info"
    assert ev["labels"] == ["service"]

    # service ECS field uses previous_active as state
    assert ev["service"]["name"] == "cups.service"
    assert ev["service"]["state"] == "inactive"

    # message contains the unit name, "disappeared" keyword, and previous_active value
    assert "cups.service" in ev["message"]
    assert "disappeared" in ev["message"]
    assert "inactive" in ev["message"]

    # raw fields
    assert ev["raw"]["source"] == "systemctl"
    assert ev["raw"]["previous_active"] == "inactive"
    assert ev["raw"]["previous_sub"] == "dead"
    assert ev["raw"]["previous_load"] == "loaded"


def test_worker_emits_service_state_changed_event() -> None:
    sink = BytesIO()
    record = _changed_record(
        unit="nginx.service",
        active="failed",
        sub="failed",
        load="loaded",
        previous_active="active",
        previous_sub="running",
        previous_load="loaded",
    )
    stream = FakeStream([[record]])
    worker = ServicesMonitorWorker(
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

    assert ev["module"] == "services_monitor"
    assert ev["action"] == "service_state_changed"
    assert ev["kind"] == "event"
    assert ev["category"] == ["configuration"]
    assert ev["type"] == ["change"]
    assert ev["severity"] == "info"
    assert ev["labels"] == ["service"]

    # service ECS field uses the new active state
    assert ev["service"]["name"] == "nginx.service"
    assert ev["service"]["state"] == "failed"

    # message shows the transition arrow and both sides
    assert "nginx.service" in ev["message"]
    assert "->" in ev["message"]
    assert "running" in ev["message"]
    assert "failed" in ev["message"]

    # raw has both new and previous fields
    assert ev["raw"]["source"] == "systemctl"
    assert ev["raw"]["active"] == "failed"
    assert ev["raw"]["sub"] == "failed"
    assert ev["raw"]["load"] == "loaded"
    assert ev["raw"]["previous_active"] == "active"
    assert ev["raw"]["previous_sub"] == "running"
    assert ev["raw"]["previous_load"] == "loaded"


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = ServicesMonitorWorker(
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
    worker = ServicesMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True


def test_worker_raises_on_unknown_action() -> None:
    sink = BytesIO()
    record: dict[str, Any] = {"action": "service_exploded", "unit": "foo.service"}
    stream = FakeStream([[record]])
    worker = ServicesMonitorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    with pytest.raises(ValueError, match="unknown action"):
        worker.step(poll_timeout_ms=10)
    worker.stop()
