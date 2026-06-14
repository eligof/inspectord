"""Tests for FirewallInspectorWorker, independent of the real FirewallSource.

The worker is parameterised with a stream_factory so tests inject a FakeStream
that yields a fixed sequence of records without shelling out to nft/iptables.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.firewall_inspector.__main__ import FirewallInspectorWorker


class FakeStream:
    """Stand-in for FirewallSource."""

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


def _changed_record(
    *,
    backend: str = "nftables",
    previous_digest: str = "aaa",
    digest: str = "bbb",
    added: int = 2,
    removed: int = 1,
    diff: str = "+added line\n+another line\n-removed line",
) -> dict[str, Any]:
    return {
        "action": "firewall_ruleset_changed",
        "backend": backend,
        "previous_digest": previous_digest,
        "digest": digest,
        "added": added,
        "removed": removed,
        "diff": diff,
    }


def test_worker_emits_firewall_ruleset_changed_event() -> None:
    sink = BytesIO()
    record = _changed_record(
        backend="nftables",
        previous_digest="aaabbb",
        digest="cccddd",
        added=2,
        removed=1,
        diff="+new rule\n+another rule\n-old rule",
    )
    stream = FakeStream([[record]])
    worker = FirewallInspectorWorker(
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

    assert ev["module"] == "firewall_inspector"
    assert ev["action"] == "firewall_ruleset_changed"
    assert ev["kind"] == "state"
    assert ev["category"] == ["configuration"]
    assert ev["type"] == ["change"]
    assert ev["severity"] == "medium"
    assert ev["host"]["name"] == "test-host"
    assert ev["labels"] == ["firewall"]

    # message contains backend name and change counts
    assert "nftables" in ev["message"]
    assert "+2" in ev["message"]
    assert "-1" in ev["message"]

    # raw fields
    assert ev["raw"]["source"] == "nftables"
    assert ev["raw"]["digest"] == "cccddd"
    assert ev["raw"]["previous_digest"] == "aaabbb"
    assert ev["raw"]["added"] == 2
    assert ev["raw"]["removed"] == 1
    assert ev["raw"]["diff"] == "+new rule\n+another rule\n-old rule"


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = FirewallInspectorWorker(
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
    worker = FirewallInspectorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
