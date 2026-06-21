"""Tests the PersistenceSnapshotterWorker independently of the real filesystem source.

The worker is parameterised with a ``snapshot_fn`` so tests can inject a fake
that yields a fixed sequence of ``(entries, failed_kinds)`` tuples.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.persistence_snapshotter.__main__ import (
    PersistenceSnapshotterWorker,
)


class FakeSnapshot:
    """Stand-in for source.snapshot(): returns queued (entries, failed) tuples."""

    def __init__(self, batches: list[tuple[dict[str, dict[str, Any]], set[str]]]) -> None:
        self._batches = batches

    def __call__(self) -> tuple[dict[str, dict[str, Any]], set[str]]:
        if not self._batches:
            return {}, set()
        return self._batches.pop(0)


def _read_events(buf: BytesIO) -> list[dict[str, Any]]:
    buf.seek(0)
    return [json.loads(line) for line in buf.read().splitlines() if line]


def _cron_attrs(key: str, name: str = "j", path: str = "/etc/crontab") -> dict[str, Any]:
    return {
        "kind": "cron",
        "name": name,
        "source_path": path,
        "details": "d",
        "key": key,
    }


def _authkey_attrs(key: str) -> dict[str, Any]:
    return {
        "kind": "authorized_key",
        "name": "user@host",
        "source_path": "/home/u/.ssh/authorized_keys",
        "details": "ssh-ed25519 SHA256:abc",
        "key": key,
    }


def test_first_step_emits_all_as_added() -> None:
    """The first step emits every current entry as persistence_added."""
    k1, k2 = "persist:cron:/etc/crontab:aaa", "persist:cron:/etc/crontab:bbb"
    a1, a2 = _cron_attrs(k1), _cron_attrs(k2, name="k")
    sink = BytesIO()
    worker = PersistenceSnapshotterWorker(
        snapshot_fn=FakeSnapshot([({k1: a1, k2: a2}, set())]),
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step()
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 2, events
    keys = set()
    for ev in events:
        assert ev["action"] == "persistence_added"
        assert ev["module"] == "persistence_snapshotter"
        assert ev["persistence"]["key"]
        keys.add(ev["persistence"]["key"])
    assert keys == {k1, k2}


def test_removal_emits_one_removed_event() -> None:
    """After two-key state, dropping k2 emits exactly one persistence_removed."""
    k1, k2 = "persist:cron:/etc/crontab:aaa", "persist:cron:/etc/crontab:bbb"
    a1, a2 = _cron_attrs(k1), _cron_attrs(k2, name="k")
    sink = BytesIO()
    worker = PersistenceSnapshotterWorker(
        snapshot_fn=FakeSnapshot([({k1: a1, k2: a2}, set()), ({k1: a1}, set())]),
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step()  # populate
    sink.seek(0)
    sink.truncate(0)
    worker.step()  # k2 removed, k1 unchanged
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 1, events
    assert events[0]["action"] == "persistence_removed"
    assert events[0]["persistence"]["key"] == k2


def test_carry_forward_suppresses_removal_on_failed_source() -> None:
    """A failed cron source carries the previous cron entries forward (no removal)."""
    k1, k2 = "persist:cron:/etc/crontab:aaa", "persist:cron:/etc/crontab:bbb"
    a1, a2 = _cron_attrs(k1), _cron_attrs(k2, name="k")
    sink = BytesIO()
    worker = PersistenceSnapshotterWorker(
        snapshot_fn=FakeSnapshot(
            [
                ({k1: a1, k2: a2}, set()),  # populate
                ({}, {"cron"}),  # cron failed -> carry forward, no events
                ({k1: a1}, set()),  # cron healthy, k2 gone -> remove k2 only
            ]
        ),
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step()  # populate
    sink.seek(0)
    sink.truncate(0)
    worker.step()  # failed cron -> no events
    assert _read_events(sink) == []
    sink.seek(0)
    sink.truncate(0)
    worker.step()  # k2 removed only
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 1, events
    assert events[0]["action"] == "persistence_removed"
    assert events[0]["persistence"]["key"] == k2


def test_severity_by_kind() -> None:
    """authorized_key entries are medium severity; cron entries are low."""
    ck, ak = "persist:cron:/etc/crontab:aaa", "persist:authkey:ssh-ed25519:abc"
    sink = BytesIO()
    worker = PersistenceSnapshotterWorker(
        snapshot_fn=FakeSnapshot([({ck: _cron_attrs(ck), ak: _authkey_attrs(ak)}, set())]),
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step()
    worker.stop()

    by_kind = {ev["persistence"]["kind"]: ev for ev in _read_events(sink)}
    assert by_kind["authorized_key"]["severity"] == "medium"
    assert by_kind["cron"]["severity"] == "low"


def test_event_shape() -> None:
    """Emitted event carries persistence labels and details."""
    k1 = "persist:cron:/etc/crontab:aaa"
    sink = BytesIO()
    worker = PersistenceSnapshotterWorker(
        snapshot_fn=FakeSnapshot([({k1: _cron_attrs(k1)}, set())]),
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step()
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 1, events
    ev = events[0]
    assert "persistence" in ev["labels"]
    assert "persist:cron" in ev["labels"]
    assert ev["persistence"]["details"] == "d"
