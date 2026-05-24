"""Tests for the event router."""

from __future__ import annotations

from datetime import UTC, datetime
from queue import Empty as QueueEmpty

import pytest

from inspectord.router import DropPolicy, EventRouter, RouterFull
from inspectord.schemas.event import Event


def _ev(action: str = "synthetic", severity: str = "info") -> Event:
    return Event.model_validate(
        {
            "schema_version": "1.0.0",
            "ts": datetime.now(UTC).isoformat(),
            "event_id": "01900000-0000-7000-8000-000000000000",
            "kind": "event",
            "category": ["host"],
            "type": ["start"],
            "action": action,
            "severity": severity,
            "module": "test",
        }
    )


def test_subscribe_receives_event() -> None:
    r = EventRouter()
    sub = r.subscribe(name="t", queue_size=8, drop_policy=DropPolicy.drop_oldest_non_critical)
    r.publish(_ev())
    got = sub.get_nowait()
    assert got.action == "synthetic"


def test_subscribe_filter() -> None:
    r = EventRouter()
    sub = r.subscribe(
        name="t",
        queue_size=8,
        drop_policy=DropPolicy.drop_oldest_non_critical,
        filter_fn=lambda e: e.severity.value == "critical",
    )
    r.publish(_ev(severity="info"))
    r.publish(_ev(severity="critical"))
    got = sub.get_nowait()
    assert got.severity.value == "critical"
    with pytest.raises(QueueEmpty):
        sub.get_nowait()


def test_drop_oldest_non_critical() -> None:
    r = EventRouter()
    sub = r.subscribe(name="t", queue_size=2, drop_policy=DropPolicy.drop_oldest_non_critical)
    r.publish(_ev(action="a"))
    r.publish(_ev(action="b"))
    r.publish(_ev(action="c"))
    drained = []
    while True:
        try:
            drained.append(sub.get_nowait().action)
        except Exception:
            break
    assert drained == ["b", "c"]
    assert sub.dropped == 1


def test_critical_events_never_dropped() -> None:
    r = EventRouter()
    sub = r.subscribe(name="t", queue_size=2, drop_policy=DropPolicy.drop_oldest_non_critical)
    r.publish(_ev(action="a", severity="critical"))
    r.publish(_ev(action="b", severity="critical"))
    with pytest.raises(RouterFull):
        r.publish(_ev(action="c", severity="critical"))
    drained = []
    while True:
        try:
            drained.append(sub.get_nowait().action)
        except Exception:
            break
    assert drained == ["a", "b"]
    assert sub.dropped == 0
    assert sub.blocked >= 1
