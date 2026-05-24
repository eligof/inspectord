"""Tests for the worker contract base class."""

from __future__ import annotations

import io
import json
import threading
import time

from inspectord.workers.contract import Worker


class _DummyWorker(Worker):
    def setup(self) -> None:
        self._counter = 0

    def step(self) -> None:
        self._counter += 1
        self.emit_event(
            {
                "schema_version": "1.0.0",
                "ts": "2026-05-24T00:00:00Z",
                "event_id": f"id-{self._counter}",
                "kind": "event",
                "category": ["host"],
                "type": ["start"],
                "action": "tick",
                "severity": "info",
                "module": "dummy",
            }
        )

    def step_interval_s(self) -> float:
        return 0.01


def test_worker_emits_events() -> None:
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = _DummyWorker(name="dummy", stdout=stdout, stderr=stderr)
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.05)
    w.request_stop()
    t.join(timeout=1)

    stdout_text = stdout.getvalue().decode("utf-8")
    events = [json.loads(line) for line in stdout_text.splitlines() if line.strip()]
    assert len(events) >= 2
    assert all(e["action"] == "tick" for e in events)


def test_worker_emits_heartbeats() -> None:
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = _DummyWorker(name="dummy", stdout=stdout, stderr=stderr)
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.05)
    w.request_stop()
    t.join(timeout=1)

    hb_text = stderr.getvalue().decode("utf-8")
    hbs = [json.loads(line) for line in hb_text.splitlines() if line.strip()]
    assert len(hbs) >= 1
    assert hbs[0]["kind"] == "heartbeat"
    assert hbs[0]["worker"] == "dummy"
