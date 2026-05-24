"""Tests for the healthcheck worker."""

from __future__ import annotations

import io
import json
import threading
import time

from inspectord.workers.healthcheck.__main__ import HealthcheckWorker


def test_healthcheck_emits_synthetic_event() -> None:
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = HealthcheckWorker(name="healthcheck", stdout=stdout, stderr=stderr)
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.05)
    w.request_stop()
    t.join(timeout=1)

    events = [
        json.loads(line) for line in stdout.getvalue().decode("utf-8").splitlines() if line.strip()
    ]
    assert events
    assert all(e["module"] == "healthcheck" for e in events)
    assert all(e["action"] == "synthetic_heartbeat" for e in events)
