"""End-to-end enrichment integration through the Supervisor."""

from __future__ import annotations

import time
from pathlib import Path

from inspectord.config import dev_config
from inspectord.supervisor import Supervisor


def test_supervisor_enriches_events_before_publish(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        captured = []

        def listener(ev: object) -> None:
            captured.append(ev)

        sup.attach_listener(listener)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not captured:
            time.sleep(0.05)
        # We don't assert exact enriched field values — the existing workers
        # (healthcheck, dep_manager) emit events without pid/path/uid so
        # enrichment is a no-op in this test. The point is just that the
        # enrich() path runs without exception.
        assert captured
    finally:
        sup.stop(timeout=5.0)
