"""End-to-end deps worker integration test."""

from __future__ import annotations

import signal
import time
from pathlib import Path

import pytest

from inspectord.storage.db import Database


@pytest.mark.integration
def test_dependency_manager_emits_state_events(daemon: dict[str, object]) -> None:
    """Wait until the dep_manager worker writes at least one event to DuckDB."""
    tmp_path = daemon["tmp_path"]
    proc = daemon["proc"]
    assert isinstance(tmp_path, Path)

    # The worker is configured with interval_s=30 in dev_config, but it ticks
    # immediately on startup (the step happens before the first wait). Give it
    # a couple of seconds, then SIGTERM the daemon so DuckDB releases its lock
    # before we query (DuckDB holds an exclusive write lock while the daemon runs).
    time.sleep(2.5)
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except Exception:  # proc may already be dead
        proc.kill()

    db_path = tmp_path / "var" / "inspectord.duckdb"
    deadline = time.monotonic() + 10.0
    found = False
    while time.monotonic() < deadline and not found:
        if db_path.exists():
            with Database(db_path) as db:
                rows = db.query(
                    "SELECT COUNT(*) FROM events_enriched WHERE module = 'dependency_manager'"
                ).fetchall()
            if rows[0][0] >= 1:
                found = True
                break
        time.sleep(0.2)
    assert found, "dependency_manager worker never wrote any event"
