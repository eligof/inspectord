"""Tests for process-state boot reconciliation."""

from __future__ import annotations

from pathlib import Path

from inspectord.state.reconcile import reconcile_processes
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _seed(db: Database, pid: int, boot_id: str, status: str) -> None:
    db.execute(
        "INSERT INTO process_state (pid, boot_id, status, first_seen, last_seen) "
        "VALUES (?, ?, ?, TIMESTAMP '2026-06-16 00:00:00', TIMESTAMP '2026-06-16 00:00:00')",
        [pid, boot_id, status],
    )


def test_reconcile_marks_stale_boot_processes_exited(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    _seed(db, 100, "old-boot", "running")
    _seed(db, 200, "current-boot", "running")
    reconcile_processes(db, "current-boot")
    rows = dict(db.query("SELECT boot_id, status FROM process_state ORDER BY boot_id").fetchall())
    assert rows == {"current-boot": "running", "old-boot": "exited"}
    db.close()
