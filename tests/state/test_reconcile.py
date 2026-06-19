"""Tests for process-state boot reconciliation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inspectord.schemas.event import Event, EventKind, Severity
from inspectord.state.projector import project
from inspectord.state.reconcile import reconcile_processes
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _process_start(event_id: str, pid: int) -> Event:
    return Event(
        ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event_id=event_id,
        kind=EventKind.event,
        category=["process"],
        type=["start"],
        action="process_start",
        severity=Severity.info,
        module="process_collector",
        process={"pid": pid, "name": "bash", "command_line": "bash"},
        user={"id": "1000"},
        raw={"source": "ebpf"},
    )


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


def test_projected_stale_boot_row_reconciled_end_to_end(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    # Project a running row under the previous boot and another under the current boot.
    project(_process_start("p1", 100), db, boot_id="old-boot")
    project(_process_start("p2", 200), db, boot_id="current-boot")
    reconcile_processes(db, "current-boot")
    rows = dict(db.query("SELECT boot_id, status FROM process_state ORDER BY boot_id").fetchall())
    assert rows == {"current-boot": "running", "old-boot": "exited"}
    db.close()
