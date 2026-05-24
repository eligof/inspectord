"""Tests for the dep audit log writer."""

from __future__ import annotations

from pathlib import Path

from inspectord.dependencies.audit import log_dep_action
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_log_dep_action_inserts_row(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    log_dep_action(
        db_path=db_path,
        actor="eli@local",
        action="plan_created",
        target="auditd",
        plan_id="01900000-0000-7000-8000-000000000000",
    )
    with Database(db_path) as db:
        rows = db.query("SELECT actor, action, target, plan_id FROM dep_audit").fetchall()
    assert rows == [("eli@local", "plan_created", "auditd", "01900000-0000-7000-8000-000000000000")]


def test_log_dep_action_truncates_long_stderr(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    long_stderr = "x" * 5000
    log_dep_action(
        db_path=db_path,
        actor="pkg-helper",
        action="install_failed",
        target="auditd",
        stderr_tail=long_stderr,
    )
    with Database(db_path) as db:
        row = db.query("SELECT stderr_tail FROM dep_audit").fetchall()[0][0]
    assert len(row) <= 2000
