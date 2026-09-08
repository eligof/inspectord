"""Tests for migration 0014 — the quarantine table (quarantine design §3.1)."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_migration_0014_is_idempotent(tmp_path: Path) -> None:
    """The runner is not transactional: a crash mid-file re-applies the whole
    file, so every statement must be re-runnable against the altered schema."""
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    first = run_migrations(db)
    assert first >= 14
    # Force a real re-application of 0014's statements, not the runner's
    # schema_version short-circuit.
    db.execute("DELETE FROM schema_version WHERE version = 14")
    second = run_migrations(db)
    assert second == first
    db.close()


def test_quarantine_table_has_spec_columns(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {r[1] for r in db.query("PRAGMA table_info('quarantine')").fetchall()}
    assert cols == {
        "quarantine_id",
        "sha256",
        "original_path",
        "file_mode",
        "file_uid",
        "file_gid",
        "size_bytes",
        "pkg_owner",
        "note",
        "alert_id",
        "case_id",
        "status",
        "quarantined_at",
        "restored_at",
        "deleted_at",
    }
    db.close()
