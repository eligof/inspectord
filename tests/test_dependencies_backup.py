"""Tests for edit-with-backup utility."""

from __future__ import annotations

import hashlib
from pathlib import Path

from inspectord.dependencies.backup import (
    BackupRecord,
    apply_edit_with_backup,
    list_backups,
    restore_backup,
)
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_apply_inserts_markers(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    target = tmp_path / "config.conf"
    target.write_text("# original\nkey=value\n")
    rec = apply_edit_with_backup(
        db_path=db_path,
        dep_name="rsyslog",
        target_path=target,
        managed_block="# our line\n",
        backup_root=tmp_path / "deps_backups",
    )
    text = target.read_text()
    assert "# >>> inspectord BEGIN" in text
    assert "# <<< inspectord END" in text
    assert "# our line" in text
    assert isinstance(rec, BackupRecord)


def test_apply_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    target = tmp_path / "config.conf"
    target.write_text("# original\n")
    apply_edit_with_backup(
        db_path=db_path,
        dep_name="rsyslog",
        target_path=target,
        managed_block="# one\n",
        backup_root=tmp_path / "deps_backups",
    )
    first = target.read_text()
    apply_edit_with_backup(
        db_path=db_path,
        dep_name="rsyslog",
        target_path=target,
        managed_block="# two\n",
        backup_root=tmp_path / "deps_backups",
    )
    second = target.read_text()
    assert second.count("# >>> inspectord BEGIN") == 1
    assert "# two" in second
    assert "# one" not in second
    assert first != second


def test_backups_recorded_in_db(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    target = tmp_path / "config.conf"
    target.write_text("# original\n")
    apply_edit_with_backup(
        db_path=db_path,
        dep_name="rsyslog",
        target_path=target,
        managed_block="# x\n",
        backup_root=tmp_path / "deps_backups",
    )
    backups = list_backups(db_path=db_path, dep_name="rsyslog")
    assert len(backups) == 1
    assert backups[0].original_path == str(target)


def test_restore_returns_to_original(tmp_path: Path) -> None:
    db_path = tmp_path / "t.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
    target = tmp_path / "config.conf"
    original = "# original content\nfoo=bar\n"
    target.write_text(original)
    original_sha = hashlib.sha256(original.encode()).hexdigest()
    rec = apply_edit_with_backup(
        db_path=db_path,
        dep_name="rsyslog",
        target_path=target,
        managed_block="# x\n",
        backup_root=tmp_path / "deps_backups",
    )
    assert target.read_text() != original
    restore_backup(db_path=db_path, backup_id=rec.backup_id)
    assert target.read_text() == original
    assert hashlib.sha256(target.read_bytes()).hexdigest() == original_sha
