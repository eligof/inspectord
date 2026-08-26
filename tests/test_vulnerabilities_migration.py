"""Tests for migration 0012 — vulnerabilities table (vuln-scanner design §5)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pytest

from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    return db


def test_vulnerabilities_table_created(tmp_path: Path) -> None:
    db = _db(tmp_path)
    # PRAGMA table_info rows are (cid, name, type, notnull, dflt, pk).
    cols = {r[1] for r in db.query("PRAGMA table_info('vulnerabilities')").fetchall()}
    assert {
        "avg_id",
        "cve_id",
        "package",
        "installed_version",
        "fixed_version",
        "severity",
        "status",
        "fix_in_testing",
        "first_seen_at",
        "last_seen",
        "last_event_id",
        "resolved_at",
        "acked_at",
        "acked_note",
    } <= cols
    db.close()


def test_vulnerabilities_pk_is_avg_cve_package(tmp_path: Path) -> None:
    db = _db(tmp_path)
    now = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)
    row = ["AVG-1", "CVE-1", "openssl", now, now]
    db.execute(
        "INSERT INTO vulnerabilities (avg_id, cve_id, package, first_seen_at, last_seen)"
        " VALUES (?, ?, ?, ?, ?)",
        row,
    )
    with pytest.raises(duckdb.ConstraintException):
        db.execute(
            "INSERT INTO vulnerabilities (avg_id, cve_id, package, first_seen_at, last_seen)"
            " VALUES (?, ?, ?, ?, ?)",
            row,
        )
    # A different member of the composite key is a different row.
    db.execute(
        "INSERT INTO vulnerabilities (avg_id, cve_id, package, first_seen_at, last_seen)"
        " VALUES (?, ?, ?, ?, ?)",
        ["AVG-1", "CVE-1", "openssl-1.1", now, now],
    )
    db.close()
