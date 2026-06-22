"""Tests for migration 0007 — case_evidence table."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_case_evidence_table_created(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {r[1] for r in db.query("PRAGMA table_info('case_evidence')").fetchall()}
    assert {"case_id", "kind", "sha256", "original_path", "captured_at", "meta_json"} <= cols
    db.close()
