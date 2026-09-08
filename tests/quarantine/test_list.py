"""list_quarantine (quarantine design §3.6/§4): bounds, order, health flags.

A row must never lie: the list computes per-row reconciliation flags from the
filesystem (original path still present, blob missing), and the startup
helper logs every ``isolating`` row as incomplete.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from inspectord.evidence.store import ForensicStore
from inspectord.quarantine import ops
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations

BASE_TS = datetime(2026, 9, 1, 12, 0)


@pytest.fixture
def db(tmp_path: Path) -> Any:
    handle = Database(tmp_path / "db.duckdb")
    handle.connect()
    run_migrations(handle)
    yield handle
    handle.close()


@pytest.fixture
def store(tmp_path: Path) -> ForensicStore:
    return ForensicStore(tmp_path / "evidence")


def _seed(
    db: Database,
    qid: str,
    *,
    sha: str,
    status: str,
    original_path: str = "/tmp/gone",
    at: datetime = BASE_TS,
) -> None:
    db.execute(
        "INSERT INTO quarantine (quarantine_id, sha256, original_path, file_mode, file_uid, "
        "file_gid, size_bytes, status, quarantined_at) VALUES (?, ?, ?, 420, 1000, 1000, 4, ?, ?)",
        [qid, sha, original_path, status, at],
    )


def test_list_bounded_ordered_and_echoed(db: Database, store: ForensicStore) -> None:
    for i in range(5):
        sha = store.put(f"content-{i}".encode())
        _seed(db, f"q{i}", sha=sha, status="active", at=BASE_TS + timedelta(minutes=i))
    result = ops.list_quarantine(db, store, limit=3)
    assert result["limit"] == 3
    assert [row["quarantine_id"] for row in result["rows"]] == ["q4", "q3", "q2"]


def test_list_default_limit_echoed(db: Database, store: ForensicStore) -> None:
    result = ops.list_quarantine(db, store)
    assert result["limit"] == 200
    assert result["rows"] == []


def test_list_limit_clamped_to_max(db: Database, store: ForensicStore) -> None:
    result = ops.list_quarantine(db, store, limit=99999)
    assert result["limit"] == 1000


def test_active_row_with_recreated_file_flagged(
    db: Database, store: ForensicStore, tmp_path: Path
) -> None:
    recreated = tmp_path / "recreated"
    recreated.write_bytes(b"back again")
    sha = store.put(b"held")
    _seed(db, "q1", sha=sha, status="active", original_path=str(recreated))
    (row,) = ops.list_quarantine(db, store)["rows"]
    assert "file_still_present" in row["flags"]
    assert "blob_missing" not in row["flags"]


def test_isolating_and_failed_rows_flagged_incomplete(db: Database, store: ForensicStore) -> None:
    sha = store.put(b"held")
    _seed(db, "q1", sha=sha, status="isolating")
    _seed(db, "q2", sha=sha, status="failed", at=BASE_TS + timedelta(minutes=1))
    rows = {row["quarantine_id"]: row for row in ops.list_quarantine(db, store)["rows"]}
    assert "isolation_incomplete" in rows["q1"]["flags"]
    assert "isolation_incomplete" in rows["q2"]["flags"]


def test_missing_blob_flagged(db: Database, store: ForensicStore) -> None:
    sha = store.put(b"held")
    _seed(db, "q1", sha=sha, status="active")
    store.path_for(sha).unlink()
    (row,) = ops.list_quarantine(db, store)["rows"]
    assert "blob_missing" in row["flags"]


def test_deleted_row_not_flagged_for_missing_blob(db: Database, store: ForensicStore) -> None:
    _seed(db, "q1", sha="ab" * 32, status="deleted")  # blob never existed
    (row,) = ops.list_quarantine(db, store)["rows"]
    assert row["flags"] == []


def test_clean_active_row_has_no_flags(db: Database, store: ForensicStore) -> None:
    sha = store.put(b"held")
    _seed(db, "q1", sha=sha, status="active", original_path="/tmp/definitely-gone-xyz")
    (row,) = ops.list_quarantine(db, store)["rows"]
    assert row["flags"] == []
    assert row["sha256"] == sha
    assert row["status"] == "active"


def test_startup_logs_isolating_rows(
    db: Database, store: ForensicStore, caplog: pytest.LogCaptureFixture
) -> None:
    sha = store.put(b"held")
    _seed(db, "q1", sha=sha, status="isolating", original_path="/tmp/half-done")
    _seed(db, "q2", sha=sha, status="active", at=BASE_TS + timedelta(minutes=1))
    with caplog.at_level(logging.WARNING, logger="inspectord.quarantine.ops"):
        count = ops.log_incomplete_isolations(db)
    assert count == 1
    assert len(caplog.records) == 1
    assert "q1" in caplog.text
    assert "/tmp/half-done" in caplog.text
