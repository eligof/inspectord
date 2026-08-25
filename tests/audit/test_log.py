"""Tests for the hash-chained audit log writer (spec 2026-08-25 §3/§6)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path

from inspectord.audit.log import _row_hash_from_stored, append_audit, reset_for_tests
from inspectord.journal import ZERO_HASH
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


def _rows(db_path: Path):
    with Database(db_path) as db:
        return db.query(
            "SELECT seq, ts, actor, action, target, details_json, prev_hash, row_hash "
            "FROM audit_log ORDER BY seq"
        ).fetchall()


def setup_function(_fn) -> None:
    reset_for_tests()  # drop the module connection + counters between tests


def test_genesis_row(tmp_path):
    db_path = _fresh(tmp_path)
    seq = append_audit(
        db_path, actor="user:local", action="alert_acked", target="alert:a1", details={}
    )
    assert seq == 1
    rows = _rows(db_path)
    assert len(rows) == 1
    assert rows[0][6] == ZERO_HASH  # prev_hash
    assert len(rows[0][7]) == 64


def test_chain_links(tmp_path):
    db_path = _fresh(tmp_path)
    for i in range(3):
        append_audit(
            db_path,
            actor="user:local",
            action="case_opened",
            target=f"case:{i}",
            details={"title": "t"},
        )
    rows = _rows(db_path)
    assert [r[0] for r in rows] == [1, 2, 3]
    assert rows[1][6] == rows[0][7]
    assert rows[2][6] == rows[1][7]


def test_ts_round_trip_hash_recomputes(tmp_path):
    # Both a sub-second and a zero-microsecond ts must verify after DB re-read.
    db_path = _fresh(tmp_path)
    append_audit(db_path, actor="user:local", action="a", target=None, details={})
    append_audit(
        db_path,
        actor="user:local",
        action="b",
        target="x",
        details={"k": 1},
        _ts=datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC),  # zero microseconds
    )
    for seq, ts, actor, action, target, details_json, prev_hash, row_hash in _rows(db_path):
        assert (
            _row_hash_from_stored(
                seq=seq,
                ts=ts,
                actor=actor,
                action=action,
                target=target,
                details_json=details_json,
                prev_hash=prev_hash,
            )
            == row_hash
        )


def test_reopen_continues_chain(tmp_path):
    db_path = _fresh(tmp_path)
    append_audit(db_path, actor="user:local", action="a", target=None, details={})
    reset_for_tests()  # simulate daemon restart (new module connection)
    append_audit(db_path, actor="user:local", action="b", target=None, details={})
    rows = _rows(db_path)
    assert [r[0] for r in rows] == [1, 2]
    assert rows[1][6] == rows[0][7]


def test_concurrent_appends_dense_and_linked(tmp_path):
    db_path = _fresh(tmp_path)
    n = 24

    def w(i: int) -> None:
        append_audit(
            db_path,
            actor="user:local",
            action="hunt_query_saved",
            target=f"hunt:{i}",
            details={},
        )

    threads = [threading.Thread(target=w, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rows = _rows(db_path)
    assert [r[0] for r in rows] == list(range(1, n + 1))
    for a, b in pairwise(rows):
        assert b[6] == a[7]


def test_unserializable_details_does_not_raise(tmp_path):
    db_path = _fresh(tmp_path)
    seq = append_audit(
        db_path,
        actor="user:local",
        action="a",
        target=None,
        details={"path": Path("/etc")},  # not JSON-serializable natively
    )
    assert seq == 1  # default=str kicked in, row written
