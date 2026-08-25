"""Tamper-detection tests for verify_audit_chain (spec §6/§8/§9)."""

from __future__ import annotations

from pathlib import Path

from inspectord.audit.log import append_audit, reset_for_tests, verify_audit_chain
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


def _seed(db_path: Path, n: int = 5) -> None:
    for i in range(n):
        append_audit(
            db_path,
            actor="user:local",
            action="case_opened",
            target=f"case:{i}",
            details={"i": i},
        )


def setup_function(_fn) -> None:
    reset_for_tests()


def test_clean_chain_ok(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path)
    with Database(db_path) as db:
        v = verify_audit_chain(db)
    assert v.ok and v.rows == 5 and v.first_bad_seq is None
    assert v.last_good is not None and v.last_good["seq"] == 5


def test_empty_table_ok_zero_rows(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        v = verify_audit_chain(db)
    assert v.ok and v.rows == 0


def test_edited_row_detected(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path)
    with Database(db_path) as db:
        db.execute("UPDATE audit_log SET actor='auto:evil' WHERE seq=3")
        v = verify_audit_chain(db)
    assert not v.ok and v.first_bad_seq == 3 and v.reason == "row_hash_mismatch"
    assert v.last_good is not None and v.last_good["seq"] == 2
    assert v.first_bad is not None and v.first_bad["seq"] == 3


def test_interior_delete_detected(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path)
    with Database(db_path) as db:
        db.execute("DELETE FROM audit_log WHERE seq=3")
        v = verify_audit_chain(db)
    assert not v.ok and v.first_bad_seq == 4 and v.reason == "seq_gap"


def test_inserted_row_detected(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path, 2)
    with Database(db_path) as db:
        # Forge a row 3 with a bogus hash pair.
        db.execute(
            "INSERT INTO audit_log VALUES (3, TIMESTAMP '2026-08-25 12:00:00', "
            "'user:local', 'x', NULL, '{}', 'f'||repeat('0',63), 'a'||repeat('0',63))"
        )
        v = verify_audit_chain(db)
    assert not v.ok and v.first_bad_seq == 3


def test_tail_truncation_clean_without_anchor_flagged_with_anchor(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path)
    with Database(db_path) as db:
        head = db.query("SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        db.execute("DELETE FROM audit_log WHERE seq > 3")
        clean = verify_audit_chain(db)
        anchored = verify_audit_chain(db, anchor=(head[0], head[1]))
    assert clean.ok  # honest limitation: no anchor -> truncation invisible
    assert not clean.anchor_checked
    assert not anchored.ok and anchored.reason == "anchor_mismatch"
    assert anchored.anchor_checked


def test_wipe_to_empty_flagged_with_anchor(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path, 2)
    with Database(db_path) as db:
        head = db.query("SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        db.execute("DELETE FROM audit_log")
        v = verify_audit_chain(db, anchor=(head[0], head[1]))
    assert not v.ok and v.reason == "anchor_mismatch"
