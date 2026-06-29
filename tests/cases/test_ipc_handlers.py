"""Tests for the cases IPC handlers (spec §5)."""

from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path

from inspectord.cases import export, ipc_handlers, store
from inspectord.cases.ipc_handlers import (
    handle_add_note,
    handle_attach_alert,
    handle_close_case,
    handle_get_case,
    handle_list_cases,
    handle_open_case,
)
from inspectord.evidence.store import ForensicStore
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "test.duckdb"


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _seed_alert_db(db: Database, alert_id: str, short: str = "sshd brute force") -> None:
    db.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
        "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, payload_json) "
        "VALUES (?, 'r1', TIMESTAMP '2026-06-20 00:00:00', 'high', 'new', 'auth', 'dk', 1, "
        "TIMESTAMP '2026-06-20 00:00:00', TIMESTAMP '2026-06-20 00:00:00', ?, 'detail', '{}')",
        [alert_id, short],
    )


def _seed_alert(db_path: Path, alert_id: str, short: str = "sshd brute force") -> None:
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
            "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, "
            "payload_json) VALUES (?, 'r1', TIMESTAMP '2026-06-20 00:00:00', 'high', 'new', "
            "'auth', 'dk', 1, TIMESTAMP '2026-06-20 00:00:00', TIMESTAMP '2026-06-20 00:00:00', "
            "?, 'detail', '{}')",
            [alert_id, short],
        )


def test_open_case_returns_case_id(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    result = handle_open_case(params={"alert_id": "a1"}, db_path=db_path)
    assert result["schema_version"] == "1.0.0"
    assert isinstance(result["case_id"], str)
    assert result["case_id"]


def test_attach_alert_returns_ok(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    _seed_alert(db_path, "a2")
    case_id = handle_open_case(params={"alert_id": "a1"}, db_path=db_path)["case_id"]
    result = handle_attach_alert(params={"case_id": case_id, "alert_id": "a2"}, db_path=db_path)
    assert result == {"schema_version": "1.0.0", "ok": True}


def test_attach_alert_unknown_case_is_ok(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    result = handle_attach_alert(params={"case_id": "nope", "alert_id": "a1"}, db_path=db_path)
    assert result == {"schema_version": "1.0.0", "ok": True}


def test_add_note_returns_ok(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    case_id = handle_open_case(params={"alert_id": "a1"}, db_path=db_path)["case_id"]
    result = handle_add_note(params={"case_id": case_id, "text": "note"}, db_path=db_path)
    assert result == {"schema_version": "1.0.0", "ok": True}


def test_add_note_unknown_case_is_ok(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    result = handle_add_note(params={"case_id": "nope", "text": "note"}, db_path=db_path)
    assert result == {"schema_version": "1.0.0", "ok": True}


def test_close_case_returns_ok(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    case_id = handle_open_case(params={"alert_id": "a1"}, db_path=db_path)["case_id"]
    result = handle_close_case(params={"case_id": case_id}, db_path=db_path)
    assert result == {"schema_version": "1.0.0", "ok": True}


def test_close_case_unknown_case_is_ok(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    result = handle_close_case(params={"case_id": "nope"}, db_path=db_path)
    assert result == {"schema_version": "1.0.0", "ok": True}


def test_list_cases_renders_iso(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    handle_open_case(params={"alert_id": "a1"}, db_path=db_path)
    result = handle_list_cases(params={}, db_path=db_path)
    assert result["schema_version"] == "1.0.0"
    assert len(result["cases"]) == 1
    case = result["cases"][0]
    assert case["alert_count"] == 1
    assert isinstance(case["opened_at"], str)
    assert case["closed_at"] is None


def test_get_case_renders_iso(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    case_id = handle_open_case(params={"alert_id": "a1"}, db_path=db_path)["case_id"]
    result = handle_get_case(params={"case_id": case_id}, db_path=db_path)
    assert result["schema_version"] == "1.0.0"
    case = result["case"]
    assert case is not None
    assert isinstance(case["opened_at"], str)
    assert len(case["alerts"]) == 1
    assert isinstance(case["alerts"][0]["ts"], str)
    kinds = [t["kind"] for t in case["timeline"]]
    assert "opened" in kinds
    assert "alert_attached" in kinds
    assert all(isinstance(t["ts"], str) for t in case["timeline"])


def test_get_case_missing_returns_none(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    result = handle_get_case(params={"case_id": "nope"}, db_path=db_path)
    assert result == {"schema_version": "1.0.0", "case": None}


def test_get_case_renders_evidence_captured_at_iso(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")
    case_id = handle_open_case(params={"alert_id": "a1"}, db_path=db_path)["case_id"]
    with Database(db_path) as db:
        db.execute(
            "INSERT INTO case_evidence (case_id, kind, sha256, original_path, captured_at, "
            "meta_json) VALUES (?, 'file', 'deadbeef', '/etc/sudoers', "
            "TIMESTAMP '2026-06-22 00:00:00', '{\"size\": 42}')",
            [case_id],
        )
    result = handle_get_case(params={"case_id": case_id}, db_path=db_path)
    case = result["case"]
    assert case is not None
    assert len(case["evidence"]) == 1
    assert isinstance(case["evidence"][0]["captured_at"], str)


def _seed_case_with_evidence(db, fstore):
    _seed_alert_db(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"payload")
    db.execute(
        "INSERT INTO case_evidence (case_id, kind, sha256, original_path, captured_at, meta_json) "
        "VALUES (?, 'file', ?, '/etc/x', TIMESTAMP '2026-06-20 00:00:00', '{}')",
        [case_id, sha],
    )
    return case_id, sha


def test_export_case_zip_handler_round_trip_and_custody(tmp_path) -> None:
    db = _db(tmp_path)
    fstore = ForensicStore(tmp_path / "evidence")
    case_id, _sha = _seed_case_with_evidence(db, fstore)
    db.close()

    resp = ipc_handlers.handle_export_case_zip(
        params={"case_id": case_id},
        db_path=tmp_path / "t.duckdb",
        evidence_dir=tmp_path / "evidence",
    )
    raw = base64.b64decode(resp["content_b64"])
    assert "case.json" in zipfile.ZipFile(io.BytesIO(raw)).namelist()
    assert resp["filename"].endswith(".zip")

    db2 = _db(tmp_path)  # reopen; migrations are idempotent
    try:
        kinds = [
            r[0]
            for r in db2.query(
                "SELECT kind FROM case_event WHERE case_id = ?", [case_id]
            ).fetchall()
        ]
        assert "exported" in kinds
    finally:
        db2.close()


def test_export_case_zip_handler_not_found(tmp_path) -> None:
    _db(tmp_path).close()
    resp = ipc_handlers.handle_export_case_zip(
        params={"case_id": "nope"},
        db_path=tmp_path / "t.duckdb",
        evidence_dir=tmp_path / "evidence",
    )
    assert resp["ok"] is False and resp["error"] == "not found"


def test_download_evidence_handler_round_trip_and_custody(tmp_path) -> None:
    db = _db(tmp_path)
    fstore = ForensicStore(tmp_path / "evidence")
    case_id, sha = _seed_case_with_evidence(db, fstore)
    db.close()

    resp = ipc_handlers.handle_download_evidence(
        params={"case_id": case_id, "sha": sha},
        db_path=tmp_path / "t.duckdb",
        evidence_dir=tmp_path / "evidence",
    )
    assert base64.b64decode(resp["content_b64"]) == b"payload"
    assert resp["media_type"] == "application/octet-stream"

    db2 = _db(tmp_path)
    try:
        kinds = [
            r[0]
            for r in db2.query(
                "SELECT kind FROM case_event WHERE case_id = ?", [case_id]
            ).fetchall()
        ]
        assert "evidence_downloaded" in kinds
    finally:
        db2.close()


def test_download_evidence_handler_not_found(tmp_path) -> None:
    db = _db(tmp_path)
    _seed_alert_db(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    db.close()
    resp = ipc_handlers.handle_download_evidence(
        params={"case_id": case_id, "sha": "d" * 64},
        db_path=tmp_path / "t.duckdb",
        evidence_dir=tmp_path / "evidence",
    )
    assert resp["ok"] is False and resp["error"] == "not found"


def test_export_case_zip_handler_too_large(tmp_path, monkeypatch) -> None:
    db = _db(tmp_path)
    fstore = ForensicStore(tmp_path / "evidence")
    case_id, _sha = _seed_case_with_evidence(db, fstore)
    db.close()
    monkeypatch.setattr(export, "_MAX_EXPORT_BYTES", 1)
    resp = ipc_handlers.handle_export_case_zip(
        params={"case_id": case_id},
        db_path=tmp_path / "t.duckdb",
        evidence_dir=tmp_path / "evidence",
    )
    assert resp["schema_version"] == "1.0.0"
    assert resp["ok"] is False and resp["error"] == "too_large"


def test_download_evidence_handler_too_large(tmp_path, monkeypatch) -> None:
    db = _db(tmp_path)
    fstore = ForensicStore(tmp_path / "evidence")
    case_id, sha = _seed_case_with_evidence(db, fstore)
    db.close()
    monkeypatch.setattr(export, "_MAX_EXPORT_BYTES", 1)
    resp = ipc_handlers.handle_download_evidence(
        params={"case_id": case_id, "sha": sha},
        db_path=tmp_path / "t.duckdb",
        evidence_dir=tmp_path / "evidence",
    )
    assert resp["schema_version"] == "1.0.0"
    assert resp["ok"] is False and resp["error"] == "too_large"
