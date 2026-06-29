"""Tests for case ZIP export (spec §2.1)."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from inspectord.cases import export, store
from inspectord.evidence.store import ForensicStore
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _store(tmp_path: Path) -> ForensicStore:
    return ForensicStore(tmp_path / "evidence")


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _seed_alert(db: Database, alert_id: str) -> None:
    db.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
        "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, payload_json) "
        "VALUES (?, 'r1', TIMESTAMP '2026-06-20 00:00:00', 'high', 'new', 'auth', 'dk', 1, "
        "TIMESTAMP '2026-06-20 00:00:00', TIMESTAMP '2026-06-20 00:00:00', 'short', 'detail', "
        "?)",
        [alert_id, json.dumps({"alert_id": alert_id, "rule_id": "r1"})],
    )


def _add_evidence(db: Database, case_id: str, kind: str, sha: str, path: str = "") -> None:
    db.execute(
        "INSERT INTO case_evidence (case_id, kind, sha256, original_path, captured_at, meta_json) "
        "VALUES (?, ?, ?, ?, TIMESTAMP '2026-06-20 00:00:00', '{}')",
        [case_id, kind, sha, path],
    )


def test_sha_re_accepts_valid_and_rejects_invalid() -> None:
    assert export._SHA_RE.match("a" * 64)
    assert not export._SHA_RE.match("A" * 64)  # uppercase rejected
    assert not export._SHA_RE.match("../../etc/passwd")
    assert not export._SHA_RE.match("a" * 63)


def test_read_blob_returns_bytes_for_stored_content(tmp_path: Path) -> None:
    store = _store(tmp_path)
    sha = store.put(b"hello evidence")
    assert export._read_blob(store, sha) == b"hello evidence"


def test_read_blob_returns_none_for_missing(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert export._read_blob(store, "b" * 64) is None


def test_build_narrative_includes_core_fields_and_missing_section() -> None:
    case = {
        "case_id": "c1",
        "title": "sshd brute force",
        "status": "open",
        "opened_at": "2026-06-20T00:00:00+00:00",
        "closed_at": None,
        "alerts": [
            {"alert_id": "a1", "rule_id": "r1", "severity": "high", "rendered_short": "brute"}
        ],
        "timeline": [{"ts": "2026-06-20T00:00:00+00:00", "kind": "opened", "text": None}],
        "evidence": [
            {"kind": "file", "sha256": "a" * 64, "original_path": "/etc/passwd", "meta": {}}
        ],
    }
    text = export._build_narrative(case, skipped=[("b" * 64, "missing on disk")])
    assert "sshd brute force" in text
    assert "high" in text and "brute" in text
    assert "opened" in text
    assert "/etc/passwd" in text
    assert "Missing evidence" in text
    assert "b" * 64 in text
    assert "missing on disk" in text


def test_build_narrative_omits_missing_section_when_none() -> None:
    case = {
        "case_id": "c1",
        "title": "t",
        "status": "closed",
        "opened_at": "x",
        "closed_at": "y",
        "alerts": [],
        "timeline": [],
        "evidence": [],
    }
    text = export._build_narrative(case, skipped=[])
    assert "Missing evidence" not in text


def test_build_case_zip_contains_expected_members(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"captured bytes")
    _add_evidence(db, case_id, "file", sha, "/etc/passwd")

    data = export.build_case_zip(db, fstore, case_id)
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = set(zf.namelist())
    assert "case.json" in names
    assert "alerts/a1.json" in names
    assert f"evidence/{sha}" in names
    assert "narrative.md" in names
    parsed = json.loads(zf.read("case.json"))
    assert parsed["case_id"] == case_id
    assert zf.read(f"evidence/{sha}") == b"captured bytes"
    assert json.loads(zf.read("alerts/a1.json"))["alert_id"] == "a1"


def test_build_case_zip_missing_case_raises(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(export.CaseNotFound):
        export.build_case_zip(db, _store(tmp_path), "nope")


def test_build_case_zip_skips_missing_blob(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    _add_evidence(db, case_id, "file", "c" * 64, "/gone")  # no blob on disk
    data = export.build_case_zip(db, fstore, case_id)
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert f"evidence/{'c' * 64}" not in set(zf.namelist())
    assert "Missing evidence" in zf.read("narrative.md").decode()


def test_build_case_zip_skips_invalid_sha(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    _add_evidence(db, case_id, "file", "../../etc/passwd", "/x")
    data = export.build_case_zip(db, fstore, case_id)  # must not raise / traverse
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert not any(n.startswith("evidence/..") for n in zf.namelist())


def test_build_case_zip_dedupes_duplicate_sha(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"dup")
    _add_evidence(db, case_id, "file", sha, "/a")
    _add_evidence(db, case_id, "file", sha, "/b")  # same sha, different original_path
    data = export.build_case_zip(db, fstore, case_id)
    names = [n for n in zipfile.ZipFile(io.BytesIO(data)).namelist() if n.startswith("evidence/")]
    assert names.count(f"evidence/{sha}") == 1


def test_build_case_zip_size_cap_raises(tmp_path: Path, monkeypatch) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"x" * 1000)
    _add_evidence(db, case_id, "file", sha, "/big")
    monkeypatch.setattr(export, "_MAX_EXPORT_BYTES", 100)
    with pytest.raises(export.ExportTooLarge):
        export.build_case_zip(db, fstore, case_id)


def test_build_case_zip_empty_case_is_valid(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    data = export.build_case_zip(db, fstore, case_id)
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert "case.json" in zf.namelist() and "narrative.md" in zf.namelist()


def test_read_evidence_blob_file_kind(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"file bytes")
    _add_evidence(db, case_id, "file", sha, "/etc/shadow")
    data, filename, media = export.read_evidence_blob(db, fstore, case_id, sha)
    assert data == b"file bytes"
    assert filename == "shadow"
    assert media == "application/octet-stream"


def test_read_evidence_blob_json_kind(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"{}")
    _add_evidence(db, case_id, "net_state", sha, "")
    _data, filename, media = export.read_evidence_blob(db, fstore, case_id, sha)
    assert media == "application/json"
    assert filename == f"{sha[:12]}-net_state.json"


def test_read_evidence_blob_rejects_non_hex(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(export.EvidenceNotFound):
        export.read_evidence_blob(db, _store(tmp_path), "c1", "NOTHEX")


def test_read_evidence_blob_sha_not_in_case(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"orphan")  # blob exists but not linked to this case
    with pytest.raises(export.EvidenceNotFound):
        export.read_evidence_blob(db, fstore, case_id, sha)
