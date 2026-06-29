"""Tests for case ZIP export (spec §2.1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.cases import export
from inspectord.evidence.store import ForensicStore


def _store(tmp_path: Path) -> ForensicStore:
    return ForensicStore(tmp_path / "evidence")


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
        "case_id": "c1", "title": "t", "status": "closed",
        "opened_at": "x", "closed_at": "y",
        "alerts": [], "timeline": [], "evidence": [],
    }
    text = export._build_narrative(case, skipped=[])
    assert "Missing evidence" not in text
