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
