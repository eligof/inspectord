"""Tests for the content-addressed forensic store (spec §3.1)."""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path

from inspectord.evidence.store import ForensicStore


def test_put_is_content_addressed_and_0600(tmp_path: Path) -> None:
    store = ForensicStore(tmp_path / "ev")
    sha = store.put(b"hello")
    assert sha == hashlib.sha256(b"hello").hexdigest()
    p = store.path_for(sha)
    assert p.read_bytes() == b"hello"
    assert p == (tmp_path / "ev") / sha[:2] / sha
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700
    assert list(p.parent.iterdir()) == [p]  # no .tmp leftover


def test_put_idempotent(tmp_path: Path) -> None:
    store = ForensicStore(tmp_path / "ev")
    assert store.put(b"x") == store.put(b"x")
    assert store.put(b"y") != store.put(b"x")
    # putting the same bytes twice leaves exactly one file.
    sha = store.put(b"x")
    assert list(store.path_for(sha).parent.iterdir()) == [store.path_for(sha)]


def test_path_for(tmp_path: Path) -> None:
    store = ForensicStore(tmp_path / "ev")
    sha = "abcdef0123"
    assert store.path_for(sha) == (tmp_path / "ev") / "ab" / sha
