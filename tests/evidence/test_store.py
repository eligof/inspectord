"""Tests for the content-addressed forensic store (spec §3.1)."""

from __future__ import annotations

import hashlib
import stat
import threading
from pathlib import Path

from inspectord.evidence.store import ForensicStore


def test_put_is_content_addressed_and_0600(tmp_path: Path) -> None:
    root = tmp_path / "ev"
    store = ForensicStore(root)
    sha = store.put(b"hello")
    assert sha == hashlib.sha256(b"hello").hexdigest()
    p = store.path_for(sha)
    assert p.read_bytes() == b"hello"
    assert p == root / sha[:2] / sha
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700  # shard dir
    assert stat.S_IMODE(root.stat().st_mode) == 0o700  # root dir private too
    assert list(p.parent.iterdir()) == [p]  # no .tmp leftover


def test_concurrent_put_same_content_does_not_clobber(tmp_path: Path) -> None:
    # Two threads putting identical content must not collide on the tmp name (pid alone
    # is not unique across threads) — neither should raise, and one blob results.
    store = ForensicStore(tmp_path / "ev")
    errors: list[BaseException] = []

    def _put() -> None:
        try:
            for _ in range(20):
                store.put(b"concurrent")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=_put) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    sha = hashlib.sha256(b"concurrent").hexdigest()
    assert list(store.path_for(sha).parent.iterdir()) == [store.path_for(sha)]


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
