"""Tests for the content-addressed forensic store (spec §3.1)."""

from __future__ import annotations

import hashlib
import os
import resource
import stat
import threading
from pathlib import Path

import pytest

from inspectord.evidence.store import BlobTooLarge, ForensicStore


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


# ---------------------------------------------------------------------------
# put_stream (quarantine design §3.2): O(chunk) memory, refusal-not-truncation
# ---------------------------------------------------------------------------


def _open_ro(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC)


def test_put_stream_matches_put(tmp_path: Path) -> None:
    data = b"streamed bytes" * 100
    src = tmp_path / "src"
    src.write_bytes(data)
    store = ForensicStore(tmp_path / "ev")
    fd = _open_ro(src)
    try:
        sha, size = store.put_stream(fd, max_bytes=1 << 20)
    finally:
        os.close(fd)
    assert sha == hashlib.sha256(data).hexdigest()
    assert size == len(data)
    blob = store.path_for(sha)
    assert blob.read_bytes() == data
    assert stat.S_IMODE(blob.stat().st_mode) == 0o600
    assert stat.S_IMODE(blob.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "ev").stat().st_mode) == 0o700
    assert list(blob.parent.iterdir()) == [blob]  # no .tmp leftover
    # Byte-for-byte the same destination `put` would have chosen.
    assert store.put(data) == sha


def test_put_stream_dedups_existing_blob_without_rewrite(tmp_path: Path) -> None:
    data = b"already stored"
    store = ForensicStore(tmp_path / "ev")
    sha_put = store.put(data)
    before = store.path_for(sha_put).stat()
    src = tmp_path / "src"
    src.write_bytes(data)
    fd = _open_ro(src)
    try:
        sha, size = store.put_stream(fd, max_bytes=1 << 20)
    finally:
        os.close(fd)
    assert sha == sha_put
    assert size == len(data)
    after = store.path_for(sha).stat()
    assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)
    assert list(store.path_for(sha).parent.iterdir()) == [store.path_for(sha)]
    assert [p for p in (tmp_path / "ev").iterdir() if p.name.startswith(".tmp")] == []


def test_put_stream_over_cap_refuses_and_cleans_tmp(tmp_path: Path) -> None:
    data = b"x" * 100
    src = tmp_path / "src"
    src.write_bytes(data)
    store = ForensicStore(tmp_path / "ev")
    fd = _open_ro(src)
    try:
        with pytest.raises(BlobTooLarge):
            store.put_stream(fd, max_bytes=10)
    finally:
        os.close(fd)
    # No destination, no tmp: the tree holds nothing at all.
    leftovers = [p for p in (tmp_path / "ev").rglob("*")]
    assert leftovers == []


def test_put_stream_memory_stays_o_chunk(tmp_path: Path) -> None:
    # A ~64 MiB source must not be slurped: peak-RSS growth stays far under
    # the file size (the whole point of put_stream — design §3.2).
    src = tmp_path / "big"
    chunk = os.urandom(1 << 20)
    with open(src, "wb") as fh:
        for _ in range(64):
            fh.write(chunk)
    store = ForensicStore(tmp_path / "ev")
    before_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    fd = _open_ro(src)
    try:
        sha, size = store.put_stream(fd, max_bytes=128 << 20)
    finally:
        os.close(fd)
    after_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assert size == 64 << 20
    assert store.path_for(sha).stat().st_size == 64 << 20
    assert (after_kib - before_kib) * 1024 < 32 << 20, "put_stream buffered too much"
