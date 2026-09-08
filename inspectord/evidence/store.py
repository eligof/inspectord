"""Content-addressed forensic blob store (spec §3.1).

Blobs are written atomically with mode 0600 (no world/group-readable window) into a
0700 sharded tree: <root>/<sha[:2]>/<sha>. Idempotent: identical content is stored once.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

#: One os.read per loop turn — put_stream's peak memory is one of these.
_STREAM_CHUNK_BYTES = 1024 * 1024


class BlobTooLarge(Exception):
    """A streaming put exceeded its byte cap.

    Refusal, not truncation (quarantine design §3.2): a truncated blob could
    never restore, so the tmp file is unlinked and nothing is stored.
    """

    def __init__(self, max_bytes: int) -> None:
        super().__init__(f"source exceeds the {max_bytes}-byte cap; nothing was stored")
        self.max_bytes = max_bytes


class ForensicStore:
    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def path_for(self, sha: str) -> Path:
        return self._root / sha[:2] / sha

    def put(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        dest = self.path_for(sha)
        if dest.exists():
            return sha
        shard = dest.parent
        os.makedirs(shard, mode=0o700, exist_ok=True)
        # makedirs honors umask on intermediate dirs; force 0700 on BOTH the root and the
        # shard so the whole tree is private (the root would otherwise be umask-dependent).
        os.chmod(self._root, 0o700)
        os.chmod(shard, 0o700)
        # Unique tmp name per call: pid alone collides across the threaded workers that drive
        # capture, so a second thread putting identical content would hit O_EXCL otherwise.
        tmp = shard / f".tmp-{sha}-{os.getpid()}-{secrets.token_hex(8)}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            # os.open honors umask; force 0600 so the mode holds regardless of umask.
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, dest)  # atomic; dest inherits tmp's 0600
        finally:
            if tmp.exists():
                tmp.unlink()
        return sha

    def put_stream(self, fd: int, *, max_bytes: int) -> tuple[str, int]:
        """Stream `fd` into the store with O(chunk) memory. Returns (sha, size).

        Same discipline as `put` — O_EXCL 0600 tmp file, fsync before the
        atomic rename, content-addressed dedup — but chunked, so a near-cap
        file never peaks at ~2x its size in RAM (quarantine design §3.2).
        Exceeding `max_bytes` unlinks the tmp file and raises `BlobTooLarge`;
        the dedup check happens at rename time, after the true hash is known.
        """
        os.makedirs(self._root, mode=0o700, exist_ok=True)
        os.chmod(self._root, 0o700)
        hasher = hashlib.sha256()
        size = 0
        tmp = self._root / f".tmp-stream-{os.getpid()}-{secrets.token_hex(8)}"
        out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            # os.open honors umask; force 0600 so the mode holds regardless.
            os.fchmod(out, 0o600)
            with os.fdopen(out, "wb") as fh:
                while chunk := os.read(fd, _STREAM_CHUNK_BYTES):
                    size += len(chunk)
                    if size > max_bytes:
                        raise BlobTooLarge(max_bytes)
                    hasher.update(chunk)
                    fh.write(chunk)
                fh.flush()
                os.fsync(fh.fileno())
            sha = hasher.hexdigest()
            dest = self.path_for(sha)
            if dest.exists():
                return sha, size  # dedup; the finally clause removes the tmp
            shard = dest.parent
            os.makedirs(shard, mode=0o700, exist_ok=True)
            os.chmod(shard, 0o700)
            os.replace(tmp, dest)  # atomic; dest inherits tmp's 0600
            return sha, size
        finally:
            if tmp.exists():
                tmp.unlink()
