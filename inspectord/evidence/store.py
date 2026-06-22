"""Content-addressed forensic blob store (spec §3.1).

Blobs are written atomically with mode 0600 (no world/group-readable window) into a
0700 sharded tree: <root>/<sha[:2]>/<sha>. Idempotent: identical content is stored once.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


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
        # makedirs honors umask on intermediate dirs; force the shard mode explicitly.
        os.chmod(shard, 0o700)
        tmp = shard / f".tmp-{sha}-{os.getpid()}"
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
