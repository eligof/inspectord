"""Symlink/TOCTOU-safe capture of an attacker-influenced file path, as the root daemon.

Never follows a symlink, never blocks (FIFO/device), never exceeds the size cap, and
refuses sensitive paths — so a crafted implicated path cannot hang a worker thread or
exfiltrate secrets into the forensic store (spec §3.3, §11).
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

log = logging.getLogger(__name__)

_MAX_FILE_BYTES = 32 * 1024 * 1024  # 32 MiB

# Resolved-path prefixes we refuse to read into the forensic store.
_DENY_PREFIXES = (
    "/proc",
    "/sys",
    "/dev",
    "/etc/shadow",
    "/etc/gshadow",
    "/root/.ssh",
)


def _path_allowed(path: str) -> bool:
    if not os.path.isabs(path):
        return False
    if ".." in Path(path).parts:
        return False
    real = os.path.realpath(path)
    return not any(real == deny or real.startswith(deny + "/") for deny in _DENY_PREFIXES)


def read_capture(path: str, *, max_bytes: int = _MAX_FILE_BYTES) -> bytes | None:
    """Return up to max_bytes of the file, or None if it can't/shouldn't be captured.

    Truncates silently at max_bytes (the caller records `truncated`). Best-effort: any
    error or unsafe condition returns None.
    """
    if not _path_allowed(path):
        log.info("evidence: refused implicated path %r", path)
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        log.info("evidence: cannot open %r: %r", path, exc)
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None  # FIFO/device/dir/socket — never read
        # Read from THIS fd (never re-open by path); cap on the read, not the pre-stat size.
        chunks: list[bytes] = []
        remaining = max_bytes
        while remaining > 0:
            try:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
            except BlockingIOError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError as exc:
        log.info("evidence: read failed %r: %r", path, exc)
        return None
    finally:
        os.close(fd)
