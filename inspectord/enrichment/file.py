"""File enricher — adds hash/size/owner/mode/setuid where the path exists."""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path
from typing import Any

from inspectord.schemas.event import Event

_HASH_CACHE: dict[tuple[str, int, float, int], str] = {}


def _sha256(path: Path) -> str:
    st = path.stat()
    key = (str(path), st.st_ino, st.st_mtime, st.st_size)
    if key in _HASH_CACHE:
        return _HASH_CACHE[key]
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    digest = h.hexdigest()
    _HASH_CACHE[key] = digest
    return digest


def enrich_file(ev: Event) -> Event:
    f = ev.file
    if not f:
        return ev
    raw_path = f.get("path")
    if not isinstance(raw_path, str):
        return ev
    p = Path(raw_path)
    if not p.exists() or not p.is_file():
        return ev
    new_file: dict[str, Any] = dict(f)
    try:
        st = p.stat()
        new_file["size"] = st.st_size
        new_file["mtime"] = st.st_mtime
        new_file["mode"] = oct(st.st_mode & 0o7777)
        new_file["owner"] = st.st_uid
        new_file["setuid"] = bool(st.st_mode & stat.S_ISUID)
        new_file["setgid"] = bool(st.st_mode & stat.S_ISGID)
        try:
            digest = _sha256(p)
            existing_hash = dict(new_file.get("hash", {}))
            existing_hash["sha256"] = digest
            new_file["hash"] = existing_hash
        except (PermissionError, OSError):
            pass
    except (PermissionError, OSError):
        return ev
    return ev.model_copy(update={"file": new_file})


def reset_hash_cache() -> None:
    """For tests."""
    _HASH_CACHE.clear()
