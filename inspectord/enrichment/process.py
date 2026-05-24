"""Process enricher.

Given an Event with ``process.pid`` set, fills in:
  - ``process.executable`` (from /proc/<pid>/exe symlink)
  - ``process.hash.sha256`` (SHA-256 of the executable; cached)
  - ``process.command_line`` (from /proc/<pid>/cmdline)
  - ``process.parent`` (pid + name from /proc/<pid>/stat)

A missing process is a no-op — by the time we're enriching, the process may
have exited and that's fine.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Protocol

from inspectord.schemas.event import Event


class ProcReader(Protocol):
    def read_pid(self, pid: int) -> dict[str, object] | None: ...


class _RealProcReader:
    """Reads /proc/<pid>/ directly. SHA-256 cached by (path, mtime)."""

    def __init__(self) -> None:
        self._hash_cache: dict[tuple[str, float], str] = {}

    def read_pid(self, pid: int) -> dict[str, object] | None:
        base = Path(f"/proc/{pid}")
        if not base.exists():
            return None
        out: dict[str, object] = {}
        try:
            exe = (base / "exe").resolve()
            if exe.exists():
                out["exe"] = str(exe)
                stat = exe.stat()
                key = (str(exe), stat.st_mtime)
                if key not in self._hash_cache:
                    self._hash_cache[key] = self._sha256(exe)
                out["exe_sha256"] = self._hash_cache[key]
        except (PermissionError, FileNotFoundError):
            pass
        try:
            raw = (base / "cmdline").read_bytes().replace(b"\x00", b" ")
            cmdline = raw.decode("utf-8", "replace").strip()
            if cmdline:
                out["cmdline"] = cmdline
        except (PermissionError, FileNotFoundError):
            pass
        try:
            stat_text = (base / "stat").read_text(encoding="utf-8", errors="replace")
            close = stat_text.rfind(")")
            if close > 0:
                fields = stat_text[close + 1 :].strip().split()
                if len(fields) >= 2:
                    out["ppid"] = int(fields[1])
        except (PermissionError, FileNotFoundError, ValueError):
            pass
        if out.get("ppid"):
            parent = Path(f"/proc/{out['ppid']}")
            try:
                pcomm = (parent / "comm").read_text(encoding="utf-8", errors="replace").strip()
                if pcomm:
                    out["parent_comm"] = pcomm
            except (PermissionError, FileNotFoundError):
                pass
        return out or None

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


_default_reader = _RealProcReader()


def enrich_process(ev: Event, *, reader: ProcReader | None = None) -> Event:
    """Return a new Event with process fields filled in where possible."""
    proc = ev.process
    if not proc or "pid" not in proc:
        return ev
    pid_raw = proc.get("pid")
    try:
        pid = int(pid_raw) if pid_raw is not None else None
    except (TypeError, ValueError):
        return ev
    if pid is None:
        return ev
    data = (reader or _default_reader).read_pid(pid)
    if data is None:
        return ev
    new_process: dict[str, Any] = dict(proc)
    if "exe" in data and "executable" not in new_process:
        new_process["executable"] = data["exe"]
    if "exe_sha256" in data:
        hash_block = dict(new_process.get("hash", {}))
        hash_block["sha256"] = data["exe_sha256"]
        new_process["hash"] = hash_block
    if "cmdline" in data and "command_line" not in new_process:
        new_process["command_line"] = data["cmdline"]
    if "ppid" in data:
        new_process["parent"] = {"pid": data["ppid"]}
        if "parent_comm" in data:
            new_process["parent"]["name"] = data["parent_comm"]
    return ev.model_copy(update={"process": new_process})
