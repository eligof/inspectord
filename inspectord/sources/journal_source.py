"""journalctl --follow --output=json subprocess wrapper."""

from __future__ import annotations

import contextlib
import json
import subprocess
import time
from collections.abc import Callable
from typing import Any, Protocol


class _Proc(Protocol):
    stdout: Any
    stderr: Any
    returncode: int | None

    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None = None) -> int: ...


def _default_spawn(argv: list[str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)


class JournalSource:
    """Spawns ``journalctl --follow --output=json`` and yields parsed entries."""

    def __init__(
        self,
        *,
        argv: list[str] | None = None,
        spawn: Callable[[list[str]], _Proc] | None = None,
    ) -> None:
        self._argv = argv or [
            "journalctl",
            "--follow",
            "--output=json",
            "--no-pager",
        ]
        self._spawn = spawn if spawn is not None else _default_spawn
        self._proc: _Proc | None = None

    def open(self) -> None:
        if self._proc is not None:
            return
        self._proc = self._spawn(self._argv)

    def close(self) -> None:
        if self._proc is None:
            return
        with contextlib.suppress(Exception):
            self._proc.terminate()
        try:
            self._proc.wait(timeout=2.0)
        except Exception:
            with contextlib.suppress(Exception):
                self._proc.kill()
        self._proc = None

    def read_one(self, *, timeout: float = 0.5) -> dict[str, Any] | None:
        if self._proc is None or self._proc.stdout is None:
            return None
        deadline = time.monotonic() + timeout
        while time.monotonic() <= deadline:
            line = self._proc.stdout.readline()
            if not line:
                if self._proc.poll() is not None:
                    return None
                time.sleep(0.02)
                continue
            try:
                obj = json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                return obj
        return None
