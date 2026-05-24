"""Append-mode file tailer with simple inode-rotation handling."""

from __future__ import annotations

import os
import time
from io import TextIOWrapper
from pathlib import Path


class TailingFileSource:
    def __init__(self, path: Path, *, from_start: bool = False) -> None:
        self._path = Path(path)
        self._from_start = from_start
        self._fh: TextIOWrapper | None = None
        self._inode: int | None = None
        self._buffer = ""

    def open(self) -> None:
        self._reopen_if_needed(initial=True)

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None
        self._inode = None
        self._buffer = ""

    def _reopen_if_needed(self, *, initial: bool = False) -> None:
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
                self._inode = None
            return
        if self._inode == stat.st_ino and self._fh is not None:
            return
        if self._fh is not None:
            self._fh.close()
        self._fh = self._path.open("r", encoding="utf-8", errors="replace")
        self._inode = stat.st_ino
        if initial and not self._from_start:
            self._fh.seek(0, os.SEEK_END)

    def read_one(self, *, timeout: float = 0.5) -> str | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() <= deadline:
            self._reopen_if_needed()
            if self._fh is not None:
                chunk = self._fh.readline()
                if chunk:
                    self._buffer += chunk
                    if self._buffer.endswith("\n"):
                        line = self._buffer[:-1]
                        self._buffer = ""
                        return line
            time.sleep(0.02)
        return None
