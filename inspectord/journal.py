"""Append-only NDJSON.gz journal with rolling SHA-256 hash chain.

Each line is a JSON object containing the caller-provided payload plus a
`prev_hash` field. `prev_hash` of the first line is 64 zeroes. The hash for
line N is sha256(line_N_serialized_without_terminator). Tampering with any
line breaks the chain from that point on.

The journal rotates daily (UTC) by default.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from inspectord.schemas.versions import JOURNAL_FORMAT_VERSION

ZERO_HASH = "0" * 64


class JournalError(RuntimeError):
    pass


class Journal:
    """Append-only journal. Caller must call close() (or use as context manager)."""

    def __init__(self, dir_path: Path) -> None:
        self._dir = Path(dir_path)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._fh: gzip.GzipFile | None = None
        self._current_date: date | None = None
        self._prev_hash = ZERO_HASH
        self._closed = False

    def _path_for(self, d: date) -> Path:
        return self._dir / f"{d.isoformat()}.jsonl.gz"

    def _open_for_today(self) -> None:
        today = datetime.now(UTC).date()
        if self._fh is not None and self._current_date == today:
            return
        if self._fh is not None:
            self._fh.close()
        path = self._path_for(today)
        if path.exists():
            with gzip.open(path, "rt", encoding="utf-8") as f:
                for raw in f:
                    stripped = raw.rstrip("\n")
                    if not stripped:
                        continue
                    self._prev_hash = hashlib.sha256(stripped.encode("utf-8")).hexdigest()
        else:
            self._prev_hash = ZERO_HASH
        self._fh = gzip.open(path, "ab")  # noqa: SIM115
        self._current_date = today

    def append(self, payload: dict[str, Any]) -> None:
        if self._closed:
            raise JournalError("journal is closed")
        self._open_for_today()
        record = {
            **payload,
            "journal_format_version": JOURNAL_FORMAT_VERSION,
            "prev_hash": self._prev_hash,
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        assert self._fh is not None
        self._fh.write((line + "\n").encode("utf-8"))
        self._prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()

    def flush(self) -> None:
        if self._fh is not None:
            self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        self._closed = True


def verify_chain(path: Path) -> bool:
    """Return True iff every line's prev_hash matches sha256(previous line)."""
    prev_hash = ZERO_HASH
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.rstrip("\n")
            if not stripped:
                continue
            record = json.loads(stripped)
            if record.get("prev_hash") != prev_hash:
                return False
            prev_hash = hashlib.sha256(stripped.encode("utf-8")).hexdigest()
    return True
