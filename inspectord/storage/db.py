"""DuckDB connection wrapper.

Centralizes connect/close, parametrized queries, and transactional helpers.
The wrapper is intentionally thin — DuckDB's own API is already pleasant.
"""

from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import Any

import duckdb


class Database:
    """A single-process DuckDB handle. Not thread-safe — use one per process."""

    def __init__(self, path: Path, *, read_only: bool = False) -> None:
        self._path = Path(path)
        self._read_only = read_only
        self._conn: duckdb.DuckDBPyConnection | None = None

    @property
    def path(self) -> Path:
        return self._path

    def connect(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = duckdb.connect(str(self._path), read_only=self._read_only)
        # Always interpret TIMESTAMP columns as UTC so naive datetimes returned
        # by DuckDB are consistent across hosts regardless of the local timezone.
        self._conn.execute("SET TimeZone='UTC'")

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _require(self) -> duckdb.DuckDBPyConnection:
        if self._conn is None:
            raise RuntimeError("Database is not connected")
        return self._conn

    def execute(self, sql: str, params: list[Any] | None = None) -> None:
        self._require().execute(sql, params or [])

    def query(self, sql: str, params: list[Any] | None = None) -> duckdb.DuckDBPyConnection:
        return self._require().execute(sql, params or [])

    def __enter__(self) -> Database:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
