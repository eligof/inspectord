"""DuckDB connection wrapper.

Centralizes connect/close, parametrized queries, and transactional helpers.
The wrapper is intentionally thin — DuckDB's own API is already pleasant.
"""

from __future__ import annotations

import threading
from pathlib import Path
from types import TracebackType
from typing import Any

import duckdb


class Database:
    """A single-process DuckDB handle, safe to share across threads.

    ``duckdb.threadsafety`` is 1 — "threads may share the module, but not
    connections". Sharing one connection is specifically unsafe for *reads*:
    ``query()`` hands the connection back so the caller can ``.fetchall()``,
    and a concurrent ``execute()`` on another thread replaces the pending
    result set in between — wrong rows, no exception. So every thread gets its
    own ``.cursor()`` (a thread-local connection to the same database, which is
    DuckDB's own recommendation) transparently, and call sites need no changes.

    A cursor does NOT inherit the parent's session settings, so each one is
    given the same ``SET TimeZone='UTC'`` the parent connection gets.
    """

    def __init__(self, path: Path, *, read_only: bool = False) -> None:
        self._path = Path(path)
        self._read_only = read_only
        self._conn: duckdb.DuckDBPyConnection | None = None
        # Per-thread cursor, plus the connection it was derived from so a
        # reconnect invalidates cursors left over from the previous one.
        self._local = threading.local()

    @property
    def path(self) -> Path:
        return self._path

    def connect(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = duckdb.connect(str(self._path), read_only=self._read_only)
        self._configure(self._conn)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        # Drop this thread's cursor eagerly; other threads' cursors are
        # invalidated by the connection identity check in _require() and are
        # released when their owning thread ends.
        self._local.__dict__.clear()

    @staticmethod
    def _configure(conn: duckdb.DuckDBPyConnection) -> None:
        # Always interpret TIMESTAMP columns as UTC so naive datetimes returned
        # by DuckDB are consistent across hosts regardless of the local timezone.
        # This is a *session* setting, so it must be applied per cursor too.
        conn.execute("SET TimeZone='UTC'")

    def _require(self) -> duckdb.DuckDBPyConnection:
        conn = self._conn
        if conn is None:
            raise RuntimeError("Database is not connected")
        cursor: duckdb.DuckDBPyConnection | None = getattr(self._local, "cursor", None)
        if cursor is None or getattr(self._local, "conn", None) is not conn:
            cursor = conn.cursor()
            self._configure(cursor)
            self._local.conn = conn
            self._local.cursor = cursor
        return cursor

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
