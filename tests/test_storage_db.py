"""Tests for the DuckDB connection wrapper."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from inspectord.storage.db import Database


def test_database_creates_file(tmp_path: Path) -> None:
    db_path = tmp_path / "test.duckdb"
    db = Database(db_path)
    db.connect()
    db.close()
    assert db_path.exists()


def test_database_execute_and_query(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    try:
        db.execute("CREATE TABLE t (a INTEGER, b VARCHAR)")
        db.execute("INSERT INTO t VALUES (?, ?)", [1, "hello"])
        rows = db.query("SELECT a, b FROM t").fetchall()
        assert rows == [(1, "hello")]
    finally:
        db.close()


def test_database_context_manager_closes(tmp_path: Path) -> None:
    db_path = tmp_path / "test.duckdb"
    with Database(db_path) as db:
        db.execute("CREATE TABLE t (a INTEGER)")
    with Database(db_path) as db2:
        rows = db2.query("SELECT * FROM t").fetchall()
        assert rows == []


def test_database_reraises_query_after_close(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    db.close()
    with pytest.raises(RuntimeError):
        db.query("SELECT 1")


# --------------------------------------------------------------------------
# Thread safety: one Database, one cursor per thread
# --------------------------------------------------------------------------


def test_query_result_is_not_stolen_by_another_thread(tmp_path: Path) -> None:
    """A pending result set must survive another thread querying in between.

    ``query()`` hands the connection back so the caller can ``.fetchall()``.
    On a shared connection a concurrent query replaces the pending result in
    that window, and the first caller silently fetches the *other* thread's
    rows -- wrong answers, zero exceptions.

    The two Events pin the interleaving, so this fails every time on a shared
    connection rather than only when the timing happens to line up.
    """
    with Database(tmp_path / "test.duckdb") as db:
        db.execute("CREATE TABLE t (who VARCHAR)")
        db.execute("INSERT INTO t VALUES ('a'), ('b')")

        queried = threading.Event()
        interleaved = threading.Event()
        got: list[list[tuple[str]]] = []

        def reader() -> None:
            cursor = db.query("SELECT who FROM t WHERE who = 'a'")
            queried.set()
            # Hold the result open across the other thread's query.
            interleaved.wait(timeout=10)
            got.append(cursor.fetchall())

        thread = threading.Thread(target=reader)
        thread.start()
        assert queried.wait(timeout=10)
        assert db.query("SELECT who FROM t WHERE who = 'b'").fetchall() == [("b",)]
        interleaved.set()
        thread.join(timeout=10)
        assert not thread.is_alive()

        assert got == [[("a",)]], f"the reader thread got another thread's rows: {got}"


def test_every_thread_gets_the_utc_session_timezone(tmp_path: Path) -> None:
    """A per-thread cursor does NOT inherit SET TimeZone -- it must be set on each."""
    with Database(tmp_path / "test.duckdb") as db:
        assert db.query("SELECT current_setting('TimeZone')").fetchall() == [("UTC",)]

        seen: list[list[tuple[str]]] = []

        def reader() -> None:
            seen.append(db.query("SELECT current_setting('TimeZone')").fetchall())

        thread = threading.Thread(target=reader)
        thread.start()
        thread.join(timeout=10)
        assert seen == [[("UTC",)]], f"a worker thread was not on UTC: {seen}"


def test_concurrent_writers_all_land(tmp_path: Path) -> None:
    """Every row written from every thread must be there -- no loss, no error."""
    threads_n, rows_n = 8, 200
    with Database(tmp_path / "test.duckdb") as db:
        db.execute("CREATE TABLE t (tid INTEGER, i INTEGER)")
        # Nobody writes until every thread is ready, so the writes really overlap.
        gate = threading.Barrier(threads_n)
        errors: list[BaseException] = []

        def writer(tid: int) -> None:
            try:
                gate.wait(timeout=30)
                for i in range(rows_n):
                    db.execute("INSERT INTO t VALUES (?, ?)", [tid, i])
            except BaseException as exc:  # reported below, never swallowed
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(tid,)) for tid in range(threads_n)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
            assert not thread.is_alive()

        assert not errors, f"concurrent writes raised: {errors!r}"
        assert db.query("SELECT COUNT(*) FROM t").fetchall() == [(threads_n * rows_n,)]
        assert db.query("SELECT COUNT(DISTINCT tid) FROM t").fetchall() == [(threads_n,)]


def test_reconnect_gives_threads_a_fresh_cursor(tmp_path: Path) -> None:
    """A thread that used the old connection must not keep a cursor onto it."""
    db_path = tmp_path / "test.duckdb"
    db = Database(db_path)
    db.connect()
    try:
        db.execute("CREATE TABLE t (a INTEGER)")

        rows: list[list[tuple[int]]] = []
        errors: list[BaseException] = []
        step = threading.Event()
        reconnected = threading.Event()

        def reader() -> None:
            try:
                db.query("SELECT * FROM t").fetchall()  # binds this thread's cursor
                step.set()
                assert reconnected.wait(timeout=10)
                rows.append(db.query("SELECT a FROM t").fetchall())
            except BaseException as exc:  # reported below, never swallowed
                errors.append(exc)

        thread = threading.Thread(target=reader)
        thread.start()
        assert step.wait(timeout=10)
        db.close()
        db.connect()
        db.execute("INSERT INTO t VALUES (7)")
        reconnected.set()
        thread.join(timeout=10)
        assert not thread.is_alive()

        assert not errors, f"the reader thread kept a cursor onto the closed connection: {errors!r}"
        assert rows == [[(7,)]]
    finally:
        db.close()
