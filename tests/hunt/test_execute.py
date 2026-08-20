"""Running compiled queries against a real DuckDB file: ordering and truncation."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from inspectord.hunt import (
    HuntError,
    HuntExecutionError,
    compile_hunt_query,
    run_hunt_query,
)
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
from inspectord.storage.migrations import run_migrations

BASE = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    with Database(tmp_path / "hunt.duckdb") as handle:
        run_migrations(handle)
        for index in range(5):
            event = build_event(
                module="probe",
                action="tick",
                category=["c"],
                type_=["t"],
                severity="info",
                process={"name": f"p{index}"},
                ts=BASE + timedelta(minutes=index),
            )
            insert_event(handle, event, event.model_dump_json())
        yield handle


def test_all_rows_when_under_the_limit(db: Database) -> None:
    result = run_hunt_query(db, compile_hunt_query('event.module == "probe"', limit=10))
    assert len(result.rows) == 5
    assert result.truncated is False


def test_truncation_is_reported(db: Database) -> None:
    """A silently-cut result set during an investigation is misleading."""
    result = run_hunt_query(db, compile_hunt_query('event.module == "probe"', limit=2))
    assert len(result.rows) == 2
    assert result.truncated is True
    assert result.limit == 2


def test_exactly_the_limit_is_not_truncated(db: Database) -> None:
    result = run_hunt_query(db, compile_hunt_query('event.module == "probe"', limit=5))
    assert len(result.rows) == 5
    assert result.truncated is False


def test_rows_are_newest_first(db: Database) -> None:
    result = run_hunt_query(db, compile_hunt_query('event.module == "probe"', limit=10))
    timestamps = [row.ts for row in result.rows]
    assert timestamps == sorted(timestamps, reverse=True)
    # Truncation keeps the newest half, which is the useful half.
    truncated = run_hunt_query(db, compile_hunt_query('event.module == "probe"', limit=2))
    assert [row.payload_json for row in truncated.rows] == [
        row.payload_json for row in result.rows[:2]
    ]


def test_time_bound_filters_on_the_ts_column(db: Database) -> None:
    result = run_hunt_query(
        db,
        compile_hunt_query('event.module == "probe"', since=BASE + timedelta(minutes=3)),
    )
    assert len(result.rows) == 2


def test_rows_carry_the_persisted_payload(db: Database) -> None:
    result = run_hunt_query(db, compile_hunt_query('process.name == "p3"'))
    assert len(result.rows) == 1
    row = result.rows[0]
    assert row.module == "probe"
    assert row.severity == "info"
    assert '"p3"' in row.payload_json
    assert result.event_ids == (row.event_id,)


def test_no_matches_is_an_empty_untruncated_result(db: Database) -> None:
    result = run_hunt_query(db, compile_hunt_query('process.name == "nobody"'))
    assert result.rows == ()
    assert result.truncated is False


# --------------------------------------------------------------------------
# DuckDB errors never reach a client raw (PR1's deferred item; PR2 owns the
# first external caller, so PR2 owns the wrap).
# --------------------------------------------------------------------------

#: Fragments of the compiled statement and of the daemon's internals. None of
#: these may appear in the message an IPC client is handed.
_INTERNALS = (
    "SELECT",
    "FROM events_enriched",
    "events_enriched",
    "payload_json",
    "json_extract_string",
    "regexp_matches",
    "LINE ",
    "ORDER BY",
    "LIMIT",
)


def test_a_duckdb_runtime_error_becomes_a_hunt_error(db: Database) -> None:
    """RE2 rejects a repetition Python's `re` accepts — a real runtime failure."""
    compiled = compile_hunt_query('process.name MATCHES "a{1001}"')
    with pytest.raises(HuntExecutionError) as caught:
        run_hunt_query(db, compiled)
    assert isinstance(caught.value, HuntError)


def test_the_wrapped_message_shows_the_users_query_and_no_sql(db: Database) -> None:
    compiled = compile_hunt_query('process.name MATCHES "a{1001}"')
    with pytest.raises(HuntExecutionError) as caught:
        run_hunt_query(db, compiled)
    message = str(caught.value)
    assert 'process.name MATCHES "a{1001}"' in message
    for fragment in _INTERNALS:
        assert fragment not in message


def test_a_sql_quoting_duckdb_error_still_leaks_nothing(tmp_path: Path) -> None:
    """DuckDB's catalog errors quote the statement itself; the wrap must not.

    A database with no `events_enriched` produces a `Catalog Error` whose text
    contains `LINE 2: FROM events_enriched` — i.e. the failing SQL fragment and
    a caret. That is precisely what must not reach an IPC client.
    """
    db_path = tmp_path / "no-migrations-here.duckdb"
    with Database(db_path) as handle:
        compiled = compile_hunt_query('process.name == "curl"')
        with pytest.raises(HuntExecutionError) as caught:
            run_hunt_query(handle, compiled)
    message = str(caught.value)
    assert 'process.name == "curl"' in message
    for fragment in _INTERNALS:
        assert fragment not in message
    # Nor a filesystem path.
    assert str(db_path) not in message
    assert "no-migrations-here" not in message


def test_the_duckdb_detail_is_logged_daemon_side(
    db: Database, caplog: pytest.LogCaptureFixture
) -> None:
    """Stripped from the client message, not from the daemon's own log."""
    compiled = compile_hunt_query('process.name MATCHES "a{1001}"')
    with (
        caplog.at_level(logging.WARNING, logger="inspectord.hunt.execute"),
        pytest.raises(HuntExecutionError),
    ):
        run_hunt_query(db, compiled)
    assert "invalid repetition size" in caplog.text
