"""Running compiled queries against a real DuckDB file: ordering and truncation."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from inspectord.hunt import compile_hunt_query, run_hunt_query
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
