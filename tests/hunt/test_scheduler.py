"""HuntScheduler (hunt-followups design §4) — driven synchronously via tick().

No test sleeps: the thread loop is a thin `while not stop: tick(); wait()`, so
every behavior here is exercised by calling `tick(now=...)` directly with a
controlled clock.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import inspectord.hunt.scheduler as scheduler_mod
from inspectord.hunt import store
from inspectord.hunt.compiler import MAX_LIMIT, CompiledQuery
from inspectord.hunt.errors import HuntExecutionError
from inspectord.hunt.scheduler import HuntScheduler
from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
from inspectord.storage.migrations import run_migrations

NOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)
EXPR = 'process.name == "beacon"'


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    with Database(tmp_path / "sched.duckdb") as handle:
        run_migrations(handle)
        yield handle


def _insert(db: Database, *, name: str = "beacon", ts: datetime | None = None) -> Event:
    event = build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"name": name},
        ts=ts,
    )
    insert_event(db, event, event.model_dump_json())
    return event


def _max_seq(db: Database) -> int:
    row = db.query("SELECT COALESCE(MAX(ingest_seq), 0) FROM events_enriched").fetchall()
    return int(row[0][0])


def _schedule(
    db: Database,
    *,
    name: str = "q1",
    expression: str = EXPR,
    interval_s: int = 300,
    severity: str = "medium",
) -> None:
    store.save_query(db, name=name, expression=expression)
    store.schedule_query(
        db, name=name, interval_s=interval_s, severity=severity, max_ingest_seq=_max_seq(db)
    )


def _row(db: Database, name: str = "q1") -> store.HuntQuery:
    query = store.get_query(db, name)
    assert query is not None
    return query


# --------------------------------------------------------------------------
# emission shape (§4.4)
# --------------------------------------------------------------------------


def test_match_run_emits_exactly_one_summary_event(db: Database) -> None:
    _schedule(db)
    matching = [_insert(db) for _ in range(3)]
    _insert(db, name="innocent")
    upper = _max_seq(db)

    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)

    assert len(emitted) == 1
    event = emitted[0]
    assert event.module == "hunt_scheduler"
    assert event.action == "hunt_match"
    assert event.kind.value == "signal"
    assert event.severity.value == "medium"
    assert event.hunt is not None
    assert event.hunt["name"] == "q1"
    assert event.hunt["severity"] == "medium"
    assert event.hunt["match_count"] == 3
    assert sorted(event.hunt["sample_event_ids"]) == sorted(e.event_id for e in matching)
    assert event.hunt["window_upper_seq"] == upper
    assert isinstance(event.hunt["run_duration_s"], float)
    assert event.hunt["truncated"] is False
    assert event.hunt["pruned_gap"] is False
    # §4.4: the expression may contain the hostile bytes it hunts for — it
    # never rides in the payload.
    assert "expression" not in event.hunt


def test_event_severity_follows_schedule_severity(db: Database) -> None:
    _schedule(db, severity="high")
    _insert(db)
    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)
    assert emitted[0].severity.value == "high"
    assert emitted[0].hunt is not None
    assert emitted[0].hunt["severity"] == "high"


def test_sample_event_ids_are_capped_at_twenty(db: Database) -> None:
    _schedule(db)
    for _ in range(25):
        _insert(db)
    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)
    assert len(emitted) == 1
    assert emitted[0].hunt is not None
    assert emitted[0].hunt["match_count"] == 25
    assert len(emitted[0].hunt["sample_event_ids"]) == 20


# --------------------------------------------------------------------------
# watermark semantics (§4.3)
# --------------------------------------------------------------------------


def test_zero_matches_emits_nothing_but_advances_watermark(db: Database) -> None:
    _schedule(db)
    _insert(db, name="innocent")
    upper = _max_seq(db)

    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)

    assert emitted == []
    row = _row(db)
    assert row.watermark_seq == upper
    assert row.last_run_at == NOW
    assert row.last_status == "ok"


def test_no_new_events_skips_run_entirely(db: Database) -> None:
    _insert(db)
    _schedule(db)  # watermark starts at the current MAX(ingest_seq)

    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)

    assert emitted == []
    row = _row(db)
    # No run happened at all: nothing was stamped.
    assert row.last_run_at is None
    assert row.last_status is None


def test_empty_table_skips_run_entirely(db: Database) -> None:
    _schedule(db)
    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)
    assert emitted == []
    assert _row(db).last_run_at is None


def test_late_persisted_event_with_old_ts_is_matched_by_next_run(db: Database) -> None:
    """The concilium-BLOCKING regression: the watermark is ingest order, never
    event `ts`, so an event persisted late — with a `ts` far older than the
    previous run — must be picked up by the next run."""
    _schedule(db)
    _insert(db)
    emitted: list[Event] = []
    scheduler = HuntScheduler(db=db, emit=emitted.append)
    scheduler.tick(now=NOW)
    assert len(emitted) == 1
    emitted.clear()

    # Old capture time (well outside any "recent" default window), fresh ingest.
    late = _insert(db, ts=NOW - timedelta(days=30))
    scheduler.tick(now=NOW + timedelta(seconds=301))

    assert len(emitted) == 1
    assert emitted[0].hunt is not None
    assert emitted[0].hunt["match_count"] == 1
    assert emitted[0].hunt["sample_event_ids"] == [late.event_id]


def test_truncated_run_sets_flag_and_still_advances_watermark(db: Database) -> None:
    _schedule(db)
    # MAX_LIMIT + 1 matching rows in one INSERT..SELECT: same columns and the
    # same nextval() the real insert path uses, just not one statement per row.
    db.execute(
        "INSERT INTO events_enriched "
        "(event_id, ts, kind, module, action, severity, payload_json, ingest_seq) "
        "SELECT 'bulk-' || i, ?, 'event', 'process_collector', 'process_start', 'info', "
        '\'{"process": {"name": "beacon"}}\', nextval(\'event_ingest_seq\') '
        f"FROM range({MAX_LIMIT + 1}) t(i)",
        [NOW],
    )
    upper = _max_seq(db)

    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)

    assert len(emitted) == 1
    assert emitted[0].hunt is not None
    assert emitted[0].hunt["truncated"] is True
    assert emitted[0].hunt["match_count"] == MAX_LIMIT
    # §4.3 item 3: the uncounted remainder is deliberately not re-scanned.
    assert _row(db).watermark_seq == upper


def test_pruned_gap_is_flagged_when_watermark_predates_surviving_rows(db: Database) -> None:
    _schedule(db)  # watermark 0
    for _ in range(3):
        _insert(db)
    # Retention ate the oldest rows of the un-scanned gap.
    db.execute("DELETE FROM events_enriched WHERE ingest_seq <= 2")

    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)

    assert len(emitted) == 1
    assert emitted[0].hunt is not None
    assert emitted[0].hunt["pruned_gap"] is True


# --------------------------------------------------------------------------
# failure handling (§4.4, §4.7)
# --------------------------------------------------------------------------


def _breaker(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(db: Database, compiled: CompiledQuery) -> Any:
        raise HuntExecutionError("the database could not run this query")

    monkeypatch.setattr(scheduler_mod, "run_hunt_query", boom)


def test_failure_emits_on_transition_only_and_holds_watermark(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_run = scheduler_mod.run_hunt_query
    _schedule(db)
    _insert(db)
    emitted: list[Event] = []
    scheduler = HuntScheduler(db=db, emit=emitted.append)

    _breaker(monkeypatch)
    scheduler.tick(now=NOW)
    assert len(emitted) == 1
    failed = emitted[0]
    assert failed.action == "hunt_run_failed"
    assert failed.module == "hunt_scheduler"
    assert failed.severity.value == "medium"
    assert failed.hunt == {"name": "q1", "severity": "medium", "error_kind": "execution"}
    row = _row(db)
    assert row.last_status == "failed:execution"
    assert row.watermark_seq == 0  # held: the window is retried

    # Second failing tick: still failed, no re-emission (288/day is flood).
    scheduler.tick(now=NOW + timedelta(seconds=301))
    assert len(emitted) == 1
    assert _row(db).last_run_at == NOW + timedelta(seconds=301)

    # Recovery: the next successful run matches and the streak resets.
    monkeypatch.setattr(scheduler_mod, "run_hunt_query", real_run)
    scheduler.tick(now=NOW + timedelta(seconds=602))
    assert len(emitted) == 2
    assert emitted[1].action == "hunt_match"
    assert _row(db).last_status == "ok"

    # A fresh failure after the success is a new ok→failed transition: it emits.
    _insert(db)
    _breaker(monkeypatch)
    scheduler.tick(now=NOW + timedelta(seconds=903))
    assert len(emitted) == 3
    assert emitted[2].action == "hunt_run_failed"


def test_backoff_after_three_consecutive_failures(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    _schedule(db, interval_s=300)
    _insert(db)
    emitted: list[Event] = []
    scheduler = HuntScheduler(db=db, emit=emitted.append)
    _breaker(monkeypatch)

    third = NOW + timedelta(seconds=602)
    scheduler.tick(now=NOW)
    scheduler.tick(now=NOW + timedelta(seconds=301))
    scheduler.tick(now=third)
    assert _row(db).last_run_at == third

    # Streak is 3: not due again before max(interval, 3600) s after the last run.
    scheduler.tick(now=third + timedelta(seconds=3599))
    assert _row(db).last_run_at == third

    retry = third + timedelta(seconds=3601)
    scheduler.tick(now=retry)
    assert _row(db).last_run_at == retry
    # Transition-only emission: exactly the first failure emitted.
    assert len(emitted) == 1


def test_unschedule_mid_run_discards_the_result(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The --off-while-running race (§4.3 item 4): the guarded stamp reports
    the schedule changed under the run and the run's result is discarded."""
    real_run = scheduler_mod.run_hunt_query
    _schedule(db)
    _insert(db)

    def unschedule_then_run(handle: Database, compiled: CompiledQuery) -> Any:
        store.unschedule_query(db, name="q1")
        return real_run(handle, compiled)

    monkeypatch.setattr(scheduler_mod, "run_hunt_query", unschedule_then_run)
    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)

    assert emitted == []
    row = _row(db)
    assert row.watermark_seq == 0  # nothing was stamped
    assert row.last_run_at is None


def test_unschedule_mid_failing_run_discards_the_failure(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The --off-while-running race on the FAILURE path (§4.3 item 4): the
    guarded stamp reports the schedule changed under the run, so no failure
    event may be emitted for a query that is no longer a standing detection."""
    _schedule(db)
    _insert(db)

    def unschedule_then_boom(handle: Database, compiled: CompiledQuery) -> Any:
        store.unschedule_query(db, name="q1")
        raise HuntExecutionError("boom")

    monkeypatch.setattr(scheduler_mod, "run_hunt_query", unschedule_then_boom)
    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)

    assert emitted == []
    row = _row(db)
    assert row.last_status is None  # nothing was stamped
    assert row.last_run_at is None


def test_unexpected_exception_in_one_query_is_contained(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#127 lesson: one query blowing up must not take the tick — or the other
    due queries — down with it."""
    real_run = scheduler_mod.run_hunt_query
    expr_a = 'process.name == "aaa"'
    _schedule(db, name="a", expression=expr_a)
    _schedule(db, name="b")
    _insert(db)
    _insert(db, name="aaa")

    def explode_for_a(handle: Database, compiled: CompiledQuery) -> Any:
        if compiled.expression == expr_a:
            raise RuntimeError("boom")
        return real_run(handle, compiled)

    monkeypatch.setattr(scheduler_mod, "run_hunt_query", explode_for_a)
    emitted: list[Event] = []
    HuntScheduler(db=db, emit=emitted.append).tick(now=NOW)

    actions = [(e.hunt or {}).get("name") for e in emitted]
    assert ("a" in actions) and ("b" in actions)
    by_name = {(e.hunt or {}).get("name"): e for e in emitted}
    assert by_name["a"].action == "hunt_run_failed"
    assert by_name["a"].hunt is not None
    assert by_name["a"].hunt["error_kind"] == "internal"
    assert by_name["b"].action == "hunt_match"
    assert _row(db, "a").last_status == "failed:internal"
    assert _row(db, "b").last_status == "ok"


# --------------------------------------------------------------------------
# lifecycle
# --------------------------------------------------------------------------


def test_start_stop_and_liveness(db: Database) -> None:
    scheduler = HuntScheduler(db=db, emit=lambda event: None)
    assert scheduler.is_alive() is False
    scheduler.start()
    assert scheduler.is_alive() is True
    scheduler.stop()
    assert scheduler.is_alive() is False


def test_tick_stamps_last_tick_at(db: Database) -> None:
    scheduler = HuntScheduler(db=db, emit=lambda event: None)
    assert scheduler.last_tick_at is None
    scheduler.tick(now=NOW)
    assert scheduler.last_tick_at == NOW
