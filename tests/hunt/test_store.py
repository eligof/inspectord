"""Saved hunt queries: name rules, compile-on-save, and the collision policy."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from inspectord.hunt import store
from inspectord.hunt.errors import (
    HuntBoundsError,
    HuntNameError,
    HuntPathError,
    HuntQueryExists,
    HuntQueryNotFound,
    HuntRequestError,
    HuntSyntaxError,
    HuntUnsupportedError,
)
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations

GOOD = 'process.name == "curl"'


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    with Database(tmp_path / "hunt.duckdb") as handle:
        run_migrations(handle)
        yield handle


# --------------------------------------------------------------------------
# names
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "curl",
        "suspicious-curl",
        "curl_2",
        "team.curl",
        "A",
        "0",
        "a" * 64,
    ],
)
def test_valid_names_are_accepted(name: str) -> None:
    assert store.validate_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        " ",
        "a" * 65,
        "-leading-hyphen",
        ".leading-dot",
        "_leading-underscore",
        "has space",
        "has\ttab",
        "has\nnewline",
        "quote'd",
        'quote"d',
        "<script>",
        "a&b",
        "semi;colon",
        "slash/es",
        "back\\slash",
        "percent%",
        "\x1b[31mred",  # ANSI escape — this text is printed to a terminal
        "café",  # non-ASCII: no homoglyphs, no RTL override
        "\u202ereversed",  # right-to-left override
        "null\x00byte",
    ],
)
def test_invalid_names_are_rejected(name: str) -> None:
    with pytest.raises(HuntNameError):
        store.validate_name(name)


def test_the_name_rejection_quotes_the_offending_name() -> None:
    with pytest.raises(HuntNameError) as caught:
        store.validate_name("has space")
    assert "has space" in str(caught.value)


def test_an_overlong_name_says_so() -> None:
    with pytest.raises(HuntNameError) as caught:
        store.validate_name("a" * 65)
    assert "64" in str(caught.value)


# --------------------------------------------------------------------------
# saving compiles (§8)
# --------------------------------------------------------------------------


def test_save_stores_a_compilable_query(db: Database) -> None:
    outcome = store.save_query(db, name="curl", expression=GOOD, description="finds curl")
    assert outcome.replaced is False
    assert outcome.previous_expression is None

    saved = store.get_query(db, "curl")
    assert saved is not None
    assert saved.expression == GOOD
    assert saved.description == "finds curl"
    assert saved.created_at == saved.updated_at


@pytest.mark.parametrize(
    ("expression", "error"),
    [
        ("garbage", HuntSyntaxError),
        ("", HuntSyntaxError),
        ('process..name == "curl"', HuntPathError),
        ('event.ts == "yesterday"', HuntUnsupportedError),
        ('process.name MATCHES "(?=x)"', HuntUnsupportedError),
    ],
)
def test_a_query_that_cannot_compile_is_refused_at_save_time(
    db: Database, expression: str, error: type[Exception]
) -> None:
    """§8: rejected at save time rather than at 2am."""
    with pytest.raises(error):
        store.save_query(db, name="broken", expression=expression)
    assert store.get_query(db, "broken") is None


def test_a_query_matching_nothing_is_still_saveable(db: Database) -> None:
    """§8: saving does not validate a query against events."""
    store.save_query(db, name="quiet", expression='process.name == "nothing-ever"')
    assert store.get_query(db, "quiet") is not None


def test_an_overlong_expression_is_rejected(db: Database) -> None:
    too_long = 'process.name == "' + "a" * store.MAX_EXPRESSION_CHARS + '"'
    with pytest.raises(HuntBoundsError) as caught:
        store.save_query(db, name="huge", expression=too_long)
    assert str(store.MAX_EXPRESSION_CHARS) in str(caught.value)
    assert store.get_query(db, "huge") is None


def test_an_overlong_description_is_rejected_not_truncated(db: Database) -> None:
    with pytest.raises(HuntBoundsError):
        store.save_query(
            db,
            name="wordy",
            expression=GOOD,
            description="d" * (store.MAX_DESCRIPTION_CHARS + 1),
        )
    assert store.get_query(db, "wordy") is None


# --------------------------------------------------------------------------
# collisions
# --------------------------------------------------------------------------


def test_a_colliding_name_is_refused(db: Database) -> None:
    store.save_query(db, name="curl", expression=GOOD)
    with pytest.raises(HuntQueryExists) as caught:
        store.save_query(db, name="curl", expression='process.name == "wget"')
    # The refusal shows what would have been destroyed.
    assert GOOD in str(caught.value)
    assert "replace" in str(caught.value)
    assert store.get_query(db, "curl").expression == GOOD  # type: ignore[union-attr]


def test_replace_overwrites_and_reports_the_previous_expression(db: Database) -> None:
    first = store.save_query(db, name="curl", expression=GOOD)
    second = store.save_query(db, name="curl", expression='process.name == "wget"', replace=True)
    assert second.replaced is True
    assert second.previous_expression == GOOD
    saved = store.get_query(db, "curl")
    assert saved is not None
    assert saved.expression == 'process.name == "wget"'
    # created_at survives a replace; updated_at does not.
    assert saved.created_at == first.created_at
    assert saved.updated_at >= saved.created_at


def test_replace_of_a_missing_name_is_a_plain_create(db: Database) -> None:
    outcome = store.save_query(db, name="new", expression=GOOD, replace=True)
    assert outcome.replaced is False
    assert outcome.previous_expression is None


def test_a_failed_replace_leaves_the_existing_query_intact(db: Database) -> None:
    store.save_query(db, name="curl", expression=GOOD)
    with pytest.raises(HuntSyntaxError):
        store.save_query(db, name="curl", expression="garbage", replace=True)
    saved = store.get_query(db, "curl")
    assert saved is not None
    assert saved.expression == GOOD


# --------------------------------------------------------------------------
# list / get / delete
# --------------------------------------------------------------------------


def test_list_is_alphabetical_by_name(db: Database) -> None:
    for name in ("zeta", "alpha", "mid"):
        store.save_query(db, name=name, expression=GOOD)
    assert [q.name for q in store.list_queries(db)] == ["alpha", "mid", "zeta"]


def test_list_is_empty_on_a_fresh_database(db: Database) -> None:
    assert store.list_queries(db) == []


def test_get_of_a_missing_name_is_none_not_an_error(db: Database) -> None:
    assert store.get_query(db, "nope") is None


def test_get_validates_the_name_before_touching_the_database(db: Database) -> None:
    with pytest.raises(HuntNameError):
        store.get_query(db, "has space")


def test_delete_returns_what_it_deleted(db: Database) -> None:
    store.save_query(db, name="curl", expression=GOOD)
    deleted = store.delete_query(db, "curl")
    assert deleted.expression == GOOD
    assert store.get_query(db, "curl") is None


def test_delete_of_a_missing_name_raises(db: Database) -> None:
    with pytest.raises(HuntQueryNotFound) as caught:
        store.delete_query(db, "nope")
    assert "nope" in str(caught.value)


def test_timestamps_are_utc_aware_on_the_way_out(db: Database) -> None:
    before = datetime.now(tz=UTC)
    store.save_query(db, name="curl", expression=GOOD)
    saved = store.get_query(db, "curl")
    assert saved is not None
    assert saved.created_at.tzinfo is not None
    assert saved.created_at >= before.replace(microsecond=0)


# --------------------------------------------------------------------------
# scheduling (hunt-followups design §4.3, §4.6)
# --------------------------------------------------------------------------

NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)


def _saved(db: Database, name: str = "curl") -> None:
    store.save_query(db, name=name, expression=GOOD)


def test_first_schedule_sets_the_watermark_to_the_given_max(db: Database) -> None:
    _saved(db)
    scheduled = store.schedule_query(
        db, name="curl", interval_s=900, severity="high", max_ingest_seq=42
    )
    assert scheduled.name == "curl"
    assert scheduled.expression == GOOD
    assert scheduled.interval_s == 900
    assert scheduled.severity == "high"
    assert scheduled.watermark_seq == 42
    assert scheduled.last_run_at is None
    assert scheduled.last_status is None


def test_rescheduling_never_touches_the_watermark(db: Database) -> None:
    """An interval/severity change must not re-open or skip any window."""
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=900, severity="medium", max_ingest_seq=42)
    changed = store.schedule_query(
        db, name="curl", interval_s=3600, severity="high", max_ingest_seq=99
    )
    assert changed.interval_s == 3600
    assert changed.severity == "high"
    assert changed.watermark_seq == 42


def test_unschedule_clears_only_the_schedule_pair(db: Database) -> None:
    """Watermark, last_run_at and last_status survive an --off (§4.3: the
    off-gap IS scanned on re-schedule; only delete destroys the watermark)."""
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=900, severity="medium", max_ingest_seq=42)
    assert store.record_run(db, name="curl", watermark_seq=50, status="ok", now=NOW) is True
    prior = store.unschedule_query(db, name="curl")
    assert prior.interval_s == 900
    assert prior.severity == "medium"
    remaining = store.get_query(db, "curl")
    assert remaining is not None
    assert remaining.schedule_interval_s is None
    assert remaining.schedule_severity is None
    assert remaining.watermark_seq == 50
    assert remaining.last_run_at is not None
    assert remaining.last_status == "ok"


def test_reschedule_after_off_keeps_the_preserved_watermark(db: Database) -> None:
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=900, severity="medium", max_ingest_seq=42)
    store.unschedule_query(db, name="curl")
    resumed = store.schedule_query(
        db, name="curl", interval_s=900, severity="medium", max_ingest_seq=1000
    )
    assert resumed.watermark_seq == 42  # NOT reset — the off-gap gets scanned


def test_unschedule_of_an_unknown_name_raises(db: Database) -> None:
    with pytest.raises(HuntQueryNotFound):
        store.unschedule_query(db, name="nope")


def test_schedule_interval_floor_is_enforced(db: Database) -> None:
    _saved(db)
    with pytest.raises(HuntBoundsError) as caught:
        store.schedule_query(db, name="curl", interval_s=299, severity="medium", max_ingest_seq=0)
    assert str(store.SCHEDULE_MIN_INTERVAL_S) in str(caught.value)
    saved = store.get_query(db, "curl")
    assert saved is not None
    assert saved.schedule_interval_s is None


def test_schedule_severity_enum_is_enforced(db: Database) -> None:
    _saved(db)
    with pytest.raises(HuntRequestError):
        store.schedule_query(db, name="curl", interval_s=900, severity="critical", max_ingest_seq=0)


def test_schedule_of_an_unknown_name_raises(db: Database) -> None:
    with pytest.raises(HuntQueryNotFound):
        store.schedule_query(db, name="nope", interval_s=900, severity="medium", max_ingest_seq=0)


def test_record_run_stamps_and_returns_true_while_scheduled(db: Database) -> None:
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=900, severity="medium", max_ingest_seq=42)
    assert store.record_run(db, name="curl", watermark_seq=77, status="ok", now=NOW) is True
    row = store.get_query(db, "curl")
    assert row is not None
    assert row.watermark_seq == 77
    assert row.last_run_at == NOW
    assert row.last_status == "ok"


def test_record_run_with_none_watermark_leaves_it_untouched(db: Database) -> None:
    """A failure stamp must not advance the window — it is retried (§4.3)."""
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=900, severity="medium", max_ingest_seq=42)
    assert (
        store.record_run(db, name="curl", watermark_seq=None, status="failed:execution", now=NOW)
        is True
    )
    row = store.get_query(db, "curl")
    assert row is not None
    assert row.watermark_seq == 42
    assert row.last_status == "failed:execution"


def test_record_run_after_unschedule_writes_nothing(db: Database) -> None:
    """The --off-mid-run race: the guarded UPDATE hits zero rows and the
    caller discards the run's result (§4.3 item 4)."""
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=900, severity="medium", max_ingest_seq=42)
    store.unschedule_query(db, name="curl")
    assert store.record_run(db, name="curl", watermark_seq=77, status="ok", now=NOW) is False
    row = store.get_query(db, "curl")
    assert row is not None
    assert row.watermark_seq == 42
    assert row.last_run_at is None
    assert row.last_status is None


def test_never_run_scheduled_query_is_due(db: Database) -> None:
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=900, severity="medium", max_ingest_seq=0)
    due = store.due_queries(db, now=NOW)
    assert [q.name for q in due] == ["curl"]


def test_recently_run_query_is_not_due(db: Database) -> None:
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=300, severity="medium", max_ingest_seq=0)
    store.record_run(db, name="curl", watermark_seq=1, status="ok", now=NOW - timedelta(seconds=10))
    assert store.due_queries(db, now=NOW) == []
    # ...and it comes due once the interval has fully elapsed.
    assert [q.name for q in store.due_queries(db, now=NOW + timedelta(seconds=290))] == ["curl"]


def test_due_queries_are_ordered_by_name(db: Database) -> None:
    for name in ("zeta", "alpha", "mid"):
        _saved(db, name)
        store.schedule_query(db, name=name, interval_s=900, severity="medium", max_ingest_seq=0)
    _saved(db, "idle")  # saved but unscheduled: never due
    assert [q.name for q in store.due_queries(db, now=NOW)] == ["alpha", "mid", "zeta"]


def test_delete_still_returns_the_scheduled_row(db: Database) -> None:
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=900, severity="medium", max_ingest_seq=42)
    deleted = store.delete_query(db, "curl")
    assert deleted.expression == GOOD
    assert deleted.schedule_interval_s == 900
    assert store.get_query(db, "curl") is None


def test_save_replace_preserves_all_five_schedule_columns(db: Database) -> None:
    """§4.6: save-replace rewrites the detection but never its schedule state."""
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=900, severity="high", max_ingest_seq=42)
    store.record_run(db, name="curl", watermark_seq=50, status="ok", now=NOW)
    store.save_query(db, name="curl", expression='process.name == "wget"', replace=True)
    row = store.get_query(db, "curl")
    assert row is not None
    assert row.expression == 'process.name == "wget"'
    assert row.schedule_interval_s == 900
    assert row.schedule_severity == "high"
    assert row.watermark_seq == 50
    assert row.last_run_at == NOW
    assert row.last_status == "ok"


def test_list_queries_carries_schedule_state(db: Database) -> None:
    _saved(db)
    store.schedule_query(db, name="curl", interval_s=900, severity="low", max_ingest_seq=7)
    listed = store.list_queries(db)
    assert len(listed) == 1
    assert listed[0].schedule_interval_s == 900
    assert listed[0].schedule_severity == "low"
    assert listed[0].watermark_seq == 7
