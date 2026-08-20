"""Saved hunt queries: name rules, compile-on-save, and the collision policy."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from inspectord.hunt import store
from inspectord.hunt.errors import (
    HuntBoundsError,
    HuntNameError,
    HuntPathError,
    HuntQueryExists,
    HuntQueryNotFound,
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
