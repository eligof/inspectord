"""Hunt IPC handlers: bounds, the default window, and error shapes."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from inspectord.__main__ import _ipc_methods
from inspectord.config import dev_config
from inspectord.hunt import ipc_handlers as h
from inspectord.hunt import store
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
from inspectord.storage.migrations import run_migrations

NOW = datetime.now(tz=UTC)


@pytest.fixture
def db_path(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "hunt.duckdb"
    with Database(path) as db:
        run_migrations(db)
        for index, name in enumerate(["curl", "wget", "curl"]):
            event = build_event(
                module="probe",
                action="exec",
                category=["process"],
                type_=["start"],
                severity="info",
                process={"name": name},
                message=f"ran {name}",
                ts=NOW - timedelta(minutes=index),
            )
            insert_event(db, event, event.model_dump_json())
        # One event far outside the default window.
        old = build_event(
            module="probe",
            action="exec",
            category=["process"],
            type_=["start"],
            severity="info",
            process={"name": "curl"},
            message="ancient curl",
            ts=NOW - timedelta(days=400),
        )
        insert_event(db, old, old.model_dump_json())
    yield path


def _run(db_path: Path, **params: Any) -> dict[str, Any]:
    return h.handle_run_hunt_query(params=params, db_path=db_path)


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------


def test_run_an_ad_hoc_expression(db_path: Path) -> None:
    result = _run(db_path, expression='process.name == "curl"')
    assert result["ok"] is True
    assert result["expression"] == 'process.name == "curl"'
    assert result["count"] == 2
    assert result["truncated"] is False
    assert result["name"] is None


def test_run_returns_the_payload_under_its_own_key(db_path: Path) -> None:
    result = _run(db_path, expression='process.name == "wget"')
    event = result["events"][0]
    assert event["module"] == "probe"
    assert event["severity"] == "info"
    assert event["payload"]["process"]["name"] == "wget"
    assert event["payload"]["message"] == "ran wget"
    assert event["ts"].startswith(str(NOW.year))


def test_events_are_newest_first(db_path: Path) -> None:
    result = _run(db_path, expression='event.module == "probe"')
    stamps = [e["ts"] for e in result["events"]]
    assert stamps == sorted(stamps, reverse=True)


def test_the_default_window_is_applied_and_reported(db_path: Path) -> None:
    """§7: every query gets a time bound, and the caller can see which."""
    result = _run(db_path, expression='process.name == "curl"')
    assert result["since"] is not None
    since = datetime.fromisoformat(result["since"])
    assert timedelta(0) < NOW - since <= h.DEFAULT_WINDOW + timedelta(minutes=1)
    # The 400-day-old event is outside it.
    assert all("ancient" not in e["payload"]["message"] for e in result["events"])


def test_an_explicit_since_widens_the_window(db_path: Path) -> None:
    since = (NOW - timedelta(days=500)).isoformat()
    result = _run(db_path, expression='process.name == "curl"', since=since)
    assert result["count"] == 3
    assert result["since"] == since


def test_an_unreadable_since_is_rejected_clearly(db_path: Path) -> None:
    result = _run(db_path, expression='process.name == "curl"', since="yesterday")
    assert result["ok"] is False
    assert result["error_kind"] == "bounds"
    assert "since" in result["error"]


def test_truncation_is_reported(db_path: Path) -> None:
    result = _run(db_path, expression='event.module == "probe"', limit=1)
    assert result["truncated"] is True
    assert result["count"] == 1
    assert result["limit"] == 1


def test_no_matches_is_an_ok_empty_result(db_path: Path) -> None:
    result = _run(db_path, expression='process.name == "nothing-ever"')
    assert result["ok"] is True
    assert result["count"] == 0
    assert result["events"] == []
    assert result["truncated"] is False


def test_a_compile_error_says_what_was_wrong_with_the_query(db_path: Path) -> None:
    result = _run(db_path, expression="garbage")
    assert result["ok"] is False
    assert result["error_kind"] == "syntax"
    # Not flattened into "invalid query": the user's own text is in the message.
    assert "garbage" in result["error"]


def test_a_path_error_names_the_segment(db_path: Path) -> None:
    result = _run(db_path, expression='process..name == "curl"')
    assert result["ok"] is False
    assert result["error_kind"] == "path"


def test_an_overlong_expression_is_rejected_at_the_edge(db_path: Path) -> None:
    """§7: the compiler would happily turn a megabyte of OR into a megabyte of SQL."""
    huge = " OR ".join(['process.name == "curl"'] * 5000)
    assert len(huge) > store.MAX_EXPRESSION_CHARS
    result = _run(db_path, expression=huge)
    assert result["ok"] is False
    assert result["error_kind"] == "bounds"
    assert str(store.MAX_EXPRESSION_CHARS) in result["error"]


def test_a_database_error_reaches_the_client_without_sql(db_path: Path) -> None:
    """The DuckDB wrap is what a client actually sees."""
    result = _run(db_path, expression='process.name MATCHES "a{1001}"')
    assert result["ok"] is False
    assert result["error_kind"] == "execution"
    assert 'process.name MATCHES "a{1001}"' in result["error"]
    for fragment in ("SELECT", "events_enriched", "payload_json", "json_extract_string"):
        assert fragment not in result["error"]


def test_run_needs_exactly_one_of_name_or_expression(db_path: Path) -> None:
    neither = _run(db_path)
    assert neither["ok"] is False
    assert neither["error_kind"] == "request"
    both = _run(db_path, name="curl", expression='process.name == "curl"')
    assert both["ok"] is False
    assert both["error_kind"] == "request"


def test_run_a_saved_query_by_name(db_path: Path) -> None:
    with Database(db_path) as db:
        store.save_query(db, name="curl-hunt", expression='process.name == "curl"')
    result = _run(db_path, name="curl-hunt")
    assert result["ok"] is True
    assert result["name"] == "curl-hunt"
    assert result["expression"] == 'process.name == "curl"'
    assert result["count"] == 2


def test_running_an_unknown_name_is_a_not_found(db_path: Path) -> None:
    result = _run(db_path, name="nope")
    assert result["ok"] is False
    assert result["error_kind"] == "not_found"
    assert "nope" in result["error"]


def test_an_invalid_limit_is_rejected(db_path: Path) -> None:
    result = _run(db_path, expression='process.name == "curl"', limit=0)
    assert result["ok"] is False
    assert result["error_kind"] == "bounds"


def test_the_limit_is_capped_not_honoured_blindly(db_path: Path) -> None:
    result = _run(db_path, expression='process.name == "curl"', limit=10_000_000)
    assert result["ok"] is True
    assert result["limit"] == 5000


# --------------------------------------------------------------------------
# save / list / get / delete
# --------------------------------------------------------------------------


def test_save_then_list_and_get(db_path: Path) -> None:
    saved = h.handle_save_hunt_query(
        params={
            "name": "curl-hunt",
            "expression": 'process.name == "curl"',
            "description": "curl execs",
        },
        db_path=db_path,
    )
    assert saved["ok"] is True
    assert saved["replaced"] is False
    assert saved["previous_expression"] is None

    listed = h.handle_list_hunt_queries(params={}, db_path=db_path)
    assert [q["name"] for q in listed["queries"]] == ["curl-hunt"]
    assert listed["queries"][0]["description"] == "curl execs"
    assert listed["queries"][0]["created_at"] is not None

    got = h.handle_get_hunt_query(params={"name": "curl-hunt"}, db_path=db_path)
    assert got["query"]["expression"] == 'process.name == "curl"'


def test_get_of_an_unknown_name_is_ok_with_a_null_query(db_path: Path) -> None:
    got = h.handle_get_hunt_query(params={"name": "nope"}, db_path=db_path)
    assert got["ok"] is True
    assert got["query"] is None


def test_save_refuses_a_colliding_name(db_path: Path) -> None:
    params = {"name": "curl-hunt", "expression": 'process.name == "curl"'}
    h.handle_save_hunt_query(params=params, db_path=db_path)
    again = h.handle_save_hunt_query(
        params={"name": "curl-hunt", "expression": 'process.name == "wget"'},
        db_path=db_path,
    )
    assert again["ok"] is False
    assert again["error_kind"] == "exists"
    assert 'process.name == "curl"' in again["error"]

    with Database(db_path) as db:
        assert store.get_query(db, "curl-hunt").expression == 'process.name == "curl"'  # type: ignore[union-attr]


def test_save_with_replace_reports_what_it_replaced(db_path: Path) -> None:
    h.handle_save_hunt_query(
        params={"name": "curl-hunt", "expression": 'process.name == "curl"'},
        db_path=db_path,
    )
    replaced = h.handle_save_hunt_query(
        params={
            "name": "curl-hunt",
            "expression": 'process.name == "wget"',
            "replace": True,
        },
        db_path=db_path,
    )
    assert replaced["ok"] is True
    assert replaced["replaced"] is True
    assert replaced["previous_expression"] == 'process.name == "curl"'


def test_save_compiles_before_storing(db_path: Path) -> None:
    result = h.handle_save_hunt_query(
        params={"name": "broken", "expression": "garbage"}, db_path=db_path
    )
    assert result["ok"] is False
    assert result["error_kind"] == "syntax"
    with Database(db_path) as db:
        assert store.get_query(db, "broken") is None


def test_save_rejects_a_hostile_name(db_path: Path) -> None:
    result = h.handle_save_hunt_query(
        params={"name": "<script>x</script>", "expression": 'process.name == "curl"'},
        db_path=db_path,
    )
    assert result["ok"] is False
    assert result["error_kind"] == "name"


def test_delete_returns_the_expression_it_removed(db_path: Path) -> None:
    h.handle_save_hunt_query(
        params={"name": "curl-hunt", "expression": 'process.name == "curl"'},
        db_path=db_path,
    )
    deleted = h.handle_delete_hunt_query(params={"name": "curl-hunt"}, db_path=db_path)
    assert deleted["ok"] is True
    assert deleted["expression"] == 'process.name == "curl"'
    assert h.handle_get_hunt_query(params={"name": "curl-hunt"}, db_path=db_path)["query"] is None


def test_delete_of_an_unknown_name_is_a_not_found(db_path: Path) -> None:
    result = h.handle_delete_hunt_query(params={"name": "nope"}, db_path=db_path)
    assert result["ok"] is False
    assert result["error_kind"] == "not_found"


def test_every_response_is_json_serializable(db_path: Path) -> None:
    """The IPC server json.dumps() whatever a handler returns."""
    responses = [
        _run(db_path, expression='process.name == "curl"'),
        _run(db_path, expression="garbage"),
        h.handle_save_hunt_query(
            params={"name": "curl-hunt", "expression": 'process.name == "curl"'},
            db_path=db_path,
        ),
        h.handle_list_hunt_queries(params={}, db_path=db_path),
        h.handle_get_hunt_query(params={"name": "curl-hunt"}, db_path=db_path),
        h.handle_delete_hunt_query(params={"name": "curl-hunt"}, db_path=db_path),
    ]
    for response in responses:
        assert json.loads(json.dumps(response))["schema_version"] == "1.0.0"


def test_the_daemon_registers_the_hunt_methods_with_the_right_mutates(tmp_path: Path) -> None:
    """`mutates` is a future polkit gate on user intent, so it is asserted here.

    Running a query authorizes nothing (Hunt is read-only by construction) and
    happens constantly; saving and deleting write durable named state, and a
    replace destroys the previous query.
    """
    cfg = dev_config(base=tmp_path)
    mutates = {m.name: m.mutates for m in _ipc_methods(None, cfg)}  # type: ignore[arg-type]
    assert mutates["run_hunt_query"] is False
    assert mutates["list_hunt_queries"] is False
    assert mutates["get_hunt_query"] is False
    assert mutates["save_hunt_query"] is True
    assert mutates["delete_hunt_query"] is True
