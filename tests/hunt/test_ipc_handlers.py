"""Hunt IPC handlers: bounds, the default window, and error shapes."""

from __future__ import annotations

import hashlib
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
from inspectord.ratelimit import SlidingWindowLimiter
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


def _store_with(tmp_path: Path, stamps: list[datetime]) -> Path:
    """A store holding one curl exec per timestamp — for horizon assertions."""
    path = tmp_path / "horizon.duckdb"
    with Database(path) as db:
        run_migrations(db)
        for ts in stamps:
            event = build_event(
                module="probe",
                action="exec",
                category=["process"],
                type_=["start"],
                severity="info",
                process={"name": "curl"},
                message="ran curl",
                ts=ts,
            )
            insert_event(db, event, event.model_dump_json())
    return path


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


def test_run_reports_data_horizon(tmp_path: Path) -> None:
    """§2: the horizon is MIN(ts) over the whole store, not over the window."""
    path = _store_with(
        tmp_path,
        [datetime(2026, 9, 5, tzinfo=UTC), datetime(2026, 9, 1, tzinfo=UTC)],
    )
    result = _run(path, expression='process.name == "curl"')
    assert result["ok"] is True
    # MIN(ts), ISO, as stored (DuckDB strips the tz, so naive UTC).
    assert result["data_horizon"] == "2026-09-01T00:00:00"


def test_run_reports_null_horizon_on_empty_store(tmp_path: Path) -> None:
    path = _store_with(tmp_path, [])
    result = _run(path, expression='process.name == "curl"')
    assert result["ok"] is True
    assert result["data_horizon"] is None


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


# --------------------------------------------------------------------------
# schedule / unschedule (hunt-followups design §4.6)
# --------------------------------------------------------------------------


def _audit_rows(db_path: Path) -> list[tuple[str, str, dict[str, Any]]]:
    with Database(db_path) as db:
        rows = db.query(
            "SELECT action, target, details_json FROM audit_log ORDER BY seq"
        ).fetchall()
    return [(str(r[0]), str(r[1]), json.loads(str(r[2]))) for r in rows]


def _save(db_path: Path, name: str = "curl-hunt") -> None:
    result = h.handle_save_hunt_query(
        params={"name": name, "expression": 'process.name == "curl"'}, db_path=db_path
    )
    assert result["ok"] is True


def _schedule(db_path: Path, name: str = "curl-hunt", **overrides: Any) -> dict[str, Any]:
    params: dict[str, Any] = {"name": name, "interval_s": 900, "severity": "medium", **overrides}
    return h.handle_schedule_hunt_query(params=params, db_path=db_path)


def test_schedule_happy_path_is_visible_in_list_and_audited(db_path: Path) -> None:
    _save(db_path)
    result = _schedule(db_path)
    assert result["ok"] is True
    assert result["name"] == "curl-hunt"
    assert result["interval_s"] == 900
    assert result["severity"] == "medium"

    listed = h.handle_list_hunt_queries(params={}, db_path=db_path)
    (query,) = listed["queries"]
    assert query["schedule_interval_s"] == 900
    assert query["schedule_severity"] == "medium"
    assert query["last_run_at"] is None
    assert query["last_status"] is None

    rows = [r for r in _audit_rows(db_path) if r[0] == "hunt_query_scheduled"]
    assert len(rows) == 1
    _action, target, details = rows[0]
    assert target == "hunt:curl-hunt"
    assert details == {"interval_s": 900, "severity": "medium", "watermark_preserved": False}


def test_schedule_validation_rejections_write_nothing(db_path: Path) -> None:
    _save(db_path)
    floor = _schedule(db_path, interval_s=60)
    assert floor["ok"] is False
    assert floor["error_kind"] == "bounds"
    enum = _schedule(db_path, severity="critical")
    assert enum["ok"] is False
    assert enum["error_kind"] == "request"
    unknown = h.handle_schedule_hunt_query(
        params={"name": "nope", "interval_s": 900, "severity": "low"}, db_path=db_path
    )
    assert unknown["ok"] is False
    assert unknown["error_kind"] == "not_found"

    # No write happened...
    listed = h.handle_list_hunt_queries(params={}, db_path=db_path)
    assert listed["queries"][0]["schedule_interval_s"] is None
    # ...and no audit row either: a rejected request never touched state.
    assert all(a != "hunt_query_scheduled" for a, _, _ in _audit_rows(db_path))


def test_unschedule_audits_what_was_destroyed(db_path: Path) -> None:
    _save(db_path)
    _schedule(db_path, severity="high")
    result = h.handle_unschedule_hunt_query(params={"name": "curl-hunt"}, db_path=db_path)
    assert result["ok"] is True
    assert result["interval_s"] == 900
    assert result["severity"] == "high"

    listed = h.handle_list_hunt_queries(params={}, db_path=db_path)
    assert listed["queries"][0]["schedule_interval_s"] is None

    rows = [r for r in _audit_rows(db_path) if r[0] == "hunt_query_unscheduled"]
    assert len(rows) == 1
    assert rows[0][1] == "hunt:curl-hunt"
    assert rows[0][2] == {"interval_s": 900, "severity": "high"}


def test_reschedule_preserves_the_watermark_and_says_so(db_path: Path) -> None:
    _save(db_path)
    _schedule(db_path)
    h.handle_unschedule_hunt_query(params={"name": "curl-hunt"}, db_path=db_path)
    again = _schedule(db_path, severity="low")
    assert again["ok"] is True
    rows = [r for r in _audit_rows(db_path) if r[0] == "hunt_query_scheduled"]
    assert rows[-1][2]["watermark_preserved"] is True


def test_mutating_hunt_calls_share_a_rate_limit(db_path: Path) -> None:
    """13th mutating call in the window is refused; first rejection audited once."""
    clock = [0.0]
    limiter = SlidingWindowLimiter(monotonic=lambda: clock[0])
    _save(db_path)
    for index in range(12):
        result = h.handle_schedule_hunt_query(
            params={"name": "curl-hunt", "interval_s": 900 + index, "severity": "medium"},
            db_path=db_path,
            limiter=limiter,
        )
        assert result["ok"] is True
    rejected = h.handle_schedule_hunt_query(
        params={"name": "curl-hunt", "interval_s": 900, "severity": "medium"},
        db_path=db_path,
        limiter=limiter,
    )
    assert rejected["ok"] is False
    assert rejected["error_kind"] == "rate_limited"
    # The second rejection of the same window is NOT audited again.
    again = h.handle_delete_hunt_query(
        params={"name": "curl-hunt"}, db_path=db_path, limiter=limiter
    )
    assert again["ok"] is False
    assert again["error_kind"] == "rate_limited"
    rate_rows = [r for r in _audit_rows(db_path) if r[2].get("reason") == "rate_limited"]
    assert len(rate_rows) == 1


def test_save_replace_on_a_scheduled_name_needs_scheduled_ok(db_path: Path) -> None:
    _save(db_path)
    _schedule(db_path)
    refused = h.handle_save_hunt_query(
        params={"name": "curl-hunt", "expression": 'process.name == "wget"', "replace": True},
        db_path=db_path,
    )
    assert refused["ok"] is False
    assert refused["error_kind"] == "scheduled"
    with Database(db_path) as db:
        assert store.get_query(db, "curl-hunt").expression == 'process.name == "curl"'  # type: ignore[union-attr]

    replaced = h.handle_save_hunt_query(
        params={
            "name": "curl-hunt",
            "expression": 'process.name == "wget"',
            "replace": True,
            "scheduled_ok": True,
        },
        db_path=db_path,
    )
    assert replaced["ok"] is True
    with Database(db_path) as db:
        query = store.get_query(db, "curl-hunt")
    assert query is not None
    assert query.expression == 'process.name == "wget"'
    # Save-replace preserves the schedule AND the watermark (§4.6).
    assert query.schedule_interval_s == 900
    assert query.schedule_severity == "medium"
    assert query.watermark_seq is not None


def test_save_audit_details_distinguish_idle_edits_from_gutted_detections(db_path: Path) -> None:
    _save(db_path)
    _schedule(db_path)
    h.handle_save_hunt_query(
        params={
            "name": "curl-hunt",
            "expression": 'process.name == "wget"',
            "replace": True,
            "scheduled_ok": True,
        },
        db_path=db_path,
    )
    rows = [r for r in _audit_rows(db_path) if r[0] == "hunt_query_saved"]
    assert rows[0][2] == {
        "replaced": False,
        "was_scheduled": False,
        "old_expression_sha256": None,
        "new_expression_sha256": hashlib.sha256(b'process.name == "curl"').hexdigest(),
    }
    assert rows[1][2] == {
        "replaced": True,
        "was_scheduled": True,
        "old_expression_sha256": hashlib.sha256(b'process.name == "curl"').hexdigest(),
        "new_expression_sha256": hashlib.sha256(b'process.name == "wget"').hexdigest(),
    }


def test_delete_of_a_scheduled_name_needs_scheduled_ok_and_audits_the_schedule(
    db_path: Path,
) -> None:
    _save(db_path)
    _schedule(db_path)
    refused = h.handle_delete_hunt_query(params={"name": "curl-hunt"}, db_path=db_path)
    assert refused["ok"] is False
    assert refused["error_kind"] == "scheduled"
    with Database(db_path) as db:
        assert store.get_query(db, "curl-hunt") is not None

    deleted = h.handle_delete_hunt_query(
        params={"name": "curl-hunt", "scheduled_ok": True}, db_path=db_path
    )
    assert deleted["ok"] is True
    rows = [r for r in _audit_rows(db_path) if r[0] == "hunt_query_deleted"]
    assert rows[0][2] == {
        "expression_sha256": hashlib.sha256(b'process.name == "curl"').hexdigest(),
        "was_scheduled": True,
        "schedule_interval_s": 900,
    }


def test_delete_of_an_unscheduled_name_needs_no_scheduled_ok(db_path: Path) -> None:
    _save(db_path)
    deleted = h.handle_delete_hunt_query(params={"name": "curl-hunt"}, db_path=db_path)
    assert deleted["ok"] is True
    rows = [r for r in _audit_rows(db_path) if r[0] == "hunt_query_deleted"]
    assert rows[0][2]["was_scheduled"] is False
    assert rows[0][2]["schedule_interval_s"] is None


def test_the_daemon_registers_schedule_methods_as_mutating(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    mutates = {m.name: m.mutates for m in _ipc_methods(None, cfg)}  # type: ignore[arg-type]
    assert mutates["schedule_hunt_query"] is True
    assert mutates["unschedule_hunt_query"] is True


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
