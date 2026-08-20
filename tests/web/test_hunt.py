"""Tests for the /hunt panel (plan 2026-08-20-hunt-panel §10)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectord.hunt.ipc_handlers import handle_list_hunt_queries, handle_run_hunt_query
from inspectord.hunt.store import save_query
from inspectord.ipc_server import Method
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
from inspectord.storage.migrations import run_migrations

_EVENT: dict[str, Any] = {
    "event_id": "01919e2a-0000-7000-8000-000000000001",
    "ts": "2026-08-20T02:00:00+00:00",
    "kind": "event",
    "module": "process_collector",
    "action": "process_exec",
    "severity": "medium",
    "payload": {
        "message": "curl spawned by bash",
        "process": {"name": "curl", "pid": 4242, "command_line": "curl http://evil.example"},
        "user": {"name": "eli"},
        "destination": {"ip": "203.0.113.9", "port": 443},
    },
}


def _result(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": "1.0.0",
        "ok": True,
        "name": None,
        "expression": 'process.name == "curl"',
        "since": "2026-08-13T02:00:00+00:00",
        "until": None,
        "limit": 500,
        "truncated": False,
        "count": 1,
        "events": [_EVENT],
    }
    return {**base, **overrides}


def _run(
    response: dict[str, Any] | Callable[[dict[str, Any]], dict[str, Any]],
    calls: list[dict[str, Any]] | None = None,
) -> Method:
    def handler(params: dict[str, Any]) -> dict[str, Any]:
        if calls is not None:
            calls.append(dict(params))
        return response(params) if callable(response) else response

    return Method(name="run_hunt_query", handler=handler, mutates=False)


def _saved(*queries: dict[str, Any]) -> Method:
    def handler(params: dict[str, Any]) -> dict[str, Any]:
        return {"schema_version": "1.0.0", "ok": True, "queries": list(queries)}

    return Method(name="list_hunt_queries", handler=handler, mutates=False)


def _query(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "curl-downloads",
        "expression": 'process.name == "curl"',
        "description": "outbound downloads",
        "created_at": "2026-08-01T00:00:00+00:00",
        "updated_at": "2026-08-19T00:00:00+00:00",
    }
    return {**base, **overrides}


def test_idle_page_renders_the_form_and_runs_nothing(ipc_factory) -> None:
    """Opening /hunt must not fire a query at the database."""
    calls: list[dict[str, Any]] = []
    client = ipc_factory([_run(_result(), calls), _saved()])
    response = client.get("/hunt")
    assert response.status_code == 200
    assert calls == []
    assert 'name="q"' in response.text
    assert "<nav>" in response.text


def test_nav_links_to_hunt(ipc_factory) -> None:
    client = ipc_factory([_run(_result()), _saved()])
    assert '<a href="/hunt"' in client.get("/hunt").text


def test_ad_hoc_query_runs_and_renders_its_rows(ipc_factory) -> None:
    calls: list[dict[str, Any]] = []
    client = ipc_factory([_run(_result(), calls), _saved()])
    response = client.get("/hunt", params={"q": 'process.name == "curl"'})
    assert response.status_code == 200
    assert calls == [{"expression": 'process.name == "curl"'}]
    assert "curl spawned by bash" in response.text
    assert "process_collector" in response.text
    assert "process_exec" in response.text
    assert "medium" in response.text
    assert "2026-08-20T02:00:00" in response.text


def test_result_rows_show_the_payload_fields_an_investigation_pivots_on(ipc_factory) -> None:
    client = ipc_factory([_run(_result()), _saved()])
    body = client.get("/hunt", params={"q": "x"}).text
    # The label is the queryable path, so a pivot is a copy-paste away.
    for expected in (
        "process.name",
        "curl",
        "process.pid",
        "4242",
        "curl http://evil.example",
        "user.name",
        "eli",
        "destination.ip",
        "203.0.113.9",
        "443",
    ):
        assert expected in body, expected
    # The event id is the handle for pivoting into a case.
    assert _EVENT["event_id"] in body


def test_row_details_omit_the_raw_blob(ipc_factory) -> None:
    """`raw` is the unparsed source line — a wall of JSON, not a panel."""
    event = {**_EVENT, "payload": {**_EVENT["payload"], "raw": {"line": "UNPARSED-SOURCE-LINE"}}}
    client = ipc_factory([_run(_result(events=[event])), _saved()])
    body = client.get("/hunt", params={"q": "x"}).text
    assert "UNPARSED-SOURCE-LINE" not in body


def test_a_long_value_is_clipped_and_says_so(ipc_factory) -> None:
    long_value = "A" * 5000
    event = {
        **_EVENT,
        "payload": {**_EVENT["payload"], "process": {"name": "curl", "command_line": long_value}},
    }
    client = ipc_factory([_run(_result(events=[event])), _saved()])
    body = client.get("/hunt", params={"q": "x"}).text
    assert long_value not in body
    assert "A" * 300 in body
    # A silent clip is the same lie as a silent truncation.
    assert "…" in body


def test_the_window_and_the_limit_are_always_visible(ipc_factory) -> None:
    """§7: a bound the user cannot see is itself a silent truncation."""
    client = ipc_factory([_run(_result()), _saved()])
    body = client.get("/hunt", params={"q": "x"}).text
    assert "window" in body
    assert "2026-08-13T02:00:00" in body
    assert "now" in body
    assert "limit" in body
    assert "500" in body


def test_the_limit_shown_is_the_one_the_daemon_resolved(ipc_factory) -> None:
    """Ask for 99999, get the daemon's cap — and see the cap, not the ask."""
    client = ipc_factory([_run(_result(limit=5000)), _saved()])
    body = client.get("/hunt", params={"q": "x", "limit": "99999"}).text
    assert "5000" in body
    assert "99999" not in body


def test_a_truncated_result_says_so(ipc_factory) -> None:
    client = ipc_factory([_run(_result(truncated=True, count=500)), _saved()])
    body = client.get("/hunt", params={"q": "x"}).text
    assert "TRUNCATED" in body
    assert "newest" in body
    assert "complete for this window" not in body


def test_a_complete_result_says_so(ipc_factory) -> None:
    client = ipc_factory([_run(_result()), _saved()])
    body = client.get("/hunt", params={"q": "x"}).text
    assert "complete for this window" in body
    assert "TRUNCATED" not in body


def test_an_empty_result_says_no_matches_rather_than_nothing(ipc_factory) -> None:
    client = ipc_factory([_run(_result(count=0, events=[])), _saved()])
    body = client.get("/hunt", params={"q": "x"}).text
    assert "no matches" in body
    assert "0 events in this window" in body
    # ...and how to widen it, because "nothing here" and "wrong window" differ.
    assert "widen" in body.lower()
    assert "TRUNCATED" not in body
    assert "complete for this window" not in body


def test_saved_queries_are_listed_with_run_links(ipc_factory) -> None:
    client = ipc_factory([_run(_result()), _saved(_query(), _query(name="ssh-failures"))])
    body = client.get("/hunt").text
    assert "curl-downloads" in body
    assert "outbound downloads" in body
    assert "/hunt?name=curl-downloads" in body
    assert "ssh-failures" in body


def test_no_saved_queries_names_the_cli_command(ipc_factory) -> None:
    client = ipc_factory([_run(_result()), _saved()])
    body = client.get("/hunt").text
    assert "no saved queries" in body
    assert "inspectorctl hunt save" in body


def test_page_says_saving_and_deleting_live_in_the_cli(ipc_factory) -> None:
    """The missing button is a documented choice, not a hole (plan §4)."""
    client = ipc_factory([_run(_result()), _saved(_query())])
    body = client.get("/hunt").text
    assert "read-only" in body
    assert "inspectorctl hunt save" in body
    assert "inspectorctl hunt delete" in body


def test_running_a_saved_query_passes_the_name_and_names_it_back(ipc_factory) -> None:
    calls: list[dict[str, Any]] = []
    client = ipc_factory(
        [_run(_result(name="curl-downloads"), calls), _saved(_query())],
    )
    body = client.get("/hunt", params={"name": "curl-downloads"}).text
    assert calls == [{"name": "curl-downloads"}]
    assert "curl-downloads" in body
    assert "saved" in body


def test_running_a_saved_query_fills_the_box_with_its_expression(ipc_factory) -> None:
    """The next question is asked by editing this one."""
    result = _result(name="curl-downloads", expression='process.name == "curl"')
    client = ipc_factory([_run(result), _saved(_query())])
    body = client.get("/hunt", params={"name": "curl-downloads"}).text
    assert 'name="q" value="process.name == &#34;curl&#34;"' in body


def test_since_shorthand_reaches_the_daemon_as_an_iso_timestamp(ipc_factory) -> None:
    calls: list[dict[str, Any]] = []
    client = ipc_factory([_run(_result(), calls), _saved()])
    client.get("/hunt", params={"q": "x", "since": "24h"})
    assert len(calls) == 1
    since = calls[0]["since"]
    parsed = datetime.fromisoformat(since)
    assert parsed.tzinfo is not None
    delta = datetime.now(tz=UTC) - parsed
    assert 23 * 3600 < delta.total_seconds() < 25 * 3600


def test_an_iso_since_is_passed_through_unchanged(ipc_factory) -> None:
    calls: list[dict[str, Any]] = []
    client = ipc_factory([_run(_result(), calls), _saved()])
    client.get("/hunt", params={"q": "x", "since": "2026-08-01T00:00:00+00:00"})
    assert calls[0]["since"] == "2026-08-01T00:00:00+00:00"


def test_a_rejected_query_shows_the_daemons_own_message(ipc_factory) -> None:
    """A `HuntError` is written for the person who typed the query (#136)."""
    failure = {
        "schema_version": "1.0.0",
        "ok": False,
        "error": "cannot parse 'process.name curl': expected '<path> <operator> <value>'",
        "error_kind": "syntax",
    }
    client = ipc_factory([_run(failure), _saved()])
    response = client.get("/hunt", params={"q": "process.name curl"})
    assert response.status_code == 200
    body = response.text
    assert "query rejected" in body
    assert "syntax" in body
    assert "expected " in body
    # The typed text survives so it can be edited rather than retyped.
    assert "process.name curl" in body
    # A rejection is not a result: no bounds line, no empty-result claim.
    assert "complete for this window" not in body
    assert "no matches" not in body


def test_an_internal_error_does_not_blame_the_query(ipc_factory) -> None:
    def boom(params: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("secret internals /var/lib/inspectord/db")

    client = ipc_factory([Method(name="run_hunt_query", handler=boom), _saved()])
    body = client.get("/hunt", params={"q": "x"}).text
    assert "error_ref" in body
    # The daemon's own sanitisation must not be undone by the panel.
    assert "secret internals" not in body
    # It is the daemon that failed, not the user's query.
    assert "query rejected" not in body
    assert "not a problem with your query" in body


def test_daemon_unreachable(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "no.sock")
    client = TestClient(app)
    response = client.get("/hunt", params={"q": "x"})
    assert response.status_code == 200
    assert "daemon unreachable" in response.text


def test_saved_query_list_failure_does_not_lose_the_query_box(ipc_factory) -> None:
    """A broken list must not take the whole panel down."""

    def boom(params: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("nope")

    client = ipc_factory(
        [_run(_result()), Method(name="list_hunt_queries", handler=boom)],
    )
    body = client.get("/hunt", params={"q": "x"}).text
    assert 'name="q"' in body
    assert "curl spawned by bash" in body


def test_escapes_every_attacker_influenceable_field(ipc_factory) -> None:
    """Every string on this page is attacker-influenceable.

    Event payloads carry process names, file paths and scanner findings — and a
    filename can forge report text (see the scanner adapters' docstrings) — so
    module, action, severity, kind, the message and every payload value may be
    attacker-chosen. So may a saved query's name, expression and description,
    and the expression echoed back into the form.

    `store.NAME_PATTERN` rejects `<` and `&` in *new* names, but a row already
    in the table predates any pattern, so the page must not lean on it.
    """
    payload = "<script>alert(1)</script>"
    escaped = "&lt;script&gt;alert(1)&lt;/script&gt;"
    event = {
        "event_id": f"id{payload}",
        "ts": "2026-08-20T02:00:00+00:00",
        "kind": payload,
        "module": payload,
        "action": payload,
        "severity": payload,
        "payload": {
            "message": f"message {payload}",
            "process": {"name": f"proc{payload}"},
            "file": {"path": f"/tmp/{payload}"},
        },
    }
    client = ipc_factory(
        [
            _run(_result(expression=payload, count=1, events=[event])),
            _saved(
                _query(
                    name=f"name{payload}",
                    expression=f"expr{payload}",
                    description=f"desc{payload}",
                )
            ),
        ]
    )
    response = client.get("/hunt", params={"q": payload})
    assert response.status_code == 200
    # Nothing reaches the page as markup...
    assert payload not in response.text
    assert "<script>" not in response.text
    # ...and every field's escaped form is present. The count is exact rather
    # than generous, so a silently dropped field cannot make this test pass:
    # event_id, kind, module, action, message, process.name, file.path (7),
    # severity twice (badge class + badge text), the echoed expression twice
    # (form value + results header), and the saved query's name, expression and
    # description (3) — 14.
    assert response.text.count(escaped) == 14


def test_escapes_a_rejection_message_that_quotes_the_query_back(ipc_factory) -> None:
    """The daemon's error message quotes the user's own text (hunt/errors.py)."""
    payload = "<img src=x onerror=alert(1)>"
    escaped = "&lt;img src=x onerror=alert(1)&gt;"
    failure = {
        "schema_version": "1.0.0",
        "ok": False,
        "error": f"cannot parse {payload!r}: expected '<path> <operator> <value>'",
        "error_kind": "syntax",
    }
    client = ipc_factory([_run(failure), _saved()])
    response = client.get("/hunt", params={"q": payload})
    assert payload not in response.text
    assert "<img" not in response.text
    # The message and the echoed query box.
    assert response.text.count(escaped) == 2


def test_end_to_end_against_the_real_daemon_handlers(ipc_factory, tmp_path: Path) -> None:
    """The fakes above encode a response shape; this proves the shape is real.

    Every other test in this file answers `run_hunt_query` with a hand-written
    dict. If the daemon's actual response drifted — a renamed field, a missing
    `truncated` — those tests would keep passing while the panel rendered
    nothing. So one test drives the panel through the real handlers over a real
    database.
    """
    db_path = tmp_path / "hunt.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        event = build_event(
            module="probe",
            action="exec",
            category=["process"],
            type_=["start"],
            severity="info",
            process={"name": "curl", "pid": 4242},
            message="ran curl",
            ts=datetime.now(tz=UTC),
        )
        insert_event(db, event, event.model_dump_json())
        save_query(db, name="curl-downloads", expression='process.name == "curl"', description=None)

    client = ipc_factory(
        [
            Method(
                name="run_hunt_query",
                handler=lambda params: handle_run_hunt_query(params=params, db_path=db_path),
                mutates=False,
            ),
            Method(
                name="list_hunt_queries",
                handler=lambda params: handle_list_hunt_queries(params=params, db_path=db_path),
                mutates=False,
            ),
        ]
    )

    body = client.get("/hunt", params={"name": "curl-downloads"}).text
    assert "ran curl" in body
    assert "process.name" in body
    assert "4242" in body
    # Bounds come back from the real handler, not from a fixture.
    assert "window" in body
    assert "limit 500" in body
    assert "complete for this window" in body
    assert "curl-downloads" in body

    # And a real rejection keeps the compiler's own wording.
    rejected = client.get("/hunt", params={"q": "process.name curl"}).text
    assert "query rejected (syntax)" in rejected
    assert "cannot parse" in rejected
