"""inspectorctl hunt — end to end over a real socket against the real handlers.

The daemon side here is the actual `IpcServer` plus the actual hunt handlers on
a temporary DuckDB, so what these tests assert is what an investigator sees.
Nothing sleeps: every assertion is on the synchronous result of one command.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from inspectorctl.cli.app import app
from inspectord.hunt import ipc_handlers as h
from inspectord.ipc_server import IpcServer, Method
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
from inspectord.storage.migrations import run_migrations

# A wide terminal so rich renders full cells; assertions are on content, not
# on where an 80-column table happens to fold.
ENV = {"COLUMNS": "220", "TERM": "dumb"}

runner = CliRunner()
NOW = datetime.now(tz=UTC)


def _seed(db_path: Path, count: int = 3) -> None:
    with Database(db_path) as db:
        run_migrations(db)
        for index in range(count):
            event = build_event(
                module="probe",
                action="exec",
                category=["process"],
                type_=["start"],
                severity="info",
                process={"name": "curl"},
                message=f"ran curl #{index}",
                ts=NOW - timedelta(minutes=index),
            )
            insert_event(db, event, event.model_dump_json())


@pytest.fixture
def socket_path(tmp_path: Path) -> Iterator[Path]:
    db_path = tmp_path / "hunt.duckdb"
    _seed(db_path)
    sock = tmp_path / "ipc.sock"
    methods = [
        Method(
            name="run_hunt_query",
            handler=lambda params: h.handle_run_hunt_query(params=params, db_path=db_path),
            mutates=False,
        ),
        Method(
            name="save_hunt_query",
            handler=lambda params: h.handle_save_hunt_query(params=params, db_path=db_path),
            mutates=True,
        ),
        Method(
            name="list_hunt_queries",
            handler=lambda params: h.handle_list_hunt_queries(params=params, db_path=db_path),
            mutates=False,
        ),
        Method(
            name="delete_hunt_query",
            handler=lambda params: h.handle_delete_hunt_query(params=params, db_path=db_path),
            mutates=True,
        ),
    ]
    server = IpcServer(socket_path=sock, methods=methods, allowed_uids=[])
    server.start()
    try:
        yield sock
    finally:
        server.stop()


def _invoke(socket_path: Path, *args: str) -> Any:
    return runner.invoke(app, [*args, "--socket", str(socket_path)], env=ENV)


# --------------------------------------------------------------------------
# save
# --------------------------------------------------------------------------


def test_save_reports_a_new_query(socket_path: Path) -> None:
    result = _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    assert result.exit_code == 0
    assert "saved" in result.stdout
    assert "curl-hunt" in result.stdout
    assert "REPLACED" not in result.stdout


def test_save_refuses_a_taken_name_and_says_how_to_override(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    result = _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "wget"')
    assert result.exit_code == 1
    assert "not saved" in result.stdout
    assert "--replace" in result.stdout
    # The old query is still there, unharmed, and the CLI says what it is.
    assert 'process.name == "curl"' in result.stdout


def test_replace_says_loudly_that_something_was_destroyed(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    result = _invoke(
        socket_path, "hunt", "save", "curl-hunt", 'process.name == "wget"', "--replace"
    )
    assert result.exit_code == 0
    assert "REPLACED" in result.stdout
    assert "was:" in result.stdout
    assert 'process.name == "curl"' in result.stdout
    assert 'process.name == "wget"' in result.stdout
    # A replace and a first save must never print the same thing.
    assert "saved" not in result.stdout.replace("not saved", "")


def test_save_refuses_a_query_that_cannot_compile(socket_path: Path) -> None:
    result = _invoke(socket_path, "hunt", "save", "broken", "garbage")
    assert result.exit_code == 1
    assert "syntax" in result.stdout
    # The user's own text, not "invalid query".
    assert "garbage" in result.stdout


def test_save_refuses_a_hostile_name(socket_path: Path) -> None:
    result = _invoke(socket_path, "hunt", "save", "<script>", 'process.name == "curl"')
    assert result.exit_code == 1
    assert "name" in result.stdout


def test_a_query_that_matches_nothing_still_saves(socket_path: Path) -> None:
    result = _invoke(socket_path, "hunt", "save", "quiet", 'process.name == "nothing-ever"')
    assert result.exit_code == 0
    assert "saved" in result.stdout


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------


def test_run_a_saved_query(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    result = _invoke(socket_path, "hunt", "run", "curl-hunt")
    assert result.exit_code == 0
    assert "ran curl #0" in result.stdout
    assert "3 matches" in result.stdout
    assert "curl-hunt" in result.stdout


def test_run_prints_the_window_it_used(socket_path: Path) -> None:
    """§7: a default time bound the user cannot see is a silent truncation."""
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    result = _invoke(socket_path, "hunt", "run", "curl-hunt")
    assert "window" in result.stdout
    assert "limit" in result.stdout


def test_a_truncated_run_says_so(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    result = _invoke(socket_path, "hunt", "run", "curl-hunt", "--limit", "2")
    assert result.exit_code == 0
    assert "TRUNCATED" in result.stdout
    assert "showing 2 of possibly more" in result.stdout
    assert "--limit" in result.stdout


def test_an_untruncated_run_does_not_cry_wolf(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    result = _invoke(socket_path, "hunt", "run", "curl-hunt", "--limit", "3")
    assert "TRUNCATED" not in result.stdout
    assert "complete for this window" in result.stdout


def test_running_an_unknown_name_is_a_clear_rejection(socket_path: Path) -> None:
    result = _invoke(socket_path, "hunt", "run", "nope")
    assert result.exit_code == 1
    assert "not_found" in result.stdout
    assert "nope" in result.stdout


def test_a_run_with_no_matches_says_no_matches(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "quiet", 'process.name == "nothing-ever"')
    result = _invoke(socket_path, "hunt", "run", "quiet")
    assert result.exit_code == 0
    assert "no matches" in result.stdout
    assert "--since" in result.stdout


# --------------------------------------------------------------------------
# list / delete
# --------------------------------------------------------------------------


def test_list_shows_saved_queries(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    result = _invoke(socket_path, "hunt", "list")
    assert result.exit_code == 0
    assert "curl-hunt" in result.stdout


def test_list_with_nothing_saved_is_not_a_blank_screen(socket_path: Path) -> None:
    result = _invoke(socket_path, "hunt", "list")
    assert result.exit_code == 0
    assert "no saved queries" in result.stdout


def test_delete_prints_what_it_removed(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    result = _invoke(socket_path, "hunt", "delete", "curl-hunt")
    assert result.exit_code == 0
    assert "deleted" in result.stdout
    # Printed so a mistaken delete can be undone by retyping it.
    assert 'process.name == "curl"' in result.stdout
    assert "no saved queries" in _invoke(socket_path, "hunt", "list").stdout


def test_deleting_an_unknown_name_fails_clearly(socket_path: Path) -> None:
    result = _invoke(socket_path, "hunt", "delete", "nope")
    assert result.exit_code == 1
    assert "not_found" in result.stdout


# --------------------------------------------------------------------------
# rendering safety
# --------------------------------------------------------------------------


def test_event_text_is_not_treated_as_rich_markup(tmp_path: Path) -> None:
    """A message can carry `[red]`; rich must print it, not obey it."""
    db_path = tmp_path / "hunt.duckdb"
    with Database(db_path) as db:
        run_migrations(db)
        event = build_event(
            module="probe",
            action="exec",
            category=["process"],
            type_=["start"],
            severity="info",
            process={"name": "curl"},
            message="[red]not really red[/red]",
        )
        insert_event(db, event, event.model_dump_json())
    sock = tmp_path / "ipc.sock"
    server = IpcServer(
        socket_path=sock,
        methods=[
            Method(
                name="run_hunt_query",
                handler=lambda params: h.handle_run_hunt_query(params=params, db_path=db_path),
                mutates=False,
            )
        ],
        allowed_uids=[],
    )
    server.start()
    try:
        result = _invoke(sock, "events", "search", 'process.name == "curl"')
    finally:
        server.stop()
    assert result.exit_code == 0
    assert "[red]not really red[/red]" in result.stdout
