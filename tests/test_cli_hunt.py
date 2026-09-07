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
from inspectorctl.cli.hunt import horizon_note, render_result
from inspectord.hunt import ipc_handlers as h
from inspectord.hunt import store
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
        Method(
            name="schedule_hunt_query",
            handler=lambda params: h.handle_schedule_hunt_query(params=params, db_path=db_path),
            mutates=True,
        ),
        Method(
            name="unschedule_hunt_query",
            handler=lambda params: h.handle_unschedule_hunt_query(params=params, db_path=db_path),
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
# schedule (hunt-followups design §4.6)
# --------------------------------------------------------------------------


def test_schedule_prints_what_now_stands(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    result = _invoke(socket_path, "hunt", "schedule", "curl-hunt", "--every", "15m")
    assert result.exit_code == 0
    assert "SCHEDULED" in result.stdout
    assert "curl-hunt" in result.stdout
    assert "15m" in result.stdout
    assert "medium" in result.stdout  # the default severity


def test_schedule_severity_passes_through(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    result = _invoke(
        socket_path, "hunt", "schedule", "curl-hunt", "--every", "1h", "--severity", "high"
    )
    assert result.exit_code == 0
    listed = _invoke(socket_path, "hunt", "list").stdout
    assert "1h" in listed
    assert "high" in listed


def test_schedule_floor_is_checked_client_side(tmp_path: Path) -> None:
    """`--every 2m` never reaches the daemon (which re-validates anyway):
    the socket below does not exist, so an IPC call would fail loudly."""
    result = _invoke(tmp_path / "no-such.sock", "hunt", "schedule", "q1", "--every", "2m")
    assert result.exit_code == 1
    assert "300" in result.stdout or "5m" in result.stdout
    assert "ERROR" not in result.stdout  # no transport error: no call was made


def test_schedule_rejects_unreadable_every_client_side(tmp_path: Path) -> None:
    result = _invoke(tmp_path / "no-such.sock", "hunt", "schedule", "q1", "--every", "soon")
    assert result.exit_code == 1
    assert "soon" in result.stdout
    assert "ERROR" not in result.stdout


def test_schedule_off_prints_what_was_destroyed(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    _invoke(socket_path, "hunt", "schedule", "curl-hunt", "--every", "15m")
    result = _invoke(socket_path, "hunt", "schedule", "curl-hunt", "--off")
    assert result.exit_code == 0
    assert "UNSCHEDULED" in result.stdout
    assert "15m" in result.stdout
    assert "medium" in result.stdout


def test_schedule_every_and_off_together_is_an_error(tmp_path: Path) -> None:
    result = _invoke(tmp_path / "no-such.sock", "hunt", "schedule", "q1", "--every", "15m", "--off")
    assert result.exit_code == 1
    assert "--every" in result.stdout
    assert "--off" in result.stdout


def test_schedule_needs_every_or_off(tmp_path: Path) -> None:
    result = _invoke(tmp_path / "no-such.sock", "hunt", "schedule", "q1")
    assert result.exit_code == 1
    assert "--every" in result.stdout


def test_list_shows_schedule_columns_and_dashes_for_unscheduled(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    _invoke(socket_path, "hunt", "save", "idle", 'process.name == "wget"')
    _invoke(socket_path, "hunt", "schedule", "curl-hunt", "--every", "15m", "--severity", "low")
    result = _invoke(socket_path, "hunt", "list")
    assert result.exit_code == 0
    assert "Every" in result.stdout
    assert "Severity" in result.stdout
    assert "Last run" in result.stdout
    assert "Last status" in result.stdout
    assert "15m" in result.stdout
    assert "low" in result.stdout
    assert "-" in result.stdout  # the unscheduled row shows dashes


def test_list_marks_an_overdue_schedule(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    _invoke(socket_path, "hunt", "schedule", "curl-hunt", "--every", "15m")
    db_path = socket_path.parent / "hunt.duckdb"
    with Database(db_path) as db:
        assert store.record_run(
            db,
            name="curl-hunt",
            watermark_seq=None,
            status="ok",
            now=NOW - timedelta(hours=2),
        )
    result = _invoke(socket_path, "hunt", "list")
    assert "overdue" in result.stdout
    assert "ok" in result.stdout


def test_save_replace_on_a_scheduled_query_hints_at_scheduled_ok(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    _invoke(socket_path, "hunt", "schedule", "curl-hunt", "--every", "15m")
    refused = _invoke(
        socket_path, "hunt", "save", "curl-hunt", 'process.name == "wget"', "--replace"
    )
    assert refused.exit_code == 1
    assert "scheduled" in refused.stdout
    assert "--scheduled-ok" in refused.stdout

    replaced = _invoke(
        socket_path,
        "hunt",
        "save",
        "curl-hunt",
        'process.name == "wget"',
        "--replace",
        "--scheduled-ok",
    )
    assert replaced.exit_code == 0
    assert "REPLACED" in replaced.stdout


def test_delete_of_a_scheduled_query_hints_at_scheduled_ok(socket_path: Path) -> None:
    _invoke(socket_path, "hunt", "save", "curl-hunt", 'process.name == "curl"')
    _invoke(socket_path, "hunt", "schedule", "curl-hunt", "--every", "15m")
    refused = _invoke(socket_path, "hunt", "delete", "curl-hunt")
    assert refused.exit_code == 1
    assert "--scheduled-ok" in refused.stdout

    deleted = _invoke(socket_path, "hunt", "delete", "curl-hunt", "--scheduled-ok")
    assert deleted.exit_code == 0
    assert "deleted" in deleted.stdout


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


# --------------------------------------------------------------------------
# effective coverage (spec 2026-09-07 §2)
# --------------------------------------------------------------------------


def test_horizon_note_none_when_horizon_before_since() -> None:
    """The common case — data older than the window — must not over-claim."""
    note = horizon_note(
        {"data_horizon": "2026-08-01T00:00:00", "since": "2026-09-01T00:00:00+00:00"}
    )
    assert note is None


def test_horizon_note_warns_when_window_reaches_past_data() -> None:
    # data_horizon is naive (DuckDB strips tz), since is aware: the mix must
    # not raise TypeError inside the comparison.
    note = horizon_note(
        {"data_horizon": "2026-09-03T00:00:00", "since": "2026-09-01T00:00:00+00:00"}
    )
    assert note is not None
    assert "2026-09-03" in note
    assert "only cover" in note


def test_horizon_note_empty_store() -> None:
    note = horizon_note({"data_horizon": None, "since": "2026-09-01T00:00:00+00:00"})
    assert note == "no events in the store"


def test_horizon_note_absent_from_an_older_daemon_claims_nothing() -> None:
    assert horizon_note({"since": "2026-09-01T00:00:00+00:00"}) is None


def test_render_result_prints_horizon_note_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    render_result(
        {
            "ok": True,
            "name": None,
            "expression": 'process.name == "curl"',
            "since": "2026-09-01T00:00:00+00:00",
            "until": None,
            "limit": 500,
            "truncated": False,
            "count": 1,
            "data_horizon": "2026-09-03T00:00:00",
            "events": [
                {
                    "ts": "2026-09-05T00:00:00",
                    "severity": "info",
                    "module": "probe",
                    "action": "exec",
                    "payload": {"message": "ran curl"},
                }
            ],
        }
    )
    captured = capsys.readouterr()
    assert "only cover" in captured.err
    assert "only cover" not in captured.out
