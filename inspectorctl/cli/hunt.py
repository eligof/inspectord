"""inspectorctl hunt subcommands (parent spec §24, hunt design §7/§8).

Output rules, because this is an investigation tool and not a report generator:

* A **truncated** result says so, loudly. Printing 500 rows and stopping reads
  as "there were exactly 500", which is a wrong answer with no error attached.
* An **empty** result says "no matches", never a blank screen — an ambiguous
  blank reads as "the command failed" or "there is nothing there", and those
  are different facts.
* The **window** is always printed. A query is bounded to a recent window by
  default (§7); a bound the user cannot see is a silent truncation of history.
* A **compile error** is shown as the daemon wrote it: those messages name the
  offending path, operator or regex. Flattening them into "invalid query"
  throws away the only part that helps.

Every string that came from an event or from a saved query is passed through
`rich.markup.escape` before printing: event text is attacker-influenced (a
filename can carry `[red]`), and rich would otherwise treat it as markup.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich import print as rprint
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from inspectorctl.ipc_client import IpcClient, IpcError

_err_console = Console(stderr=True)

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Saved and ad-hoc hunt queries over stored event history.",
)

_DEFAULT_SOCKET = Path("var") / "inspectord.sock"

_DURATION_RE = re.compile(r"^(\d+)([smhdw])$")
_DURATION_UNITS = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
    "w": "weeks",
}


def _client(socket: Path) -> IpcClient:
    return IpcClient(socket_path=socket)


def to_iso(value: str) -> str:
    """Turn `24h` / `7d` into an absolute timestamp; pass anything else through.

    Relative shorthand is client-side sugar. Anything that is not shorthand is
    handed to the daemon unchanged, so there is exactly one ISO-8601 parser and
    one rejection message for a bad timestamp.
    """
    match = _DURATION_RE.match(value)
    if match is None:
        return value
    amount = int(match.group(1))
    unit = _DURATION_UNITS[match.group(2)]
    return (datetime.now(tz=UTC) - timedelta(**{unit: amount})).isoformat()


def to_seconds(value: str) -> int | None:
    """Turn `15m` / `1h` / `1d` into whole seconds, or None for anything else.

    Unlike `to_iso` there is no pass-through: an interval that is not
    shorthand is a mistake, and the caller says so.
    """
    match = _DURATION_RE.match(value)
    if match is None:
        return None
    unit = _DURATION_UNITS[match.group(2)]
    return int(timedelta(**{unit: int(match.group(1))}).total_seconds())


#: The daemon's schedule floor (hunt-followups §4.6). Checked client-side as
#: UX only — the daemon re-validates every schedule request.
_SCHEDULE_FLOOR_S = 300

#: Largest-exact-unit rendering for a stored interval: 900 → 15m, 3600 → 1h.
_INTERVAL_UNITS = ((604_800, "w"), (86_400, "d"), (3_600, "h"), (60, "m"))


def format_interval(seconds: int) -> str:
    for unit_s, suffix in _INTERVAL_UNITS:
        if seconds >= unit_s and seconds % unit_s == 0:
            return f"{seconds // unit_s}{suffix}"
    return f"{seconds}s"


def _call(socket: Path, method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Call the daemon, turning a transport failure into a clean exit."""
    try:
        result = _client(socket).call(method, params)
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {escape(str(exc))}")
        raise typer.Exit(code=1) from exc
    return dict(result)


def _fail(result: dict[str, Any]) -> NoReturn:
    """Print a daemon-side rejection the way its author wrote it, then exit."""
    kind = str(result.get("error_kind", "hunt"))
    rprint(f"[red]query rejected[/red] ({kind})")
    rprint(f"  {escape(str(result.get('error', 'unknown error')))}")
    raise typer.Exit(code=1)


def _as_utc(value: datetime) -> datetime:
    """Naive timestamps are UTC by contract (DuckDB strips tz on read)."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def horizon_note(result: dict[str, Any]) -> str | None:
    """The effective-coverage warning for one run response, or None.

    Only warns when the requested window reaches past the surviving data
    (spec §2: the common case — horizon far older than the window — must not
    over-claim coverage, so it renders nothing). Shared by the CLI and the
    web route so there is exactly one implementation of the conditional.
    """
    if "data_horizon" not in result:
        return None  # older daemon; claim nothing
    horizon = result.get("data_horizon")
    if horizon is None:
        return "no events in the store"
    since = result.get("since")
    if since is None:
        return None
    try:
        horizon_ts = _as_utc(datetime.fromisoformat(str(horizon)))
        since_ts = _as_utc(datetime.fromisoformat(str(since)))
    except ValueError:
        return None
    if horizon_ts > since_ts:
        return (
            "your window reaches past the surviving data; "
            f"results only cover since {horizon_ts.isoformat()}"
        )
    return None


def _short_ts(value: object) -> str:
    text = str(value or "")
    return text.replace("T", " ")[:19] if text else "-"


def render_result(result: dict[str, Any]) -> None:
    """Render a `run_hunt_query` response. Exits non-zero on a rejection."""
    if not result.get("ok", False):
        _fail(result)

    name = result.get("name")
    header = f"[bold]query[/bold] {escape(str(result.get('expression', '')))}"
    if name:
        header += f"  [dim](saved as {escape(str(name))})[/dim]"
    rprint(header)
    window_from = _short_ts(result.get("since"))
    window_to = _short_ts(result.get("until")) if result.get("until") else "now"
    rprint(f"[dim]window[/dim] {window_from} → {window_to}  [dim]limit[/dim] {result.get('limit')}")
    note = horizon_note(result)
    if note is not None:
        _err_console.print(f"[yellow]{escape(note)}[/yellow]")

    events = list(result.get("events", []))
    if not events:
        # Never an ambiguous blank: say which of "it worked" and "nothing
        # matched" happened, and how to widen the search.
        rprint("[yellow]no matches[/yellow] — 0 events in this window")
        rprint("[dim]widen it with --since (e.g. --since 30d), or check the query[/dim]")
        return

    table = Table(title=None)
    table.add_column("Time")
    table.add_column("Severity")
    table.add_column("Module")
    table.add_column("Action")
    table.add_column("Message")
    for event in events:
        payload = event.get("payload") or {}
        table.add_row(
            _short_ts(event.get("ts")),
            escape(str(event.get("severity", ""))),
            escape(str(event.get("module", ""))),
            escape(str(event.get("action", ""))),
            escape(str(payload.get("message") or "")),
        )
    rprint(table)

    count = int(result.get("count", len(events)))
    if result.get("truncated"):
        limit = result.get("limit")
        rprint(
            f"[yellow]TRUNCATED[/yellow] showing {count} of possibly more — "
            "these are the newest matches, so older ones are missing."
        )
        rprint(
            f"[dim]narrow the query, shorten the window, or raise --limit "
            f"(currently {limit}, max 5000)[/dim]"
        )
    else:
        rprint(f"[dim]{count} match{'' if count == 1 else 'es'} — complete for this window[/dim]")


def run_query(
    *,
    socket: Path,
    expression: str | None = None,
    name: str | None = None,
    limit: int | None = None,
    since: str | None = None,
    until: str | None = None,
) -> None:
    """Shared by `hunt run` and `events search`."""
    params: dict[str, Any] = {}
    if expression is not None:
        params["expression"] = expression
    if name is not None:
        params["name"] = name
    if limit is not None:
        params["limit"] = limit
    if since is not None:
        params["since"] = to_iso(since)
    if until is not None:
        params["until"] = to_iso(until)
    render_result(_call(socket, "run_hunt_query", params))


@app.command("run")
def run_cmd(
    name: str,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    limit: Annotated[int | None, typer.Option("--limit")] = None,
    since: Annotated[str | None, typer.Option("--since", help="ISO-8601 or 7d/24h/30m")] = None,
    until: Annotated[str | None, typer.Option("--until", help="ISO-8601 or 7d/24h/30m")] = None,
) -> None:
    """Run a saved query."""
    run_query(socket=socket, name=name, limit=limit, since=since, until=until)


@app.command("save")
def save_cmd(
    name: str,
    query: str,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    description: Annotated[str | None, typer.Option("--description")] = None,
    replace: Annotated[
        bool,
        typer.Option("--replace", help="overwrite an existing query of the same name"),
    ] = False,
    scheduled_ok: Annotated[
        bool,
        typer.Option(
            "--scheduled-ok",
            help="confirm replacing a SCHEDULED query (it rewrites a standing detection)",
        ),
    ] = False,
) -> None:
    """Compile a query and save it under a name.

    The expression is compiled before it is stored, so a query that cannot
    compile is refused now rather than at 2am. An existing name is **refused**
    unless `--replace` is given — and a *scheduled* name additionally needs
    `--scheduled-ok`, because its expression is a standing detection.
    """
    params: dict[str, Any] = {"name": name, "expression": query, "replace": replace}
    if scheduled_ok:
        params["scheduled_ok"] = True
    if description is not None:
        params["description"] = description
    result = _call(socket, "save_hunt_query", params)
    if not result.get("ok", False):
        if result.get("error_kind") == "exists":
            rprint(f"[red]not saved[/red] — the name {escape(name)} is taken")
            rprint(f"  {escape(str(result.get('error', '')))}")
            rprint("[dim]re-run with --replace to overwrite it, or pick another name[/dim]")
            raise typer.Exit(code=1)
        if result.get("error_kind") == "scheduled":
            rprint(f"[red]not saved[/red] — {escape(name)} is a scheduled standing detection")
            rprint(f"  {escape(str(result.get('error', '')))}")
            rprint("[dim]re-run with --scheduled-ok to confirm rewriting it[/dim]")
            raise typer.Exit(code=1)
        _fail(result)

    if result.get("replaced"):
        # Loudly different from a plain save: something was destroyed here.
        rprint(f"[yellow]REPLACED[/yellow] {escape(name)} — the previous query is gone")
        rprint(f"  [dim]was:[/dim] {escape(str(result.get('previous_expression', '')))}")
        rprint(f"  [dim]now:[/dim] {escape(str(result.get('expression', '')))}")
    else:
        rprint(f"[green]saved[/green] {escape(name)}")
        rprint(f"  [dim]expression:[/dim] {escape(str(result.get('expression', '')))}")
    rprint(f"[dim]run it with: inspectorctl hunt run {escape(name)}[/dim]")


@app.command("list")
def list_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """List saved queries."""
    result = _call(socket, "list_hunt_queries", {})
    if not result.get("ok", False):
        _fail(result)
    queries = list(result.get("queries", []))
    if not queries:
        rprint("[yellow]no saved queries[/yellow]")
        rprint('[dim]save one with: inspectorctl hunt save <name> "<query>"[/dim]')
        return
    table = Table(title="Saved hunt queries")
    table.add_column("Name")
    table.add_column("Expression")
    table.add_column("Description")
    table.add_column("Updated")
    table.add_column("Every")
    table.add_column("Severity")
    table.add_column("Last run")
    table.add_column("Last status")
    now = datetime.now(tz=UTC)
    for query in queries:
        interval = query.get("schedule_interval_s")
        last_run = _short_ts(query.get("last_run_at")) if query.get("last_run_at") else "-"
        # Overdue-ness is derived here, not sent by the daemon (§4.1): a run
        # that should have happened by now and has not is worth a loud mark —
        # a dead scheduler must be visible without reading logs.
        if interval is not None and query.get("last_run_at"):
            try:
                ran = _as_utc(datetime.fromisoformat(str(query["last_run_at"])))
                if ran + timedelta(seconds=int(interval)) < now:
                    last_run += " [red]overdue[/red]"
            except ValueError:
                pass
        table.add_row(
            escape(str(query.get("name", ""))),
            escape(str(query.get("expression", ""))),
            escape(str(query.get("description") or "")),
            _short_ts(query.get("updated_at")),
            format_interval(int(interval)) if interval is not None else "-",
            escape(str(query.get("schedule_severity"))) if query.get("schedule_severity") else "-",
            last_run,
            escape(str(query.get("last_status"))) if query.get("last_status") else "-",
        )
    rprint(table)


@app.command("delete")
def delete_cmd(
    name: str,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    scheduled_ok: Annotated[
        bool,
        typer.Option(
            "--scheduled-ok",
            help="confirm deleting a SCHEDULED query (it destroys a standing detection)",
        ),
    ] = False,
) -> None:
    """Delete a saved query, printing what it was so it can be retyped."""
    params: dict[str, Any] = {"name": name}
    if scheduled_ok:
        params["scheduled_ok"] = True
    result = _call(socket, "delete_hunt_query", params)
    if not result.get("ok", False):
        if result.get("error_kind") == "scheduled":
            rprint(f"[red]not deleted[/red] — {escape(name)} is a scheduled standing detection")
            rprint(f"  {escape(str(result.get('error', '')))}")
            rprint("[dim]re-run with --scheduled-ok to confirm destroying it[/dim]")
            raise typer.Exit(code=1)
        _fail(result)
    expression = str(result.get("expression", ""))
    rprint(f"[green]deleted[/green] {escape(name)}")
    rprint(f"  [dim]expression:[/dim] {escape(expression)}")
    rprint(
        f"[dim]restore it with: inspectorctl hunt save {escape(name)} '{escape(expression)}'[/dim]"
    )


@app.command("schedule")
def schedule_cmd(
    name: str,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    every: Annotated[
        str | None,
        typer.Option("--every", help="run interval: 15m / 1h / 1d (floor 5m)"),
    ] = None,
    severity: Annotated[
        str,
        typer.Option("--severity", help="alert severity for matches: low, medium or high"),
    ] = "medium",
    off: Annotated[
        bool,
        typer.Option("--off", help="stop the standing detection (the watermark is preserved)"),
    ] = False,
) -> None:
    """Run a saved query on a schedule over newly ingested events (§4.6).

    Scheduling makes the query a standing detection: every `--every` interval
    it scans only events ingested since its last run, and any match raises an
    alert at `--severity`. `--off` stops it; the watermark survives, so
    re-scheduling scans the off-gap. The client-side checks below are UX only:
    the daemon re-validates every request.
    """
    if every is not None and off:
        rprint("[red]pass --every or --off[/red], not both: they are opposite acts")
        raise typer.Exit(code=1)
    if every is None and not off:
        rprint("[red]nothing to do[/red] — pass --every <interval> to schedule, or --off to stop")
        raise typer.Exit(code=1)

    if off:
        result = _call(socket, "unschedule_hunt_query", {"name": name})
        if not result.get("ok", False):
            _fail(result)
        interval = format_interval(int(result.get("interval_s", 0)))
        prior_severity = escape(str(result.get("severity", "")))
        # Loudly different from scheduling: a standing detection was destroyed.
        rprint(
            f"[yellow]UNSCHEDULED[/yellow] {escape(name)} — "
            f"was every {interval}, severity {prior_severity}"
        )
        rprint(
            "[dim]the watermark is preserved: re-scheduling scans the gap; "
            "only delete destroys it[/dim]"
        )
        return

    assert every is not None  # the exclusivity checks above guarantee it
    seconds = to_seconds(every)
    if seconds is None:
        rprint(f"[red]cannot read --every {escape(every)}[/red]: use 15m, 1h or 1d")
        raise typer.Exit(code=1)
    if seconds < _SCHEDULE_FLOOR_S:
        rprint(
            f"[red]interval too small[/red] — {escape(every)} is under the floor of "
            f"{_SCHEDULE_FLOOR_S}s (5m); the daemon enforces this too"
        )
        raise typer.Exit(code=1)

    result = _call(
        socket,
        "schedule_hunt_query",
        {"name": name, "interval_s": seconds, "severity": severity},
    )
    if not result.get("ok", False):
        _fail(result)
    stands_interval = format_interval(int(result.get("interval_s", seconds)))
    stands_severity = escape(str(result.get("severity", severity)))
    rprint(
        f"[green]SCHEDULED[/green] {escape(name)} — every {stands_interval}, "
        f"severity {stands_severity}"
    )
    rprint(
        "[dim]it scans only newly ingested events from now on; matches raise a "
        f"{stands_severity} alert. Stop it with: inspectorctl hunt schedule "
        f"{escape(name)} --off[/dim]"
    )
