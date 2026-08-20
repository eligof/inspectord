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
from rich.markup import escape
from rich.table import Table

from inspectorctl.ipc_client import IpcClient, IpcError

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
) -> None:
    """Compile a query and save it under a name.

    The expression is compiled before it is stored, so a query that cannot
    compile is refused now rather than at 2am. An existing name is **refused**
    unless `--replace` is given.
    """
    params: dict[str, Any] = {"name": name, "expression": query, "replace": replace}
    if description is not None:
        params["description"] = description
    result = _call(socket, "save_hunt_query", params)
    if not result.get("ok", False):
        if result.get("error_kind") == "exists":
            rprint(f"[red]not saved[/red] — the name {escape(name)} is taken")
            rprint(f"  {escape(str(result.get('error', '')))}")
            rprint("[dim]re-run with --replace to overwrite it, or pick another name[/dim]")
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
    for query in queries:
        table.add_row(
            escape(str(query.get("name", ""))),
            escape(str(query.get("expression", ""))),
            escape(str(query.get("description") or "")),
            _short_ts(query.get("updated_at")),
        )
    rprint(table)


@app.command("delete")
def delete_cmd(
    name: str,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Delete a saved query, printing what it was so it can be retyped."""
    result = _call(socket, "delete_hunt_query", {"name": name})
    if not result.get("ok", False):
        _fail(result)
    expression = str(result.get("expression", ""))
    rprint(f"[green]deleted[/green] {escape(name)}")
    rprint(f"  [dim]expression:[/dim] {escape(expression)}")
    rprint(
        f"[dim]restore it with: inspectorctl hunt save {escape(name)} '{escape(expression)}'[/dim]"
    )
