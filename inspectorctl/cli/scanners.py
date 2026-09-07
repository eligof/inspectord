"""inspectorctl scanners subcommands (parent spec §24; hunt-followups spec §3).

`run` is a *trigger*, not a wait: the command channel is at-most-once and
trigger-only, so success here means "the worker was told", never "the scan
finished". The daemon's allowlist, rate limit and audit apply unchanged —
the name check below is UX, not enforcement.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer
from rich import print as rprint
from rich.markup import escape

from inspectorctl.ipc_client import IpcClient, IpcError

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Trigger the periodic scanners on demand.",
)

_DEFAULT_SOCKET = Path("var") / "inspectord.sock"

#: name → run_worker_command params, mirroring the web Run-now buttons
#: (inspectorctl/web/routes/scanners.py / routes/vulnerabilities.py) exactly —
#: a second derivation of these dicts would drift.
_TRIGGERS: dict[str, dict[str, Any]] = {
    "aide": {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "aide"}},
    "rkhunter": {
        "worker": "scanner_runner",
        "command": "run_scanner",
        "args": {"name": "rkhunter"},
    },
    "yara": {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "yara"}},
    "vuln": {"worker": "vuln_scanner", "command": "rescan"},
}


@app.command("run")
def run_cmd(
    name: str,
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
) -> None:
    """Trigger one scanner now: aide, rkhunter, yara or vuln."""
    params = _TRIGGERS.get(name)
    if params is None:
        rprint(f"[red]unknown scanner[/red] {escape(name)}")
        rprint(f"[dim]valid names: {', '.join(sorted(_TRIGGERS))}[/dim]")
        raise typer.Exit(code=2)
    try:
        result = IpcClient(socket_path=socket).call("run_worker_command", params)
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {escape(str(exc))}")
        raise typer.Exit(code=1) from exc
    status = str(result.get("status", "error"))
    detail = str(result.get("detail", ""))
    if status == "accepted":
        rprint(f"[green]triggered[/green] {escape(name)}")
        rprint("[dim]watch /scanners or the events feed for the result[/dim]")
        return
    rprint(f"[red]{escape(status)}[/red] {escape(name)}")
    if detail:
        rprint(f"  {escape(detail)}")
    raise typer.Exit(code=1)
