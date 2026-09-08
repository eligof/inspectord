"""inspectorctl quarantine subcommands (quarantine design §4).

The daemon enforces everything — polkit gate, rate limits, deny-list,
validation; nothing here is enforcement. What the CLI owes:

* **A polkit agent on a TTY.** In an SSH session no desktop agent answers, so
  a mutating verb would get an instant unexplained deny; when stdin is a TTY
  the CLI spawns `pkttyagent --fallback` for the duration of that one call.
  Nothing else ever spawns one, and `list` never needs it.
* **Distinct exit codes**: 0 ok, 1 error, 2 usage (typer's own), **3** for an
  authorization denial — recognized by the -32001 code, never by message text.
* **Honest success output**: the restore hint, the pkg-owner warning and the
  running-PID caution ride every quarantine that carries them (§3.2 step 6).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any

import typer
from rich import print as rprint
from rich.markup import escape

from inspectorctl.ipc_client import IpcClient, IpcError
from inspectord.ipc_server import AUTHZ_DENIED_CODE

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Quarantine files into the forensic store — and bring them back.",
)

_DEFAULT_SOCKET = Path("var") / "inspectord.sock"

SocketOpt = Annotated[Path, typer.Option("--socket", "-s")]


def _stdin_is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


@contextlib.contextmanager
def _tty_agent() -> Iterator[None]:
    """`pkttyagent --fallback` for the duration of one mutating call (§4).

    Only when stdin is a TTY and the binary exists; the desktop case already
    has a session agent and the non-TTY case gets the daemon's actionable
    `agent_missing` message instead of a hung prompt nobody can see.
    """
    if not _stdin_is_tty() or shutil.which("pkttyagent") is None:
        yield
        return
    proc = subprocess.Popen(["pkttyagent", "--process", str(os.getpid()), "--fallback"])
    try:
        yield
    finally:
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=5)


def _call(socket: Path, method: str, params: dict[str, Any], *, agent: bool) -> dict[str, Any]:
    """One IPC call with the exit-code contract applied.

    Exits 3 on the -32001 authorization channel, 1 on transport/daemon errors
    and on `{ok: False}` responses (after printing the daemon's own message).
    """
    try:
        with _tty_agent() if agent else contextlib.nullcontext():
            result = IpcClient(socket_path=socket).call(method, params)
    except IpcError as exc:
        if exc.code == AUTHZ_DENIED_CODE:
            rprint(f"[red]not authorized[/red] {escape(str(exc))}")
            raise typer.Exit(code=3) from exc
        rprint(f"[red]ERROR[/red] {escape(str(exc))}")
        raise typer.Exit(code=1) from exc
    if not result.get("ok", False):
        kind = str(result.get("error_kind", "error"))
        rprint(f"[red]{escape(kind)}[/red] {escape(str(result.get('error', '')))}")
        raise typer.Exit(code=1)
    return result


@app.command("file")
def file_cmd(
    path: str,
    alert_id: Annotated[str | None, typer.Option("--alert-id")] = None,
    case_id: Annotated[str | None, typer.Option("--case-id")] = None,
    note: Annotated[str | None, typer.Option("--note")] = None,
    socket: SocketOpt = _DEFAULT_SOCKET,
) -> None:
    """Quarantine a file: copy it into the forensic store, remove the original."""
    params: dict[str, Any] = {"path": path}
    if alert_id is not None:
        params["alert_id"] = alert_id
    if case_id is not None:
        params["case_id"] = case_id
    if note is not None:
        params["note"] = note
    result = _call(socket, "quarantine_file", params, agent=True)
    qid = str(result.get("quarantine_id", ""))
    rprint(f"[green]quarantined[/green] {escape(path)}")
    rprint(f"  id: {escape(qid)}  sha256: {escape(str(result.get('sha256', '')))}")
    for warning in result.get("warnings", []):
        rprint(f"  [yellow]warning[/yellow] {escape(str(warning))}")
    pids = result.get("running_pids", [])
    if pids:
        listed = ", ".join(f"{p.get('pid')} ({p.get('comm', '?')})" for p in pids)
        rprint(f"  [yellow]still running:[/yellow] {escape(listed)}")
    rprint(f"[dim]undo with: inspectorctl quarantine restore {escape(qid)}[/dim]")


@app.command("list")
def list_cmd(
    limit: Annotated[int | None, typer.Option("--limit")] = None,
    socket: SocketOpt = _DEFAULT_SOCKET,
) -> None:
    """List quarantined files, newest first, with health flags."""
    params: dict[str, Any] = {} if limit is None else {"limit": limit}
    result = _call(socket, "list_quarantine", params, agent=False)
    rows = result.get("rows", [])
    if not rows:
        rprint("[dim]nothing in quarantine[/dim]")
        return
    for row in rows:
        flags = row.get("flags", [])
        flag_str = f"  [yellow]{escape(', '.join(flags))}[/yellow]" if flags else ""
        rprint(
            f"{escape(str(row.get('quarantine_id', '')))}  "
            f"{escape(str(row.get('status', '')))}  "
            f"{escape(str(row.get('original_path', '')))}  "
            f"{escape(str(row.get('sha256', ''))[:12])}{flag_str}"
        )
    rprint(f"[dim]{len(rows)} row(s), limit {result.get('limit')}[/dim]")


@app.command("restore")
def restore_cmd(quarantine_id: str, socket: SocketOpt = _DEFAULT_SOCKET) -> None:
    """Put a quarantined file back at its original path."""
    result = _call(socket, "restore_quarantined", {"quarantine_id": quarantine_id}, agent=True)
    rprint(f"[green]restored[/green] {escape(str(result.get('original_path', '')))}")
    if result.get("setuid_warning"):
        rprint(
            "[red]warning[/red] the restored file carries a setuid/setgid bit — "
            "it is runnable with elevated rights again"
        )


@app.command("delete")
def delete_cmd(quarantine_id: str, socket: SocketOpt = _DEFAULT_SOCKET) -> None:
    """Discard a quarantined file for good. This is NOT undoable."""
    result = _call(socket, "delete_quarantined", {"quarantine_id": quarantine_id}, agent=True)
    rprint(f"[red]deleted[/red] {escape(str(result.get('original_path', '')))}")
    if result.get("blob_removed"):
        rprint("[dim]the stored bytes are gone; there is no way back[/dim]")
    else:
        rprint("[dim]the stored bytes remain (still referenced by a case or another row)[/dim]")
