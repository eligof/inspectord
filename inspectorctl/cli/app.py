"""Top-level Typer app for inspectorctl."""

from __future__ import annotations

import typer

from inspectorctl.cli import deps, self_test, status, version

app = typer.Typer(no_args_is_help=True, add_completion=False)
app.command(name="status")(status.cmd)
app.command(name="self-test")(self_test.cmd)
app.command(name="version")(version.cmd)
app.add_typer(deps.app, name="deps")
