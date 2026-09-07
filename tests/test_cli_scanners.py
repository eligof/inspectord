"""CLI `scanners run` — mapping, passthrough, exit codes (spec §3).

Like the hunt CLI tests, the daemon side is the real `IpcServer` over a real
socket; only the `run_worker_command` handler is a stub that captures the
params it was sent and replies with a canned `{ok, status, detail}` response.
What these tests assert is therefore the exact wire params — the same dicts
the web Run-now buttons send — and the CLI's rendering of the daemon verdict.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from inspectorctl.cli.app import app
from inspectord.ipc_server import IpcServer, Method

# A wide terminal so rich never folds a path or a detail string mid-assertion.
ENV = {"COLUMNS": "220", "TERM": "dumb"}

runner = CliRunner()


class _CommandChannel:
    """Captures every run_worker_command params dict; replies with a canned response."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.response: dict[str, Any] = {"ok": True, "status": "accepted", "detail": ""}

    def handle(self, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(params)
        return self.response


@pytest.fixture
def channel(tmp_path: Path) -> Iterator[tuple[Path, _CommandChannel]]:
    chan = _CommandChannel()
    sock = tmp_path / "ipc.sock"
    server = IpcServer(
        socket_path=sock,
        methods=[Method(name="run_worker_command", handler=chan.handle, mutates=True)],
        allowed_uids=[],
    )
    server.start()
    try:
        yield sock, chan
    finally:
        server.stop()


def _invoke(socket_path: Path, *args: str) -> Any:
    return runner.invoke(app, [*args, "--socket", str(socket_path)], env=ENV)


@pytest.mark.parametrize(
    ("name", "expected_params"),
    [
        ("aide", {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "aide"}}),
        (
            "rkhunter",
            {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "rkhunter"}},
        ),
        ("yara", {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "yara"}}),
        ("vuln", {"worker": "vuln_scanner", "command": "rescan"}),
    ],
)
def test_run_sends_the_web_buttons_params(
    name: str, expected_params: dict[str, Any], channel: tuple[Path, _CommandChannel]
) -> None:
    """Each CLI name maps to exactly the params the web Run-now button sends."""
    sock, chan = channel
    result = _invoke(sock, "scanners", "run", name)
    assert result.exit_code == 0
    assert "triggered" in result.stdout
    assert chan.calls == [expected_params]


def test_run_unknown_name_rejected_client_side(channel: tuple[Path, _CommandChannel]) -> None:
    """An unknown name never reaches the daemon, and the error lists the valid names."""
    sock, chan = channel
    result = _invoke(sock, "scanners", "run", "clamav")
    assert result.exit_code != 0
    assert chan.calls == []
    for valid in ("aide", "rkhunter", "yara", "vuln"):
        assert valid in result.stdout


def test_run_daemon_rejection_passes_through(channel: tuple[Path, _CommandChannel]) -> None:
    """The daemon's status and detail are shown as written, and the exit code is 1."""
    sock, chan = channel
    chan.response = {"ok": False, "status": "rejected", "detail": "scanner disabled: aide"}
    result = _invoke(sock, "scanners", "run", "aide")
    assert result.exit_code == 1
    assert "rejected" in result.stdout
    assert "scanner disabled: aide" in result.stdout


def test_run_daemon_unreachable(tmp_path: Path) -> None:
    """No daemon on the socket → exit 1 with the IpcError text, not a traceback."""
    result = _invoke(tmp_path / "no-daemon.sock", "scanners", "run", "aide")
    assert result.exit_code == 1
    assert "socket not found" in result.stdout
