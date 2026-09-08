"""CLI `quarantine file|list|restore|delete` — mapping, exit codes, pkttyagent (spec §4).

Like the scanners CLI tests, the daemon side is the real `IpcServer` over a
real socket; the quarantine handlers are stubs that capture the wire params
and reply with canned responses. The gate lives server-side, so the denial
test registers a gated method with no authz_check — the server's own
fail-closed -32001 answer is what the CLI must turn into exit code 3.
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


class _Daemon:
    """Captures every quarantine call's params; replies with canned responses."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.responses: dict[str, dict[str, Any]] = {
            "quarantine_file": {
                "schema_version": "1.0.0",
                "ok": True,
                "quarantine_id": "q-1",
                "sha256": "ab" * 32,
                "pkg_owner": None,
                "running_pids": [],
                "warnings": [],
            },
            "list_quarantine": {
                "schema_version": "1.0.0",
                "ok": True,
                "rows": [],
                "limit": 200,
            },
            "restore_quarantined": {
                "schema_version": "1.0.0",
                "ok": True,
                "quarantine_id": "q-1",
                "original_path": "/tmp/restored.bin",
                "sha256": "ab" * 32,
                "setuid_warning": False,
            },
            "delete_quarantined": {
                "schema_version": "1.0.0",
                "ok": True,
                "quarantine_id": "q-1",
                "original_path": "/tmp/deleted.bin",
                "blob_removed": True,
            },
        }

    def handler(self, name: str):
        def _handle(params: dict[str, Any]) -> dict[str, Any]:
            self.calls.append((name, params))
            return self.responses[name]

        return _handle


@pytest.fixture
def daemon(tmp_path: Path) -> Iterator[tuple[Path, _Daemon]]:
    d = _Daemon()
    sock = tmp_path / "ipc.sock"
    server = IpcServer(
        socket_path=sock,
        methods=[
            Method(name="quarantine_file", handler=d.handler("quarantine_file"), mutates=True),
            Method(name="list_quarantine", handler=d.handler("list_quarantine")),
            Method(
                name="restore_quarantined", handler=d.handler("restore_quarantined"), mutates=True
            ),
            Method(
                name="delete_quarantined", handler=d.handler("delete_quarantined"), mutates=True
            ),
        ],
        allowed_uids=[],
    )
    server.start()
    try:
        yield sock, d
    finally:
        server.stop()


def _invoke(socket_path: Path, *args: str) -> Any:
    return runner.invoke(app, [*args, "--socket", str(socket_path)], env=ENV)


# ---------------------------------------------------------------------------
# verb → params mapping
# ---------------------------------------------------------------------------


def test_file_sends_path_and_options(daemon: tuple[Path, _Daemon]) -> None:
    sock, d = daemon
    result = _invoke(
        sock,
        "quarantine",
        "file",
        "/tmp/evil.bin",
        "--alert-id",
        "a-1",
        "--case-id",
        "c-1",
        "--note",
        "from the alert",
    )
    assert result.exit_code == 0
    assert d.calls == [
        (
            "quarantine_file",
            {
                "path": "/tmp/evil.bin",
                "alert_id": "a-1",
                "case_id": "c-1",
                "note": "from the alert",
            },
        )
    ]


def test_file_omits_absent_options(daemon: tuple[Path, _Daemon]) -> None:
    sock, d = daemon
    result = _invoke(sock, "quarantine", "file", "/tmp/evil.bin")
    assert result.exit_code == 0
    assert d.calls == [("quarantine_file", {"path": "/tmp/evil.bin"})]


def test_list_sends_limit(daemon: tuple[Path, _Daemon]) -> None:
    sock, d = daemon
    result = _invoke(sock, "quarantine", "list", "--limit", "17")
    assert result.exit_code == 0
    assert d.calls == [("list_quarantine", {"limit": 17})]


def test_restore_and_delete_send_quarantine_id(daemon: tuple[Path, _Daemon]) -> None:
    sock, d = daemon
    assert _invoke(sock, "quarantine", "restore", "q-1").exit_code == 0
    assert _invoke(sock, "quarantine", "delete", "q-1").exit_code == 0
    assert d.calls == [
        ("restore_quarantined", {"quarantine_id": "q-1"}),
        ("delete_quarantined", {"quarantine_id": "q-1"}),
    ]


# ---------------------------------------------------------------------------
# success output: restore hint, warnings, PID caution, setuid warning
# ---------------------------------------------------------------------------


def test_file_success_shows_restore_hint_and_warnings(daemon: tuple[Path, _Daemon]) -> None:
    sock, d = daemon
    d.responses["quarantine_file"] = {
        **d.responses["quarantine_file"],
        "pkg_owner": "coreutils",
        "running_pids": [{"pid": 1234, "comm": "evil"}],
        "warnings": [
            "file is owned by package coreutils",
            "processes already running from this file are NOT stopped",
        ],
    }
    result = _invoke(sock, "quarantine", "file", "/tmp/evil.bin")
    assert result.exit_code == 0
    assert "quarantine restore q-1" in result.stdout  # the undo is one command away
    assert "coreutils" in result.stdout
    assert "NOT stopped" in result.stdout
    assert "1234" in result.stdout


def test_restore_success_shows_setuid_warning(daemon: tuple[Path, _Daemon]) -> None:
    sock, d = daemon
    d.responses["restore_quarantined"] = {
        **d.responses["restore_quarantined"],
        "setuid_warning": True,
    }
    result = _invoke(sock, "quarantine", "restore", "q-1")
    assert result.exit_code == 0
    assert "setuid" in result.stdout


def test_output_escapes_daemon_strings(daemon: tuple[Path, _Daemon]) -> None:
    """Rich markup in a daemon-controlled string must render literally."""
    sock, d = daemon
    d.responses["restore_quarantined"] = {
        **d.responses["restore_quarantined"],
        "original_path": "/tmp/[red]tricky[/red].bin",
    }
    result = _invoke(sock, "quarantine", "restore", "q-1")
    assert result.exit_code == 0
    assert "[red]tricky[/red]" in result.stdout


# ---------------------------------------------------------------------------
# exit codes: 0 ok, 1 error, 3 authorization denied
# ---------------------------------------------------------------------------


def test_daemon_refusal_is_exit_1(daemon: tuple[Path, _Daemon]) -> None:
    sock, d = daemon
    d.responses["quarantine_file"] = {
        "schema_version": "1.0.0",
        "ok": False,
        "error": "path is on the quarantine deny-list",
        "error_kind": "denied",
    }
    result = _invoke(sock, "quarantine", "file", "/etc/shadow")
    assert result.exit_code == 1
    assert "deny-list" in result.stdout


def test_daemon_unreachable_is_exit_1(tmp_path: Path) -> None:
    result = _invoke(tmp_path / "no-daemon.sock", "quarantine", "list")
    assert result.exit_code == 1
    assert "socket not found" in result.stdout


def test_authz_denial_is_exit_3(tmp_path: Path) -> None:
    """A -32001 answer maps to exit 3, message shown — no string matching."""
    sock = tmp_path / "ipc.sock"
    server = IpcServer(
        socket_path=sock,
        methods=[
            Method(
                name="quarantine_file",
                handler=lambda _p: {"ok": True},
                mutates=True,
                polkit_action="org.inspectord.quarantine",
            )
        ],
        allowed_uids=[],
        # No authz_check: the server fails closed with -32001 polkit_unavailable.
    )
    server.start()
    try:
        result = _invoke(sock, "quarantine", "file", "/tmp/evil.bin")
    finally:
        server.stop()
    assert result.exit_code == 3
    assert "polkit_unavailable" in result.stdout


# ---------------------------------------------------------------------------
# pkttyagent: spawned around mutating calls on a TTY, never for list/non-TTY
# ---------------------------------------------------------------------------


class _FakeAgent:
    def __init__(self) -> None:
        self.spawns: list[list[str]] = []
        self.terminated = 0

    def popen(self, argv: list[str], **_kwargs: Any) -> Any:
        self.spawns.append(argv)
        fake = self

        class _Proc:
            def terminate(self) -> None:
                fake.terminated += 1

            def wait(self, timeout: float | None = None) -> int:
                return 0

        return _Proc()


@pytest.fixture
def agent(monkeypatch: pytest.MonkeyPatch) -> _FakeAgent:
    fake = _FakeAgent()
    monkeypatch.setattr("inspectorctl.cli.quarantine.subprocess.Popen", fake.popen)
    monkeypatch.setattr("inspectorctl.cli.quarantine.shutil.which", lambda name: f"/usr/bin/{name}")
    return fake


def test_tty_agent_spawned_around_mutating_call(
    daemon: tuple[Path, _Daemon], agent: _FakeAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("inspectorctl.cli.quarantine._stdin_is_tty", lambda: True)
    sock, _d = daemon
    result = _invoke(sock, "quarantine", "file", "/tmp/evil.bin")
    assert result.exit_code == 0
    [argv] = agent.spawns
    assert argv[0] == "pkttyagent"
    assert "--fallback" in argv
    assert "--process" in argv
    assert agent.terminated == 1


def test_tty_agent_not_spawned_for_list(
    daemon: tuple[Path, _Daemon], agent: _FakeAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("inspectorctl.cli.quarantine._stdin_is_tty", lambda: True)
    sock, _d = daemon
    assert _invoke(sock, "quarantine", "list").exit_code == 0
    assert agent.spawns == []


def test_tty_agent_not_spawned_without_tty(
    daemon: tuple[Path, _Daemon], agent: _FakeAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("inspectorctl.cli.quarantine._stdin_is_tty", lambda: False)
    sock, _d = daemon
    assert _invoke(sock, "quarantine", "file", "/tmp/evil.bin").exit_code == 0
    assert agent.spawns == []
