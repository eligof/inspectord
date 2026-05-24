"""Tests for inspectorctl deps CLI."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from inspectorctl.cli.app import app
from inspectord.ipc_server import IpcServer, Method

runner = CliRunner()


def test_deps_status_renders(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def list_deps(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "dependencies": [
                {
                    "name": "auditd",
                    "installed": True,
                    "installed_version": "3.1.5-1",
                    "dropin_present": False,
                    "last_verify_pass": None,
                }
            ],
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="list_dependencies", handler=list_deps, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(app, ["deps", "status", "--socket", str(sock_path)])
        assert result.exit_code == 0
        assert "auditd" in result.stdout
    finally:
        server.stop()


def test_deps_plan_prints_items(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def plan_handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "plan_id": "01900000-0000-7000-8000-000000000000",
            "distro": "arch",
            "package_manager": "pacman",
            "items": [
                {
                    "name": "auditd",
                    "action": "install",
                    "packages": ["audit"],
                    "expected_command": "pacman install audit",
                    "config_dropin": None,
                    "service_actions": ["systemctl enable --now auditd.service"],
                    "permission_actions": [],
                    "post_install_hooks": [],
                }
            ],
            "expires_at": "2026-05-24T16:00:00+00:00",
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="plan_dependency_install", handler=plan_handler, mutates=True)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(
            app, ["deps", "plan", "--socket", str(sock_path), "--profile", "minimal"]
        )
        assert result.exit_code == 0
        assert "auditd" in result.stdout
        assert "audit" in result.stdout
    finally:
        server.stop()
