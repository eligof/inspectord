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


_MANUAL_ITEM = {
    "name": "aide",
    "action": "manual",
    "packages": [],
    "expected_command": None,
    "config_dropin": None,
    "service_actions": [],
    "permission_actions": [],
    "post_install_hooks": [],
    "manual_reason": "AUR-only on Arch; inspectord will not build AUR PKGBUILDs",
    "manual_instructions": "install it yourself, e.g. `paru -S aide`",
}


def _plan_server(sock_path: Path, items: list[dict[str, object]]) -> IpcServer:
    def plan_handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "plan_id": "01900000-0000-7000-8000-000000000000",
            "distro": "arch",
            "package_manager": "pacman",
            "items": items,
            "expires_at": "2026-05-24T16:00:00+00:00",
        }

    return IpcServer(
        socket_path=sock_path,
        methods=[Method(name="plan_dependency_install", handler=plan_handler, mutates=True)],
        allowed_uids=[],
    )


def test_deps_plan_renders_manual_item(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"
    server = _plan_server(sock_path, [dict(_MANUAL_ITEM)])
    server.start()
    try:
        result = runner.invoke(app, ["deps", "plan", "--socket", str(sock_path)])
        assert result.exit_code == 0
        out = " ".join(result.stdout.split())
        assert "aide" in out
        assert "manual" in out.lower()
        assert "paru -S aide" in out
        # A plan of nothing but manual items must not tell the user to run `deps install`.
        assert "deps install" not in out
    finally:
        server.stop()


def test_deps_install_refuses_to_apply_a_manual_only_plan(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"
    applied: list[str] = []

    def plan_handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "plan_id": "01900000-0000-7000-8000-000000000001",
            "distro": "arch",
            "package_manager": "pacman",
            "items": [dict(_MANUAL_ITEM)],
            "expires_at": "2026-05-24T16:00:00+00:00",
        }

    def apply_handler(params: dict[str, object]) -> dict[str, object]:
        applied.append(str(params.get("plan_id")))
        return {"schema_version": "1.0.0", "plan_id": "x", "ok": True, "notes": []}

    server = IpcServer(
        socket_path=sock_path,
        methods=[
            Method(name="plan_dependency_install", handler=plan_handler, mutates=True),
            Method(name="apply_dependency_plan", handler=apply_handler, mutates=True),
        ],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(app, ["deps", "install", "--socket", str(sock_path), "--yes"])
        assert result.exit_code == 0
        out = " ".join(result.stdout.split())
        assert "paru -S aide" in out
        assert applied == []
    finally:
        server.stop()
