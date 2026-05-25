"""Tests for the /deps page."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method


def _deps_listing() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "dependencies": [
                {
                    "name": "auditd",
                    "description": "Linux audit daemon",
                    "required_when_profiles": ["minimal", "standard"],
                    "packages_for_arch": ["audit"],
                    "installed": True,
                    "installed_version": "3.1.5-1",
                    "dropin_present": True,
                    "last_verify_ts": "2026-05-25T00:01:02+00:00",
                    "last_verify_pass": True,
                    "last_verify_detail": "auditd.service active",
                },
                {
                    "name": "yara",
                    "description": "YARA matcher",
                    "required_when_profiles": ["minimal", "standard"],
                    "packages_for_arch": ["yara"],
                    "installed": False,
                    "installed_version": None,
                    "dropin_present": False,
                    "last_verify_ts": None,
                    "last_verify_pass": None,
                    "last_verify_detail": None,
                },
            ],
        }

    return Method(name="list_dependencies", handler=handler, mutates=False)


def test_deps_page_renders_table(ipc_factory) -> None:
    client = ipc_factory([_deps_listing()])
    response = client.get("/deps")
    assert response.status_code == 200
    assert "auditd" in response.text
    assert "yara" in response.text
    assert "3.1.5-1" in response.text


def test_deps_page_when_daemon_unreachable(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "absent.sock")
    client = TestClient(app)
    response = client.get("/deps")
    assert response.status_code == 200
    assert "error" in response.text.lower() or "unreachable" in response.text.lower()
