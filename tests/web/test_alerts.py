"""Tests for the /alerts panel."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectord.ipc_server import IpcServer, Method


def _alerts_listing() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "alerts": [
                {
                    "alert_id": "01900000-0000-7000-8000-000000000001",
                    "rule_id": "lolbin.bash_dev_tcp",
                    "ts": "2026-05-25T14:23:10+00:00",
                    "severity": "critical",
                    "status": "new",
                    "category": "intrusion_detection",
                    "dedup_count": 3,
                    "rendered_short": "Reverse shell pid 9999",
                }
            ],
        }

    return Method(name="list_alerts", handler=handler, mutates=False)


def _get_alert() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "alert": {
                "alert_id": "01900000-0000-7000-8000-000000000001",
                "rule": {
                    "id": "lolbin.bash_dev_tcp",
                    "name": "Reverse-shell pattern",
                    "severity": "critical",
                    "why": "bash -i >& /dev/tcp/ is a classic reverse-shell idiom",
                    "false_positives": ["pentest/CTF tools"],
                },
                "ts": "2026-05-25T14:23:10+00:00",
                "severity": "critical",
                "status": "new",
                "category": "intrusion_detection",
                "rendered": {"short": "Reverse shell pid 9999", "detail": "long detail"},
                "entities": [{"kind": "process", "key": "pid:9999"}],
                "dedup_count": 3,
                "first_seen_at": "2026-05-25T14:00:00+00:00",
                "last_seen_at": "2026-05-25T14:23:10+00:00",
                "labels": ["lolbin", "reverse-shell"],
            },
        }

    return Method(name="get_alert", handler=handler, mutates=False)


def _resolve_alert() -> Method:
    def handler(_params: dict) -> dict:  # type: ignore[type-arg]
        return {"schema_version": "1.0.0", "ok": True, "status": "resolved"}

    return Method(name="resolve_alert", handler=handler, mutates=True)


def _suppress_alert() -> Method:
    def handler(_params: dict) -> dict:  # type: ignore[type-arg]
        return {"schema_version": "1.0.0", "ok": True, "status": "suppressed"}

    return Method(name="suppress_alert", handler=handler, mutates=True)


def test_alerts_list_renders(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    client = ipc_factory([_alerts_listing()])
    response = client.get("/alerts")
    assert response.status_code == 200
    assert "lolbin.bash_dev_tcp" in response.text
    assert "Reverse shell pid 9999" in response.text


def test_alerts_list_filter_by_status(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    calls: list[dict] = []  # type: ignore[type-arg]

    def handler(params: dict) -> dict:  # type: ignore[type-arg]
        calls.append(params)
        return {"schema_version": "1.0.0", "alerts": []}

    client = ipc_factory([Method(name="list_alerts", handler=handler, mutates=False)])
    client.get("/alerts?status=new")
    assert any(c.get("status") == "new" for c in calls)


def test_alert_detail_renders(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    client = ipc_factory([_get_alert()])
    response = client.get("/alerts/01900000-0000-7000-8000-000000000001")
    assert response.status_code == 200
    assert "Reverse-shell pattern" in response.text
    assert "long detail" in response.text
    assert "pentest/CTF tools" in response.text


def test_alert_detail_404_when_missing(tmp_path: Path) -> None:
    def handler(_params: dict) -> dict:  # type: ignore[type-arg]
        return {"schema_version": "1.0.0", "alert": None}

    sock = tmp_path / "ipc.sock"
    server = IpcServer(
        socket_path=sock,
        methods=[Method(name="get_alert", handler=handler, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        client = TestClient(create_app(socket_path=sock))
        response = client.get("/alerts/absent")
        assert response.status_code == 404
    finally:
        server.stop()


def test_ack_alert_post_redirects_to_list(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    ack_calls: list[dict] = []  # type: ignore[type-arg]

    def ack_handler(params: dict) -> dict:  # type: ignore[type-arg]
        ack_calls.append(params)
        return {"schema_version": "1.0.0", "ok": True, "status": "acknowledged"}

    ack_method = Method(name="ack_alert", handler=ack_handler, mutates=True)
    client = ipc_factory([_get_alert(), ack_method])
    response = client.post(
        "/alerts/01900000-0000-7000-8000-000000000001/ack",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith("/alerts")
    assert any(c.get("alert_id") == "01900000-0000-7000-8000-000000000001" for c in ack_calls)


def test_resolve_alert_post(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    client = ipc_factory([_get_alert(), _resolve_alert()])
    response = client.post(
        "/alerts/01900000-0000-7000-8000-000000000001/resolve",
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_suppress_alert_post(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    client = ipc_factory([_get_alert(), _suppress_alert()])
    response = client.post(
        "/alerts/01900000-0000-7000-8000-000000000001/suppress",
        follow_redirects=False,
    )
    assert response.status_code == 303
