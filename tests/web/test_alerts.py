"""Tests for the /alerts panel."""

from __future__ import annotations

from pathlib import Path

from inspectorctl.web.app import create_app
from inspectord.ipc_server import IpcServer, Method
from tests.web import SAME_ORIGIN, web_client


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
        client = web_client(create_app(socket_path=sock))
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
        headers=SAME_ORIGIN,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith("/alerts")
    assert any(c.get("alert_id") == "01900000-0000-7000-8000-000000000001" for c in ack_calls)


def test_resolve_alert_post(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    client = ipc_factory([_get_alert(), _resolve_alert()])
    response = client.post(
        "/alerts/01900000-0000-7000-8000-000000000001/resolve",
        headers=SAME_ORIGIN,
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_suppress_alert_post(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    client = ipc_factory([_get_alert(), _suppress_alert()])
    response = client.post(
        "/alerts/01900000-0000-7000-8000-000000000001/suppress",
        headers=SAME_ORIGIN,
        follow_redirects=False,
    )
    assert response.status_code == 303


def _get_alert_a1() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "alert": {
                "alert_id": "a1",
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


def _list_cases(cases: list[dict]) -> Method:  # type: ignore[type-arg]
    return Method(
        name="list_cases",
        handler=lambda _params: {"schema_version": "1.0.0", "cases": cases},
        mutates=False,
    )


def test_open_case_post_redirects_to_case(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    open_calls: list[dict] = []  # type: ignore[type-arg]

    def open_handler(params: dict) -> dict:  # type: ignore[type-arg]
        open_calls.append(params)
        return {"schema_version": "1.0.0", "case_id": "c9"}

    open_method = Method(name="open_case", handler=open_handler, mutates=True)
    client = ipc_factory([_get_alert_a1(), open_method])
    response = client.post("/alerts/a1/open-case", headers=SAME_ORIGIN, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/cases/c9"
    assert any(c.get("alert_id") == "a1" for c in open_calls)


def test_attach_case_post_redirects_to_alert(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    attach_calls: list[dict] = []  # type: ignore[type-arg]

    def attach_handler(params: dict) -> dict:  # type: ignore[type-arg]
        attach_calls.append(params)
        return {"schema_version": "1.0.0", "ok": True}

    attach_method = Method(name="attach_alert", handler=attach_handler, mutates=True)
    client = ipc_factory([_get_alert_a1(), attach_method])
    response = client.post(
        "/alerts/a1/attach-case",
        data={"case_id": "c1"},
        headers=SAME_ORIGIN,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/alerts/a1"
    assert any(c.get("case_id") == "c1" and c.get("alert_id") == "a1" for c in attach_calls)


def test_alert_detail_renders_case_actions(ipc_factory) -> None:  # type: ignore[no-untyped-def]
    open_case = {
        "case_id": "c1",
        "title": "sshd brute force",
        "status": "open",
        "opened_at": "2026-06-20T00:00:00",
        "alert_count": 1,
    }
    client = ipc_factory([_get_alert_a1(), _list_cases([open_case])])
    response = client.get("/alerts/a1")
    assert response.status_code == 200
    assert "/alerts/a1/open-case" in response.text
    assert "/alerts/a1/attach-case" in response.text
    assert 'value="c1"' in response.text
    assert "sshd brute force" in response.text


def _get_alert_with_boot_id() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        base = _get_alert().handler(_params)
        alert = dict(base["alert"])
        alert["entities"] = [
            {"kind": "process", "key": "pid:9999"},
            {"kind": "ip", "key": "1.2.3.4"},
            {"kind": "event", "key": "e1"},
        ]
        return {**base, "alert": alert, "boot_id": "boot-1"}

    return Method(name="get_alert", handler=handler, mutates=False)


def test_alert_detail_links_entities(ipc_factory) -> None:
    client = ipc_factory([_get_alert_with_boot_id()])
    response = client.get("/alerts/01900000-0000-7000-8000-000000000001")
    assert response.status_code == 200
    assert "/entity/process?key=9999%40boot-1" in response.text
    assert "/entity/ip?key=1.2.3.4" in response.text
    # An "event" entity has no card kind, so it stays plain text.
    assert "/entity/event" not in response.text


def test_alert_detail_process_entity_plain_without_boot_id(ipc_factory) -> None:
    client = ipc_factory([_get_alert()])
    response = client.get("/alerts/01900000-0000-7000-8000-000000000001")
    assert response.status_code == 200
    assert "/entity/process" not in response.text
    assert "pid:9999" in response.text
