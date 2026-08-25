"""Tests for the /audit panel (audit trail + chain verification)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method
from tests.web import SAME_ORIGIN, web_client


def _list_method(response: dict[str, Any]) -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return response

    return Method(name="list_audit_log", handler=handler, mutates=False)


def _verify_method(response: dict[str, Any]) -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return response

    return Method(name="verify_audit_log", handler=handler, mutates=False)


def _ok_rows(rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if rows is None:
        rows = [
            {
                "seq": 2,
                "ts": "2026-08-25T00:01:00+00:00",
                "actor": "user:local",
                "action": "alert_acked",
                "target": "alert:a1",
                "details": None,
            },
            {
                "seq": 1,
                "ts": "2026-08-25T00:00:00+00:00",
                "actor": "daemon",
                "action": "case_created",
                "target": "case:c1",
                "details": "auto",
            },
        ]
    return {"schema_version": "1.0.0", "ok": True, "rows": rows}


def _ok_verification(**overrides: Any) -> dict[str, Any]:
    verification: dict[str, Any] = {
        "ok": True,
        "rows": 5,
        "first_bad_seq": None,
        "reason": None,
        "anchor_checked": True,
        "last_good": None,
        "first_bad": None,
    }
    verification.update(overrides)
    return {"schema_version": "1.0.0", "ok": True, "verification": verification}


def test_audit_page_lists_rows(ipc_factory) -> None:
    client = ipc_factory([_list_method(_ok_rows())])
    response = client.get("/audit")
    assert response.status_code == 200
    assert "alert_acked" in response.text
    assert "user:local" in response.text


def test_audit_page_daemon_down_banner(tmp_path: Path) -> None:
    # No server is listening on this socket, so the IPC call fails.
    app = create_app(socket_path=tmp_path / "no.sock")
    client = web_client(app)
    response = client.get("/audit")
    assert response.status_code == 200
    assert "daemon unreachable" in response.text


def test_verify_post_redirects_and_renders_ok(ipc_factory) -> None:
    client = ipc_factory([_list_method(_ok_rows()), _verify_method(_ok_verification())])
    response = client.post("/audit/verify", headers=SAME_ORIGIN, follow_redirects=True)
    assert response.status_code == 200
    assert "chain consistent" in response.text.lower()


def test_verify_post_renders_break_guidance(ipc_factory) -> None:
    broken = _ok_verification(
        ok=False,
        rows=5,
        first_bad_seq=3,
        reason="row_hash_mismatch",
        last_good={
            "seq": 2,
            "ts": "2026-08-25T00:01:00+00:00",
            "actor": "user:local",
            "action": "alert_acked",
        },
        first_bad={
            "seq": 3,
            "ts": "2026-08-25T00:02:00+00:00",
            "actor": "daemon",
            "action": "case_created",
        },
    )
    client = ipc_factory([_list_method(_ok_rows()), _verify_method(broken)])
    response = client.post("/audit/verify", headers=SAME_ORIGIN, follow_redirects=True)
    assert response.status_code == 200
    assert "untrusted" in response.text  # spec §7 break guidance
    assert "3" in response.text
    assert "row_hash_mismatch" in response.text


def test_audit_page_escapes_hostile_values(ipc_factory) -> None:
    hostile = "<script>alert(1)</script>"
    rows = [
        {
            "seq": 1,
            "ts": "2026-08-25T00:00:00+00:00",
            "actor": "daemon",
            "action": "case_created",
            "target": hostile,
            "details": None,
        },
    ]
    client = ipc_factory([_list_method(_ok_rows(rows))])
    response = client.get("/audit")
    assert response.status_code == 200
    assert "<script>alert(1)" not in response.text
    assert "&lt;script&gt;" in response.text
