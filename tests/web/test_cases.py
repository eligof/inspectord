"""Tests for the /cases panel."""

from __future__ import annotations

import base64
import copy
import io
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method

CASE = {
    "case_id": "c1",
    "title": "sshd brute force",
    "status": "open",
    "opened_at": "2026-06-20T00:00:00",
    "closed_at": None,
    "alerts": [
        {
            "alert_id": "a1",
            "rule_id": "auth.ssh",
            "severity": "high",
            "status": "new",
            "rendered_short": "brute force",
            "ts": "2026-06-20T00:00:00",
        }
    ],
    "timeline": [
        {"ts": "2026-06-20T00:00:00", "seq": 0, "kind": "opened", "text": None},
        {"ts": "2026-06-20T00:00:00", "seq": 1, "kind": "alert_attached", "text": "a1"},
    ],
    "evidence": [
        {
            "kind": "file",
            "sha256": "abc123def456abc7890",
            "original_path": "/etc/sudoers",
            "captured_at": "2026-06-22T00:00:00",
            "meta": {"size": 42},
        },
    ],
}


def _list_cases(cases: list[dict]) -> Method:
    return Method(
        name="list_cases",
        handler=lambda params: {"schema_version": "1.0.0", "cases": cases},
        mutates=False,
    )


def _get_case(case: dict | None) -> Method:
    return Method(
        name="get_case",
        handler=lambda params: {"schema_version": "1.0.0", "case": case},
        mutates=False,
    )


def _add_note(calls: list[dict]) -> Method:
    def handler(params: dict) -> dict:
        calls.append(params)
        return {"schema_version": "1.0.0", "ok": True}

    return Method(name="add_note", handler=handler, mutates=True)


def _close_case(calls: list[dict]) -> Method:
    def handler(params: dict) -> dict:
        calls.append(params)
        return {"schema_version": "1.0.0", "ok": True}

    return Method(name="close_case", handler=handler, mutates=True)


def test_cases_list_renders(ipc_factory) -> None:
    cases = [
        {
            "case_id": "c1",
            "title": "sshd brute force",
            "status": "open",
            "opened_at": "2026-06-20T00:00:00",
            "alert_count": 1,
        }
    ]
    client = ipc_factory([_list_cases(cases)])
    response = client.get("/cases")
    assert response.status_code == 200
    assert "sshd brute force" in response.text
    assert "/cases/c1" in response.text


def test_cases_list_empty_state(ipc_factory) -> None:
    client = ipc_factory([_list_cases([])])
    response = client.get("/cases")
    assert response.status_code == 200
    assert "No cases yet" in response.text


def test_cases_list_daemon_unreachable(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "no.sock")
    client = TestClient(app)
    response = client.get("/cases")
    assert response.status_code == 200
    assert "daemon unreachable" in response.text


def test_case_detail_renders(ipc_factory) -> None:
    client = ipc_factory([_get_case(CASE)])
    response = client.get("/cases/c1")
    assert response.status_code == 200
    assert "sshd brute force" in response.text
    assert "/alerts/a1" in response.text
    assert "opened" in response.text
    assert "alert_attached" in response.text
    assert "/cases/c1/notes" in response.text
    assert "/cases/c1/close" in response.text


def test_case_detail_renders_evidence(ipc_factory) -> None:
    client = ipc_factory([_get_case(CASE)])
    response = client.get("/cases/c1")
    assert response.status_code == 200
    assert "Evidence" in response.text
    assert "/etc/sudoers" in response.text
    assert "abc123def456abc7" in response.text


def test_case_detail_escapes_evidence_path(ipc_factory) -> None:
    case = copy.deepcopy(CASE)
    case["evidence"].append(
        {
            "kind": "file",
            "sha256": "deadbeefdeadbeef0000",
            "original_path": "<script>alert(1)</script>",
            "captured_at": "2026-06-22T00:00:00",
            "meta": {"size": 7},
        }
    )
    client = ipc_factory([_get_case(case)])
    response = client.get("/cases/c1")
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_case_detail_evidence_empty_state(ipc_factory) -> None:
    case = copy.deepcopy(CASE)
    case["evidence"] = []
    client = ipc_factory([_get_case(case)])
    response = client.get("/cases/c1")
    assert response.status_code == 200
    assert "No evidence captured." in response.text
    # A zero-evidence case still exports a valid minimal ZIP (spec §3) — button must show.
    assert 'action="/cases/c1/export"' in response.text


def test_case_detail_missing_404(ipc_factory) -> None:
    client = ipc_factory([_get_case(None)])
    response = client.get("/cases/missing")
    assert response.status_code == 404


def test_case_detail_escapes_note_text(ipc_factory) -> None:
    case = copy.deepcopy(CASE)
    case["timeline"].append(
        {
            "ts": "2026-06-20T00:00:00",
            "seq": 2,
            "kind": "note",
            "text": "<script>alert(1)</script>",
        }
    )
    client = ipc_factory([_get_case(case)])
    response = client.get("/cases/c1")
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_case_add_note_post(ipc_factory) -> None:
    calls: list[dict] = []
    client = ipc_factory([_get_case(CASE), _add_note(calls)])
    response = client.post("/cases/c1/notes", data={"text": "hi"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/cases/c1"
    assert len(calls) == 1
    assert calls[0]["case_id"] == "c1"
    assert calls[0]["text"] == "hi"


def test_case_close_post(ipc_factory) -> None:
    calls: list[dict] = []
    client = ipc_factory([_get_case(CASE), _close_case(calls)])
    response = client.post("/cases/c1/close", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/cases/c1"
    assert len(calls) == 1
    assert calls[0]["case_id"] == "c1"


def _export_ok() -> Method:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("case.json", '{"case_id": "c1"}')
    content_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return Method(
        name="export_case_zip",
        handler=lambda params: {
            "schema_version": "1.0.0",
            "ok": True,
            "filename": "case-c1.zip",
            "content_b64": content_b64,
        },
        mutates=False,
    )


def _export_error(error: str) -> Method:
    return Method(
        name="export_case_zip",
        handler=lambda params: {"schema_version": "1.0.0", "ok": False, "error": error},
        mutates=False,
    )


def test_case_export_returns_zip(ipc_factory) -> None:
    client = ipc_factory([_export_ok()])
    response = client.post("/cases/c1/export")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert 'attachment; filename="case-c1.zip"' in response.headers["content-disposition"]
    zf = zipfile.ZipFile(io.BytesIO(response.content))
    assert "case.json" in zf.namelist()


def test_case_export_not_found_404(ipc_factory) -> None:
    client = ipc_factory([_export_error("not found")])
    response = client.post("/cases/c1/export")
    assert response.status_code == 404


def test_case_export_too_large_413(ipc_factory) -> None:
    client = ipc_factory([_export_error("too_large")])
    response = client.post("/cases/c1/export")
    assert response.status_code == 413
    assert "forensic store" in response.text  # friendly retrieve-from-disk message


def _download_ok() -> Method:
    content_b64 = base64.b64encode(b"file bytes").decode("ascii")
    return Method(
        name="download_evidence",
        handler=lambda params: {
            "schema_version": "1.0.0",
            "ok": True,
            "filename": "sudoers",
            "media_type": "application/octet-stream",
            "content_b64": content_b64,
        },
        mutates=False,
    )


def _download_error(error: str) -> Method:
    return Method(
        name="download_evidence",
        handler=lambda params: {"schema_version": "1.0.0", "ok": False, "error": error},
        mutates=False,
    )


def test_case_evidence_download_returns_blob(ipc_factory) -> None:
    client = ipc_factory([_download_ok()])
    response = client.post("/cases/c1/evidence/" + "a" * 64)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert 'attachment; filename="sudoers"' in response.headers["content-disposition"]
    assert response.content == b"file bytes"


def test_case_evidence_download_not_in_case_404(ipc_factory) -> None:
    client = ipc_factory([_download_error("not found")])
    response = client.post("/cases/c1/evidence/" + "b" * 64)
    assert response.status_code == 404


def test_case_detail_shows_export_and_download_links(ipc_factory) -> None:
    client = ipc_factory([_get_case(CASE)])
    response = client.get("/cases/c1")
    assert response.status_code == 200
    # Export button posts to the export route
    assert 'action="/cases/c1/export"' in response.text
    # Per-evidence-row download button posts to the evidence route with the sha
    assert f'action="/cases/c1/evidence/{CASE["evidence"][0]["sha256"]}"' in response.text
    # The old placeholder text is gone
    assert "coming soon" not in response.text
