"""Tests for the /vulnerabilities panel (vuln-scanner design §6-§7)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from inspectorctl.web.app import create_app
from inspectord.ipc_server import Method
from tests.web import SAME_ORIGIN, web_client


def _row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "avg_id": "AVG-2871",
        "cve_id": "CVE-2026-0001",
        "package": "openssl",
        "installed_version": "3.3.1-1",
        "fixed_version": "3.3.2-1",
        "severity": "Critical",
        "status": "Fixed",
        "fix_in_testing": False,
        "first_seen_at": "2026-08-26T12:00:00",
        "last_seen": "2026-08-26T12:00:00",
        "last_event_id": "e1",
        "resolved_at": None,
        "acked_at": None,
        "acked_note": None,
    }
    row.update(overrides)
    return row


def _completed_scan(**overrides: Any) -> dict[str, Any]:
    scan: dict[str, Any] = {
        "action": "vuln_scan_completed",
        "ts": "2026-08-26T12:00:00",
        "advisory_mtime": (datetime.now(UTC) - timedelta(days=2)).isoformat(),
        "counts": {"advisories": 12, "matched": 1, "new": 0, "warnings": 0},
    }
    scan.update(overrides)
    return scan


def _ok(
    rows: list[dict[str, Any]] | None = None,
    last_scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "ok": True,
        "rows": rows if rows is not None else [_row()],
        "last_scan": last_scan,
    }


def _list_method(response: dict[str, Any], calls: list[dict[str, Any]] | None = None) -> Method:
    def handler(params: dict[str, Any]) -> dict[str, Any]:
        if calls is not None:
            calls.append(params)
        return response

    return Method(name="list_vulnerabilities", handler=handler, mutates=False)


def _ack_method(
    response: dict[str, Any] | None = None, calls: list[dict[str, Any]] | None = None
) -> Method:
    def handler(params: dict[str, Any]) -> dict[str, Any]:
        if calls is not None:
            calls.append(params)
        if response is not None:
            return response
        return {"schema_version": "1.0.0", "ok": True, "acked_at": "2026-08-26T12:00:00"}

    return Method(name="ack_vulnerability", handler=handler, mutates=True)


def test_page_lists_rows(ipc_factory) -> None:
    client = ipc_factory([_list_method(_ok())])
    response = client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "openssl" in response.text
    assert "3.3.1-1" in response.text
    assert "CVE-2026-0001" in response.text
    # Advisory link built server-side from the row's avg_id, never from the feed.
    assert 'href="https://security.archlinux.org/AVG-2871"' in response.text
    assert 'rel="noopener"' in response.text
    assert "sev-critical" in response.text  # severity badge
    assert "3.3.2-1" in response.text  # fixed-in
    assert "pacman -Syu openssl" in response.text  # remediation suggestion


def test_fix_in_testing_qualifier(ipc_factory) -> None:
    client = ipc_factory([_list_method(_ok([_row(fix_in_testing=True)]))])
    response = client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "(in [testing])" in response.text


def test_resolved_and_acked_markers(ipc_factory) -> None:
    rows = [
        _row(avg_id="AVG-1", resolved_at="2026-08-26T13:00:00"),
        _row(avg_id="AVG-2", acked_at="2026-08-26T14:00:00", acked_note="known issue"),
    ]
    client = ipc_factory([_list_method(_ok(rows))])
    response = client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "resolved" in response.text
    assert "acked" in response.text
    assert "known issue" in response.text


def test_filters_forwarded_to_ipc(ipc_factory) -> None:
    calls: list[dict[str, Any]] = []
    client = ipc_factory([_list_method(_ok([]), calls)])
    response = client.get(
        "/vulnerabilities?severity=High&include_acked=0&include_resolved=1&limit=50"
    )
    assert response.status_code == 200
    assert calls == [
        {"limit": 50, "severity": "High", "include_acked": False, "include_resolved": True}
    ]


def test_default_filters(ipc_factory) -> None:
    calls: list[dict[str, Any]] = []
    client = ipc_factory([_list_method(_ok([]), calls)])
    assert client.get("/vulnerabilities").status_code == 200
    assert calls == [{"limit": 100, "include_acked": True, "include_resolved": False}]


def test_hostile_package_name_escaped(ipc_factory) -> None:
    hostile = "<script>alert(1)</script>"
    client = ipc_factory([_list_method(_ok([_row(package=hostile)]))])
    response = client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "<script>alert(1)" not in response.text
    assert "&lt;script&gt;" in response.text


def test_ack_post_calls_ipc_and_redirects(ipc_factory) -> None:
    calls: list[dict[str, Any]] = []
    client = ipc_factory([_list_method(_ok()), _ack_method(calls=calls)])
    response = client.post(
        "/vulnerabilities/ack",
        headers=SAME_ORIGIN,
        data={
            "avg_id": "AVG-2871",
            "cve_id": "CVE-2026-0001",
            "package": "openssl",
            "note": "reviewed",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/vulnerabilities"
    assert calls == [
        {
            "avg_id": "AVG-2871",
            "cve_id": "CVE-2026-0001",
            "package": "openssl",
            "note": "reviewed",
        }
    ]


def test_ack_post_without_note_omits_note(ipc_factory) -> None:
    calls: list[dict[str, Any]] = []
    client = ipc_factory([_list_method(_ok()), _ack_method(calls=calls)])
    response = client.post(
        "/vulnerabilities/ack",
        headers=SAME_ORIGIN,
        data={"avg_id": "AVG-2871", "cve_id": "CVE-2026-0001", "package": "openssl"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert calls == [{"avg_id": "AVG-2871", "cve_id": "CVE-2026-0001", "package": "openssl"}]


def test_ack_post_not_found_is_404(ipc_factory) -> None:
    not_found = {"schema_version": "1.0.0", "ok": False, "error": "not_found"}
    client = ipc_factory([_list_method(_ok()), _ack_method(response=not_found)])
    response = client.post(
        "/vulnerabilities/ack",
        headers=SAME_ORIGIN,
        data={"avg_id": "AVG-9999", "cve_id": "CVE-1", "package": "nope"},
        follow_redirects=False,
    )
    assert response.status_code == 404


# --------------------------------------------------------------------------
# freshness (§6)
# --------------------------------------------------------------------------


def test_freshness_completed_fresh(ipc_factory) -> None:
    client = ipc_factory([_list_method(_ok(last_scan=_completed_scan()))])
    response = client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "last scan 2026-08-26T12:00:00" in response.text
    assert "advisories updated 2 days ago" in response.text
    assert 'class="warn"' not in response.text


def test_freshness_completed_stale_advisories_warn(ipc_factory) -> None:
    stale = _completed_scan(advisory_mtime=(datetime.now(UTC) - timedelta(days=20)).isoformat())
    client = ipc_factory([_list_method(_ok(last_scan=stale))])
    response = client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "advisories updated 20 days ago" in response.text
    assert 'class="warn"' in response.text


def test_freshness_failed(ipc_factory) -> None:
    failed = {
        "action": "vuln_scan_failed",
        "ts": "2026-08-26T12:00:00",
        "reason": "pacman_db_locked",
    }
    client = ipc_factory([_list_method(_ok(last_scan=failed))])
    response = client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "last scan attempt 2026-08-26T12:00:00" in response.text
    assert "failed: pacman_db_locked" in response.text
    assert 'class="error"' in response.text


def test_freshness_never_scanned(ipc_factory) -> None:
    client = ipc_factory([_list_method(_ok([], last_scan=None))])
    response = client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "never scanned" in response.text


def test_daemon_down_banner(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "no.sock")
    client = web_client(app)
    response = client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "daemon unreachable" in response.text


def test_nav_link_present(ipc_factory) -> None:
    client = ipc_factory([_list_method(_ok([]))])
    response = client.get("/vulnerabilities")
    assert 'href="/vulnerabilities"' in response.text
    assert "Vulnerabilities" in response.text
