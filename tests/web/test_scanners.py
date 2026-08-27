"""Tests for the /scanners panel (plan 2026-08-20-scanner-panel §5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inspectorctl.web.app import create_app
from inspectord.ipc_commands import RATE_LIMIT_PER_MIN, WorkerCommandError
from inspectord.ipc_server import Method
from tests.web import SAME_ORIGIN, web_client

_SUCCESS_RUN: dict[str, Any] = {
    "run_id": "run-1",
    "scanner": "aide",
    "state": "success",
    "reason": None,
    "exit_code": 0,
    "duration_s": 42.5,
    "finding_count": 3,
    "findings_dropped": 0,
    "truncated": False,
    "output_truncated": False,
    "output_excerpt": None,
    "started_at": "2026-08-20T02:00:00",
    "completed_at": "2026-08-20T02:00:42",
}


def _runs(*scanners: dict[str, Any]) -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return {"schema_version": "1.0.0", "scanners": list(scanners)}

    return Method(name="list_scan_runs", handler=handler, mutates=False)


def _findings(*items: dict[str, Any]) -> Method:
    def handler(params: dict[str, object]) -> dict[str, object]:
        return {"schema_version": "1.0.0", "findings": list(items)}

    return Method(name="list_scan_findings", handler=handler, mutates=False)


def _run(**overrides: Any) -> dict[str, Any]:
    return {**_SUCCESS_RUN, **overrides}


def test_scanners_shell_renders(ipc_factory) -> None:
    client = ipc_factory([_runs(_SUCCESS_RUN), _findings()])
    response = client.get("/scanners")
    assert response.status_code == 200
    assert "hx-get" in response.text
    assert "/scanners/feed" in response.text
    assert "scanners-feed" in response.text


def test_nav_links_to_scanners(ipc_factory) -> None:
    client = ipc_factory([_runs(_SUCCESS_RUN), _findings()])
    response = client.get("/scanners")
    assert '<a href="/scanners"' in response.text


def test_feed_renders_a_successful_run(ipc_factory) -> None:
    client = ipc_factory([_runs(_SUCCESS_RUN), _findings()])
    response = client.get("/scanners/feed")
    assert response.status_code == 200
    assert "aide" in response.text
    assert "success" in response.text
    assert "2026-08-20T02:00:00" in response.text
    assert "42.5" in response.text
    assert ">3<" in response.text
    # The feed is a fragment, never a whole page.
    assert "<nav>" not in response.text


def test_feed_renders_a_failed_run_with_reason_and_output(ipc_factory) -> None:
    client = ipc_factory(
        [
            _runs(
                _run(
                    state="failure",
                    reason="timeout",
                    exit_code=None,
                    duration_s=3600.0,
                    finding_count=None,
                    output_excerpt="aide: IO error while reading /var/lib/inspectord/aide/db",
                )
            ),
            _findings(),
        ]
    )
    response = client.get("/scanners/feed")
    assert response.status_code == 200
    assert "failure" in response.text
    assert "timeout" in response.text
    # The user must be able to see WHY, not just that nothing came back.
    assert "IO error while reading" in response.text


def test_feed_renders_a_skipped_run_with_its_reason(ipc_factory) -> None:
    client = ipc_factory(
        [
            _runs(
                _run(
                    run_id="skip:e9",
                    state="skipped",
                    reason="database_missing",
                    exit_code=None,
                    duration_s=None,
                    finding_count=None,
                    completed_at="2026-08-20T02:00:00",
                )
            ),
            _findings(),
        ]
    )
    response = client.get("/scanners/feed")
    assert response.status_code == 200
    assert "skipped" in response.text
    assert "database_missing" in response.text


def test_feed_renders_an_interrupted_run(ipc_factory) -> None:
    client = ipc_factory(
        [
            _runs(
                _run(
                    state="interrupted",
                    exit_code=None,
                    duration_s=None,
                    finding_count=None,
                    completed_at=None,
                )
            ),
            _findings(),
        ]
    )
    response = client.get("/scanners/feed")
    assert response.status_code == 200
    assert "interrupted" in response.text
    # A run that never completed must not read as success, nor as "still
    # running" with no end in sight.
    assert "success" not in response.text
    assert "no scan_completed" in response.text


def test_feed_renders_a_running_run(ipc_factory) -> None:
    client = ipc_factory(
        [
            _runs(
                _run(
                    state="running",
                    exit_code=None,
                    duration_s=None,
                    finding_count=None,
                    completed_at=None,
                )
            ),
            _findings(),
        ]
    )
    response = client.get("/scanners/feed")
    assert response.status_code == 200
    assert "running" in response.text
    assert "in progress" in response.text


def test_feed_flags_a_truncated_finding_list(ipc_factory) -> None:
    client = ipc_factory(
        [_runs(_run(finding_count=500, findings_dropped=37, truncated=True)), _findings()]
    )
    response = client.get("/scanners/feed")
    assert "37" in response.text
    assert "truncated" in response.text


def test_feed_renders_findings(ipc_factory) -> None:
    client = ipc_factory(
        [
            _runs(_SUCCESS_RUN),
            _findings(
                {
                    "event_id": "f1",
                    "ts": "2026-08-20T02:00:05",
                    "scanner": "yara",
                    "run_id": "run-1",
                    "path": "/home/eli/sample.bin",
                    "indicator_type": "yara_rule",
                    "indicator_value": "SUSP_Example_Rule",
                    "scanner_severity": "high",
                    "message": "yara matched SUSP_Example_Rule",
                }
            ),
        ]
    )
    response = client.get("/scanners/feed")
    assert "SUSP_Example_Rule" in response.text
    assert "/home/eli/sample.bin" in response.text


def test_feed_states_the_untrusted_output_bound(ipc_factory) -> None:
    client = ipc_factory([_runs(_SUCCESS_RUN), _findings()])
    response = client.get("/scanners/feed")
    # The adapters' residual bound: a filename can forge a report line, so a
    # finding's path, rule name and message may be attacker-chosen.
    assert "untrusted" in response.text.lower()


def test_feed_escapes_scanner_derived_text(ipc_factory) -> None:
    """Every scanner-derived string on this page is attacker-influenceable.

    A filename can forge a report line (see the aide/rkhunter/yara adapter
    docstrings), so a finding's path, indicator value and message, and a failed
    run's reason and output excerpt, may all contain attacker-chosen text.
    """
    payload = "<script>alert(1)</script>"
    escaped = "&lt;script&gt;alert(1)&lt;/script&gt;"
    client = ipc_factory(
        [
            _runs(
                _run(
                    scanner="aide",
                    state="failure",
                    reason=payload,
                    finding_count=None,
                    output_excerpt=f"aide: cannot stat {payload}",
                )
            ),
            _findings(
                {
                    "event_id": "f1",
                    "ts": "2026-08-20T02:00:05",
                    "scanner": "yara",
                    "run_id": "run-1",
                    # A filename is attacker-influenceable — this is the case
                    # the parser hardening could not remove.
                    "path": f"/tmp/{payload}",
                    "indicator_type": "yara_rule",
                    "indicator_value": f"Rule{payload}",
                    "scanner_severity": "high",
                    "message": f"matched {payload}",
                }
            ),
        ]
    )
    response = client.get("/scanners/feed")
    assert response.status_code == 200
    # Nothing scanner-derived may reach the page as markup...
    assert payload not in response.text
    assert "<script>" not in response.text
    # ...and the escaped form must be present, so a silently dropped field
    # cannot make this test pass by accident.
    assert response.text.count(escaped) >= 5


def test_feed_empty_state(ipc_factory) -> None:
    client = ipc_factory([_runs(), _findings()])
    response = client.get("/scanners/feed")
    assert response.status_code == 200
    # A scanner that never ran has no row at all — say so, rather than
    # implying every scanner is fine.
    assert "No scan runs recorded" in response.text


def test_feed_daemon_unreachable(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "no.sock")
    client = web_client(app)
    response = client.get("/scanners/feed")
    assert response.status_code == 200
    assert "daemon unreachable" in response.text


def test_populated_table_says_a_missing_scanner_is_not_clean(ipc_factory) -> None:
    """A short table must not read as "these are all the scanners".

    The panel can only list scanners that have produced an event; the roster
    lives in the worker's stdin config and there is no IPC->worker channel. So a
    configured-but-never-run scanner is simply absent, and the page has to say so
    — otherwise one green row implies coverage the daemon does not have.
    """
    client = ipc_factory([_runs(_run(scanner="aide")), _findings()])
    body = client.get("/scanners/feed").text
    assert "has never run" in body
    assert "not the same as clean" in body


# --------------------------------------------------------------------------
# Run now (worker-command-channel design §2 PR2, §6, §8)
# --------------------------------------------------------------------------


def _cmd_method(
    response: dict[str, Any] | None = None,
    calls: list[dict[str, Any]] | None = None,
    error: Exception | None = None,
) -> Method:
    def handler(params: dict[str, Any]) -> dict[str, Any]:
        if calls is not None:
            calls.append(params)
        if error is not None:
            raise error
        if response is not None:
            return response
        return {"schema_version": "1.0.0", "ok": True, "status": "accepted", "detail": ""}

    return Method(name="run_worker_command", handler=handler, mutates=True)


def test_feed_renders_run_now_button_per_scanner(ipc_factory) -> None:
    client = ipc_factory([_runs(_SUCCESS_RUN), _findings()])
    response = client.get("/scanners/feed")
    assert 'action="/scanners/run"' in response.text
    assert 'name="name" value="aide"' in response.text
    assert "Run now" in response.text


def test_run_post_calls_ipc_and_redirects(ipc_factory) -> None:
    calls: list[dict[str, Any]] = []
    client = ipc_factory([_runs(), _findings(), _cmd_method(calls=calls)])
    response = client.post(
        "/scanners/run", headers=SAME_ORIGIN, data={"name": "aide"}, follow_redirects=False
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/scanners?")
    assert "cmd_status=accepted" in location
    assert calls == [
        {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "aide"}}
    ]


def test_run_accepted_banner_on_shell(ipc_factory) -> None:
    client = ipc_factory([_runs(), _findings(), _cmd_method()])
    response = client.post(
        "/scanners/run", headers=SAME_ORIGIN, data={"name": "aide"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert "accepted" in response.text
    assert 'class="notice"' in response.text


def test_run_rejected_banner_shows_scanner_disabled_detail(ipc_factory) -> None:
    rejected = {
        "schema_version": "1.0.0",
        "ok": False,
        "status": "rejected",
        "detail": "scanner_disabled",
    }
    client = ipc_factory([_runs(), _findings(), _cmd_method(response=rejected)])
    response = client.post(
        "/scanners/run", headers=SAME_ORIGIN, data={"name": "aide"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert "rejected" in response.text
    assert "scanner_disabled" in response.text
    assert 'class="notice-warn"' in response.text


def test_run_rate_limited_error_banner(ipc_factory) -> None:
    limited = WorkerCommandError(
        f"run_worker_command rate limit exceeded ({RATE_LIMIT_PER_MIN}/min)"
    )
    client = ipc_factory([_runs(), _findings(), _cmd_method(error=limited)])
    response = client.post(
        "/scanners/run", headers=SAME_ORIGIN, data={"name": "aide"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert "rate limit exceeded" in response.text
    assert 'class="error"' in response.text


def test_run_hostile_detail_escaped(ipc_factory) -> None:
    hostile = "<script>alert(1)</script>"
    rejected = {"schema_version": "1.0.0", "ok": False, "status": "rejected", "detail": hostile}
    client = ipc_factory([_runs(), _findings(), _cmd_method(response=rejected)])
    response = client.post(
        "/scanners/run", headers=SAME_ORIGIN, data={"name": "aide"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert "<script>alert(1)" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text


def test_run_daemon_down_redirects_with_error_banner(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "no.sock")
    client = web_client(app)
    response = client.post(
        "/scanners/run", headers=SAME_ORIGIN, data={"name": "aide"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert "cmd_status=error" in response.headers["location"]
    followed = client.get(response.headers["location"])
    assert followed.status_code == 200
    assert "command failed" in followed.text
