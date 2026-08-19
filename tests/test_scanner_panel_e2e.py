"""End-to-end: real scanner_runner events -> scan_run -> the panel's IPC handlers.

Every other test in this slice feeds the projector hand-written events. This one
drives the **real** `ScannerRunnerWorker` (fake adapter, real subprocess) and
projects exactly what it emits, so a drift between the runner's `raw` keys and
the projector's reads fails here rather than silently blanking the panel.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from io import BytesIO
from pathlib import Path
from typing import Any

from inspectord.schemas.event import Event
from inspectord.state.ipc_handlers import handle_list_scan_findings, handle_list_scan_runs
from inspectord.state.projector import project
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations
from inspectord.workers.scanner_runner.runner import ScannerRunnerWorker
from inspectord.workers.scanner_runner.scanners.base import Finding, ScanOutcome


class _FakeAdapter:
    """A ScannerAdapter whose scan is a short real `sh -c` command."""

    name = "fake"
    binary = "sh"

    def __init__(self, *, argv: Sequence[str], findings: Sequence[Finding] = ()) -> None:
        self._argv = list(argv)
        self._findings = list(findings)
        self.preflight_reason: str | None = None

    def argv(self, config: Mapping[str, Any]) -> list[str]:
        return list(self._argv)

    def preflight(self, config: Mapping[str, Any]) -> str | None:
        return self.preflight_reason

    def interpret_outcome(self, code: int, stdout: str, stderr: str) -> ScanOutcome:
        if code == 0:
            return ScanOutcome.clean
        if code == 1:
            return ScanOutcome.findings
        return ScanOutcome.failure

    def parse(self, stdout: str, stderr: str) -> list[Finding]:
        return list(self._findings)


def _config(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "interval_s": 0.01,
        "startup_delay_s": 0.0,
        "retry_backoff_s": 0.0,
        "scanners": {"fake": {"enabled": True, "interval_s": 1000.0, "timeout_s": 30.0}},
    }
    config.update(overrides)
    return config


def _drive(adapter: _FakeAdapter, **config_overrides: Any) -> list[dict[str, Any]]:
    """Tick the real worker until it has emitted a scan_completed or scan_skipped."""
    buf = BytesIO()
    worker = ScannerRunnerWorker(
        name="scanner_runner",
        adapters=[adapter],
        config=_config(**config_overrides),
        stdout=buf,
        stderr=BytesIO(),
        host_name="testhost",
    )
    deadline = time.monotonic() + 15.0
    try:
        while True:
            worker.step()
            events = [json.loads(line) for line in buf.getvalue().splitlines() if line]
            terminal = {"scan_completed", "scan_skipped"}
            if any(e["action"] in terminal for e in events) or time.monotonic() > deadline:
                return events
            time.sleep(0.01)
    finally:
        worker.teardown()


def _project_all(events: Sequence[dict[str, Any]], db_path: Path) -> None:
    with Database(db_path) as db:
        for record in events:
            project(Event.model_validate(record), db)
            db.execute(
                "INSERT INTO events_enriched "
                "(event_id, ts, kind, module, action, severity, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    record["event_id"],
                    record["ts"],
                    record["kind"],
                    record["module"],
                    record["action"],
                    record["severity"],
                    json.dumps(record),
                ],
            )


def _fresh(tmp_path: Path) -> Path:
    db_path = tmp_path / "t.duckdb"
    db = Database(db_path)
    db.connect()
    run_migrations(db)
    db.close()
    return db_path


def _finding(path: str) -> Finding:
    return Finding(
        indicator_type="aide_change",
        indicator_value="changed",
        raw_line=f"f...: {path}",
        category="file",
        path=path,
        message=f"AIDE: changed {path}",
    )


def test_a_real_run_with_findings_reaches_the_panel(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    events = _drive(
        _FakeAdapter(
            argv=["sh", "-c", "sleep 0.05; exit 1"],
            findings=[_finding("/etc/passwd"), _finding("/etc/shadow")],
        )
    )
    assert [e["action"] for e in events][:1] == ["scan_started"]
    _project_all(events, db_path)

    scanners = handle_list_scan_runs(params={}, db_path=db_path)["scanners"]
    assert len(scanners) == 1
    run = scanners[0]
    assert run["scanner"] == "fake"
    assert run["state"] == "success"
    assert run["finding_count"] == 2
    assert run["duration_s"] is not None and run["duration_s"] > 0
    assert run["started_at"] is not None
    assert run["completed_at"] is not None

    findings = handle_list_scan_findings(params={"run_ids": [run["run_id"]]}, db_path=db_path)[
        "findings"
    ]
    assert {f["path"] for f in findings} == {"/etc/passwd", "/etc/shadow"}
    assert {f["scanner"] for f in findings} == {"fake"}


def test_a_real_failed_run_reaches_the_panel_with_its_reason(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    # A long retry backoff keeps the runner's automatic retry from starting a
    # second run, so the latest row is the failure itself.
    events = _drive(
        _FakeAdapter(argv=["sh", "-c", "echo 'boom' >&2; exit 9"]), retry_backoff_s=600.0
    )
    assert [e["action"] for e in events] == ["scan_started", "scan_completed"]
    _project_all(events, db_path)

    run = handle_list_scan_runs(params={}, db_path=db_path)["scanners"][0]
    assert run["state"] == "failure"
    assert run["reason"] == "scanner_error"
    assert run["exit_code"] == 9
    # A failed scan must say why, in the scanner's own words.
    assert run["output_excerpt"] is not None and "boom" in run["output_excerpt"]


def test_a_real_skip_reaches_the_panel_and_is_not_a_run(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    adapter = _FakeAdapter(argv=["sh", "-c", "exit 0"])
    adapter.preflight_reason = "database_missing"
    events = _drive(adapter)
    assert [e["action"] for e in events] == ["scan_skipped"]
    _project_all(events, db_path)

    run = handle_list_scan_runs(params={}, db_path=db_path)["scanners"][0]
    assert run["state"] == "skipped"
    assert run["reason"] == "database_missing"
    # A skip is not a run: no duration, no findings, and its key is synthesized.
    assert run["duration_s"] is None
    assert run["finding_count"] is None
    assert run["run_id"].startswith("skip:")
