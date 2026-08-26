"""Tests for the vuln_scanner worker (vuln-scanner design §3, §5, §6)."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from inspectord.schemas.event import Event
from inspectord.workers.vuln_scanner.worker import (
    FILE_TRIGGER_MIN_INTERVAL_S,
    MAX_SKIPPED_AVG_IDS,
    VulnScannerWorker,
)

_INTERVAL_S = 86400.0
_POLL_S = 60.0


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class _FakeVercmpRun:
    """subprocess.run stand-in for the vercmp wrapper."""

    def __init__(self, results: dict[tuple[str, str], int] | None = None) -> None:
        self.results = results if results is not None else {}
        self.calls: list[tuple[str, str]] = []
        self.missing = False

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if self.missing:
            raise FileNotFoundError("vercmp")
        self.calls.append((argv[1], argv[2]))
        result = self.results.get((argv[1], argv[2]), 0)
        return subprocess.CompletedProcess(argv, 0, stdout=f"{result}\n", stderr="")


def _avg(avg_id: str, package: str, **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": avg_id,
        "packages": [package],
        "status": "Fixed",
        "severity": "Critical",
        "affected": "1.0-1",
        "fixed": "2.0-1",
        "issues": [f"CVE-{avg_id.removeprefix('AVG-')}"],
    }
    entry.update(overrides)
    return entry


class _Harness:
    def __init__(self, tmp_path: Path) -> None:
        self.advisory_path = tmp_path / "advisories.json"
        self.pacman_local = tmp_path / "pacman-local"
        self.pacman_local.mkdir()
        self.lock_path = tmp_path / "db.lck"
        self.clock = _Clock()
        self.stdout = BytesIO()
        self.vercmp_run = _FakeVercmpRun({("1.0-1", "2.0-1"): -1, ("5.0-1", "2.0-1"): 1})
        self.pacman_output = "openssl 1.0-1\nbash 1.0-1\n"
        self.pacman_exit = 0
        self._mtime = 1_700_000_000

    def write_advisories(self, entries: list[dict[str, Any]]) -> None:
        self.advisory_path.write_text(json.dumps(entries))
        # Force a visible stat change even within one mtime granule.
        self._mtime += 100
        os.utime(self.advisory_path, (self._mtime, self._mtime))

    def touch_pacman_db(self) -> None:
        self._mtime += 100
        os.utime(self.pacman_local, (self._mtime, self._mtime))

    def _pacman_q(self) -> tuple[int, str]:
        return self.pacman_exit, self.pacman_output

    def worker(self, **config_overrides: Any) -> VulnScannerWorker:
        config: dict[str, Any] = {
            "advisory_path": str(self.advisory_path),
            "interval_s": _INTERVAL_S,
            "poll_s": _POLL_S,
            "advisory_stale_after_s": 14 * 86400.0,
        }
        config.update(config_overrides)
        return VulnScannerWorker(
            config=config,
            stdout=self.stdout,
            stderr=BytesIO(),
            host_name="testhost",
            pacman_q=self._pacman_q,
            pacman_local_dir=self.pacman_local,
            pacman_lock_path=self.lock_path,
            monotonic=self.clock,
            vercmp_run=self.vercmp_run,
        )

    def events(self) -> list[Event]:
        lines = self.stdout.getvalue().decode().splitlines()
        return [Event.model_validate_json(line) for line in lines if line]

    def drain(self) -> list[Event]:
        events = self.events()
        self.stdout.seek(0)
        self.stdout.truncate()
        return events


@pytest.fixture
def harness(tmp_path: Path) -> _Harness:
    h = _Harness(tmp_path)
    h.write_advisories([_avg("AVG-1", "openssl")])
    return h


def _by_action(events: list[Event], action: str) -> list[Event]:
    return [e for e in events if e.action == action]


# -- first scan / baseline ---------------------------------------------------


def test_first_scan_emits_full_set_marked_first_seen(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()
    events = harness.events()
    found = _by_action(events, "vulnerability_found")
    assert len(found) == 1
    ev = found[0]
    assert ev.module == "vuln_scanner"
    assert ev.kind.value == "state"
    assert ev.first_seen is True
    assert ev.vulnerability is not None
    assert ev.vulnerability["avg_id"] == "AVG-1"
    assert ev.vulnerability["cve_id"] == "CVE-1"
    assert ev.vulnerability["package"] == "openssl"
    assert ev.vulnerability["installed_version"] == "1.0-1"
    assert ev.vulnerability["fixed_version"] == "2.0-1"
    assert ev.vulnerability["severity"] == "Critical"
    assert ev.vulnerability["status"] == "Fixed"
    assert ev.vulnerability["fix_in_testing"] is False
    assert ev.vulnerability["new"] is False  # first scan is never "new"
    assert ev.vulnerability["advisory_url"] == "https://security.archlinux.org/AVG-1"
    completed = _by_action(events, "vuln_scan_completed")
    assert len(completed) == 1


def test_summary_fields(harness: _Harness) -> None:
    harness.write_advisories(
        [
            _avg("AVG-1", "openssl"),
            _avg("AVG-2", "bash", packages="broken"),  # skipped, id recorded
            _avg("AVG-3", "notinstalled"),
        ]
    )
    worker = harness.worker()
    worker.step()
    completed = _by_action(harness.events(), "vuln_scan_completed")[0]
    raw = completed.raw or {}
    assert raw["advisories"] == 2
    assert raw["matched"] == 1
    assert raw["new"] == 0
    assert raw["warnings"] == 1
    assert raw["skipped_avg_ids"] == ["AVG-2"]
    assert isinstance(raw["duration_ms"], int)
    assert isinstance(raw["scan_started_at"], str)
    # The advisory file's mtime is surfaced as an ISO timestamp (§6).
    mtime = harness.advisory_path.stat().st_mtime
    assert isinstance(raw["advisory_mtime"], str)
    assert abs(datetime.fromisoformat(raw["advisory_mtime"]).timestamp() - mtime) < 1


def test_no_rescan_before_interval(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()
    harness.drain()
    harness.clock.advance(_POLL_S)
    worker.step()
    assert harness.events() == []


def test_interval_rescan_reemits_full_set_not_first_seen(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()
    harness.drain()
    harness.clock.advance(_INTERVAL_S + 1)
    worker.step()
    found = _by_action(harness.events(), "vulnerability_found")
    assert len(found) == 1  # the whole current set again
    assert found[0].first_seen is False
    assert found[0].vulnerability is not None
    assert found[0].vulnerability["new"] is False  # present last scan too


def test_new_flag_marks_only_genuinely_new_matches(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()
    harness.drain()
    harness.write_advisories([_avg("AVG-1", "openssl"), _avg("AVG-9", "bash")])
    harness.clock.advance(_POLL_S)
    worker.step()
    found: dict[str, dict[str, Any]] = {}
    first_seen: dict[str, bool] = {}
    for ev in _by_action(harness.events(), "vulnerability_found"):
        assert ev.vulnerability is not None
        found[ev.vulnerability["avg_id"]] = ev.vulnerability
        first_seen[ev.vulnerability["avg_id"]] = ev.first_seen
    assert set(found) == {"AVG-1", "AVG-9"}
    assert found["AVG-1"]["new"] is False
    assert found["AVG-9"]["new"] is True
    assert first_seen["AVG-9"] is False


# -- triggers ----------------------------------------------------------------


def test_advisory_file_change_triggers_rescan(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()
    harness.drain()
    harness.write_advisories([_avg("AVG-1", "openssl")])
    harness.clock.advance(_POLL_S)
    worker.step()
    assert len(_by_action(harness.events(), "vuln_scan_completed")) == 1


def test_file_triggered_scans_are_rate_limited(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()
    harness.drain()
    harness.write_advisories([_avg("AVG-1", "openssl")])
    harness.clock.advance(_POLL_S)
    worker.step()  # first file-triggered scan runs
    assert len(_by_action(harness.drain(), "vuln_scan_completed")) == 1
    harness.write_advisories([_avg("AVG-1", "openssl"), _avg("AVG-2", "bash")])
    harness.clock.advance(_POLL_S)
    worker.step()  # inside the 300 s window: deferred, not lost
    assert _by_action(harness.drain(), "vuln_scan_completed") == []
    harness.clock.advance(FILE_TRIGGER_MIN_INTERVAL_S)
    worker.step()
    assert len(_by_action(harness.drain(), "vuln_scan_completed")) == 1


def test_pacman_db_mtime_change_triggers_rescan(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()
    harness.drain()
    harness.touch_pacman_db()
    harness.clock.advance(_POLL_S)
    worker.step()
    assert len(_by_action(harness.events(), "vuln_scan_completed")) == 1


# -- guards & failure honesty ------------------------------------------------


def test_pacman_db_lock_defers_scan_and_reports_once(harness: _Harness) -> None:
    harness.lock_path.write_text("")
    worker = harness.worker()
    worker.step()
    failed = _by_action(harness.drain(), "vuln_scan_failed")
    assert len(failed) == 1
    assert (failed[0].raw or {})["reason"] == "pacman_db_locked"
    for _ in range(3):  # retried each poll, but reported once per attempt
        harness.clock.advance(_POLL_S)
        worker.step()
    assert harness.drain() == []
    harness.lock_path.unlink()
    harness.clock.advance(_POLL_S)
    worker.step()
    assert len(_by_action(harness.drain(), "vuln_scan_completed")) == 1


@pytest.mark.parametrize(
    ("prepare", "reason"),
    [
        (lambda h: h.advisory_path.unlink(), "advisories_missing"),
        (lambda h: h.advisory_path.write_text("[]"), "advisories_empty"),
        (lambda h: h.advisory_path.write_text("{never json"), "parse_failed"),
        (lambda h: setattr(h, "pacman_exit", 1), "pacman_failed"),
        (lambda h: setattr(h.vercmp_run, "missing", True), "vercmp_missing"),
    ],
)
def test_failure_reasons(harness: _Harness, prepare: Any, reason: str) -> None:
    prepare(harness)
    worker = harness.worker()
    worker.step()
    events = harness.events()
    assert _by_action(events, "vulnerability_found") == []
    assert _by_action(events, "vuln_scan_completed") == []
    failed = _by_action(events, "vuln_scan_failed")
    assert len(failed) == 1
    assert (failed[0].raw or {})["reason"] == reason
    assert failed[0].outcome is not None
    assert failed[0].outcome.value == "failure"


def test_oversize_advisory_file_fails_with_file_too_large(tmp_path: Path) -> None:
    harness = _Harness(tmp_path)
    harness.write_advisories([_avg("AVG-1", "openssl")])
    worker = harness.worker(advisory_max_bytes=16)
    worker.step()
    failed = _by_action(harness.events(), "vuln_scan_failed")
    assert len(failed) == 1
    assert (failed[0].raw or {})["reason"] == "file_too_large"


def test_failures_fire_at_scan_cadence_not_per_poll(harness: _Harness) -> None:
    harness.advisory_path.unlink()
    worker = harness.worker()
    worker.step()
    for _ in range(5):
        harness.clock.advance(_POLL_S)
        worker.step()
    assert len(_by_action(harness.events(), "vuln_scan_failed")) == 1
    harness.drain()
    harness.clock.advance(_INTERVAL_S)
    worker.step()
    assert len(_by_action(harness.drain(), "vuln_scan_failed")) == 1


def test_advisory_file_appearing_later_triggers_a_scan(harness: _Harness) -> None:
    harness.advisory_path.unlink()
    worker = harness.worker()
    worker.step()  # fails: advisories_missing
    harness.drain()
    harness.write_advisories([_avg("AVG-1", "openssl")])
    harness.clock.advance(_POLL_S)
    worker.step()
    assert len(_by_action(harness.drain(), "vuln_scan_completed")) == 1


def test_more_than_500_skipped_avgs_fails_the_scan(harness: _Harness) -> None:
    # More skips than the cap means the file is broken; completing would let a
    # truncated skipped list feed the sweep and resolve rows it must protect.
    entries: list[dict[str, Any]] = [
        _avg(f"AVG-{i}", "openssl", packages="broken") for i in range(MAX_SKIPPED_AVG_IDS + 1)
    ]
    entries.append(_avg("AVG-900000", "openssl"))
    harness.write_advisories(entries)
    worker = harness.worker()
    worker.step()
    events = harness.events()
    assert _by_action(events, "vulnerability_found") == []
    failed = _by_action(events, "vuln_scan_failed")
    assert len(failed) == 1
    assert (failed[0].raw or {})["reason"] == "parse_failed"


# -- vercmp cache ------------------------------------------------------------


def test_vercmp_cache_survives_across_scans(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()
    harness.clock.advance(_INTERVAL_S + 1)
    worker.step()
    assert len(_by_action(harness.events(), "vuln_scan_completed")) == 2
    assert harness.vercmp_run.calls == [("1.0-1", "2.0-1")]  # second scan hit the cache


# -- scheduling plumbing -----------------------------------------------------


def test_step_interval_is_poll_s(harness: _Harness) -> None:
    assert harness.worker().step_interval_s() == _POLL_S
