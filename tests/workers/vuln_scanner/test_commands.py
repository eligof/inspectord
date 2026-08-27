"""vuln_scanner `rescan` command tests (worker-command-channel design §7).

A rescan makes the next poll unconditionally due: it bypasses
FILE_TRIGGER_MIN_INTERVAL_S (that guard absorbs mid-`mv` mtime flapping, not
human clicks) without touching the file-trigger bookkeeping. The natural bound
is one scan per poll tick, and the pacman db.lck guard still applies — the
request stays pending and is retried on the next poll.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.workers.vuln_scanner.worker import FILE_TRIGGER_MIN_INTERVAL_S

from .test_worker import _avg, _by_action, _Harness

_POLL_S = 60.0


@pytest.fixture
def harness(tmp_path: Path) -> _Harness:
    h = _Harness(tmp_path)
    h.write_advisories([_avg("AVG-1", "openssl")])
    return h


def test_rescan_command_is_accepted_and_flags_the_next_poll(harness: _Harness) -> None:
    worker = harness.worker()
    result = worker.handle_command("rescan", {})
    assert result["status"] == "accepted"
    assert worker._rescan_requested is True


def test_unknown_command_is_rejected(harness: _Harness) -> None:
    worker = harness.worker()
    result = worker.handle_command("frobnicate", {})
    assert result["status"] == "rejected"
    assert worker._rescan_requested is False


def test_rescan_bypasses_the_file_trigger_min_interval(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()  # first scan (interval due on start)
    harness.drain()
    # A file-triggered scan opens the 300s window.
    harness.write_advisories([_avg("AVG-1", "openssl"), _avg("AVG-9", "bash")])
    harness.clock.advance(_POLL_S)
    worker.step()
    assert len(_by_action(harness.drain(), "vuln_scan_completed")) == 1

    # "file refreshed -> auto scan -> user clicks Rescan": the click must not
    # be accepted and then silently deferred for five minutes.
    worker.handle_command("rescan", {})
    harness.clock.advance(_POLL_S)
    assert _POLL_S < FILE_TRIGGER_MIN_INTERVAL_S
    worker.step()
    assert len(_by_action(harness.drain(), "vuln_scan_completed")) == 1, (
        "the rescan was deferred by the file-trigger window"
    )


def test_rescan_does_not_touch_file_trigger_bookkeeping(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()  # first scan
    harness.drain()
    harness.write_advisories([_avg("AVG-1", "openssl"), _avg("AVG-9", "bash")])
    harness.clock.advance(_POLL_S)
    worker.step()  # file-triggered scan: records _last_file_scan
    window_anchor = worker._last_file_scan
    assert window_anchor is not None

    worker.handle_command("rescan", {})
    harness.clock.advance(_POLL_S)
    worker.step()  # the rescan
    assert worker._last_file_scan == window_anchor, "a rescan moved the file-trigger window anchor"
    assert worker._pending_file_trigger is False


def test_rescan_respects_the_poll_cadence_one_scan_per_tick(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()  # first scan
    harness.drain()
    worker.handle_command("rescan", {})
    worker.handle_command("rescan", {})  # double-click
    harness.clock.advance(_POLL_S)
    worker.step()
    assert len(_by_action(harness.drain(), "vuln_scan_completed")) == 1
    # The request was consumed: the next poll does not scan again.
    harness.clock.advance(_POLL_S)
    worker.step()
    assert len(_by_action(harness.drain(), "vuln_scan_completed")) == 0


def test_rescan_still_defers_to_the_pacman_lock(harness: _Harness) -> None:
    worker = harness.worker()
    worker.step()  # first scan
    harness.drain()
    harness.lock_path.touch()
    worker.handle_command("rescan", {})
    harness.clock.advance(_POLL_S)
    worker.step()
    events = harness.drain()
    assert len(_by_action(events, "vuln_scan_completed")) == 0
    failed = _by_action(events, "vuln_scan_failed")
    assert len(failed) == 1
    assert (failed[0].raw or {})["reason"] == "pacman_db_locked"
    # The trigger stays pending: once the lock clears, the next poll scans.
    harness.lock_path.unlink()
    harness.clock.advance(_POLL_S)
    worker.step()
    assert len(_by_action(harness.drain(), "vuln_scan_completed")) == 1
