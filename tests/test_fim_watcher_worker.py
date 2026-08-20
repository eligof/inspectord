"""Tests for the fim_watcher worker."""

from __future__ import annotations

import io
import json
import threading
import time
from pathlib import Path

from inspectord.workers.fim_watcher.__main__ import FimWatcherWorker


def _events(stdout: io.BytesIO) -> list[dict]:
    return [
        json.loads(line) for line in stdout.getvalue().decode("utf-8").splitlines() if line.strip()
    ]


def _wait_for_action(stdout: io.BytesIO, action: str, *, timeout: float = 10.0) -> list[dict]:
    """Poll until `action` shows up, instead of sleeping a fixed guess.

    inotify delivery plus the worker's own loop is fast on an idle laptop and
    demonstrably slower on a loaded CI runner — a fixed `time.sleep(0.3)` here
    failed in CI while passing 15/15 locally. Polling to a generous deadline
    keeps the test fast when things are fast without asserting on a race.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events = _events(stdout)
        if any(ev["action"] == action for ev in events):
            return events
        time.sleep(0.02)
    return _events(stdout)


def test_worker_emits_event_on_file_create(tmp_path: Path) -> None:
    watched_dir = tmp_path / "etc"
    watched_dir.mkdir()
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = FimWatcherWorker(
        name="fim_watcher",
        stdout=stdout,
        stderr=stderr,
        config={"watch_paths": [str(watched_dir)]},
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.1)
    target = watched_dir / "new"
    target.write_text("hello")
    events = _wait_for_action(stdout, "file_created")
    w.request_stop()
    t.join(timeout=2.0)
    actions = {ev["action"] for ev in events}
    assert {"file_created"} & actions
    assert all(ev["module"] == "fim_watcher" for ev in events)


def test_worker_emits_event_on_file_modify(tmp_path: Path) -> None:
    watched = tmp_path / "watched.txt"
    watched.write_text("v1")
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = FimWatcherWorker(
        name="fim_watcher",
        stdout=stdout,
        stderr=stderr,
        config={"watch_paths": [str(watched)]},
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.1)
    watched.write_text("v2")
    events = _wait_for_action(stdout, "file_modified")
    w.request_stop()
    t.join(timeout=2.0)

    actions = {ev["action"] for ev in events}
    assert {"file_modified"} & actions


def test_worker_skips_missing_paths(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist"
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = FimWatcherWorker(
        name="fim_watcher",
        stdout=stdout,
        stderr=stderr,
        config={"watch_paths": [str(missing)]},
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.2)
    w.request_stop()
    t.join(timeout=2.0)
    hbs = [
        json.loads(line) for line in stderr.getvalue().decode("utf-8").splitlines() if line.strip()
    ]
    assert hbs
