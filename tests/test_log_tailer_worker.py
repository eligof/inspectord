"""Tests for the log_tailer worker."""

from __future__ import annotations

import io
import json
import threading
import time
from pathlib import Path

from inspectord.workers.log_tailer.__main__ import LogTailerWorker


class _NeverProducingJournalSource:
    def open(self) -> None: ...
    def close(self) -> None: ...

    def read_one(self, *, timeout: float = 0.5) -> dict[str, object] | None:
        time.sleep(timeout)
        return None


def test_worker_emits_event_from_pacman_log(tmp_path: Path) -> None:
    pacman_path = tmp_path / "pacman.log"
    pacman_path.write_text("")
    auth_path = tmp_path / "auth.log"

    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = LogTailerWorker(
        name="log_tailer",
        stdout=stdout,
        stderr=stderr,
        config={
            "pacman_log_path": str(pacman_path),
            "auth_log_path": str(auth_path),
        },
        journal_source=_NeverProducingJournalSource(),
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.1)
    with pacman_path.open("a") as fh:
        fh.write("[2026-05-24T14:23:10+0000] [ALPM] installed audit (3.1.5-1)\n")
        fh.flush()
    time.sleep(0.4)
    w.request_stop()
    t.join(timeout=2.0)

    events = [
        json.loads(line) for line in stdout.getvalue().decode("utf-8").splitlines() if line.strip()
    ]
    assert any(ev["action"] == "package_installed" for ev in events)
    assert all(ev["module"] == "log_tailer" for ev in events)


def test_worker_skips_missing_auth_log(tmp_path: Path) -> None:
    """When auth.log doesn't exist (e.g. on Arch), the worker continues without error."""
    pacman_path = tmp_path / "pacman.log"
    pacman_path.write_text("")
    auth_path = tmp_path / "auth.log"  # do not create

    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = LogTailerWorker(
        name="log_tailer",
        stdout=stdout,
        stderr=stderr,
        config={
            "pacman_log_path": str(pacman_path),
            "auth_log_path": str(auth_path),
        },
        journal_source=_NeverProducingJournalSource(),
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.3)
    w.request_stop()
    t.join(timeout=2.0)
    hbs = [
        json.loads(line) for line in stderr.getvalue().decode("utf-8").splitlines() if line.strip()
    ]
    assert hbs
    assert hbs[-1]["worker"] == "log_tailer"
