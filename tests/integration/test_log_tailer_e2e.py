"""End-to-end test: log_tailer + fim_watcher events land in DuckDB."""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from inspectord.storage.db import Database


@pytest.mark.integration
def test_collectors_emit_events_into_db(tmp_path: Path) -> None:
    var = tmp_path / "var"
    var.mkdir()
    fake_pacman = tmp_path / "pacman.log"
    fake_pacman.write_text("")
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()

    config_path = tmp_path / "inspectord.toml"
    config_path.write_text(
        f"""
version = "1.0.0"

[storage]
db_path = "{var / "inspectord.duckdb"}"
journal_dir = "{var / "journal"}"

[ipc]
socket_path = "{var / "inspectord.sock"}"
allowed_uids = []

[[workers]]
name = "log_tailer"
module = "inspectord.workers.log_tailer"

[workers.config]
pacman_log_path = "{fake_pacman}"
auth_log_path = "{tmp_path / "auth.log"}"

[[workers]]
name = "fim_watcher"
module = "inspectord.workers.fim_watcher"

[workers.config]
watch_paths = ["{watch_dir}"]
""".strip()
    )

    proc = subprocess.Popen(
        [sys.executable, "-m", "inspectord", "--config", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    socket_path = var / "inspectord.sock"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not socket_path.exists():
        time.sleep(0.1)
    assert socket_path.exists(), "daemon never created its IPC socket"
    # Workers are spawned as subprocesses; give them a moment to finish setup()
    # before we write the events we want them to capture.
    time.sleep(1.0)

    try:
        # Provoke fim_watcher.
        (watch_dir / "newfile").write_text("hello")
        # Provoke log_tailer's pacman parser.
        with fake_pacman.open("a") as fh:
            fh.write("[2026-05-24T14:23:10+0000] [ALPM] installed audit (3.1.5-1)\n")
            fh.flush()
        # Give workers time to pick them up.
        time.sleep(2.5)
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    db_path = var / "inspectord.duckdb"
    deadline = time.monotonic() + 10
    log_tailer_rows = fim_watcher_rows = 0
    while time.monotonic() < deadline:
        if db_path.exists():
            with Database(db_path) as db:
                log_tailer_rows = db.query(
                    "SELECT COUNT(*) FROM events_enriched WHERE module = 'log_tailer'"
                ).fetchall()[0][0]
                fim_watcher_rows = db.query(
                    "SELECT COUNT(*) FROM events_enriched WHERE module = 'fim_watcher'"
                ).fetchall()[0][0]
            if log_tailer_rows >= 1 and fim_watcher_rows >= 1:
                break
        time.sleep(0.2)

    assert log_tailer_rows >= 1, "log_tailer never wrote a pacman event to DuckDB"
    assert fim_watcher_rows >= 1, "fim_watcher never wrote a file event to DuckDB"
