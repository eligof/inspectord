"""End-to-end Phase 0 acceptance test.

Verifies that:
  1. Running `inspectord --dev` brings up the daemon.
  2. The IPC socket exists and accepts calls.
  3. The healthcheck worker emits events that land in DuckDB.
  4. The journal file exists and verifies its own hash chain.
"""

from __future__ import annotations

import signal
import subprocess
import time
from pathlib import Path

import pytest

from inspectorctl.ipc_client import IpcClient
from inspectord.journal import verify_chain
from inspectord.storage.db import Database


@pytest.mark.integration
def test_end_to_end_skeleton(daemon: dict[str, object]) -> None:
    sock_path = daemon["socket_path"]
    tmp_path = daemon["tmp_path"]
    proc = daemon["proc"]
    assert isinstance(sock_path, Path)
    assert isinstance(tmp_path, Path)
    assert isinstance(proc, subprocess.Popen)

    # 1. IPC responds.
    client = IpcClient(socket_path=sock_path)
    report = client.call("get_health")
    assert report["supervisor"] == "running"

    # 2. Allow the healthcheck worker (interval_s=1.0) to fire at least once
    # before stopping the daemon.  Two seconds is generous.
    time.sleep(2)

    # 3. Stop the daemon so it flushes the journal and releases the DuckDB
    # exclusive write lock, then verify DB row count.
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

    db_path = tmp_path / "var" / "inspectord.duckdb"
    assert db_path.exists(), "DuckDB file was not created"
    with Database(db_path) as db:
        rows_count = db.query("SELECT COUNT(*) FROM events_enriched").fetchall()[0][0]
    assert rows_count >= 1, "no synthetic events landed in DuckDB"

    # 4. The journal file exists and verifies its hash chain.
    journal_dir = tmp_path / "var" / "journal"
    journal_files = sorted(journal_dir.glob("*.jsonl.gz"))
    assert journal_files, "no journal files found"
    assert verify_chain(journal_files[0])
