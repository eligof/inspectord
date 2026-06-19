"""Tests for the entity-state projector."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inspectord.schemas.event import Event, EventKind, Severity
from inspectord.state.projector import project
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "test.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _service_event(
    action: str,
    unit: str,
    active: str,
    *,
    event_id: str,
    ts: datetime = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
) -> Event:
    return Event(
        ts=ts,
        event_id=event_id,
        kind=EventKind.event,
        category=["configuration"],
        type=["change"],
        action=action,
        severity=Severity.info,
        module="services_monitor",
        service={"name": unit, "state": active},
        raw={"source": "systemctl", "active": active, "sub": "running", "load": "loaded"},
    )


def test_service_added_inserts_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_service_event("service_added", "sshd.service", "active", event_id="e1"), db)
    rows = db.query(
        "SELECT active_state, sub_state, load_state, last_event_id FROM service_state "
        "WHERE unit='sshd.service'"
    ).fetchall()
    assert rows == [("active", "running", "loaded", "e1")]
    db.close()


def test_service_state_changed_updates_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    added_ts = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    changed_ts = datetime(2026, 6, 16, 13, 30, 0, tzinfo=UTC)
    project(
        _service_event("service_added", "sshd.service", "active", event_id="e1", ts=added_ts), db
    )
    first_seen_before = db.query(
        "SELECT first_seen FROM service_state WHERE unit='sshd.service'"
    ).fetchall()[0][0]
    project(
        _service_event(
            "service_state_changed", "sshd.service", "failed", event_id="e2", ts=changed_ts
        ),
        db,
    )
    rows = db.query(
        "SELECT active_state, first_seen, last_seen, last_event_id FROM service_state"
        " WHERE unit='sshd.service'"
    ).fetchall()
    assert rows[0][0] == "failed"
    assert rows[0][1] == first_seen_before  # first_seen preserved across the update
    assert rows[0][2] != first_seen_before  # last_seen advanced to the change ts
    assert rows[0][3] == "e2"  # last_event_id advanced
    db.close()


def test_service_removed_deletes_row(tmp_path: Path) -> None:
    db = _db(tmp_path)
    project(_service_event("service_added", "sshd.service", "active", event_id="e1"), db)
    project(_service_event("service_removed", "sshd.service", "active", event_id="e2"), db)
    rows = db.query("SELECT unit FROM service_state WHERE unit='sshd.service'").fetchall()
    assert rows == []
    db.close()


def test_services_monitor_event_with_no_service_field_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    ev = Event(
        ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event_id="e8",
        kind=EventKind.event,
        category=["configuration"],
        type=["change"],
        action="service_added",
        severity=Severity.info,
        module="services_monitor",
        service=None,
    )
    project(ev, db)  # must not raise
    assert db.query("SELECT COUNT(*) FROM service_state").fetchall()[0][0] == 0
    db.close()


def test_unknown_module_is_noop(tmp_path: Path) -> None:
    db = _db(tmp_path)
    ev = Event(
        ts=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event_id="e9",
        kind=EventKind.event,
        category=["x"],
        type=["x"],
        action="whatever",
        severity=Severity.info,
        module="some_future_collector",
    )
    project(ev, db)  # must not raise
    db.close()
