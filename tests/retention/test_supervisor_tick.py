"""Daily retention tick (retention spec §6): scheduling, audit row, failure surfacing.

Mirrors ``tests/audit/test_supervisor_integration.py``: an unstarted Supervisor
with no workers, ``_monitor_tick()`` driven directly, and emitted supervisor
events captured by replacing ``_dispatch`` on the instance.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import inspectord.supervisor as supervisor_mod
from inspectord.audit.log import append_audit, reset_for_tests
from inspectord.config import DaemonConfig, RetentionConfig, dev_config
from inspectord.parsers.base import build_event
from inspectord.retention.engine import RetentionReport
from inspectord.schemas.event import Event
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
from inspectord.storage.migrations import run_migrations
from inspectord.supervisor import RETENTION_TICK_INTERVAL_S, Supervisor


def setup_function(_fn) -> None:
    reset_for_tests()


def teardown_function(_fn) -> None:
    reset_for_tests()


def _quiet_supervisor(
    tmp_path: Path, *, enabled: bool = True, **kwargs: Any
) -> tuple[Supervisor, DaemonConfig, list[Event]]:
    cfg = dev_config(base=tmp_path).model_copy(
        update={"workers": [], "retention": RetentionConfig(enabled=enabled)}
    )
    sup = Supervisor(cfg, **kwargs)
    dispatched: list[Event] = []
    sup._dispatch = dispatched.append  # type: ignore[method-assign]
    sup._db.connect()
    run_migrations(sup._db)
    return sup, cfg, dispatched


def _seed_old_event(db: Database) -> None:
    event = build_event(
        module="probe",
        action="tick",
        category=["c"],
        type_=["t"],
        severity="info",
        ts=datetime.now(UTC) - timedelta(days=40),
    )
    insert_event(db, event, event.model_dump_json())


def _event_count(db: Database) -> int:
    row = db.query("SELECT COUNT(*) FROM events_enriched").fetchone()
    assert row is not None
    return int(row[0])


def _pruned_rows(db: Database) -> list[tuple[str, str, str]]:
    return db.query(
        "SELECT actor, target, details_json FROM audit_log WHERE action = 'retention_pruned'"
    ).fetchall()


def _actions(dispatched: list[Event], action: str) -> list[Event]:
    return [ev for ev in dispatched if ev.action == action]


# --- scheduling + audit row -------------------------------------------------


def test_retention_tick_interval_constant() -> None:
    assert RETENTION_TICK_INTERVAL_S == 86400.0


def test_tick_prunes_and_writes_one_audit_row_then_stays_quiet(tmp_path: Path) -> None:
    sup, _cfg, _dispatched = _quiet_supervisor(tmp_path, retention_tick_interval_s=0.0)
    try:
        _seed_old_event(sup._db)
        sup._monitor_tick()
        assert _event_count(sup._db) == 0
        rows = _pruned_rows(sup._db)
        assert len(rows) == 1
        actor, target, details_json = rows[0]
        assert actor == "auto:retention"
        assert target == "retention:daily"
        details = json.loads(details_json)
        assert details["events_deleted"] == 1
        assert details["journal_files_deleted"] == 0
        assert details["alerts_deleted"] == 0
        assert details["evidence_blobs_deleted"] == 0
        assert details["pruned_shas"] == []
        assert details["skipped_files"] == []
        assert details["quota_overage_bytes"] == 0
        # A no-op run writes no second row (interval 0: retention runs again).
        sup._monitor_tick()
        assert len(_pruned_rows(sup._db)) == 1
    finally:
        sup._db.close()


def test_disabled_retention_prunes_nothing_writes_nothing(tmp_path: Path) -> None:
    sup, _cfg, _dispatched = _quiet_supervisor(
        tmp_path, enabled=False, retention_tick_interval_s=0.0
    )
    try:
        _seed_old_event(sup._db)
        sup._monitor_tick()
        assert _event_count(sup._db) == 1
        assert _pruned_rows(sup._db) == []
    finally:
        sup._db.close()


def test_retention_runs_after_audit_tick_in_same_tick(tmp_path: Path) -> None:
    sup, cfg, dispatched = _quiet_supervisor(
        tmp_path, audit_tick_interval_s=0.0, retention_tick_interval_s=0.0
    )
    try:
        append_audit(cfg.storage.db_path, actor="user:local", action="a", target=None, details={})
        _seed_old_event(sup._db)
        counts_at_anchor: list[int] = []

        def capture(ev: Event) -> None:
            if ev.action == "audit_head":
                # Observed the instant the anchor is emitted: the events pruner
                # must not have run yet (§6 ordering: audit tick FIRST).
                counts_at_anchor.append(_event_count(sup._db))
            dispatched.append(ev)

        sup._dispatch = capture  # type: ignore[method-assign]
        sup._monitor_tick()
        assert counts_at_anchor == [1]
        assert _event_count(sup._db) == 0
    finally:
        sup._db.close()


def test_audit_details_cap_pruned_shas_at_50(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sup, _cfg, _dispatched = _quiet_supervisor(tmp_path, retention_tick_interval_s=0.0)
    try:
        shas = [f"sha-{i:04d}" for i in range(60)]
        report = RetentionReport(evidence_blobs_deleted=60, pruned_shas=shas)
        monkeypatch.setattr(supervisor_mod, "run_retention", lambda *a, **kw: report)
        sup._monitor_tick()
        rows = _pruned_rows(sup._db)
        assert len(rows) == 1
        details = json.loads(rows[0][2])
        assert details["pruned_shas"] == shas[:50]
        assert details["more"] == 10
    finally:
        sup._db.close()


# --- failure surfacing ------------------------------------------------------


def test_errors_emit_medium_retention_failed_event(tmp_path: Path) -> None:
    sup, _cfg, dispatched = _quiet_supervisor(tmp_path, retention_tick_interval_s=0.0)
    try:
        _seed_old_event(sup._db)
        sup._db.execute("DROP TABLE alerts")
        sup._monitor_tick()
        failed = _actions(dispatched, "retention_failed")
        assert len(failed) == 1
        assert failed[0].severity == "medium"
        assert failed[0].type == ["error"]
        # Two errors (journal critical-day query + alerts pruner): the ≤5
        # branch joins them exactly, with no "and N more" suffix.
        assert failed[0].message is not None
        assert "alerts:" in failed[0].message
        assert " more" not in failed[0].message
        assert failed[0].raw is not None
        errors = failed[0].raw["errors"]
        assert len(errors) == 2
        assert any(err.startswith("journal:") for err in errors)
    finally:
        sup._db.close()


def test_error_message_truncates_past_five_and_raw_past_twenty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sup, _cfg, dispatched = _quiet_supervisor(tmp_path, retention_tick_interval_s=0.0)
    try:
        report = RetentionReport(errors=[f"e{i}" for i in range(25)])
        monkeypatch.setattr(supervisor_mod, "run_retention", lambda *a, **kw: report)
        sup._monitor_tick()
        failed = _actions(dispatched, "retention_failed")
        assert len(failed) == 1
        assert failed[0].message == "e0; e1; e2; e3; e4 and 20 more"
        assert failed[0].raw is not None
        assert failed[0].raw["errors"] == [f"e{i}" for i in range(20)]
        assert _pruned_rows(sup._db) == []  # no deletions -> no audit row
    finally:
        sup._db.close()


def test_marker_set_before_run_so_failing_run_waits_full_interval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Default interval: the marker is set BEFORE the (raising) run, so the
    # immediately-next tick must NOT retry.
    sup, _cfg, _dispatched = _quiet_supervisor(tmp_path)
    try:
        calls: list[None] = []

        def boom(*_a: Any, **_kw: Any) -> RetentionReport:
            calls.append(None)
            raise RuntimeError("retention exploded")

        monkeypatch.setattr(supervisor_mod, "run_retention", boom)
        sup._monitor_tick()
        sup._monitor_tick()
        assert len(calls) == 1
    finally:
        sup._db.close()
