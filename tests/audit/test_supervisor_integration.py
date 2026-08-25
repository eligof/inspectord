"""Supervisor audit anchoring, periodic verify, failure escalation + startup probe.

Spec 2026-08-25-audit-log-design §6/§6a/§7. The supervisor tests drive
``_monitor_tick`` directly (deterministic, no monitor-thread timing) and capture
emitted supervisor events by replacing ``_dispatch`` on the instance — the same
observation point the router would use.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import inspectord.audit.log as audit_log
from inspectord.audit.log import (
    FAILURE_ALERT_THRESHOLD,
    FAILURE_WINDOW,
    append_audit,
    assert_audit_table,
    reset_for_tests,
    set_failure_listener,
)
from inspectord.config import dev_config
from inspectord.schemas.event import Event
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations
from inspectord.supervisor import AUDIT_TICK_INTERVAL_S, Supervisor


def setup_function(_fn) -> None:
    reset_for_tests()  # drop the module connection + counters between tests


def teardown_function(_fn) -> None:
    set_failure_listener(None)
    reset_for_tests()


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


# --------------------------------------------------------------------------
# startup probe
# --------------------------------------------------------------------------


def test_assert_audit_table_raises_when_missing(tmp_path: Path) -> None:
    # A DB without migrations: the probe must be fatal, not fail-open fodder.
    db = Database(tmp_path / "bare.duckdb")
    db.connect()
    db.close()
    with pytest.raises(RuntimeError, match="audit_log"):
        assert_audit_table(tmp_path / "bare.duckdb")


def test_assert_audit_table_ok_after_migrations(tmp_path: Path) -> None:
    assert_audit_table(_fresh(tmp_path))  # no raise


# --------------------------------------------------------------------------
# daily anchor + verify (driven through _monitor_tick)
# --------------------------------------------------------------------------


def _quiet_supervisor(tmp_path: Path, **kwargs: Any) -> tuple[Supervisor, Path, list[Event]]:
    """Unstarted supervisor with no workers; _dispatch captures emitted events."""
    cfg = dev_config(base=tmp_path).model_copy(update={"workers": []})
    sup = Supervisor(cfg, **kwargs)
    dispatched: list[Event] = []
    sup._dispatch = dispatched.append  # type: ignore[method-assign]
    sup._db.connect()
    run_migrations(sup._db)
    return sup, cfg.storage.db_path, dispatched


def _actions(dispatched: list[Event], action: str) -> list[Event]:
    return [ev for ev in dispatched if ev.action == action]


def test_audit_tick_emits_anchor_and_detects_tamper(tmp_path: Path) -> None:
    sup, db_path, dispatched = _quiet_supervisor(tmp_path, audit_tick_interval_s=0.0)
    try:
        append_audit(db_path, actor="user:local", action="a", target=None, details={})
        append_audit(db_path, actor="user:local", action="b", target=None, details={})
        sup._monitor_tick()
        anchors = _actions(dispatched, "audit_head")
        assert len(anchors) == 1
        raw = anchors[0].raw
        assert raw is not None
        assert raw["seq"] == 2
        assert isinstance(raw["row_hash"], str) and len(raw["row_hash"]) == 64
        assert not _actions(dispatched, "audit_chain_broken")
        # Tamper with a written row: the next tick's verify must flag it.
        sup._db.execute("UPDATE audit_log SET actor = 'auto:evil' WHERE seq = 1")
        sup._monitor_tick()
        broken = _actions(dispatched, "audit_chain_broken")
        assert len(broken) == 1
        assert broken[0].severity == "high"
        assert broken[0].raw is not None
        assert broken[0].raw["first_bad_seq"] == 1
        assert broken[0].raw["reason"] == "row_hash_mismatch"
    finally:
        sup._db.close()


def test_audit_tick_empty_log_emits_no_anchor(tmp_path: Path) -> None:
    sup, _db_path, dispatched = _quiet_supervisor(tmp_path, audit_tick_interval_s=0.0)
    try:
        sup._monitor_tick()
        assert not _actions(dispatched, "audit_head")
        assert not _actions(dispatched, "audit_chain_broken")
    finally:
        sup._db.close()


def test_audit_tick_respects_interval(tmp_path: Path) -> None:
    # Default interval (86400s): the first tick fires, the second is suppressed.
    sup, db_path, dispatched = _quiet_supervisor(tmp_path)
    try:
        assert AUDIT_TICK_INTERVAL_S == 86400.0
        append_audit(db_path, actor="user:local", action="a", target=None, details={})
        sup._monitor_tick()
        sup._monitor_tick()
        assert len(_actions(dispatched, "audit_head")) == 1
    finally:
        sup._db.close()


# --------------------------------------------------------------------------
# failure listener escalation
# --------------------------------------------------------------------------


def test_failure_listener_fires_once_then_cooldown_suppressed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sup, db_path, dispatched = _quiet_supervisor(tmp_path)
    try:
        set_failure_listener(sup._report_audit_log_failing)

        def _boom(_path: Path) -> None:
            raise RuntimeError("db down")

        monkeypatch.setattr(audit_log, "_conn", _boom)
        for _ in range(FAILURE_ALERT_THRESHOLD):
            append_audit(db_path, actor="user:local", action="a", target=None, details={})
        failing = _actions(dispatched, "audit_log_failing")
        assert len(failing) == 1
        assert failing[0].severity == "high"
        assert failing[0].raw == {
            "failures": FAILURE_ALERT_THRESHOLD,
            "window": FAILURE_WINDOW,
        }
        # A second burst inside the cooldown must not re-fire.
        for _ in range(FAILURE_ALERT_THRESHOLD):
            append_audit(db_path, actor="user:local", action="a", target=None, details={})
        assert len(_actions(dispatched, "audit_log_failing")) == 1
    finally:
        sup._db.close()


def test_start_registers_failure_listener(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path).model_copy(update={"workers": []})
    sup = Supervisor(cfg)
    sup.start()
    try:
        assert audit_log._failure_listener == sup._report_audit_log_failing
    finally:
        sup.stop(timeout=5.0)
