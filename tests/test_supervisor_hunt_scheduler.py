"""Supervisor wiring for HuntScheduler + status liveness (hunt-followups §4.1).

A dead scheduler thread must be visible without reading logs — silent stop of
standing detections is the #127 incident shape one layer up. So the wiring
test asserts the thread runs off the shared Database and the one dispatch
path, and the status test asserts liveness rides the `get_health` response.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inspectord.__main__ import _ipc_methods
from inspectord.config import dev_config
from inspectord.hunt.scheduler import HuntScheduler
from inspectord.supervisor import Supervisor


def _quiet_cfg(tmp_path: Path):
    cfg = dev_config(base=tmp_path)
    # No workers: these tests never need child processes.
    return cfg.model_copy(update={"workers": []})


def test_supervisor_starts_and_stops_the_hunt_scheduler(tmp_path: Path) -> None:
    sup = Supervisor(_quiet_cfg(tmp_path))
    sup.start()
    try:
        scheduler = sup._hunt_scheduler
        assert isinstance(scheduler, HuntScheduler)
        assert scheduler.is_alive()
        # The supervisor's shared Database (per-thread cursors) and the one
        # path every event takes — not a second connection, not a side door.
        assert scheduler._db is sup._db
        assert scheduler._emit == sup._dispatch
    finally:
        sup.stop(timeout=10.0)
    assert not scheduler.is_alive()


def test_get_health_reports_hunt_scheduler_liveness(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        methods = {m.name: m for m in _ipc_methods(sup, cfg)}
        report: dict[str, Any] = methods["get_health"].handler({})
        block = report["hunt_scheduler"]
        assert block["alive"] is True
        # The thread ticks on its own clock; the field may not be stamped yet,
        # but it must be present and ISO-or-null so the panel can render it.
        assert "last_tick_at" in block
        assert block["last_tick_at"] is None or isinstance(block["last_tick_at"], str)
    finally:
        sup.stop(timeout=10.0)
    report_after = {m.name: m for m in _ipc_methods(sup, cfg)}["get_health"].handler({})
    assert report_after["hunt_scheduler"]["alive"] is False
