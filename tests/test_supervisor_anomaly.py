"""End-to-end: first sighting stamps, alerts once, persists, survives restart."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.supervisor import Supervisor


def _kmod_event(name: str = "evilmod"):
    return build_event(
        module="kmod_watcher",
        action="kmod_loaded",
        category=["driver"],
        type_=["installation"],
        severity="info",
        raw={"source": "/proc/modules", "module_name": name},
    )


def _quiet_cfg(tmp_path: Path):
    cfg = dev_config(base=tmp_path)
    # No workers: this test injects events directly.
    return cfg.model_copy(update={"workers": []})


def test_first_sighting_alerts_once_and_persists(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    sup = Supervisor(cfg)
    alerts = []
    sup.attach_alert_listener(alerts.append)
    sup.start()
    try:
        sup._inject_for_test(_kmod_event())
        sup._inject_for_test(_kmod_event())  # second sighting: no stamp, no alert
        first = [a for a in alerts if a.rule.id == "anomaly.first_kmod_load"]
        assert len(first) == 1
        assert first[0].severity.value == "medium"
    finally:
        sup.stop(timeout=10.0)

    # stop() flushed the pending row.
    db = Database(cfg.storage.db_path)
    db.connect()
    rows = db.query("SELECT entity_key FROM first_seen WHERE entity_kind = 'kmod'").fetchall()
    assert rows == [("evilmod",)]
    db.close()

    # A fresh supervisor loads the table: same module is no longer a sighting.
    sup2 = Supervisor(_quiet_cfg(tmp_path))
    alerts2 = []
    sup2.attach_alert_listener(alerts2.append)
    sup2.start()
    try:
        sup2._inject_for_test(_kmod_event())
        assert not [a for a in alerts2 if a.rule.id == "anomaly.first_kmod_load"]
    finally:
        sup2.stop(timeout=10.0)


def test_catchup_event_populates_without_alerting(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    sup = Supervisor(cfg)
    alerts = []
    sup.attach_alert_listener(alerts.append)
    sup.start()
    try:
        catchup = _kmod_event("vfat")
        catchup.first_seen = True  # snapshot catch-up re-emission
        sup._inject_for_test(catchup)
        assert not alerts  # rule engine skips catch-up events
        live = _kmod_event("vfat")
        sup._inject_for_test(live)
        assert not [a for a in alerts if a.rule.id == "anomaly.first_kmod_load"]
    finally:
        sup.stop(timeout=10.0)


def test_disabled_anomaly_never_stamps(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    cfg = cfg.model_copy(update={"anomaly": cfg.anomaly.model_copy(update={"enabled": False})})
    sup = Supervisor(cfg)
    alerts = []
    sup.attach_alert_listener(alerts.append)
    sup.start()
    try:
        assert sup._first_sighting is None  # disabled: the stage is never built
        ev = _kmod_event()
        sup._inject_for_test(ev)
        assert ev.baseline is None  # ...so nothing stamps
        assert not [a for a in alerts if a.rule.id == "anomaly.first_kmod_load"]
    finally:
        sup.stop(timeout=10.0)
