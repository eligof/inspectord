"""End-to-end: first sighting stamps, alerts once, persists, survives restart."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inspectord.anomaly.stats import MetricSample
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


# --- PR2: statistical signal path -------------------------------------------


def _signal_event():
    ev = build_event(
        module="anomaly_detector",
        action="metric_anomaly",
        category=["anomaly"],
        type_=["info"],
        severity="info",
        kind="signal",
        user={"name": "eli"},
    )
    ev.baseline = {
        "metric_kind": "sudo_per_min",
        "entity_key": "eli",
        "window": "1h",
        "observed": 40.0,
        "mean": 0.5,
        "stddev": 0.7,
        "deviation": 56.4,
    }
    return ev


def test_signal_event_becomes_statistical_alert(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    sup = Supervisor(cfg)
    alerts = []
    sup.attach_alert_listener(alerts.append)
    sup.start()
    try:
        sup._inject_for_test(_signal_event())
        spikes = [a for a in alerts if a.rule.id == "anomaly.sudo_rate_spike"]
        assert len(spikes) == 1
        assert spikes[0].severity.value == "medium"
    finally:
        sup.stop(timeout=10.0)


def test_detector_is_wired_to_router_and_dispatch(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        det = sup._anomaly_detector
        assert det is not None
        assert det._sub is not None
        assert det._emit is not None
        # The subscription filter drops the detector's own signals...
        assert det._sub.filter_fn is not None
        assert det._sub.filter_fn(_signal_event()) is False
        # ...but passes ordinary worker events.
        assert det._sub.filter_fn(_kmod_event()) is True
        # Published events reach the detector's queue.
        sup._inject_for_test(_kmod_event("snd_usb_audio"))
        drained = []
        while True:
            try:
                drained.append(det._sub.get_nowait())
            except Exception:
                break
        assert any(e.action == "kmod_loaded" for e in drained)
    finally:
        sup.stop(timeout=10.0)


def test_stop_checkpoints_engine_state(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    # Huge tick so the detector thread cannot race the direct engine poke.
    cfg = cfg.model_copy(update={"anomaly": cfg.anomaly.model_copy(update={"tick_s": 3600.0})})
    sup = Supervisor(cfg)
    sup.start()
    try:
        det = sup._anomaly_detector
        assert det is not None
        det._engine.ingest(
            MetricSample(
                metric_kind="sudo_per_min",
                entity_key="eli",
                entity={"user": {"name": "eli"}},
                value=1.0,
            ),
            ts=datetime.now(UTC),
        )
    finally:
        sup.stop(timeout=10.0)
    db = Database(cfg.storage.db_path)
    db.connect()
    rows = db.query(
        "SELECT count(*) FROM metric_baseline WHERE metric_kind = 'sudo_per_min'"
    ).fetchall()
    assert rows[0][0] == 3  # one row per window
    db.close()
