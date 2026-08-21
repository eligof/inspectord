"""Anomaly detector thread (spec 2026-08-20-anomaly-detector-design.md §2).

Owns the maintenance thread. Each tick: flush the first-sighting queue, drain
the router subscription into the metric engine and the beacon tracker, close
minute buckets, emit a ``kind=signal`` event per threshold breach and per
qualifying beacon observation (re-injected into the supervisor's dispatch
path, where starter-pack ``anomaly.*`` rules turn them into alerts), and
checkpoint engine + beacon state to ``metric_baseline`` when due.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from queue import Empty as QueueEmpty
from typing import TYPE_CHECKING

from inspectord.anomaly.beacon import BeaconHit, BeaconTracker
from inspectord.anomaly.first_sighting import FirstSightingTracker
from inspectord.anomaly.metrics import extract_samples
from inspectord.anomaly.stats import MetricEngine, SignalData
from inspectord.config import AnomalyConfig
from inspectord.log import get
from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event
from inspectord.storage.db import Database

if TYPE_CHECKING:
    from inspectord.router import Subscription

log = get(__name__)


_BUCKET_LABEL = {"1h": "per minute", "24h": "per 5 min", "7d": "per 15 min"}


def _signal_event(data: SignalData, *, now: datetime) -> Event:
    # data.entity carries exactly one of process= / user= / file=; pass each
    # explicitly (rather than **data.entity) so it's checked against
    # build_event's heterogeneous kwargs.
    ev = build_event(
        module="anomaly_detector",
        action="metric_anomaly",
        category=["anomaly"],
        type_=["info"],
        kind="signal",
        severity="info",
        ts=now,
        message=(
            f"{data.metric_kind} for {data.entity_key} deviates from baseline: "
            f"observed {data.observed:g} vs mean {data.mean:g} "
            f"({_BUCKET_LABEL.get(data.window, data.window)}, "
            f"z={data.z:.1f}, {data.window} window)"
        ),
        process=data.entity.get("process"),
        user=data.entity.get("user"),
        file=data.entity.get("file"),
    )
    ev.baseline = {
        "metric_kind": data.metric_kind,
        "entity_key": data.entity_key,
        "window": data.window,
        "bucket_label": _BUCKET_LABEL.get(data.window, data.window),
        "observed": data.observed,
        "mean": data.mean,
        "stddev": data.stddev,
        "deviation": round(data.z, 2),
    }
    return ev


def _beacon_event(hit: BeaconHit, *, now: datetime) -> Event:
    ev = build_event(
        module="anomaly_detector",
        action="beacon_signature",
        category=["anomaly"],
        type_=["info"],
        kind="signal",
        severity="info",
        ts=now,
        message=(
            f"{hit.process_name} connects to {hit.dst_ip}:{hit.dst_port} "
            f"every ~{hit.mean_interval_s:.0f}s (cv={hit.cv:.3f}, "
            f"n={hit.count}) — low-variance periodic egress"
        ),
        process={"name": hit.process_name},
        destination={"ip": hit.dst_ip, "port": hit.dst_port},
    )
    ev.baseline = {
        "metric_kind": "beacon",
        "entity_key": hit.entity_key,
        "count": hit.count,
        "interval_mean_s": round(hit.mean_interval_s, 1),
        "interval_stddev_s": round(hit.stddev_interval_s, 2),
        "cv": round(hit.cv, 3),
    }
    return ev


class AnomalyDetector:
    def __init__(
        self,
        *,
        db: Database,
        tracker: FirstSightingTracker,
        config: AnomalyConfig,
        subscription: Subscription | None = None,
        emit: Callable[[Event], None] | None = None,
    ) -> None:
        self._db = db
        self._tracker = tracker
        self._cfg = config
        self._sub = subscription
        self._emit = emit
        self._engine = MetricEngine(config)
        self._beacon = BeaconTracker(config)
        self._last_checkpoint = time.monotonic()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="anomaly-detector", daemon=True)
        self._thread.start()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def load_checkpoints(self) -> int:
        """Restore engine and beacon state from metric_baseline; delete rows that fail to
        parse so a bad row cannot fail every startup forever. Never raises."""
        loaded = 0
        try:
            rows = self._db.query(
                "SELECT metric_kind, entity_key, window_name, state_json FROM metric_baseline"
            ).fetchall()
        except Exception as exc:
            log.warning("could not read metric_baseline checkpoints: %r", exc)
            return 0
        for metric_kind, entity_key, window_name, blob in rows:
            if str(window_name) == "beacon":
                ok = self._beacon.load_row(str(entity_key), blob)
            else:
                ok = self._engine.load_row(
                    str(metric_kind), str(entity_key), str(window_name), blob
                )
            if ok:
                loaded += 1
                continue
            log.warning(
                "discarding corrupt metric_baseline row (%s, %s, %s)",
                metric_kind,
                entity_key,
                window_name,
            )
            try:
                self._db.execute(
                    "DELETE FROM metric_baseline "
                    "WHERE metric_kind = ? AND entity_key = ? AND window_name = ?",
                    [metric_kind, entity_key, window_name],
                )
            except Exception as exc:
                log.warning("could not delete corrupt checkpoint row: %r", exc)
        return loaded

    def checkpoint(self) -> None:
        """Atomically rewrite metric_baseline from current engine state.

        A full-table rewrite (DELETE + one bulk INSERT) instead of per-row
        upserts: at the full 9,216-row cap, per-row INSERT OR REPLACE was
        benchmarked at ~43s (would stall the tick thread and overflow the
        router subscription), while a single bulk unnest-over-list-params
        insert runs in ~2s. The rewrite also makes evicted entities'
        rows disappear for free, so there is no separate per-evicted-key
        DELETE pass to run. Beacon tracker rows (window_name 'beacon') ride
        along in the same rewrite rather than getting a separate table.
        """
        rows = self._engine.checkpoint_rows() + self._beacon.checkpoint_rows()
        # Nothing left to track for these keys once the table is rewritten
        # from scratch below; drain anyway so the engine's internal evicted
        # list doesn't grow unbounded between checkpoints.
        self._engine.drain_evicted()
        metric_kinds, entity_keys, window_names, blobs = ([r[i] for r in rows] for i in range(4))
        try:
            self._db.execute("BEGIN")
            self._db.execute("DELETE FROM metric_baseline")
            self._db.execute(
                "INSERT INTO metric_baseline "
                "SELECT unnest(?), unnest(?), unnest(?), unnest(?), CURRENT_TIMESTAMP",
                [metric_kinds, entity_keys, window_names, blobs],
            )
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        self._last_checkpoint = time.monotonic()

    def _run(self) -> None:
        while not self._stop.wait(self._cfg.tick_s):
            self._tick(now=datetime.now(UTC))

    def _drain(self) -> dict[str, BeaconHit]:
        """Drain the subscription into the engine and beacon tracker.

        Returns beacon hits deduped per key (last observation wins), so one
        beaconing key yields at most one signal per tick regardless of how
        many buffered connections qualified during the drain.
        """
        hits: dict[str, BeaconHit] = {}
        if self._sub is None:
            return hits
        while True:
            try:
                ev = self._sub.get_nowait()
            except QueueEmpty:
                return hits
            for sample in extract_samples(ev):
                self._engine.ingest(sample, ts=ev.ts)
            hit = self._observe_beacon(ev)
            if hit is not None:
                hits[hit.entity_key] = hit

    def _observe_beacon(self, ev: Event) -> BeaconHit | None:
        if ev.action != "outbound_connection":
            return None
        name = (ev.process or {}).get("name")
        ip = (ev.destination or {}).get("ip")
        port = (ev.destination or {}).get("port")
        if not name or not ip or not isinstance(port, int):
            return None
        return self._beacon.observe(process_name=str(name), dst_ip=str(ip), dst_port=port, ts=ev.ts)

    def _tick(self, *, now: datetime | None = None) -> None:
        if now is None:
            now = datetime.now(UTC)
        try:
            self._tracker.flush(self._db)
        except Exception as exc:
            # One bad flush must never kill the thread; pending rows are gone,
            # and a re-sighting after restart is absorbed by dedup.
            log.error("first-sighting flush failed: %r", exc)
        try:
            beacon_hits = self._drain()
            for data in self._engine.tick(now=now):
                if self._emit is not None:
                    self._emit(_signal_event(data, now=now))
            if self._emit is not None:
                for hit in beacon_hits.values():
                    self._emit(_beacon_event(hit, now=now))
            if time.monotonic() - self._last_checkpoint >= self._cfg.checkpoint_interval_s:
                self.checkpoint()
        except Exception as exc:
            log.error("anomaly tick failed: %r", exc)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                # The tick thread is still mid-write; a final flush/checkpoint
                # here would race it on separate cursors over the same rows.
                # Skip and let the wedged thread's own writes stand.
                log.warning("anomaly detector thread did not stop in time; skipping final flush")
                return
        # Best-effort final flush + checkpoint so a clean shutdown loses nothing.
        try:
            self._tracker.flush(self._db)
        except Exception as exc:
            log.warning("final anomaly flush failed: %r", exc)
        try:
            self.checkpoint()
        except Exception as exc:
            log.warning("final anomaly checkpoint failed: %r", exc)
