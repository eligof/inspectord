"""Anomaly detector thread (spec 2026-08-20-anomaly-detector-design.md §2).

Owns the maintenance thread. Each tick: flush the first-sighting queue, drain
the router subscription into the metric engine and the beacon tracker, close
minute buckets, emit a ``kind=signal`` event per threshold breach and per
qualifying beacon observation (re-injected into the supervisor's dispatch
path, where starter-pack ``anomaly.*`` rules turn them into alerts), and
checkpoint engine + beacon + resource-sampler state to ``metric_baseline``
when due.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from queue import Empty as QueueEmpty
from typing import TYPE_CHECKING

from inspectord.anomaly.beacon import BeaconHit, BeaconTracker
from inspectord.anomaly.entity_baseline import ResourceSampler, ResourceSignal
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

# resource.* checkpoint rows older than this are skipped AND deleted at load:
# a days-old resource profile misrepresents the unit, and dead units' rows
# would otherwise live forever. Engine/beacon rows keep their no-cutoff
# behavior (anomaly-checkpoint spec §2.1).
_RESOURCE_CHECKPOINT_MAX_AGE_S = 86400


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


def _resource_event(sig: ResourceSignal, *, now: datetime) -> Event:
    # Self-anomaly gets its own action so the dedicated monitor_health_anomaly
    # rule (separate rule class, spec §6) is the only thing that matches it.
    action = "monitor_health_anomaly" if sig.is_self else "resource_deviation"
    subject = "inspectord" if sig.is_self else (sig.unit or sig.entity_key)
    if sig.metric_kind == "cpu_pct":
        detail = f"CPU {sig.observed:.1f}% vs baseline {sig.mean:.1f}%"
    else:
        mib = 1024 * 1024
        detail = f"RSS {sig.observed / mib:.0f} MiB vs baseline {sig.mean / mib:.0f} MiB"
    ev = build_event(
        module="anomaly_detector",
        action=action,
        category=["anomaly"],
        type_=["info"],
        kind="signal",
        severity="info",
        ts=now,
        message=(
            f"{subject}: sustained resource deviation — {detail} ({sig.factor:.1f}x baseline)"
        ),
        service={"name": sig.unit} if sig.unit else None,
        process={"name": "inspectord"} if sig.is_self else None,
    )
    ev.baseline = {
        "metric_kind": sig.metric_kind,
        "entity_key": sig.entity_key,
        "observed": round(sig.observed, 2),
        "mean": round(sig.mean, 2),
        "deviation": round(sig.factor, 2),
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
        self._sampler: ResourceSampler = ResourceSampler(config)
        self._last_checkpoint = time.monotonic()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="anomaly-detector", daemon=True)
        self._thread.start()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def load_checkpoints(self) -> int:
        """Restore engine, beacon, and resource-sampler state from metric_baseline;
        delete rows that fail to parse so a bad row cannot fail every startup
        forever. resource.* rows older than _RESOURCE_CHECKPOINT_MAX_AGE_S are
        skipped and deleted (stale profile / dead unit). Never raises."""
        loaded = 0
        try:
            # age_s in SQL sidesteps tz mixing: updated_at was written from
            # CURRENT_TIMESTAMP cast to this TIMESTAMP column, so the same
            # cast on the other side yields a like-for-like difference.
            rows = self._db.query(
                "SELECT metric_kind, entity_key, window_name, state_json, "
                "date_diff('second', updated_at, CURRENT_TIMESTAMP::TIMESTAMP) "
                "FROM metric_baseline"
            ).fetchall()
        except Exception as exc:
            log.warning("could not read metric_baseline checkpoints: %r", exc)
            return 0
        for metric_kind, entity_key, window_name, blob, age_s in rows:
            kind = str(metric_kind)
            if kind.startswith("resource."):
                if age_s is not None and age_s > _RESOURCE_CHECKPOINT_MAX_AGE_S:
                    log.info(
                        "dropping stale resource checkpoint row (%s, %s): %ds old",
                        metric_kind,
                        entity_key,
                        age_s,
                    )
                    self._delete_checkpoint_row(metric_kind, entity_key, window_name)
                    continue
                ok = self._sampler.load_row(kind, str(entity_key), str(window_name), blob)
            elif str(window_name) == "beacon":
                ok = self._beacon.load_row(str(entity_key), blob)
            else:
                ok = self._engine.load_row(kind, str(entity_key), str(window_name), blob)
            if ok:
                loaded += 1
                continue
            log.warning(
                "discarding corrupt metric_baseline row (%s, %s, %s)",
                metric_kind,
                entity_key,
                window_name,
            )
            self._delete_checkpoint_row(metric_kind, entity_key, window_name)
        return loaded

    def _delete_checkpoint_row(
        self, metric_kind: object, entity_key: object, window_name: object
    ) -> None:
        try:
            self._db.execute(
                "DELETE FROM metric_baseline "
                "WHERE metric_kind = ? AND entity_key = ? AND window_name = ?",
                [metric_kind, entity_key, window_name],
            )
        except Exception as exc:
            log.warning("could not delete checkpoint row: %r", exc)

    def checkpoint(self) -> None:
        """Atomically rewrite metric_baseline from current engine state.

        A full-table rewrite (DELETE + one bulk INSERT) instead of per-row
        upserts: at the full 9,216-row cap, per-row INSERT OR REPLACE was
        benchmarked at ~43s (would stall the tick thread and overflow the
        router subscription), while a single bulk unnest-over-list-params
        insert runs in ~2s. The rewrite also makes evicted entities'
        rows disappear for free, so there is no separate per-evicted-key
        DELETE pass to run. Beacon tracker rows (window_name 'beacon')
        and resource sampler rows (metric_kind 'resource.*') ride along in
        the same rewrite rather than getting separate tables.
        """
        rows = (
            self._engine.checkpoint_rows()
            + self._beacon.checkpoint_rows()
            + self._sampler.checkpoint_rows()
        )
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
        # Two cadences on one thread (one DB handle, no locks): resource
        # sampling every resource_tick_s (default 30 s), the main tick every
        # tick_s (default 60 s). Wake at the nearer deadline.
        next_tick = time.monotonic() + self._cfg.tick_s
        next_res = time.monotonic() + self._cfg.resource_tick_s
        while True:
            delay = min(next_tick, next_res) - time.monotonic()
            if self._stop.wait(max(delay, 0.0)):
                return
            now_m = time.monotonic()
            if now_m >= next_res:
                self._sample_resources(now=now_m)
                next_res = now_m + self._cfg.resource_tick_s
            if now_m >= next_tick:
                self._tick(now=datetime.now(UTC))
                next_tick = now_m + self._cfg.tick_s

    def _sample_resources(self, *, now: float | None = None) -> None:
        """One resource tick (spec §6). Errors are logged, never raised — a
        bad round must not kill the detector thread (spec §9)."""
        if now is None:
            now = time.monotonic()
        units: list[str] = []
        try:
            rows = self._db.query(
                "SELECT unit FROM service_state WHERE active_state = 'active'"
            ).fetchall()
            units = [str(r[0]) for r in rows]
        except Exception as exc:
            log.warning("could not list services for resource sampling: %r", exc)
        try:
            for sig in self._sampler.sample(units, now=now):
                if self._emit is not None:
                    self._emit(_resource_event(sig, now=datetime.now(UTC)))
        except Exception as exc:
            log.error("resource sampling failed: %r", exc)

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
