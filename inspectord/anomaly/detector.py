"""Anomaly detector thread (spec 2026-08-20-anomaly-detector-design.md §2).

PR1 skeleton: owns the maintenance thread and flushes the first-sighting
queue each tick. PR2 adds the statistical aggregators to ``_tick``.
"""

from __future__ import annotations

import contextlib
import threading

from inspectord.anomaly.first_sighting import FirstSightingTracker
from inspectord.config import AnomalyConfig
from inspectord.log import get
from inspectord.storage.db import Database

log = get(__name__)


class AnomalyDetector:
    def __init__(
        self, *, db: Database, tracker: FirstSightingTracker, config: AnomalyConfig
    ) -> None:
        self._db = db
        self._tracker = tracker
        self._cfg = config
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="anomaly-detector", daemon=True)
        self._thread.start()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        while not self._stop.wait(self._cfg.tick_s):
            self._tick()

    def _tick(self) -> None:
        try:
            self._tracker.flush(self._db)
        except Exception as exc:
            # One bad tick must never kill the thread; pending rows are gone,
            # and a re-sighting after restart is absorbed by dedup.
            log.error("anomaly tick failed: %r", exc)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        # Best-effort final flush so a clean shutdown loses nothing.
        with contextlib.suppress(Exception):
            self._tracker.flush(self._db)
