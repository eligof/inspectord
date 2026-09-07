"""HuntScheduler — scheduled saved hunts (hunt-followups design §4).

A supervisor-owned thread, mirroring AnomalyDetector's shape: daemon=True,
the supervisor's shared Database (per-thread cursor contract, storage/db.py),
an injected emit callable, a wake Event for prompt shutdown. The loop guard is
the #127 lesson: no exception may kill this thread — and liveness is surfaced
via last_tick_at because containment without detection is half that lesson.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from inspectord.hunt import store
from inspectord.hunt.compiler import MAX_LIMIT, compile_hunt_query
from inspectord.hunt.errors import HuntError
from inspectord.hunt.execute import HuntResult, run_hunt_query
from inspectord.hunt.ipc_handlers import _ERROR_KINDS as _HUNT_ERROR_KINDS
from inspectord.log import get
from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event
from inspectord.storage.db import Database

log = get(__name__)

__all__ = ["HuntScheduler"]

_TICK_S = 60.0
_SAMPLE_MAX = 20
_SOFT_BUDGET_S = 30.0
_FAILURE_BACKOFF_AFTER = 3
_FAILURE_BACKOFF_S = 3600

#: The `since` floor for every scheduled run. The watermark window is the real
#: bound (§4.3); an explicit epoch `since` makes sure no default "recent"
#: window can ever hide an old-`ts`-but-newly-ingested row.
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class HuntScheduler:
    def __init__(self, *, db: Database, emit: Callable[[Event], None]) -> None:
        self._db = db
        self._emit = emit
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        #: In-memory by design: a restart resets backoff. Transition state
        #: (`last_status`) lives in the DB and survives restarts.
        self._failure_streaks: dict[str, int] = {}
        self.last_tick_at: datetime | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="hunt-scheduler", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick(now=datetime.now(tz=UTC))
            except Exception as exc:  # the #127 guard: the loop never dies
                log.error("hunt scheduler tick failed: %r", exc)
            self._stop.wait(_TICK_S)

    def tick(self, *, now: datetime) -> None:
        self.last_tick_at = now
        for query in store.due_queries(self._db, now=now):
            if self._stop.is_set():
                return
            if self._in_backoff(query, now=now):
                continue
            try:
                self._run_one(query, now=now)
            except Exception as exc:
                log.error("scheduled hunt %s failed unexpectedly: %r", query.name, exc)
                self._record_failure(query, kind="internal", now=now)

    def _run_one(self, query: store.ScheduledQuery, *, now: datetime) -> None:
        rows = self._db.query("SELECT MAX(ingest_seq) FROM events_enriched").fetchall()
        upper = None if not rows or rows[0][0] is None else int(rows[0][0])
        # A NULL watermark cannot happen for a scheduled row (schedule_query
        # always sets it) — treat 0 defensively.
        watermark = query.watermark_seq if query.watermark_seq is not None else 0
        if upper is None or upper <= watermark:
            return  # nothing newly ingested: no SELECT, no stamp
        rows = self._db.query(
            "SELECT MIN(ingest_seq) FROM events_enriched WHERE ingest_seq IS NOT NULL"
        ).fetchall()
        oldest = None if not rows or rows[0][0] is None else int(rows[0][0])
        # Bounded claim (§4.3): rows in the un-scanned gap may already be
        # pruned. The gap is unknowable, not silent.
        pruned_gap = oldest is not None and oldest > watermark + 1

        started = time.monotonic()
        try:
            compiled = compile_hunt_query(
                query.expression,
                since=_EPOCH,
                limit=MAX_LIMIT,
                ingest_bounds=(watermark, upper),
            )
            result = run_hunt_query(self._db, compiled)
        except HuntError as exc:
            log.warning("scheduled hunt %s failed: %s", query.name, exc)
            self._record_failure(query, kind=_HUNT_ERROR_KINDS.get(type(exc), "hunt"), now=now)
            return
        duration = time.monotonic() - started
        if duration > _SOFT_BUDGET_S:
            log.warning(
                "scheduled hunt %s took %.1fs (soft budget %.0fs)",
                query.name,
                duration,
                _SOFT_BUDGET_S,
            )
        if self._stop.is_set():
            return  # §4.7: an interrupted run never half-advances
        if not store.record_run(
            self._db, name=query.name, watermark_seq=upper, status="ok", now=now
        ):
            return  # schedule changed mid-run: discard the result (§4.3 item 4)
        self._failure_streaks.pop(query.name, None)
        if result.rows:
            self._emit(
                self._match_event(
                    query, result, upper=upper, duration=duration, pruned_gap=pruned_gap, now=now
                )
            )

    def _in_backoff(self, query: store.ScheduledQuery, *, now: datetime) -> bool:
        if self._failure_streaks.get(query.name, 0) < _FAILURE_BACKOFF_AFTER:
            return False
        if query.last_run_at is None:
            return False
        hold = timedelta(seconds=max(query.interval_s, _FAILURE_BACKOFF_S))
        return now < query.last_run_at + hold

    def _record_failure(self, query: store.ScheduledQuery, *, kind: str, now: datetime) -> None:
        # Transition state comes from the DB row, not the in-memory streak map:
        # `last_status` survives restarts, the map deliberately does not.
        transition = not (query.last_status or "").startswith("failed")
        if not store.record_run(
            self._db, name=query.name, watermark_seq=None, status=f"failed:{kind}", now=now
        ):
            return  # schedule changed mid-run: discard the failure too (§4.3 item 4)
        self._failure_streaks[query.name] = self._failure_streaks.get(query.name, 0) + 1
        if transition:
            self._emit(
                build_event(
                    module="hunt_scheduler",
                    action="hunt_run_failed",
                    kind="signal",
                    category=["hunt"],
                    type_=["error"],
                    severity=query.severity,
                    ts=now,
                    hunt={"name": query.name, "severity": query.severity, "error_kind": kind},
                )
            )

    def _match_event(
        self,
        query: store.ScheduledQuery,
        result: HuntResult,
        *,
        upper: int,
        duration: float,
        pruned_gap: bool,
        now: datetime,
    ) -> Event:
        # NOTE: the expression is deliberately NOT in the payload (§4.4 — it
        # may legitimately contain the hostile bytes it hunts for).
        return build_event(
            module="hunt_scheduler",
            action="hunt_match",
            kind="signal",
            category=["hunt"],
            type_=["info"],
            severity=query.severity,
            ts=now,
            message=f"scheduled hunt {query.name}: {len(result.rows)} new match(es)",
            hunt={
                "name": query.name,
                "severity": query.severity,
                "match_count": len(result.rows),
                "sample_event_ids": [row.event_id for row in result.rows[:_SAMPLE_MAX]],
                "window_upper_seq": upper,
                "run_duration_s": round(duration, 3),
                "truncated": result.truncated,
                "pruned_gap": pruned_gap,
            },
        )
