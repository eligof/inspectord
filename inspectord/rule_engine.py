"""Rule engine library — runs in-process inside the supervisor."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

from inspectord.alerts.builder import build_alert
from inspectord.alerts.dedup import DedupEngine
from inspectord.allowlist.evaluator import is_suppressed
from inspectord.rules.base import EvalContext
from inspectord.rules.registry import Registry
from inspectord.schemas.alert import Alert
from inspectord.schemas.allowlist import AllowlistEntry
from inspectord.schemas.event import Event

_HISTORY_WINDOW = timedelta(seconds=300)
_HISTORY_MAX = 5000


class RuleEngine:
    def __init__(
        self,
        *,
        registry: Registry,
        db_path: Path,
        allowlist_entries: list[AllowlistEntry],
        dedup_window_s: float = 600.0,
    ) -> None:
        self._registry = registry
        self._allowlist = list(allowlist_entries)
        self._dedup = DedupEngine(db_path=db_path, window_s=dedup_window_s)
        self._history: deque[Event] = deque(maxlen=_HISTORY_MAX)

    def process(self, event: Event) -> list[Alert]:
        self._history.append(event)
        self._trim_history(event.ts)
        ctx = EvalContext(event=event, history=list(self._history))
        matches = self._registry.evaluate(ctx)
        out: list[Alert] = []
        for match in matches:
            if is_suppressed(match, self._allowlist):
                continue
            candidate = build_alert(match=match, event=event)
            persisted, _was_new = self._dedup.persist(candidate)
            out.append(persisted)
        return out

    def _trim_history(self, now: datetime) -> None:
        cutoff = now - _HISTORY_WINDOW
        while self._history and self._history[0].ts < cutoff:
            self._history.popleft()
