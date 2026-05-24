"""In-process event router with bounded queues per subscription.

Drop policy:
  - drop_oldest_non_critical: when full, drop the oldest non-critical event.
    If the buffer is full of criticals, we record a 'blocked' counter and
    raise; the publisher decides what to do (the supervisor logs + retries).
  - block: never drop; the publisher must wait.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from queue import Empty as QueueEmpty

from inspectord.schemas.event import Event, Severity


class DropPolicy(Enum):
    block = "block"
    drop_oldest_non_critical = "drop_oldest_non_critical"


@dataclass
class Subscription:
    name: str
    queue_size: int
    drop_policy: DropPolicy
    filter_fn: Callable[[Event], bool] | None = None
    _q: deque[Event] = field(default_factory=deque)
    dropped: int = 0
    blocked: int = 0

    def _try_drop_oldest_non_critical(self) -> bool:
        for i, ev in enumerate(self._q):
            if ev.severity != Severity.critical:
                del self._q[i]
                self.dropped += 1
                return True
        return False

    def get_nowait(self) -> Event:
        if not self._q:
            raise QueueEmpty
        return self._q.popleft()


class RouterFull(RuntimeError):
    pass


class EventRouter:
    def __init__(self) -> None:
        self._subs: list[Subscription] = []

    def subscribe(
        self,
        *,
        name: str,
        queue_size: int,
        drop_policy: DropPolicy,
        filter_fn: Callable[[Event], bool] | None = None,
    ) -> Subscription:
        sub = Subscription(
            name=name,
            queue_size=queue_size,
            drop_policy=drop_policy,
            filter_fn=filter_fn,
        )
        self._subs.append(sub)
        return sub

    def publish(self, event: Event) -> None:
        for sub in self._subs:
            if sub.filter_fn is not None and not sub.filter_fn(event):
                continue
            if len(sub._q) < sub.queue_size:
                sub._q.append(event)
                continue
            if sub.drop_policy is DropPolicy.drop_oldest_non_critical:
                if sub._try_drop_oldest_non_critical():
                    sub._q.append(event)
                    continue
                sub.blocked += 1
                raise RouterFull(f"subscription {sub.name!r} is saturated with critical events")
            else:
                sub.blocked += 1
                raise RouterFull(f"subscription {sub.name!r} is full")
