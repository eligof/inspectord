"""In-process rate limiters.

`TokenBucket` is a simple token bucket (single-process; not thread-safe).
`SlidingWindowLimiter` is the coarse per-minute window shared by the audited
mutating IPC surfaces (worker command channel design §6, hunt-followups §4.6):
it bounds attacker-drivable growth of the append-only audit_log, and tells the
caller to audit only the FIRST rejection of a saturated window.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class TokenBucket:
    rate_per_s: float
    capacity: int
    _tokens: float = 0.0
    _last: float = 0.0

    def __post_init__(self) -> None:
        self._tokens = float(self.capacity)
        self._last = time.monotonic()

    def try_take(self, n: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_s)
        if self._tokens >= n:
            self._tokens -= n
            return True
        return False


class SlidingWindowLimiter:
    """12/min sliding window; tells the caller when to audit a rejection.

    ``check()`` returns ``(allowed, audit_this_rejection)``: the first
    rejection of a saturated window is audited, the rest of that window's are
    not — one row per window, however hard the client hammers.
    """

    def __init__(
        self,
        limit: int = 12,
        window_s: float = 60.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._window_s = window_s
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._stamps: deque[float] = deque()
        self._rejection_audited = False

    def check(self) -> tuple[bool, bool]:
        with self._lock:
            now = self._monotonic()
            while self._stamps and now - self._stamps[0] >= self._window_s:
                self._stamps.popleft()
            if len(self._stamps) < self._limit:
                self._stamps.append(now)
                self._rejection_audited = False
                return True, False
            if self._rejection_audited:
                return False, False
            self._rejection_audited = True
            return False, True
