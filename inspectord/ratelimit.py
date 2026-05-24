"""Simple token-bucket rate limiter. Single-process; not thread-safe."""

from __future__ import annotations

import time
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
