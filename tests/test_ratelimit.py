"""Tests for token-bucket rate limiter."""

from __future__ import annotations

import time

from inspectord.ratelimit import TokenBucket


def test_bucket_allows_until_empty() -> None:
    bucket = TokenBucket(rate_per_s=10, capacity=5)
    allowed = sum(1 for _ in range(10) if bucket.try_take())
    assert allowed == 5


def test_bucket_refills_over_time() -> None:
    bucket = TokenBucket(rate_per_s=100, capacity=5)
    for _ in range(5):
        bucket.try_take()
    assert not bucket.try_take()
    time.sleep(0.06)
    assert bucket.try_take()


def test_bucket_capacity_caps_refill() -> None:
    bucket = TokenBucket(rate_per_s=1000, capacity=3)
    time.sleep(0.05)
    allowed = sum(1 for _ in range(10) if bucket.try_take())
    assert allowed == 3
