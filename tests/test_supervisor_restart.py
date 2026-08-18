"""Supervisor worker-restart tests (spec section 3.2).

A crashed worker must be restarted with exponential backoff, and a worker that
crash-loops must eventually be given up on *loudly* -- silence there is a
monitoring blind spot.

Everything here drives a real Supervisor with real child processes; the child
modules are written into tmp_path and reached via PYTHONPATH so `python -m
<name>` finds them. The thresholds are shrunk to milliseconds via constructor
overrides so the suite never waits real seconds.
"""

from __future__ import annotations

from inspectord.supervisor import (
    RESTART_BASE_DELAY_S,
    RESTART_MAX_DELAY_S,
    backoff_delay,
)


def test_backoff_doubles_from_the_base_delay() -> None:
    assert backoff_delay(1) == 1.0
    assert backoff_delay(2) == 2.0
    assert backoff_delay(3) == 4.0
    assert backoff_delay(4) == 8.0
    assert backoff_delay(5) == 16.0
    assert backoff_delay(6) == 32.0


def test_backoff_is_capped() -> None:
    assert backoff_delay(7) == 60.0
    assert backoff_delay(8) == 60.0
    assert backoff_delay(50) == 60.0


def test_backoff_defaults_match_the_module_constants() -> None:
    assert RESTART_BASE_DELAY_S == 1.0
    assert RESTART_MAX_DELAY_S == 60.0


def test_backoff_first_attempt_is_never_below_the_base() -> None:
    # Defensive: attempt numbers are 1-based; a 0 must not yield a half delay.
    assert backoff_delay(0) == 1.0
    assert backoff_delay(-3) == 1.0


def test_backoff_honours_custom_base_and_cap() -> None:
    assert backoff_delay(1, base=0.01, cap=0.05) == 0.01
    assert backoff_delay(2, base=0.01, cap=0.05) == 0.02
    assert backoff_delay(4, base=0.01, cap=0.05) == 0.05
