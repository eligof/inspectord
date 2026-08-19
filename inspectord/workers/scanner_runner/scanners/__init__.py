"""Scanner adapters: AIDE (PR1), rkhunter and YARA (PR2)."""

from __future__ import annotations

from inspectord.workers.scanner_runner.scanners.aide import AideAdapter
from inspectord.workers.scanner_runner.scanners.base import (
    Finding,
    ScannerAdapter,
    ScanOutcome,
)
from inspectord.workers.scanner_runner.scanners.rkhunter import RkhunterAdapter

__all__ = [
    "AideAdapter",
    "Finding",
    "RkhunterAdapter",
    "ScanOutcome",
    "ScannerAdapter",
    "default_adapters",
]


def default_adapters() -> list[ScannerAdapter]:
    """Every adapter this build knows about, in a deterministic order.

    Being known is not being run: each one stays inert until its config block
    sets ``enabled``, which no shipped config does.
    """
    return [AideAdapter(), RkhunterAdapter()]
