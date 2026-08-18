"""Scanner adapters. PR1 ships AIDE only; rkhunter and YARA follow in PR2."""

from __future__ import annotations

from inspectord.workers.scanner_runner.scanners.aide import AideAdapter
from inspectord.workers.scanner_runner.scanners.base import (
    Finding,
    ScannerAdapter,
    ScanOutcome,
)

__all__ = ["AideAdapter", "Finding", "ScanOutcome", "ScannerAdapter", "default_adapters"]


def default_adapters() -> list[ScannerAdapter]:
    """Every adapter this build knows about, in a deterministic order."""
    return [AideAdapter()]
