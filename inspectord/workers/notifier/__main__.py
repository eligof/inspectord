"""NotifierWorker — routes alerts to enabled sinks based on severity (spec §9.4)."""

from __future__ import annotations

import subprocess
from typing import Protocol

from inspectord.schemas.alert import Alert
from inspectord.workers.notifier.sinks.desktop import DesktopSink


class _Runner(Protocol):
    def run(
        self, argv: list[str], *, timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[bytes]: ...


_ROUTING: dict[str, set[str]] = {
    "critical": {"desktop"},
    "high": {"desktop"},
    "medium": {"desktop"},
    "low": set(),
    "info": set(),
}


class NotifierWorker:
    def __init__(self, *, runner: _Runner | None = None) -> None:
        self._desktop = DesktopSink(runner=runner)

    def on_alert(self, alert: Alert) -> None:
        sinks = _ROUTING.get(alert.severity.value, set())
        if not sinks:
            return
        title = f"[{alert.severity.value}] {alert.rule.name or alert.rule.id}"
        body = alert.rendered.short
        if "desktop" in sinks:
            self._desktop.send(severity=alert.severity.value, title=title, body=body)
