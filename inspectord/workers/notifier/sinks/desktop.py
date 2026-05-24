"""Desktop popup sink — shells out to notify-send (libnotify)."""

from __future__ import annotations

import contextlib
import subprocess
from typing import Protocol


class _Runner(Protocol):
    def run(
        self, argv: list[str], *, timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[bytes]: ...


class _DefaultRunner:
    def run(
        self, argv: list[str], *, timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            argv,
            timeout=timeout,
            check=check,
            capture_output=True,
        )


_URGENCY: dict[str, str] = {
    "info": "low",
    "low": "low",
    "medium": "normal",
    "high": "critical",
    "critical": "critical",
}


class DesktopSink:
    def __init__(self, *, runner: _Runner | None = None) -> None:
        self._runner: _Runner = runner if runner is not None else _DefaultRunner()

    def send(self, *, severity: str, title: str, body: str) -> None:
        urgency = _URGENCY.get(severity, "normal")
        argv = [
            "notify-send",
            f"--urgency={urgency}",
            "--app-name=inspectord",
            title,
            body,
        ]
        with contextlib.suppress(Exception):
            self._runner.run(argv, timeout=5.0)
