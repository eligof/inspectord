"""Tests for the desktop notify-send sink."""

from __future__ import annotations

import subprocess

from inspectord.workers.notifier.sinks.desktop import DesktopSink


class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(tuple(argv))
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"", stderr=b"")


def test_desktop_sink_invokes_notify_send() -> None:
    runner = _FakeRunner()
    sink = DesktopSink(runner=runner)
    sink.send(
        severity="critical",
        title="Reverse shell detected",
        body="bash → 1.2.3.4:4444",
    )
    assert runner.calls
    argv = runner.calls[0]
    assert argv[0] == "notify-send"
    assert "Reverse shell detected" in argv
    assert "bash → 1.2.3.4:4444" in argv


def test_desktop_sink_uses_urgency_for_severity() -> None:
    runner = _FakeRunner()
    sink = DesktopSink(runner=runner)
    sink.send(severity="critical", title="t", body="b")
    sink.send(severity="info", title="t2", body="b2")
    assert "--urgency=critical" in runner.calls[0]
    assert "--urgency=low" in runner.calls[1]
