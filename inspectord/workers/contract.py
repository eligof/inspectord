"""Worker base class.

A worker is a process that:
  * Reads its config from stdin (single JSON object on the first line).
  * Emits one event per line to stdout (NDJSON).
  * Emits a heartbeat object to stderr every 10s by default.
  * Handles SIGTERM by setting a stop flag and flushing.
"""

from __future__ import annotations

import abc
import contextlib
import json
import signal
import sys
import threading
import time
from typing import IO, Any

HEARTBEAT_INTERVAL_S = 10.0


class Worker(abc.ABC):
    def __init__(
        self,
        *,
        name: str,
        stdout: IO[bytes] | None = None,
        stderr: IO[bytes] | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self._stdout = stdout if stdout is not None else sys.stdout.buffer
        self._stderr = stderr if stderr is not None else sys.stderr.buffer
        self.config: dict[str, Any] = config or {}
        self._stop = threading.Event()
        self._events_processed = 0
        self._last_error: str | None = None
        self._started_at = time.monotonic()

    def setup(self) -> None:  # noqa: B027
        pass

    @abc.abstractmethod
    def step(self) -> None: ...

    def step_interval_s(self) -> float:
        return 1.0

    def teardown(self) -> None:  # noqa: B027
        pass

    def emit_event(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":")) + "\n"
        self._stdout.write(line.encode("utf-8"))
        with contextlib.suppress(Exception):
            self._stdout.flush()
        self._events_processed += 1

    def emit_heartbeat(self) -> None:
        hb = {
            "kind": "heartbeat",
            "worker": self.name,
            "ts": time.time(),
            "events_processed": self._events_processed,
            "queue_depth": 0,
            "last_error": self._last_error,
            "uptime_s": time.monotonic() - self._started_at,
        }
        line = json.dumps(hb, separators=(",", ":")) + "\n"
        self._stderr.write(line.encode("utf-8"))
        with contextlib.suppress(Exception):
            self._stderr.flush()

    def request_stop(self) -> None:
        self._stop.set()

    def _install_signals(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return
        signal.signal(signal.SIGTERM, lambda *_: self.request_stop())
        signal.signal(signal.SIGINT, lambda *_: self.request_stop())

    def run(self) -> None:
        self._install_signals()
        self.setup()
        last_heartbeat = time.monotonic()
        try:
            while not self._stop.is_set():
                try:
                    self.step()
                except Exception as exc:
                    self._last_error = repr(exc)
                if time.monotonic() - last_heartbeat >= HEARTBEAT_INTERVAL_S:
                    self.emit_heartbeat()
                    last_heartbeat = time.monotonic()
                if self._stop.wait(self.step_interval_s()):
                    break
        finally:
            try:
                self.emit_heartbeat()
            finally:
                self.teardown()


def read_config_from_stdin() -> dict[str, Any]:
    """Read one JSON line from stdin; return empty dict if EOF."""
    line = sys.stdin.readline()
    if not line:
        return {}
    result: dict[str, Any] = json.loads(line)
    return result
