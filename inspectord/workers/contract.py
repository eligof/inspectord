"""Worker base class.

A worker is a process that:
  * Reads its config from stdin (single JSON object on the first line).
  * Emits one event per line to stdout (NDJSON).
  * Emits a heartbeat object to stderr every 10s by default.
  * Handles SIGTERM by setting a stop flag and flushing.
  * Optionally accepts commands on stdin after the config line
    (worker-command-channel design §3-§4). The channel is strictly opt-in: a
    subclass that overrides ``handle_command`` gets a daemon reader thread;
    everything else never reads stdin past the config line.
"""

from __future__ import annotations

import abc
import contextlib
import json
import re
import signal
import sys
import threading
import time
from collections import deque
from typing import IO, Any

from inspectord.log import get
from inspectord.parsers.base import build_event

log = get(__name__)

HEARTBEAT_INTERVAL_S = 10.0

# --- command channel (worker-command-channel design §3) ----------------------
#: Read-side line cap. An over-long line is drained to the next newline,
#: logged and dropped — never parsed, never answered.
COMMAND_LINE_MAX_BYTES = 64 * 1024
#: Serialized size cap on a command's ``args`` object.
COMMAND_ARGS_MAX_BYTES = 4096
#: Command names are closed identifiers; the channel never carries code/paths.
COMMAND_NAME_RE = re.compile(r"^[a-z_]{1,64}$")
#: Bound on ``rejected`` command_result emission, so a broken supervisor
#: flooding stdin cannot turn into an event flood. Excess is logged only.
REJECTED_EMIT_MAX_PER_WINDOW = 30
REJECTED_EMIT_WINDOW_S = 60.0

_COMMAND_STATUSES = ("accepted", "rejected")


class Worker(abc.ABC):
    def __init__(
        self,
        *,
        name: str,
        stdin: IO[bytes] | None = None,
        stdout: IO[bytes] | None = None,
        stderr: IO[bytes] | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        # Resolved lazily in run(): pytest and exotic hosts can lack a real
        # sys.stdin.buffer, and a worker without command support never needs it.
        self._stdin = stdin
        self._stdout = stdout if stdout is not None else sys.stdout.buffer
        self._stderr = stderr if stderr is not None else sys.stderr.buffer
        self.config: dict[str, Any] = config or {}
        self._stop = threading.Event()
        # Set when a command is accepted so run() acts on the next loop
        # iteration instead of up to step_interval_s later (design §4).
        self._wake = threading.Event()
        self._events_processed = 0
        self._last_error: str | None = None
        self._started_at = time.monotonic()
        # Monotonic timestamps of recent rejected command_result emissions.
        self._rejected_emits: deque[float] = deque()

    def setup(self) -> None:  # noqa: B027
        pass

    @abc.abstractmethod
    def step(self) -> None: ...

    def step_interval_s(self) -> float:
        return 1.0

    def teardown(self) -> None:  # noqa: B027
        pass

    def handle_command(self, command: str, args: dict[str, Any]) -> dict[str, Any]:
        """Handle one command; runs on the stdin reader thread.

        Opt-in: the reader thread only exists when a subclass overrides this.
        Overrides must be fast and non-blocking — flip ``threading.Event``s or
        locked structures for the step loop, never do the work here. Return
        ``{"status": "accepted"|"rejected", "detail": str}``; the base class
        alone turns that into a ``command_result`` event.
        """
        return {"status": "rejected", "detail": "commands not supported"}

    def emit_event(self, event: dict[str, Any]) -> None:
        # LOAD-BEARING: exactly one write() per complete line. BufferedWriter
        # serializes concurrent calls, which is what makes cross-thread stdout
        # (step loop + command reader) safe without a lock (design §4).
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
        # Whichever of the two events run() is waiting on, it must return now.
        self._wake.set()

    def _install_signals(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return
        signal.signal(signal.SIGTERM, lambda *_: self.request_stop())
        signal.signal(signal.SIGINT, lambda *_: self.request_stop())

    def _supports_commands(self) -> bool:
        return type(self).handle_command is not Worker.handle_command

    def run(self) -> None:
        self._install_signals()
        if self._supports_commands():
            # MUST be the same buffered object the config read used
            # (read_config_from_stdin): a command written between spawn and
            # config-read is otherwise stranded in another wrapper's buffer.
            stream = self._stdin if self._stdin is not None else sys.stdin.buffer
            threading.Thread(
                target=self._command_reader,
                args=(stream,),
                name=f"{self.name}-commands",
                daemon=True,
            ).start()
        self.setup()
        last_heartbeat = time.monotonic()
        try:
            while not self._stop.is_set():
                # Cleared before step: a wake set during step stays set, so the
                # wait below returns immediately and the trigger is acted on at
                # the next iteration, never a full interval later.
                self._wake.clear()
                # request_stop() sets _stop BEFORE _wake, so a stop whose wake
                # was just erased by the clear above is still visible here —
                # without this check a SIGTERM landing in that window would
                # block a full step interval and blow the supervisor's stop
                # budget (SIGKILL, teardown skipped).
                if self._stop.is_set():
                    break
                try:
                    self.step()
                except Exception as exc:
                    self._last_error = repr(exc)
                if time.monotonic() - last_heartbeat >= HEARTBEAT_INTERVAL_S:
                    self.emit_heartbeat()
                    last_heartbeat = time.monotonic()
                self._wake.wait(self.step_interval_s())
                if self._stop.is_set():
                    break
        finally:
            try:
                self.emit_heartbeat()
            finally:
                self.teardown()

    # --- command channel (worker-command-channel design §3-§4) ---------------

    def _command_reader(self, stream: IO[bytes]) -> None:
        """Read command lines until EOF. Never raises; never busy-spins."""
        while True:
            try:
                line = stream.readline(COMMAND_LINE_MAX_BYTES + 1)
            except Exception as exc:
                log.warning("worker %s: command stream read failed: %r", self.name, exc)
                return
            if not line:
                return  # EOF: the incarnation's channel is closed.
            if len(line) > COMMAND_LINE_MAX_BYTES:
                if not line.endswith(b"\n"):
                    # Only a truncated read leaves tail bytes to discard; an
                    # exact-boundary line already consumed its newline and
                    # draining would eat the NEXT (innocent) command.
                    self._drain_overlong(stream)
                log.warning(
                    "worker %s: command line over %d bytes dropped",
                    self.name,
                    COMMAND_LINE_MAX_BYTES,
                )
                continue
            try:
                self._handle_command_line(line)
            except Exception as exc:  # never-die guard for the whole line
                log.error("worker %s: command handling failed: %r", self.name, exc)

    def _drain_overlong(self, stream: IO[bytes]) -> None:
        """Consume the rest of an over-long line up to its newline (or EOF)."""
        while True:
            try:
                chunk = stream.readline(COMMAND_LINE_MAX_BYTES)
            except Exception:
                return
            if not chunk or chunk.endswith(b"\n"):
                return

    def _handle_command_line(self, line: bytes) -> None:
        try:
            payload = json.loads(line)
        except Exception:
            log.warning("worker %s: malformed command line dropped (not JSON)", self.name)
            return
        if not isinstance(payload, dict):
            log.warning("worker %s: malformed command line dropped (not an object)", self.name)
            return

        raw_request_id = payload.get("request_id")
        request_id = raw_request_id if isinstance(raw_request_id, str) else None
        if request_id is None:
            # Without a recoverable request_id there is nothing to answer.
            log.warning("worker %s: command without request_id dropped", self.name)
            return

        # `or` folds None/falsy garbage into values the validator rejects (command) or an
        # empty args object (harmless: broken-supervisor-only path).
        command = payload.get("command") or ""
        args = payload.get("args") or {}
        error = _command_validation_error(command, args)
        if error is not None:
            self._emit_command_result(request_id, "rejected", error)
            return

        try:
            result = self.handle_command(command, args)
        except Exception as exc:
            self._emit_command_result(request_id, "rejected", f"handler error: {exc!r}")
            return
        status, detail = _coerce_command_result(result)
        if status == "accepted":
            self._wake.set()
        self._emit_command_result(request_id, status, detail)

    def _emit_command_result(self, request_id: str, status: str, detail: Any) -> None:
        """Emit the ``command_result`` event. BASE CLASS ONLY; never raises.

        Consumers never emit these themselves: the coercion here is what
        guarantees a consumer returning garbage cannot produce a
        schema-invalid event (which the supervisor would drop, turning an
        accepted command into a silent timeout) nor kill the reader thread.
        """
        try:
            if status not in _COMMAND_STATUSES:
                status = "rejected"
            try:
                detail_str = str(detail)
            except Exception:
                detail_str = "<unrepresentable detail>"
            if status == "rejected" and not self._rejected_emit_allowed():
                log.warning(
                    "worker %s: rejected command_result for %s suppressed (flood bound)",
                    self.name,
                    request_id,
                )
                return
            event = build_event(
                module=self.name,
                action="command_result",
                category=["process"],
                type_=["info"],
                severity="info",
                kind="state",
                message=f"command result: {status}",
                raw={"request_id": request_id, "status": status, "detail": detail_str},
            )
            self.emit_event(event.model_dump(mode="json", exclude_none=True))
        except Exception as exc:
            log.error("worker %s: failed to emit command_result: %r", self.name, exc)

    def _rejected_emit_allowed(self) -> bool:
        """Sliding-window bound on rejected emissions (reader thread only)."""
        now = time.monotonic()
        while self._rejected_emits and now - self._rejected_emits[0] >= REJECTED_EMIT_WINDOW_S:
            self._rejected_emits.popleft()
        if len(self._rejected_emits) >= REJECTED_EMIT_MAX_PER_WINDOW:
            return False
        self._rejected_emits.append(now)
        return True


def _command_validation_error(command: Any, args: Any) -> str | None:
    """Why ``(command, args)`` violates the wire caps (design §3), if it does."""
    if not isinstance(command, str) or not COMMAND_NAME_RE.fullmatch(command):
        return "invalid command name"
    if not isinstance(args, dict):
        return "args must be an object"
    serialized = json.dumps(args, separators=(",", ":")).encode("utf-8")
    if len(serialized) > COMMAND_ARGS_MAX_BYTES:
        return f"args over {COMMAND_ARGS_MAX_BYTES} bytes"
    return None


def _coerce_command_result(result: Any) -> tuple[str, Any]:
    """Coerce whatever ``handle_command`` returned to ``(status, detail)``."""
    if not isinstance(result, dict):
        return "rejected", f"handler returned {type(result).__name__}, expected dict"
    status = result.get("status")
    if status not in _COMMAND_STATUSES:
        return "rejected", result.get("detail", f"handler returned invalid status: {status!r}")
    return status, result.get("detail", "")


def read_config_from_stdin(stream: IO[bytes] | None = None) -> dict[str, Any]:
    """Read one JSON line from stdin; return empty dict if EOF.

    Reads through ``sys.stdin.buffer`` — the SAME buffered object the command
    reader thread later uses (buffer-steal hazard, design §4): reading the
    config through the ``sys.stdin`` text wrapper instead would let a command
    written between spawn and config-read be swallowed into that wrapper's
    decode buffer and silently lost.
    """
    if stream is None:
        stream = sys.stdin.buffer
    line = stream.readline()
    if not line:
        return {}
    result: dict[str, Any] = json.loads(line)
    return result
