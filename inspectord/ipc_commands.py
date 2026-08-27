"""The run_worker_command IPC method (worker-command-channel design §6).

An audited, allowlisted, rate-limited bridge from the IPC socket to
``Supervisor.send_worker_command``. Three properties are load-bearing:

* the allowlist is enforced BEFORE anything touches a pipe — the channel's
  command set is closed, and the daemon does not forward what it would not
  itself accept;
* EVERY attempt is audited, allowlist/caps rejections included: rejected
  attempts are the probe signature of a compromised session and are the most
  security-interesting rows (args are audited as a truncated repr on
  cap-rejects, never the full oversized payload);
* a coarse 12/min sliding window bounds attacker-drivable growth of the
  append-only audit_log — excess attempts are a client error, audited once
  per window.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any

from inspectord.audit.log import append_audit
from inspectord.ipc_errors import ClientFacingError
from inspectord.workers.contract import COMMAND_ARGS_MAX_BYTES

_SCHEMA_VERSION = "1.0.0"

#: The closed set of (worker, command) pairs a client may trigger (design §6).
ALLOWED_WORKER_COMMANDS = frozenset(
    {
        ("vuln_scanner", "rescan"),
        ("scanner_runner", "run_scanner"),
    }
)

#: Sliding-window rate limit on run_worker_command attempts.
RATE_LIMIT_PER_MIN = 12
RATE_WINDOW_S = 60.0

#: Ceiling on the repr audited for a cap-rejected payload. The point of the
#: truncation is that the audit row records the ATTEMPT, not the payload — an
#: oversized args blob must not ride into the append-only log via its own
#: rejection.
_ARGS_REPR_MAX_CHARS = 200
#: Names echoed into audit rows are attacker-typed; bound them.
_NAME_AUDIT_MAX_CHARS = 64
_DETAIL_AUDIT_MAX_CHARS = 500

#: What one command attempt looks like to the audit log.
_AUDIT_ACTION = "worker_command_sent"
_AUDIT_ACTOR = "user:local"

SendFn = Callable[[str, str, dict[str, Any]], dict[str, Any]]


class WorkerCommandError(ClientFacingError):
    """A run_worker_command request the daemon refused.

    The message may quote the caller's own worker/command back at them —
    names the client itself chose — and nothing else.
    """


class _SlidingWindowLimiter:
    """12/min sliding window; tells the caller when to audit a rejection.

    ``check()`` returns ``(allowed, audit_this_rejection)``: the first
    rejection of a saturated window is audited, the rest of that window's are
    not — one row per window, however hard the client hammers.
    """

    def __init__(
        self,
        limit: int = RATE_LIMIT_PER_MIN,
        window_s: float = RATE_WINDOW_S,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._window_s = window_s
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._stamps: deque[float] = deque()
        self._rejection_audited = False

    def check(self) -> tuple[bool, bool]:
        with self._lock:
            now = self._monotonic()
            while self._stamps and now - self._stamps[0] >= self._window_s:
                self._stamps.popleft()
            if len(self._stamps) < self._limit:
                self._stamps.append(now)
                self._rejection_audited = False
                return True, False
            if self._rejection_audited:
                return False, False
            self._rejection_audited = True
            return False, True


def _truncated_repr(value: Any) -> str:
    text = repr(value)
    if len(text) > _ARGS_REPR_MAX_CHARS:
        return text[:_ARGS_REPR_MAX_CHARS] + "...[truncated]"
    return text


def _audit(db_path: Path, worker: str, details: dict[str, Any]) -> None:
    append_audit(
        db_path,
        actor=_AUDIT_ACTOR,
        action=_AUDIT_ACTION,
        target=f"worker:{worker[:_NAME_AUDIT_MAX_CHARS]}",
        details=details,
    )


def handle_run_worker_command(
    *,
    params: dict[str, Any],
    send: SendFn,
    db_path: Path,
    limiter: _SlidingWindowLimiter,
) -> dict[str, Any]:
    worker = str(params.get("worker", ""))
    command = str(params.get("command", ""))
    raw_args = params.get("args")
    # Audit rows echo attacker-typed names; bound what rides into the log.
    audited_command = command[:_NAME_AUDIT_MAX_CHARS]

    allowed, audit_rejection = limiter.check()
    if not allowed:
        if audit_rejection:
            _audit(
                db_path,
                worker,
                {"command": audited_command, "status": "rejected", "reason": "rate_limited"},
            )
        raise WorkerCommandError(
            f"run_worker_command rate limit exceeded ({RATE_LIMIT_PER_MIN}/min)"
        )

    # Allowlist BEFORE anything touches a pipe (design §6).
    if (worker, command) not in ALLOWED_WORKER_COMMANDS:
        _audit(
            db_path,
            worker,
            {
                "command": audited_command,
                "args": _truncated_repr(raw_args),
                "status": "rejected",
                "reason": "not_allowlisted",
            },
        )
        raise WorkerCommandError(f"command not allowed: {worker}/{command}")

    # §3 caps, daemon-side: cap-rejects audit a truncated repr, never the payload.
    args = raw_args if raw_args is not None else {}
    if not isinstance(args, dict):
        _audit(
            db_path,
            worker,
            {
                "command": audited_command,
                "args": _truncated_repr(raw_args),
                "status": "rejected",
                "reason": "args_not_object",
            },
        )
        raise WorkerCommandError("args must be an object")
    serialized = json.dumps(args, separators=(",", ":")).encode("utf-8")
    if len(serialized) > COMMAND_ARGS_MAX_BYTES:
        _audit(
            db_path,
            worker,
            {
                "command": audited_command,
                "args": _truncated_repr(args),
                "status": "rejected",
                "reason": "args_too_large",
            },
        )
        raise WorkerCommandError(f"args over {COMMAND_ARGS_MAX_BYTES} bytes")

    result = send(worker, command, args)
    status = str(result.get("status", "worker_unavailable"))
    detail = str(result.get("detail", ""))
    _audit(
        db_path,
        worker,
        {
            "command": audited_command,
            "args": args,
            "status": status,
            "detail": detail[:_DETAIL_AUDIT_MAX_CHARS],
        },
    )
    return {
        "schema_version": _SCHEMA_VERSION,
        "ok": status == "accepted",
        "status": status,
        "detail": detail,
    }


def make_run_worker_command_handler(
    *,
    supervisor: Any,
    db_path: Path,
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Bind one limiter + the Supervisor reference into an IPC handler.

    The supervisor is resolved lazily at call time (attribute access happens
    per request), so registration works with whatever object carries a
    ``send_worker_command`` method.
    """
    limiter = _SlidingWindowLimiter()

    def handler(params: dict[str, Any]) -> dict[str, Any]:
        return handle_run_worker_command(
            params=params,
            send=supervisor.send_worker_command,
            db_path=db_path,
            limiter=limiter,
        )

    return handler
