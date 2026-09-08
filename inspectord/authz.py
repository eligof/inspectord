"""Polkit authorization gate (quarantine design §2).

Fail closed on every path: the ONLY outcome that authorizes is pkcheck
exiting 0. Subject identity (pid + start-time) is captured by the IPC server
at connection-accept time and passed in — never re-read here, because a
check-time /proc read would describe whatever process currently owns the pid.

The stderr phrasings matched below were verified against the installed polkit
(pkcheck version 127, 2026-09-08) — observed output, not documentation:

- unknown action (exit 127): ``Error checking for authorization <id>:
  GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: Action <id> is not
  registered``
- no agent (exit 127): ``Authorization requires authentication but no agent
  is available.`` (compiled-in string, confirmed in the binary)
- hard deny (exit 1): ``Not authorized.``; dismissed prompt (exit 126):
  ``Authentication request was dismissed.``; needs-auth without ``-u``
  (exit 2): ``Authorization requires authentication and -u wasn't passed.``
  — all of these map to ``denied``.
"""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass

#: Anything shaped like `subprocess.run` for text-mode captured output.
RunnerFn = Callable[..., "subprocess.CompletedProcess[str]"]

_PKCHECK_TIMEOUT_S = 60.0
#: One interactive prompt at a time; a second concurrent gated call is denied
#: immediately (`authz_busy`) — stacked auth dialogs are prompt-fatigue training.
_PROMPT_SEMAPHORE = threading.Semaphore(1)


@dataclass(frozen=True)
class PeerIdentity:
    pid: int
    uid: int
    start_time: int  # /proc/<pid>/stat field 22, snapshotted at accept


@dataclass(frozen=True)
class AuthzResult:
    #: One of: authorized | denied | agent_missing | action_unknown |
    #: polkit_unavailable | timeout | authz_busy | error
    outcome: str
    detail: str = ""

    @property
    def authorized(self) -> bool:
        return self.outcome == "authorized"


def _parse_start_time(raw: str) -> int | None:
    """Field 22 of a /proc/<pid>/stat line, or None on a malformed line.

    comm (field 2) may contain spaces and parens: fields resume after the
    LAST ``)``.
    """
    tail = raw.rsplit(")", 1)[-1].split()
    try:
        return int(tail[19])  # field 22 overall; tail[0] is field 3 (state)
    except (IndexError, ValueError):
        return None


def proc_start_time(pid: int) -> int | None:
    """Field 22 of /proc/<pid>/stat, or None if unreadable (peer gone)."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            raw = fh.read().decode("ascii", "replace")
    except OSError:
        return None
    return _parse_start_time(raw)


def check_polkit(
    action_id: str,
    peer: PeerIdentity,
    *,
    target: str | None = None,
    runner: RunnerFn = subprocess.run,
    interactive: bool = True,
) -> AuthzResult:
    """Ask polkit whether `peer` may perform `action_id`. Fail closed."""
    if not _PROMPT_SEMAPHORE.acquire(blocking=False):
        return AuthzResult("authz_busy")
    try:
        argv = [
            "pkcheck",
            "--action-id",
            action_id,
            "--process",
            f"{peer.pid},{peer.start_time}",
        ]
        if interactive:
            argv.append("--allow-user-interaction")
        if target is not None:
            # Makes the agent prompt say WHICH file. polkitd accepts details
            # only from trusted callers (uid 0 / action owner) — the daemon
            # runs as root, so this holds in deployment.
            argv += ["--detail", "path", target]
        try:
            proc = runner(argv, capture_output=True, text=True, timeout=_PKCHECK_TIMEOUT_S)
        except FileNotFoundError:
            return AuthzResult("polkit_unavailable", "pkcheck is not installed")
        except subprocess.TimeoutExpired:
            return AuthzResult("timeout", "no answer to the authorization prompt in 60s")
        except OSError as exc:
            return AuthzResult("error", f"pkcheck could not run: {exc}")
        return _classify(proc.returncode, proc.stderr or "")
    finally:
        _PROMPT_SEMAPHORE.release()


def _classify(returncode: int, raw_stderr: str) -> AuthzResult:
    """Map a finished pkcheck run to an outcome (phrasings: module docstring)."""
    if returncode == 0:
        return AuthzResult("authorized")
    stderr = raw_stderr.strip()
    low = stderr.lower()
    if "no agent is available" in low:
        return AuthzResult("agent_missing", stderr)
    if "is not registered" in low:
        return AuthzResult("action_unknown", stderr)
    return AuthzResult("denied", stderr)
