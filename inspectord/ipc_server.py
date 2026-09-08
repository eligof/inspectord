"""Minimal JSON-RPC 2.0 server over a Unix socket.

Each connection is line-delimited JSON. Authentication is SO_PEERCRED:
if `allowed_uids` is non-empty, the caller's uid must be in the list.

Methods carrying a `polkit_action` are additionally gated (quarantine design
§2.3). The pipeline order is load-bearing: validate → **rate limit** → polkit
→ handler, so a request flood can never stack pkcheck prompts. The peer's
(pid, uid, start-time) is snapshotted ONCE at connection accept — the peer
provably lives at that instant (it holds the connection open); a check-time
/proc read would describe whatever process currently owns the pid. Denials
answer on the dedicated -32001 channel, message prefixed with the outcome
token, and every non-authorized outcome is audited.

A handler failure answers with a generic message and a correlation id; only a
`ClientFacingError` (see `inspectord.ipc_errors`) is passed through verbatim.
"""

from __future__ import annotations

import contextlib
import grp
import json
import os
import socket
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from inspectord.authz import AuthzResult, PeerIdentity, proc_start_time
from inspectord.ipc_errors import ClientFacingError, new_error_ref
from inspectord.log import get
from inspectord.schemas.versions import IPC_PROTOCOL_VERSION

log = get(__name__)

_SO_PEERCRED = 17
_CRED_FMT = "iII"  # pid, uid, gid

#: What a client is told about a failure that was not written for it. The ref is
#: the whole message: it is what a user pastes so the traceback can be found.
_INTERNAL_ERROR = "internal error (error_ref={ref}); the daemon log has the details"

#: JSON-RPC error code for authorization/rate-limit refusals — machine-
#: distinguishable from -32000 internal errors, so the CLI's exit codes need
#: no string matching. The message always starts with the outcome token.
AUTHZ_DENIED_CODE = -32001

#: Actionable client messages per outcome (quarantine design §2.2).
_DENIAL_MESSAGES = {
    "rate_limited": "too many requests; retry in a minute",
    "peer_gone": "peer process identity could not be captured at connect; reconnect and retry",
    "polkit_unavailable": "polkit is unavailable; the daemon cannot authorize this action",
    "agent_missing": (
        "no polkit agent in this session — use a desktop terminal, "
        "or run pkttyagent --process <your pid> --fallback"
    ),
    "action_unknown": (
        "polkit policy not installed — run: "
        "sudo cp packaging/polkit/org.inspectord.policy /usr/share/polkit-1/actions/"
    ),
    "timeout": "no answer to the authorization prompt in 60s",
    "authz_busy": "another authorization prompt is in progress; retry in a moment",
    "denied": "authorization denied",
}


def _denial_message(outcome: str) -> str:
    return f"{outcome}: {_DENIAL_MESSAGES.get(outcome, 'authorization failed')}"


class RateLimiter(Protocol):
    """The `SlidingWindowLimiter` surface: (allowed, audit_this_rejection)."""

    def check(self) -> tuple[bool, bool]: ...


@dataclass
class Method:
    name: str
    handler: Callable[[dict[str, Any]], Any]
    mutates: bool = False
    #: When set, calls are polkit-gated with this action id (design §2.3).
    polkit_action: str | None = None
    #: Consulted BEFORE polkit for gated methods; shared across verbs by choice.
    limiter: RateLimiter | None = None


def _peer_creds(sock: socket.socket) -> tuple[int, int]:
    """SO_PEERCRED (pid, uid) of the connected peer."""
    raw = sock.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, struct.calcsize(_CRED_FMT))
    pid, uid, _gid = struct.unpack(_CRED_FMT, raw)
    return int(pid), int(uid)


def _err(req_id: object, code: int, message: str) -> bytes:
    return (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": code, "message": message},
            }
        )
        + "\n"
    ).encode("utf-8")


def _ok(req_id: object, result: object) -> bytes:
    return (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }
        )
        + "\n"
    ).encode("utf-8")


class IpcServer:
    def __init__(
        self,
        *,
        socket_path: Path,
        methods: list[Method],
        allowed_uids: list[int],
        socket_group: str | None = None,
        authz_check: Callable[[str, PeerIdentity, str | None], AuthzResult] | None = None,
        audit: Callable[..., object] | None = None,
    ) -> None:
        """Initialise the IPC server.

        Args:
            socket_path: Filesystem path for the Unix-domain socket.
            methods: JSON-RPC methods to expose.
            allowed_uids: UIDs permitted to call any method (empty = all).
            socket_group: If set, chown the socket to this group and apply
                mode 0o660 so group members can connect.  The parent directory
                is also hardened to 0o750 for defence-in-depth.  If the group
                does not exist or a permission operation fails, the server falls
                back to owner-only (0o600) rather than crashing.
            authz_check: Polkit gate for methods carrying a `polkit_action`
                (`check_polkit`-shaped). None = every gated method fails
                closed with `polkit_unavailable`.
            audit: Called on every non-authorized outcome of a gated method
                (`append_audit`-shaped keyword surface). None = no audit rows,
                gating still applies.
        """
        self._path = Path(socket_path)
        self._methods = {m.name: m for m in methods}
        self._allowed_uids = list(allowed_uids)
        self._socket_group = socket_group
        self._authz_check = authz_check
        self._audit = audit
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        """Bind the Unix-domain socket and begin accepting connections.

        The socket is created with a restrictive umask (0o177) so it is
        born as 0o600, eliminating the bind→chmod race window.  Final
        permissions are applied after a successful bind:

        * No ``socket_group``: 0o600 (owner-only) — explicit chmod for
          clarity even though the umask already enforces it.
        * ``socket_group`` set: resolve gid, chown to that group, chmod to
          0o660, and harden the parent directory to 0o750.  On any error
          (unknown group, PermissionError) the socket stays at 0o600 and a
          warning is logged — the daemon keeps running (fail-closed).
        """
        parent = self._path.parent
        if self._path.exists():
            self._path.unlink()
        parent.mkdir(parents=True, exist_ok=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # Bind under a restrictive umask so the socket is born 0o600,
            # eliminating the race window between bind and chmod.
            old_umask = os.umask(0o177)
            try:
                s.bind(str(self._path))
            finally:
                os.umask(old_umask)

            # Apply final permissions after a successful bind.
            if self._socket_group is not None:
                self._apply_group_permissions(parent)
            else:
                os.chmod(self._path, 0o600)
        except Exception:
            with contextlib.suppress(OSError):
                s.close()
            raise

        s.listen(16)
        self._sock = s
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _apply_group_permissions(self, parent: Path) -> None:
        """Attempt to set group ownership and mode 0o660 on the socket.

        Also hardens the parent directory to 0o750 so only the group can
        traverse to the socket.  Any failure leaves the socket at 0o600
        (fail-closed) and logs a warning rather than crashing the daemon.
        """
        assert self._socket_group is not None
        try:
            gid = grp.getgrnam(self._socket_group).gr_gid
        except KeyError:
            log.warning(
                "ipc: socket_group %r not found; socket left at 0o600 (owner-only)",
                self._socket_group,
            )
            return

        original_parent_gid = os.stat(parent).st_gid
        try:
            os.chown(self._path, -1, gid)
            os.chmod(self._path, 0o660)
            os.chown(parent, -1, gid)
            os.chmod(parent, 0o750)
        except OSError as exc:
            log.warning(
                "ipc: could not apply group permissions for %r (%s); "
                "socket left at 0o600 (owner-only)",
                self._socket_group,
                exc,
            )
            # Revert to owner-only so we don't leave a partially-applied state.
            with contextlib.suppress(OSError):
                os.chmod(self._path, 0o600)
            with contextlib.suppress(OSError):
                os.chown(parent, -1, original_parent_gid)

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        with contextlib.suppress(FileNotFoundError):
            self._path.unlink()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            pid, uid = _peer_creds(conn)
            if self._allowed_uids and uid not in self._allowed_uids:
                conn.sendall(_err(None, -32000, "peer uid not allowed"))
                return
            # Accept-time snapshot (design §2.1): the peer provably lives right
            # now — it holds this connection open. A later /proc read would
            # re-bind gated calls to whatever process owns the pid by then.
            start_time = proc_start_time(pid)
            peer = (
                None  # peer_gone: gated calls on this connection are dead
                if start_time is None
                else PeerIdentity(pid=pid, uid=uid, start_time=start_time)
            )
            with conn.makefile("rb") as rf:
                for line in rf:
                    stripped = line.rstrip(b"\n")
                    if not stripped:
                        continue
                    try:
                        req = json.loads(stripped.decode("utf-8"))
                    except Exception:
                        conn.sendall(_err(None, -32700, "parse error"))
                        continue
                    self._dispatch(conn, req, pid, uid, peer)
        finally:
            conn.close()

    def _gate(self, method: Method, pid: int, uid: int, peer: PeerIdentity | None) -> str | None:
        """Run the limiter-then-polkit pipeline. Returns a denial message or None.

        Order is the contract (design §2.3): the limiter runs BEFORE polkit so
        a request flood can never spawn concurrent 60 s pkcheck prompts.
        """
        action_id = method.polkit_action
        assert action_id is not None
        if method.limiter is not None:
            allowed, audit_this = method.limiter.check()
            if not allowed:
                if audit_this:
                    self._audit_denial(method, action_id, pid, uid, "rate_limited")
                return _denial_message("rate_limited")
        if peer is None:
            self._audit_denial(method, action_id, pid, uid, "peer_gone")
            return _denial_message("peer_gone")
        if self._authz_check is None:
            self._audit_denial(method, action_id, pid, uid, "polkit_unavailable")
            return _denial_message("polkit_unavailable")
        result = self._authz_check(action_id, peer, None)
        if result.authorized:
            return None
        self._audit_denial(method, action_id, pid, uid, result.outcome)
        return _denial_message(result.outcome)

    def _audit_denial(
        self, method: Method, action_id: str, pid: int, uid: int, reason: str
    ) -> None:
        log.info("ipc: %s refused for pid=%d uid=%d: %s", method.name, pid, uid, reason)
        if self._audit is None:
            return
        try:
            self._audit(
                action="polkit_denied",
                target=method.name,
                details={
                    "action_id": action_id,
                    "peer_pid": pid,
                    "peer_uid": uid,
                    "reason": reason,
                },
            )
        except Exception:
            # Audit is fail-open project-wide: a dropped row must never turn a
            # clean denial into a connection error.
            log.exception("ipc: audit callable failed for %s", method.name)

    def _dispatch(
        self,
        conn: socket.socket,
        req: dict[str, Any],
        pid: int,
        uid: int,
        peer: PeerIdentity | None,
    ) -> None:
        req_id = req.get("id")
        if req.get("jsonrpc") != "2.0":
            conn.sendall(_err(req_id, -32600, "invalid request"))
            return
        if req.get("schema_version") != IPC_PROTOCOL_VERSION:
            msg = f"unsupported schema_version, expected {IPC_PROTOCOL_VERSION}"
            conn.sendall(_err(req_id, -32602, msg))
            return
        method = self._methods.get(req.get("method", ""))
        if method is None:
            conn.sendall(_err(req_id, -32601, "method not found"))
            return
        if method.polkit_action is not None:
            denial = self._gate(method, pid, uid, peer)
            if denial is not None:
                conn.sendall(_err(req_id, AUTHZ_DENIED_CODE, denial))
                return
        try:
            result = method.handler(req.get("params") or {})
            response = _ok(req_id, result)
        except ClientFacingError as exc:
            # The message was written for the caller (see `inspectord.ipc_errors`),
            # so it goes through as-is. No traceback: a rejected request is a
            # normal outcome, not a daemon fault.
            log.info("ipc: %s rejected the request: %s", method.name, exc)
            response = _err(req_id, -32000, str(exc))
        except Exception:
            # Everything else is opaque to the client. `repr(exc)` used to go
            # out here, which handed over whatever the exception held — DuckDB
            # quotes the generated SQL and the database path in its own message,
            # and `inspectorctl`'s web UI renders these strings on a page. The
            # ref is the one thing worth saying: it names the log record below,
            # which carries the exception and its full traceback.
            ref = new_error_ref()
            log.exception("ipc: %s failed (error_ref=%s)", method.name, ref)
            response = _err(req_id, -32000, _INTERNAL_ERROR.format(ref=ref))
        conn.sendall(response)
