"""Tests for the IPC server."""

from __future__ import annotations

import grp
import itertools
import json
import os
import socket
import stat
from pathlib import Path

from inspectord.authz import AuthzResult, PeerIdentity
from inspectord.config import IpcConfig
from inspectord.ipc_server import PEER_PARAM, IpcServer, Method
from inspectord.schemas.versions import IPC_PROTOCOL_VERSION


def _roundtrip(sock_path: Path) -> None:
    """Connect to the IPC server and perform a single echo roundtrip."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(sock_path))
    req = {
        "jsonrpc": "2.0",
        "id": 99,
        "method": "ping",
        "params": {},
        "schema_version": IPC_PROTOCOL_VERSION,
    }
    sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
    line = b""
    while not line.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        line += chunk
    sock.close()
    resp = json.loads(line)
    assert resp["id"] == 99


def _make_ping_server(sock_path: Path, **kwargs: object) -> IpcServer:
    """Return an IpcServer with a trivial 'ping' method registered."""
    return IpcServer(
        socket_path=sock_path,
        methods=[Method(name="ping", handler=lambda _params: "pong", mutates=False)],
        allowed_uids=[],
        **kwargs,  # type: ignore[arg-type]
    )


def test_ipc_get_health(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def get_health() -> dict[str, object]:
        return {"workers": [{"name": "healthcheck", "events_processed": 42}]}

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="get_health", handler=lambda params: get_health(), mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(sock_path))
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_health",
            "params": {},
            "schema_version": "1.0.0",
        }
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        line = b""
        while not line.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            line += chunk
        sock.close()
        response = json.loads(line.decode("utf-8"))
        assert response["id"] == 1
        assert response["result"]["workers"][0]["events_processed"] == 42
    finally:
        server.stop()


def test_ipc_rejects_unknown_method(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"
    server = IpcServer(socket_path=sock_path, methods=[], allowed_uids=[])
    server.start()
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(sock_path))
        req = {"jsonrpc": "2.0", "id": 1, "method": "nope", "params": {}, "schema_version": "1.0.0"}
        sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
        line = b""
        while not line.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            line += chunk
        sock.close()
        resp = json.loads(line)
        assert resp["error"]["code"] == -32601
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Permission hardening tests
# ---------------------------------------------------------------------------


def test_socket_is_owner_only_by_default(tmp_path: Path) -> None:
    """Without socket_group the socket must be created mode 0o600 (owner-only)."""
    sock_path = tmp_path / "ipc.sock"
    server = _make_ping_server(sock_path)
    server.start()
    try:
        mode = stat.S_IMODE(os.stat(sock_path).st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
    finally:
        server.stop()


def test_socket_group_sets_group_and_mode(tmp_path: Path) -> None:
    """With socket_group set to the caller's own group, socket mode is 0o660 and gid matches."""
    own_gid = os.getgid()
    own_group_name = grp.getgrgid(own_gid).gr_name
    sock_path = tmp_path / "ipc.sock"
    server = _make_ping_server(sock_path, socket_group=own_group_name)
    server.start()
    try:
        st = os.stat(sock_path)
        mode = stat.S_IMODE(st.st_mode)
        assert mode == 0o660, f"expected 0o660, got {oct(mode)}"
        assert st.st_gid == own_gid, f"expected gid={own_gid}, got {st.st_gid}"
        parent_mode = stat.S_IMODE(os.stat(sock_path.parent).st_mode)
        assert parent_mode == 0o750, f"expected parent 0o750, got {oct(parent_mode)}"
    finally:
        server.stop()


def test_unknown_socket_group_falls_back_to_owner_only(tmp_path: Path) -> None:
    """An unknown socket_group must not crash the server; socket falls back to 0o600."""
    sock_path = tmp_path / "ipc.sock"
    server = _make_ping_server(sock_path, socket_group="definitely_not_a_real_group_xyz")
    server.start()
    try:
        # Server must still serve requests (fail-closed, not crash).
        _roundtrip(sock_path)
        mode = stat.S_IMODE(os.stat(sock_path).st_mode)
        assert mode == 0o600, f"expected 0o600 fallback, got {oct(mode)}"
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Config model test
# ---------------------------------------------------------------------------


def test_ipc_config_socket_group_field() -> None:
    """IpcConfig must accept socket_group and default to None."""
    cfg_default = IpcConfig(socket_path=Path("/run/inspectord/ipc.sock"))
    assert cfg_default.socket_group is None

    cfg_set = IpcConfig(socket_path=Path("/run/inspectord/ipc.sock"), socket_group="mygroup")
    assert cfg_set.socket_group == "mygroup"


# ---------------------------------------------------------------------------
# Polkit gating (quarantine design §2.3): pipeline is validate → rate limit →
# polkit → handler; denials ride the dedicated -32001 channel.
# ---------------------------------------------------------------------------


class _Conn:
    """One open client connection; supports several requests in sequence."""

    def __init__(self, sock_path: Path) -> None:
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(str(sock_path))

    def call(
        self, method: str, req_id: int = 1, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        req = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {},
            "schema_version": IPC_PROTOCOL_VERSION,
        }
        self._sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
        line = b""
        while not line.endswith(b"\n"):
            chunk = self._sock.recv(4096)
            if not chunk:
                break
            line += chunk
        return json.loads(line)

    def close(self) -> None:
        self._sock.close()


def _one_call(sock_path: Path, method: str) -> dict[str, object]:
    conn = _Conn(sock_path)
    try:
        return conn.call(method)
    finally:
        conn.close()


class _FakeGate:
    def __init__(self, result: AuthzResult) -> None:
        self.result = result
        self.calls: list[tuple[str, PeerIdentity, str | None]] = []

    def __call__(self, action_id: str, peer: PeerIdentity, target: str | None) -> AuthzResult:
        self.calls.append((action_id, peer, target))
        return self.result


class _FakeLimiter:
    def __init__(self, answers: list[tuple[bool, bool]]) -> None:
        self.answers = answers
        self.checks = 0

    def check(self) -> tuple[bool, bool]:
        self.checks += 1
        return self.answers.pop(0)


class _RecordingAudit:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> None:
        self.rows.append(kwargs)


def _gated_server(
    sock_path: Path,
    *,
    gate: _FakeGate | None,
    limiter: _FakeLimiter | None = None,
    audit: _RecordingAudit | None = None,
    handler_calls: list[dict[str, object]] | None = None,
    polkit_target=None,
) -> IpcServer:
    calls = handler_calls if handler_calls is not None else []

    def handler(params: dict[str, object]) -> str:
        calls.append(params)
        return "did-it"

    return IpcServer(
        socket_path=sock_path,
        methods=[
            Method(
                name="quarantine_file",
                handler=handler,
                mutates=True,
                polkit_action="org.inspectord.quarantine",
                limiter=limiter,
                polkit_target=polkit_target,
            ),
            Method(name="ping", handler=lambda _p: "pong", mutates=False, limiter=limiter),
        ],
        allowed_uids=[],
        authz_check=gate,
        audit=audit,
    )


def test_gated_denial_blocks_handler_with_32001(tmp_path: Path) -> None:
    gate = _FakeGate(AuthzResult("denied", "Not authorized."))
    audit = _RecordingAudit()
    handler_calls: list[dict[str, object]] = []
    server = _gated_server(
        tmp_path / "ipc.sock", gate=gate, audit=audit, handler_calls=handler_calls
    )
    server.start()
    try:
        resp = _one_call(tmp_path / "ipc.sock", "quarantine_file")
    finally:
        server.stop()
    error = resp["error"]
    assert error["code"] == -32001
    assert error["message"].startswith("denied")
    assert handler_calls == []
    assert len(gate.calls) == 1
    action_id, peer, target = gate.calls[0]
    assert action_id == "org.inspectord.quarantine"
    assert peer.pid == os.getpid()
    assert peer.uid == os.getuid()
    assert target is None
    [row] = audit.rows
    assert row["action"] == "polkit_denied"
    assert row["target"] == "quarantine_file"
    details = row["details"]
    assert details["action_id"] == "org.inspectord.quarantine"
    assert details["peer_pid"] == os.getpid()
    assert details["peer_uid"] == os.getuid()
    assert details["reason"] == "denied"


def test_rate_limited_call_never_reaches_gate(tmp_path: Path) -> None:
    gate = _FakeGate(AuthzResult("authorized"))
    limiter = _FakeLimiter([(False, True)])
    audit = _RecordingAudit()
    handler_calls: list[dict[str, object]] = []
    server = _gated_server(
        tmp_path / "ipc.sock",
        gate=gate,
        limiter=limiter,
        audit=audit,
        handler_calls=handler_calls,
    )
    server.start()
    try:
        resp = _one_call(tmp_path / "ipc.sock", "quarantine_file")
    finally:
        server.stop()
    error = resp["error"]
    assert error["code"] == -32001
    assert error["message"].startswith("rate_limited")
    assert gate.calls == []  # limiter BEFORE polkit — no pkcheck for a flood
    assert handler_calls == []
    [row] = audit.rows
    assert row["details"]["reason"] == "rate_limited"


def test_rate_limited_audits_only_first_rejection(tmp_path: Path) -> None:
    gate = _FakeGate(AuthzResult("authorized"))
    limiter = _FakeLimiter([(False, True), (False, False)])
    audit = _RecordingAudit()
    server = _gated_server(tmp_path / "ipc.sock", gate=gate, limiter=limiter, audit=audit)
    server.start()
    try:
        conn = _Conn(tmp_path / "ipc.sock")
        conn.call("quarantine_file", req_id=1)
        conn.call("quarantine_file", req_id=2)
        conn.close()
    finally:
        server.stop()
    assert len(audit.rows) == 1


def test_authorized_call_runs_handler(tmp_path: Path) -> None:
    gate = _FakeGate(AuthzResult("authorized"))
    audit = _RecordingAudit()
    handler_calls: list[dict[str, object]] = []
    server = _gated_server(
        tmp_path / "ipc.sock", gate=gate, audit=audit, handler_calls=handler_calls
    )
    server.start()
    try:
        resp = _one_call(tmp_path / "ipc.sock", "quarantine_file")
    finally:
        server.stop()
    assert resp["result"] == "did-it"
    assert len(handler_calls) == 1
    assert audit.rows == []  # success is the handler's audit, not the gate's


def test_ungated_method_bypasses_limiter_and_gate(tmp_path: Path) -> None:
    gate = _FakeGate(AuthzResult("denied"))
    limiter = _FakeLimiter([(False, True)])  # would refuse if consulted
    server = _gated_server(tmp_path / "ipc.sock", gate=gate, limiter=limiter)
    server.start()
    try:
        resp = _one_call(tmp_path / "ipc.sock", "ping")
    finally:
        server.stop()
    assert resp["result"] == "pong"
    assert gate.calls == []
    assert limiter.checks == 0


def test_peer_identity_snapshotted_once_at_accept(tmp_path: Path, monkeypatch) -> None:
    gate = _FakeGate(AuthzResult("authorized"))
    counter = itertools.count(1000)
    reads: list[int] = []

    def fake_start_time(pid: int) -> int:
        value = next(counter)
        reads.append(value)
        return value

    monkeypatch.setattr("inspectord.ipc_server.proc_start_time", fake_start_time)
    server = _gated_server(tmp_path / "ipc.sock", gate=gate)
    server.start()
    try:
        conn = _Conn(tmp_path / "ipc.sock")
        conn.call("quarantine_file", req_id=1)
        conn.call("quarantine_file", req_id=2)
        conn.close()
    finally:
        server.stop()
    assert reads == [1000]  # captured ONCE at connect, not per call
    assert [peer.start_time for _a, peer, _t in gate.calls] == [1000, 1000]


def test_unreadable_peer_stat_denies_with_peer_gone(tmp_path: Path, monkeypatch) -> None:
    gate = _FakeGate(AuthzResult("authorized"))
    audit = _RecordingAudit()
    monkeypatch.setattr("inspectord.ipc_server.proc_start_time", lambda pid: None)
    server = _gated_server(tmp_path / "ipc.sock", gate=gate, audit=audit)
    server.start()
    try:
        resp = _one_call(tmp_path / "ipc.sock", "quarantine_file")
    finally:
        server.stop()
    error = resp["error"]
    assert error["code"] == -32001
    assert error["message"].startswith("peer_gone")
    assert gate.calls == []
    [row] = audit.rows
    assert row["details"]["reason"] == "peer_gone"


def test_no_authz_check_fails_closed_polkit_unavailable(tmp_path: Path) -> None:
    audit = _RecordingAudit()
    handler_calls: list[dict[str, object]] = []
    server = _gated_server(
        tmp_path / "ipc.sock", gate=None, audit=audit, handler_calls=handler_calls
    )
    server.start()
    try:
        resp = _one_call(tmp_path / "ipc.sock", "quarantine_file")
    finally:
        server.stop()
    error = resp["error"]
    assert error["code"] == -32001
    assert error["message"].startswith("polkit_unavailable")
    assert handler_calls == []
    [row] = audit.rows
    assert row["details"]["reason"] == "polkit_unavailable"


def test_actionable_client_messages(tmp_path: Path) -> None:
    for outcome, needle in [
        ("agent_missing", "pkttyagent"),
        ("action_unknown", "/usr/share/polkit-1/actions"),
    ]:
        sock_path = tmp_path / f"{outcome}.sock"
        server = _gated_server(sock_path, gate=_FakeGate(AuthzResult(outcome, "raw stderr")))
        server.start()
        try:
            resp = _one_call(sock_path, "quarantine_file")
        finally:
            server.stop()
        error = resp["error"]
        assert error["code"] == -32001
        assert error["message"].startswith(outcome)
        assert needle in error["message"]


def test_gated_handler_receives_server_injected_peer(tmp_path: Path) -> None:
    """An authorized gated call hands the handler the accept-time PeerIdentity."""
    gate = _FakeGate(AuthzResult("authorized"))
    handler_calls: list[dict[str, object]] = []
    server = _gated_server(tmp_path / "ipc.sock", gate=gate, handler_calls=handler_calls)
    server.start()
    try:
        conn = _Conn(tmp_path / "ipc.sock")
        # A client-supplied reserved param must be overridden, never trusted.
        resp = conn.call("quarantine_file", params={"path": "/tmp/x", PEER_PARAM: "spoof"})
        conn.close()
    finally:
        server.stop()
    assert resp["result"] == "did-it"
    [params] = handler_calls
    peer = params[PEER_PARAM]
    assert isinstance(peer, PeerIdentity)
    assert peer.pid == os.getpid()
    assert peer.uid == os.getuid()
    assert params["path"] == "/tmp/x"


def test_ungated_handler_never_sees_reserved_param(tmp_path: Path) -> None:
    """The reserved key is stripped from client params even on ungated methods."""
    seen: list[dict[str, object]] = []

    server = IpcServer(
        socket_path=tmp_path / "ipc.sock",
        methods=[Method(name="echo", handler=lambda p: seen.append(p) or "ok")],
        allowed_uids=[],
    )
    server.start()
    try:
        conn = _Conn(tmp_path / "ipc.sock")
        conn.call("echo", params={PEER_PARAM: "spoof", "x": 1})
        conn.close()
    finally:
        server.stop()
    assert seen == [{"x": 1}]


def test_polkit_target_reaches_gate_and_audit(tmp_path: Path) -> None:
    """`polkit_target` extracts the pkcheck --detail path; denials audit it."""
    gate = _FakeGate(AuthzResult("denied", "Not authorized."))
    audit = _RecordingAudit()
    server = _gated_server(
        tmp_path / "ipc.sock",
        gate=gate,
        audit=audit,
        polkit_target=lambda params: params.get("path"),
    )
    server.start()
    try:
        conn = _Conn(tmp_path / "ipc.sock")
        conn.call("quarantine_file", params={"path": "/tmp/evil.bin"})
        conn.close()
    finally:
        server.stop()
    [(_action, _peer, target)] = gate.calls
    assert target == "/tmp/evil.bin"
    [row] = audit.rows
    assert row["details"]["path"] == "/tmp/evil.bin"
