"""The IPC error surface: what a handler failure is allowed to tell the client.

`_dispatch` used to answer every handler failure with `repr(exc)`. That hands an
IPC client — and, through `inspectorctl`'s web UI, a browser page — whatever the
exception happens to hold: DuckDB quotes the generated SQL and the database path
in its own message.

These tests drive **real** failures over a **real** socket, never a mock raising
a synthetic exception: the leak lives in what DuckDB writes, so a fake exception
would prove nothing.
"""

from __future__ import annotations

import json
import logging
import re
import socket
from pathlib import Path
from typing import Any, cast

import duckdb
import pytest

from inspectord.alerts.lifecycle import InvalidTransitionError
from inspectord.cases.ipc_handlers import handle_get_case
from inspectord.dependencies.ipc_handlers import handle_apply_dependency_plan
from inspectord.hunt.compiler import compile_hunt_query
from inspectord.hunt.errors import HuntError, HuntSyntaxError
from inspectord.ipc_errors import ClientFacingError, IpcParamError, new_error_ref
from inspectord.ipc_server import IpcServer, Method
from inspectord.schemas.versions import IPC_PROTOCOL_VERSION
from inspectord.state.ipc_handlers import handle_capture_baseline
from inspectord.storage.db import Database

_REF_RE = re.compile(r"error_ref=([0-9a-f]{16})")


def _call(sock_path: Path, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """One request/response roundtrip over the real Unix socket."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(sock_path))
    try:
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or {},
            "schema_version": IPC_PROTOCOL_VERSION,
        }
        sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
        line = b""
        while not line.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            line += chunk
    finally:
        sock.close()
    decoded: dict[str, Any] = json.loads(line)
    return decoded


def _serve(tmp_path: Path, name: str, handler: Any) -> tuple[IpcServer, Path]:
    sock_path = tmp_path / "ipc.sock"
    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name=name, handler=handler, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    return server, sock_path


# ---------------------------------------------------------------------------
# The correlation id
# ---------------------------------------------------------------------------


def test_error_ref_is_short_hex_and_unique() -> None:
    refs = {new_error_ref() for _ in range(100)}
    assert len(refs) == 100
    for ref in refs:
        assert re.fullmatch(r"[0-9a-f]{16}", ref), ref


# ---------------------------------------------------------------------------
# Sanitized: a real DuckDB failure
# ---------------------------------------------------------------------------


def test_real_duckdb_catalog_error_never_reaches_the_client(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A query against a missing table must not send back the SQL or the schema."""
    db_path = tmp_path / "empty.duckdb"

    def handler(_params: dict[str, Any]) -> Any:
        with Database(db_path) as db:
            return db.query(
                "SELECT event_id, ts\nFROM events_enriched WHERE 1=1 LIMIT 10", []
            ).fetchall()

    # Prove the leak exists at the source, so the assertions below mean something.
    with Database(db_path) as db, pytest.raises(duckdb.Error) as raised:
        db.query("SELECT event_id\nFROM events_enriched", []).fetchall()
    assert "events_enriched" in repr(raised.value)

    caplog.set_level(logging.DEBUG)
    server, sock_path = _serve(tmp_path, "list_events", handler)
    try:
        resp = _call(sock_path, "list_events")
    finally:
        server.stop()

    message = resp["error"]["message"]
    assert resp["error"]["code"] == -32000
    for leak in ("events_enriched", "Catalog Error", "CatalogException", "LINE", "SELECT"):
        assert leak not in message, f"{leak!r} leaked to the client: {message!r}"

    # The client is told exactly one thing it can act on: an id to quote.
    match = _REF_RE.search(message)
    assert match is not None, message
    ref = match.group(1)

    # ... and that same id is on the daemon-side record that carries the traceback.
    matching = [r for r in caplog.records if ref in r.getMessage()]
    assert matching, f"error_ref {ref} never reached the daemon log"
    assert any(r.exc_info is not None for r in matching), "no traceback logged"
    logged = "\n".join(
        logging.Formatter().formatException(r.exc_info) for r in matching if r.exc_info
    )
    assert "events_enriched" in logged, "the daemon lost the detail it needs to debug"


def test_real_duckdb_io_error_does_not_leak_the_database_path(tmp_path: Path) -> None:
    """DuckDB's IO error quotes the file it could not open."""
    missing = tmp_path / "no-such-dir" / "inspectord.duckdb"

    def handler(_params: dict[str, Any]) -> Any:
        duckdb.connect(str(missing), read_only=True)
        return None

    server, sock_path = _serve(tmp_path, "list_events", handler)
    try:
        resp = _call(sock_path, "list_events")
    finally:
        server.stop()

    message = resp["error"]["message"]
    assert "inspectord.duckdb" not in message, message
    assert str(missing) not in message, message
    assert _REF_RE.search(message) is not None, message


def test_os_error_message_is_not_forwarded(tmp_path: Path) -> None:
    """An OSError's own text — path included — stays daemon-side."""
    secret = tmp_path / "evidence" / "totally-secret-blob.bin"

    def handler(_params: dict[str, Any]) -> Any:
        return secret.read_bytes().decode()

    server, sock_path = _serve(tmp_path, "download_evidence", handler)
    try:
        resp = _call(sock_path, "download_evidence")
    finally:
        server.stop()

    message = resp["error"]["message"]
    assert "totally-secret-blob" not in message, message
    assert "No such file" not in message, message


def test_two_failures_get_different_refs(tmp_path: Path) -> None:
    def handler(_params: dict[str, Any]) -> Any:
        raise RuntimeError("internal detail nobody outside should read")

    server, sock_path = _serve(tmp_path, "boom", handler)
    try:
        first = _call(sock_path, "boom")["error"]["message"]
        second = _call(sock_path, "boom")["error"]["message"]
    finally:
        server.stop()

    assert "internal detail" not in first
    assert "RuntimeError" not in first
    refs = {_REF_RE.search(m).group(1) for m in (first, second) if _REF_RE.search(m)}
    assert len(refs) == 2, (first, second)


# ---------------------------------------------------------------------------
# Passed through: errors written for the person on the other end
# ---------------------------------------------------------------------------


def test_hunt_syntax_error_reaches_the_client_intact(tmp_path: Path) -> None:
    """A real compile failure: the user must be able to read what is wrong."""

    def handler(params: dict[str, Any]) -> Any:
        return compile_hunt_query(str(params["expression"])).sql

    with pytest.raises(HuntSyntaxError) as raised:
        compile_hunt_query("")
    expected = str(raised.value)

    server, sock_path = _serve(tmp_path, "run_hunt_query", handler)
    try:
        resp = _call(sock_path, "run_hunt_query", {"expression": ""})
    finally:
        server.stop()

    assert resp["error"]["message"] == expected
    assert "error_ref" not in resp["error"]["message"]


def test_hunt_errors_are_client_facing() -> None:
    assert issubclass(HuntError, ClientFacingError)
    # Still a ValueError: existing `except ValueError` call sites keep working.
    assert issubclass(HuntError, ValueError)


def test_invalid_alert_transition_reaches_the_client(tmp_path: Path) -> None:
    """A message that escapes to the client *today* and must not regress."""
    assert issubclass(InvalidTransitionError, ClientFacingError)

    def handler(_params: dict[str, Any]) -> Any:
        raise InvalidTransitionError("cannot transition 'resolved' → 'acknowledged'")

    server, sock_path = _serve(tmp_path, "ack_alert", handler)
    try:
        resp = _call(sock_path, "ack_alert")
    finally:
        server.stop()

    assert resp["error"]["message"] == "cannot transition 'resolved' → 'acknowledged'"


def test_missing_parameter_names_the_parameter(tmp_path: Path) -> None:
    """The client's own parameter name is safe to echo — and is the whole answer."""
    assert issubclass(IpcParamError, ClientFacingError)

    def handler(_params: dict[str, Any]) -> Any:
        raise IpcParamError("case_id is required")

    server, sock_path = _serve(tmp_path, "get_case", handler)
    try:
        resp = _call(sock_path, "get_case")
    finally:
        server.stop()

    assert resp["error"]["message"] == "case_id is required"


# ---------------------------------------------------------------------------
# The real handlers that used to answer with a raw exception repr
# ---------------------------------------------------------------------------


def test_get_case_without_case_id_names_the_missing_parameter(tmp_path: Path) -> None:
    """Was `KeyError('case_id')` forwarded as a repr; now it is said on purpose."""
    with pytest.raises(IpcParamError) as raised:
        handle_get_case(params={}, db_path=tmp_path / "t.duckdb")
    assert str(raised.value) == "case_id is required"


def test_capture_baseline_rejects_an_unknown_kind(tmp_path: Path) -> None:
    with pytest.raises(IpcParamError) as raised:
        handle_capture_baseline(params={"kind": "not-a-kind"}, db_path=tmp_path / "t.duckdb")
    assert "not-a-kind" in str(raised.value)
    assert "service" in str(raised.value), "say what the caller could have passed"


def test_apply_dependency_plan_without_plan_id(tmp_path: Path) -> None:
    with pytest.raises(IpcParamError) as raised:
        handle_apply_dependency_plan(
            params={},
            manifests={},
            backend=cast(Any, None),
            runner=cast(Any, None),
            db_path=tmp_path / "t.duckdb",
        )
    assert str(raised.value) == "plan_id is required"
