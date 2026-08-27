"""Tests for the run_worker_command IPC method (design §6, §8).

Every attempt is audited — the rejections most of all, since rejected attempts
are the probe signature of a compromised session. The allowlist is enforced
before anything touches a pipe, the §3 caps apply daemon-side, and a coarse
12/min sliding window bounds attacker-drivable growth of the append-only
audit_log (excess attempts are a client error, audited once per window).
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any

import pytest

from inspectord.__main__ import _ipc_methods
from inspectord.audit.log import reset_for_tests
from inspectord.config import dev_config
from inspectord.ipc_commands import (
    ALLOWED_WORKER_COMMANDS,
    RATE_LIMIT_PER_MIN,
    WorkerCommandError,
    _SlidingWindowLimiter,
    handle_run_worker_command,
    make_run_worker_command_handler,
)
from inspectord.ipc_errors import ClientFacingError
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations
from inspectord.workers.contract import COMMAND_ARGS_MAX_BYTES


def setup_function(_fn) -> None:
    reset_for_tests()


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


def _audit_rows(db_path: Path) -> list[dict[str, Any]]:
    with Database(db_path) as db:
        rows = db.query(
            "SELECT action, target, details_json FROM audit_log ORDER BY seq ASC"
        ).fetchall()
    return [{"action": r[0], "target": r[1], "details": json.loads(r[2])} for r in rows]


class _FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class _FakeSend:
    def __init__(self, result: dict[str, Any] | None = None) -> None:
        self.result = result if result is not None else {"status": "accepted", "detail": "ok"}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def __call__(self, worker: str, command: str, args: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((worker, command, args))
        return dict(self.result)


def _handle(
    db_path: Path,
    send: _FakeSend,
    params: dict[str, Any],
    limiter: _SlidingWindowLimiter | None = None,
) -> dict[str, Any]:
    return handle_run_worker_command(
        params=params,
        send=send,
        db_path=db_path,
        limiter=limiter if limiter is not None else _SlidingWindowLimiter(),
    )


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------


def test_allowlisted_command_is_sent_and_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    send = _FakeSend()
    out = _handle(db_path, send, {"worker": "vuln_scanner", "command": "rescan"})
    assert out["ok"] is True
    assert out["status"] == "accepted"
    assert out["detail"] == "ok"
    assert send.calls == [("vuln_scanner", "rescan", {})]

    rows = _audit_rows(db_path)
    assert len(rows) == 1
    assert rows[0]["action"] == "worker_command_sent"
    assert rows[0]["target"] == "worker:vuln_scanner"
    assert rows[0]["details"]["command"] == "rescan"
    assert rows[0]["details"]["status"] == "accepted"


def test_args_are_passed_through_and_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    send = _FakeSend({"status": "rejected", "detail": "unknown_scanner"})
    out = _handle(
        db_path,
        send,
        {"worker": "scanner_runner", "command": "run_scanner", "args": {"name": "aide"}},
    )
    assert out["ok"] is False
    assert out["status"] == "rejected"
    assert out["detail"] == "unknown_scanner"
    assert send.calls == [("scanner_runner", "run_scanner", {"name": "aide"})]
    [row] = _audit_rows(db_path)
    assert row["details"]["args"] == {"name": "aide"}
    assert row["details"]["status"] == "rejected"
    assert row["details"]["detail"] == "unknown_scanner"


def test_transport_outcomes_are_reported_and_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    for status in ("timeout", "worker_died", "worker_unavailable"):
        send = _FakeSend({"status": status})
        out = _handle(db_path, send, {"worker": "vuln_scanner", "command": "rescan"})
        assert out["ok"] is False
        assert out["status"] == status
    assert [r["details"]["status"] for r in _audit_rows(db_path)] == [
        "timeout",
        "worker_died",
        "worker_unavailable",
    ]


# --------------------------------------------------------------------------
# allowlist: enforced first, rejections audited with reasons
# --------------------------------------------------------------------------


def test_non_allowlisted_pairs_are_rejected_before_any_send(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    send = _FakeSend()
    attempts = [
        {"worker": "vuln_scanner", "command": "run_scanner"},
        {"worker": "scanner_runner", "command": "rescan"},
        {"worker": "evil", "command": "rescan"},
        {"worker": "vuln_scanner", "command": "rm -rf /"},
        {},
    ]
    for params in attempts:
        with pytest.raises(ClientFacingError):
            _handle(db_path, send, params)
    assert send.calls == [], "a non-allowlisted command still touched the pipe"
    rows = _audit_rows(db_path)
    assert len(rows) == len(attempts), "an allowlist rejection went unaudited"
    assert all(r["details"]["status"] == "rejected" for r in rows)
    assert all(r["details"]["reason"] == "not_allowlisted" for r in rows)


def test_allowlist_is_exactly_the_two_v1_pairs() -> None:
    expected = frozenset({("vuln_scanner", "rescan"), ("scanner_runner", "run_scanner")})
    assert expected == ALLOWED_WORKER_COMMANDS


# --------------------------------------------------------------------------
# caps: rejected + audited with a truncated repr, never the full payload
# --------------------------------------------------------------------------


def test_oversized_args_are_rejected_and_audited_truncated(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    send = _FakeSend()
    huge = {"name": "x" * (COMMAND_ARGS_MAX_BYTES + 100)}
    with pytest.raises(ClientFacingError):
        _handle(db_path, send, {"worker": "scanner_runner", "command": "run_scanner", "args": huge})
    assert send.calls == []
    [row] = _audit_rows(db_path)
    assert row["details"]["reason"] == "args_too_large"
    assert isinstance(row["details"]["args"], str)
    assert len(row["details"]["args"]) < 300, "the cap-reject audited the full oversized payload"


def test_non_object_args_are_rejected_and_audited(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    send = _FakeSend()
    with pytest.raises(ClientFacingError):
        _handle(
            db_path,
            send,
            {"worker": "vuln_scanner", "command": "rescan", "args": ["not", "a", "dict"]},
        )
    assert send.calls == []
    [row] = _audit_rows(db_path)
    assert row["details"]["reason"] == "args_not_object"
    assert isinstance(row["details"]["args"], str)


# --------------------------------------------------------------------------
# rate limit: 12/min sliding window, excess audited once per window
# --------------------------------------------------------------------------


def test_rate_limit_rejects_excess_and_audits_once_per_window(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    send = _FakeSend()
    clock = _FakeClock()
    limiter = _SlidingWindowLimiter(monotonic=clock)

    for _ in range(RATE_LIMIT_PER_MIN):
        out = _handle(db_path, send, {"worker": "vuln_scanner", "command": "rescan"}, limiter)
        assert out["ok"] is True
    # 13th and onward: client error; ONE audit row for the whole window.
    for _ in range(5):
        with pytest.raises(WorkerCommandError):
            _handle(db_path, send, {"worker": "vuln_scanner", "command": "rescan"}, limiter)
    rows = _audit_rows(db_path)
    limited = [r for r in rows if r["details"].get("reason") == "rate_limited"]
    assert len(limited) == 1, "the rate-limit rejection must be audited once per window"
    assert len(rows) == RATE_LIMIT_PER_MIN + 1

    # The window slides: a minute later attempts flow again...
    clock.t += 61.0
    out = _handle(db_path, send, {"worker": "vuln_scanner", "command": "rescan"}, limiter)
    assert out["ok"] is True
    # ...and a NEW excess in a NEW window earns its own single audit row.
    for _ in range(RATE_LIMIT_PER_MIN + 3):
        with contextlib.suppress(WorkerCommandError):
            _handle(db_path, send, {"worker": "vuln_scanner", "command": "rescan"}, limiter)
    limited = [r for r in _audit_rows(db_path) if r["details"].get("reason") == "rate_limited"]
    assert len(limited) == 2


def test_rate_limited_attempts_never_reach_the_pipe(tmp_path: Path) -> None:
    db_path = _fresh(tmp_path)
    send = _FakeSend()
    clock = _FakeClock()
    limiter = _SlidingWindowLimiter(monotonic=clock)
    for _ in range(RATE_LIMIT_PER_MIN):
        _handle(db_path, send, {"worker": "vuln_scanner", "command": "rescan"}, limiter)
    assert len(send.calls) == RATE_LIMIT_PER_MIN
    with pytest.raises(WorkerCommandError):
        _handle(db_path, send, {"worker": "vuln_scanner", "command": "rescan"}, limiter)
    assert len(send.calls) == RATE_LIMIT_PER_MIN


# --------------------------------------------------------------------------
# registration
# --------------------------------------------------------------------------


def test_run_worker_command_is_registered_and_mutates(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    methods = {m.name: m for m in _ipc_methods(None, cfg)}  # type: ignore[arg-type]
    assert "run_worker_command" in methods
    assert methods["run_worker_command"].mutates is True


def test_factory_binds_the_supervisor_lazily(tmp_path: Path) -> None:
    """Registration happens with the Supervisor reference, calls resolve late."""
    db_path = _fresh(tmp_path)

    class _Sup:
        def __init__(self) -> None:
            self.calls: list[Any] = []

        def send_worker_command(
            self, worker: str, command: str, args: dict[str, Any]
        ) -> dict[str, Any]:
            self.calls.append((worker, command, args))
            return {"status": "accepted", "detail": "ok"}

    sup = _Sup()
    handler = make_run_worker_command_handler(supervisor=sup, db_path=db_path)
    out = handler({"worker": "vuln_scanner", "command": "rescan"})
    assert out["ok"] is True
    assert sup.calls == [("vuln_scanner", "rescan", {})]
