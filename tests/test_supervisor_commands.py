"""Supervisor command-channel tests (worker-command-channel design §5, §8).

The rig mirrors test_supervisor_restart.py: throwaway worker modules written
into tmp_path and reached via PYTHONPATH, driving a real Supervisor with real
child processes. Correlation is per-incarnation: the pending map lives on the
_WorkerProc, fulfillment identity is the pipe, and death/stop/timeout each
clean up their own entries.
"""

from __future__ import annotations

import io
import json
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from inspectord.config import WorkerSpec, dev_config
from inspectord.supervisor import (
    MAX_INFLIGHT_COMMANDS_PER_WORKER,
    Supervisor,
    _WorkerProc,
)

# Reads config, then answers every command with an accepted command_result.
_ECHO_SRC = """
import json
import sys
import uuid

sys.stdin.buffer.readline()
for line in sys.stdin.buffer:
    req = json.loads(line)
    ev = {
        "schema_version": "1.0.0",
        "ts": "2026-08-27T00:00:00Z",
        "event_id": uuid.uuid4().hex,
        "kind": "state",
        "category": ["process"],
        "type": ["info"],
        "action": "command_result",
        "severity": "info",
        "module": "stub",
        "raw": {
            "request_id": req["request_id"],
            "status": "accepted",
            "detail": "ok:" + req["command"],
        },
    }
    sys.stdout.buffer.write((json.dumps(ev) + "\\n").encode("utf-8"))
    sys.stdout.buffer.flush()
"""

# Reads config, swallows every command, never answers.
_SILENT_SRC = """
import sys

sys.stdin.buffer.readline()
for line in sys.stdin.buffer:
    pass
"""

# Reads config, then one command, then dies without answering.
_DIES_ON_COMMAND_SRC = """
import sys

sys.stdin.buffer.readline()
sys.stdin.buffer.readline()
sys.exit(3)
"""

# Reads the config line, then exits immediately (stale-incarnation rig).
_DIES_SRC = """
import sys

sys.stdin.readline()
sys.exit(3)
"""


def _install_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, src: str) -> str:
    (tmp_path / f"{name}.py").write_text(src, encoding="utf-8")
    existing = os.environ.get("PYTHONPATH", "")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path) + (os.pathsep + existing if existing else ""))
    return name


def _supervisor(tmp_path: Path, module: str, *, worker: str = "stub", **kwargs: Any) -> Supervisor:
    cfg = dev_config(base=tmp_path)
    cfg.workers = [WorkerSpec(name=worker, module=module, config={})]
    params: dict[str, Any] = {
        "poll_interval_s": 0.02,
        "restart_base_delay_s": 0.01,
        "restart_max_delay_s": 0.05,
        "restart_healthy_after_s": 3600.0,
        "restart_max_attempts": 8,
    }
    params.update(kwargs)
    return Supervisor(cfg, **params)


def _wait_for(predicate: Any, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def _wp(sup: Supervisor, name: str) -> _WorkerProc:
    with sup._procs_lock:  # type: ignore[attr-defined]
        return next(wp for wp in sup._procs if wp.spec.name == name)  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------


def test_send_worker_command_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_cmd_echo", _ECHO_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    try:
        seen: list[Any] = []
        sup.attach_listener(seen.append)
        result = sup.send_worker_command("stub", "rescan", {}, timeout_s=10.0)
        assert result == {"status": "accepted", "detail": "ok:rescan"}
        # The command_result event is ALSO dispatched normally (history).
        assert _wait_for(lambda: any(getattr(e, "action", "") == "command_result" for e in seen)), (
            "the command_result event never reached the ordinary event path"
        )
        # The pending entry is gone whatever the outcome.
        assert _wp(sup, "stub").pending == {}
    finally:
        sup.stop(timeout=5.0)


def test_send_to_unknown_worker_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_cmd_echo2", _ECHO_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    try:
        result = sup.send_worker_command("nope", "rescan", {}, timeout_s=1.0)
        assert result["status"] == "worker_unavailable"
    finally:
        sup.stop(timeout=5.0)


# --------------------------------------------------------------------------
# timeout: finally-cleanup, cap never wedges
# --------------------------------------------------------------------------


def test_timeout_removes_pending_so_the_cap_never_fills(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_cmd_silent", _SILENT_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    try:
        for _ in range(MAX_INFLIGHT_COMMANDS_PER_WORKER):
            result = sup.send_worker_command("stub", "noop", {}, timeout_s=0.02)
            assert result["status"] == "timeout"
        # The 33rd command after 32 timeouts must not be refused as busy.
        result = sup.send_worker_command("stub", "noop", {}, timeout_s=0.02)
        assert result["status"] == "timeout"
        assert _wp(sup, "stub").pending == {}
    finally:
        sup.stop(timeout=5.0)


def test_inflight_cap_refuses_the_33rd_concurrent_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_cmd_silent2", _SILENT_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    try:
        results: list[dict[str, Any]] = []
        threads = [
            threading.Thread(
                target=lambda: results.append(
                    sup.send_worker_command("stub", "noop", {}, timeout_s=3.0)
                ),
                daemon=True,
            )
            for _ in range(MAX_INFLIGHT_COMMANDS_PER_WORKER)
        ]
        for t in threads:
            t.start()
        assert _wait_for(
            lambda: len(_wp(sup, "stub").pending) == MAX_INFLIGHT_COMMANDS_PER_WORKER
        ), "the 32 concurrent commands never registered"
        overflow = sup.send_worker_command("stub", "noop", {}, timeout_s=0.1)
        assert overflow["status"] == "worker_unavailable"
        for t in threads:
            t.join(timeout=10.0)
        assert len(results) == MAX_INFLIGHT_COMMANDS_PER_WORKER
        assert all(r["status"] == "timeout" for r in results)
    finally:
        sup.stop(timeout=5.0)


# --------------------------------------------------------------------------
# death and respawn
# --------------------------------------------------------------------------


def test_worker_death_fulfills_pending_with_worker_died(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_cmd_dies_on_cmd", _DIES_ON_COMMAND_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    try:
        started = time.monotonic()
        result = sup.send_worker_command("stub", "noop", {}, timeout_s=30.0)
        assert result == {"status": "worker_died"}
        # Fulfilled by the monitor (~poll cadence), not by the send timeout.
        assert time.monotonic() - started < 10.0
    finally:
        sup.stop(timeout=5.0)


def test_respawned_incarnation_starts_with_an_empty_pending_map(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_cmd_dies_on_cmd2", _DIES_ON_COMMAND_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    try:
        old = _wp(sup, "stub")
        result = sup.send_worker_command("stub", "noop", {}, timeout_s=30.0)
        assert result == {"status": "worker_died"}
        assert _wait_for(lambda: _wp(sup, "stub") is not old), "the worker was never respawned"
        assert _wp(sup, "stub").pending == {}
    finally:
        sup.stop(timeout=5.0)


def test_stale_incarnation_send_during_backoff_window_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_cmd_dies", _DIES_SRC)
    # A long restart delay keeps the reaped incarnation in _procs for a while.
    sup = _supervisor(tmp_path, mod, restart_base_delay_s=30.0, restart_max_delay_s=30.0)
    sup.start()
    try:
        assert _wait_for(lambda: _wp(sup, "stub").died_reported), "the death was never noticed"
        result = sup.send_worker_command("stub", "noop", {}, timeout_s=1.0)
        assert result["status"] == "worker_unavailable"
        assert _wp(sup, "stub").pending == {}
    finally:
        sup.stop(timeout=5.0)


# --------------------------------------------------------------------------
# shutdown
# --------------------------------------------------------------------------


def test_stop_fulfills_inflight_commands_within_the_stop_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_cmd_silent3", _SILENT_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    stopped = False
    try:
        results: list[dict[str, Any]] = []
        sender = threading.Thread(
            target=lambda: results.append(sup.send_worker_command("stub", "noop", timeout_s=30.0)),
            daemon=True,
        )
        sender.start()
        assert _wait_for(lambda: len(_wp(sup, "stub").pending) == 1)
        started = time.monotonic()
        sup.stop(timeout=5.0)
        stopped = True
        assert time.monotonic() - started < 6.0, "stop() blew its budget on an in-flight command"
        sender.join(timeout=5.0)
        assert results == [{"status": "worker_unavailable", "detail": "shutting_down"}]
        # And a send after stop fast-fails without touching any pipe.
        late = sup.send_worker_command("stub", "noop", timeout_s=30.0)
        assert late == {"status": "worker_unavailable", "detail": "shutting_down"}
    finally:
        if not stopped:
            sup.stop(timeout=5.0)


# --------------------------------------------------------------------------
# lock discipline
# --------------------------------------------------------------------------


def test_response_wait_holds_no_supervisor_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slow command must not delay a monitor tick (or any other caller)."""
    mod = _install_worker(tmp_path, monkeypatch, "sup_cmd_silent4", _SILENT_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    try:
        sender = threading.Thread(
            target=lambda: sup.send_worker_command("stub", "noop", timeout_s=3.0),
            daemon=True,
        )
        sender.start()
        wp = _wp(sup, "stub")
        assert _wait_for(lambda: len(wp.pending) == 1)
        # While the sender waits: both locks are free, and a monitor tick runs.
        assert sup._procs_lock.acquire(timeout=0.5)  # type: ignore[attr-defined]
        sup._procs_lock.release()  # type: ignore[attr-defined]
        assert wp.stdin_lock.acquire(timeout=0.5)
        wp.stdin_lock.release()
        sup._monitor_tick()  # type: ignore[attr-defined]  # must not block or raise
        sender.join(timeout=10.0)
    finally:
        sup.stop(timeout=5.0)


# --------------------------------------------------------------------------
# fulfillment identity is the pipe
# --------------------------------------------------------------------------


def test_a_worker_cannot_fulfill_another_workers_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _install_worker(tmp_path, monkeypatch, "sup_cmd_silent5", _SILENT_SRC)
    sup = _supervisor(tmp_path, mod)
    sup.start()
    try:
        results: list[dict[str, Any]] = []
        sender = threading.Thread(
            target=lambda: results.append(sup.send_worker_command("stub", "noop", timeout_s=1.5)),
            daemon=True,
        )
        sender.start()
        wp = _wp(sup, "stub")
        assert _wait_for(lambda: len(wp.pending) == 1)
        stolen_request_id = next(iter(wp.pending))

        # A DIFFERENT worker emits a command_result quoting stub's request_id.
        hostile_event = {
            "schema_version": "1.0.0",
            "ts": "2026-08-27T00:00:00Z",
            "event_id": "hostile-1",
            "kind": "state",
            "category": ["process"],
            "type": ["info"],
            "action": "command_result",
            "severity": "info",
            "module": "hostile",
            "raw": {"request_id": stolen_request_id, "status": "accepted", "detail": "pwn"},
        }
        hostile_wp = SimpleNamespace(
            spec=SimpleNamespace(name="hostile"),
            proc=SimpleNamespace(
                stdout=io.BytesIO(json.dumps(hostile_event).encode("utf-8") + b"\n")
            ),
            pending={},
            pending_lock=threading.Lock(),
        )
        sup._read_stdout(hostile_wp)  # type: ignore[attr-defined]

        sender.join(timeout=10.0)
        assert results == [{"status": "timeout"}], (
            "a command_result from another worker's pipe fulfilled the request"
        )
    finally:
        sup.stop(timeout=5.0)
