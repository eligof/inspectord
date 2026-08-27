"""Contract-side command channel tests (worker-command-channel design §3-§4, §8).

The channel is opt-in: a worker that does not override ``handle_command`` must
be byte-identical in behavior — no reader thread, no stdin reads. Workers that
do opt in get a daemon reader thread that shares the config read's buffered
stream (the buffer-steal case), a 64 KiB line cap with drain, bounded rejected
emission, base-class-only ``command_result`` events, and a wake event so an
accepted command acts on the next loop iteration instead of a full interval
later.
"""

from __future__ import annotations

import io
import json
import os
import threading
import time
from typing import IO, Any

from inspectord.schemas.event import Event
from inspectord.workers.contract import (
    COMMAND_LINE_MAX_BYTES,
    REJECTED_EMIT_MAX_PER_WINDOW,
    Worker,
    read_config_from_stdin,
)

_DEADLINE_S = 5.0


def _wait_for(predicate: Any, timeout: float = _DEADLINE_S) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return False


class _PlainWorker(Worker):
    """No handle_command override: the channel must not exist for it."""

    def step(self) -> None:
        pass

    def step_interval_s(self) -> float:
        return 0.01


class _CommandWorker(Worker):
    def __init__(self, *, interval_s: float = 0.01, **kwargs: Any) -> None:
        super().__init__(name=kwargs.pop("name", "cmdworker"), **kwargs)
        self._interval = interval_s
        self.handled: list[tuple[str, dict[str, Any]]] = []
        self.steps = 0

    def step(self) -> None:
        self.steps += 1

    def step_interval_s(self) -> float:
        return self._interval

    def handle_command(self, command: str, args: dict[str, Any]) -> dict[str, Any]:
        self.handled.append((command, args))
        if command == "boom":
            raise RuntimeError("kaboom")
        if command == "bad_result":
            return "not a dict"  # type: ignore[return-value]
        if command == "weird_detail":
            return {"status": "accepted", "detail": object()}
        if command == "reject_me":
            return {"status": "rejected", "detail": "no"}
        return {"status": "accepted", "detail": "ok"}


class _RecordingStdin:
    """A stdin stub that fails the no-read invariant loudly."""

    def __init__(self) -> None:
        self.reads = 0

    def readline(self, *_args: Any) -> bytes:
        self.reads += 1
        return b""

    def read(self, *_args: Any) -> bytes:
        self.reads += 1
        return b""


def _events(stdout: io.BytesIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]


def _results(stdout: io.BytesIO) -> list[dict[str, Any]]:
    return [e for e in _events(stdout) if e.get("action") == "command_result"]


def _command_line(
    command: str, *, args: dict[str, Any] | None = None, request_id: str | None = "req-1"
) -> bytes:
    payload: dict[str, Any] = {"command": command, "args": args or {}}
    if request_id is not None:
        payload["request_id"] = request_id
    return json.dumps(payload).encode("utf-8") + b"\n"


class _Rig:
    """A command worker wired to a real pipe, running on a background thread."""

    def __init__(self, worker: Worker, write_fd: int) -> None:
        self.worker = worker
        self._write_fd: int | None = write_fd
        self.thread = threading.Thread(target=worker.run, daemon=True)

    def send(self, data: bytes) -> None:
        assert self._write_fd is not None
        os.write(self._write_fd, data)

    def close_stdin(self) -> None:
        if self._write_fd is not None:
            os.close(self._write_fd)
            self._write_fd = None

    def stop(self) -> None:
        self.worker.request_stop()
        self.thread.join(timeout=_DEADLINE_S)
        self.close_stdin()


def _rig(**worker_kwargs: Any) -> tuple[_Rig, io.BytesIO]:
    rfd, wfd = os.pipe()
    stdin: IO[bytes] = os.fdopen(rfd, "rb")
    stdout = io.BytesIO()
    worker = _CommandWorker(stdin=stdin, stdout=stdout, stderr=io.BytesIO(), **worker_kwargs)
    rig = _Rig(worker, wfd)
    rig.thread.start()
    return rig, stdout


def _reader_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.endswith("-commands") and t.is_alive()]


# --------------------------------------------------------------------------
# opt-in: no override, no thread, no reads
# --------------------------------------------------------------------------


def test_no_override_starts_no_reader_and_never_reads_stdin() -> None:
    stdin = _RecordingStdin()
    w = _PlainWorker(name="plain", stdin=stdin, stdout=io.BytesIO(), stderr=io.BytesIO())
    before = len(_reader_threads())
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    assert _wait_for(lambda: w._events_processed >= 0)  # let run() spin up
    time.sleep(0.05)
    assert len(_reader_threads()) == before, "a no-override worker started a reader thread"
    w.request_stop()
    t.join(timeout=_DEADLINE_S)
    assert stdin.reads == 0, "a no-override worker read stdin"


# --------------------------------------------------------------------------
# buffer-steal: config read and reader thread share one buffered stream
# --------------------------------------------------------------------------


def test_early_command_written_before_config_read_is_still_delivered() -> None:
    rfd, wfd = os.pipe()
    stream: IO[bytes] = os.fdopen(rfd, "rb")
    # Both lines are in the pipe BEFORE the config read: a config read through a
    # different (text) wrapper would strand the command line in its buffer.
    os.write(wfd, json.dumps({"poll_s": 1.0}).encode("utf-8") + b"\n")
    os.write(wfd, _command_line("go"))

    config = read_config_from_stdin(stream)
    assert config == {"poll_s": 1.0}

    stdout = io.BytesIO()
    worker = _CommandWorker(config=config, stdin=stream, stdout=stdout, stderr=io.BytesIO())
    rig = _Rig(worker, wfd)
    rig.thread.start()
    try:
        assert _wait_for(lambda: worker.handled == [("go", {})]), (
            "the early command was stranded in a decode buffer and lost"
        )
        assert _wait_for(lambda: len(_results(stdout)) == 1)
        result = _results(stdout)[0]
        assert result["raw"] == {"request_id": "req-1", "status": "accepted", "detail": "ok"}
    finally:
        rig.stop()


def test_read_config_from_stdin_returns_empty_dict_on_eof() -> None:
    rfd, wfd = os.pipe()
    os.close(wfd)
    with os.fdopen(rfd, "rb") as stream:
        assert read_config_from_stdin(stream) == {}


# --------------------------------------------------------------------------
# reader lifecycle
# --------------------------------------------------------------------------


def test_reader_thread_exits_on_eof_without_spinning() -> None:
    rig, _stdout = _rig()
    try:
        assert _wait_for(lambda: len(_reader_threads()) >= 1)
        reader = _reader_threads()[0]
        rig.close_stdin()
        reader.join(timeout=_DEADLINE_S)
        assert not reader.is_alive(), "the reader thread did not exit at EOF"
        # The worker itself keeps running: EOF ends the channel, not the worker.
        steps = rig.worker.steps
        assert _wait_for(lambda: rig.worker.steps > steps)
    finally:
        rig.stop()


# --------------------------------------------------------------------------
# robustness: line cap, malformed lines, handler failures
# --------------------------------------------------------------------------


def test_overlong_line_is_drained_dropped_and_never_answered() -> None:
    rig, stdout = _rig()
    try:
        big = json.dumps(
            {
                "command": "go",
                "args": {"x": "a" * (COMMAND_LINE_MAX_BYTES + 1024)},
                "request_id": "big-1",
            }
        ).encode("utf-8")
        assert len(big) > COMMAND_LINE_MAX_BYTES
        rig.send(big + b"\n")
        rig.send(_command_line("go", request_id="after-big"))
        assert _wait_for(lambda: len(_results(stdout)) == 1)
        [result] = _results(stdout)
        assert result["raw"]["request_id"] == "after-big", (
            "the over-long line was parsed or answered instead of dropped"
        )
        assert rig.worker.handled == [("go", {})]
    finally:
        rig.stop()


def test_malformed_line_with_recoverable_request_id_is_rejected() -> None:
    rig, stdout = _rig()
    try:
        rig.send(b'{"request_id": "mal-1", "command": 42}\n')
        assert _wait_for(lambda: len(_results(stdout)) == 1)
        [result] = _results(stdout)
        assert result["raw"]["request_id"] == "mal-1"
        assert result["raw"]["status"] == "rejected"
        assert rig.worker.handled == []
    finally:
        rig.stop()


def test_malformed_line_without_request_id_is_dropped_and_the_reader_survives() -> None:
    rig, stdout = _rig()
    try:
        rig.send(b"{not json at all\n")
        rig.send(b'["a", "list"]\n')
        rig.send(b'{"command": "go"}\n')  # valid shape but no request_id: unanswerable
        rig.send(_command_line("go", request_id="alive-1"))
        assert _wait_for(lambda: len(_results(stdout)) == 1)
        [result] = _results(stdout)
        assert result["raw"]["request_id"] == "alive-1"
    finally:
        rig.stop()


def test_invalid_command_name_and_oversized_args_are_rejected() -> None:
    rig, stdout = _rig()
    try:
        rig.send(_command_line("Not-Valid!", request_id="name-1"))
        rig.send(_command_line("go", args={"pad": "x" * 5000}, request_id="args-1"))
        rig.send(b'{"command": "go", "args": "not an object", "request_id": "args-2"}\n')
        assert _wait_for(lambda: len(_results(stdout)) == 3)
        by_id = {r["raw"]["request_id"]: r["raw"] for r in _results(stdout)}
        assert set(by_id) == {"name-1", "args-1", "args-2"}
        assert all(r["status"] == "rejected" for r in by_id.values())
        assert rig.worker.handled == [], "an invalid command still reached the handler"
    finally:
        rig.stop()


def test_handler_exception_becomes_rejected_and_the_thread_survives() -> None:
    rig, stdout = _rig()
    try:
        rig.send(_command_line("boom", request_id="boom-1"))
        rig.send(_command_line("go", request_id="after-boom"))
        assert _wait_for(lambda: len(_results(stdout)) == 2)
        by_id = {r["raw"]["request_id"]: r["raw"] for r in _results(stdout)}
        assert by_id["boom-1"]["status"] == "rejected"
        assert by_id["after-boom"]["status"] == "accepted"
    finally:
        rig.stop()


def test_garbage_handler_results_still_produce_schema_valid_events() -> None:
    """A consumer returning garbage must never yield a schema-invalid event.

    The supervisor drops invalid events, which would turn an accepted command
    into a silent timeout — so the base class coerces instead.
    """
    rig, stdout = _rig()
    try:
        rig.send(_command_line("bad_result", request_id="bad-1"))
        rig.send(_command_line("weird_detail", request_id="weird-1"))
        assert _wait_for(lambda: len(_results(stdout)) == 2)
        for event in _results(stdout):
            Event.model_validate(event)  # must parse as a real Event
            assert event["raw"]["status"] in ("accepted", "rejected")
            assert isinstance(event["raw"]["detail"], str)
        by_id = {r["raw"]["request_id"]: r["raw"] for r in _results(stdout)}
        assert by_id["bad-1"]["status"] == "rejected"
        assert by_id["weird-1"]["status"] == "accepted"
    finally:
        rig.stop()


def test_rejected_emission_is_bounded() -> None:
    rig, stdout = _rig()
    try:
        total = REJECTED_EMIT_MAX_PER_WINDOW + 10
        for i in range(total):
            rig.send(_command_line("reject_me", request_id=f"rej-{i}"))
        assert _wait_for(lambda: len(rig.worker.handled) == total)
        # Give any surplus emission a moment to (wrongly) appear.
        time.sleep(0.1)
        results = _results(stdout)
        assert len(results) == REJECTED_EMIT_MAX_PER_WINDOW, (
            f"{total} rejections emitted {len(results)} events; the flood bound is broken"
        )
    finally:
        rig.stop()


# --------------------------------------------------------------------------
# wake event
# --------------------------------------------------------------------------


def test_accepted_command_wakes_the_step_loop() -> None:
    rig, _stdout = _rig(interval_s=30.0)
    try:
        assert _wait_for(lambda: rig.worker.steps >= 1)
        steps = rig.worker.steps
        rig.send(_command_line("go"))
        assert _wait_for(lambda: rig.worker.steps > steps, timeout=2.0), (
            "an accepted command waited out the full step interval"
        )
    finally:
        rig.stop()


def test_rejected_command_does_not_wake_the_step_loop() -> None:
    rig, stdout = _rig(interval_s=30.0)
    try:
        assert _wait_for(lambda: rig.worker.steps >= 1)
        steps = rig.worker.steps
        rig.send(_command_line("reject_me", request_id="rej-wake"))
        assert _wait_for(lambda: len(_results(stdout)) == 1)
        time.sleep(0.2)
        assert rig.worker.steps == steps
    finally:
        rig.stop()


# --------------------------------------------------------------------------
# cross-thread stdout: one write per complete line
# --------------------------------------------------------------------------


def test_concurrent_step_and_command_result_emission_every_line_parses() -> None:
    class _Chatty(_CommandWorker):
        def step(self) -> None:
            super().step()
            for i in range(5):
                self.emit_event(
                    {
                        "schema_version": "1.0.0",
                        "ts": "2026-08-27T00:00:00Z",
                        "event_id": f"tick-{self.steps}-{i}",
                        "kind": "event",
                        "category": ["host"],
                        "type": ["info"],
                        "action": "tick",
                        "severity": "info",
                        "module": "cmdworker",
                    }
                )

    rfd, wfd = os.pipe()
    stdin: IO[bytes] = os.fdopen(rfd, "rb")
    stdout = io.BytesIO()
    worker = _Chatty(interval_s=0.001, stdin=stdin, stdout=stdout, stderr=io.BytesIO())
    rig = _Rig(worker, wfd)
    rig.thread.start()
    try:
        total = 100
        for i in range(total):
            rig.send(_command_line("go", request_id=f"stress-{i}"))
        assert _wait_for(lambda: len(rig.worker.handled) == total, timeout=10.0)
        assert _wait_for(
            lambda: sum(1 for line in stdout.getvalue().splitlines() if line.strip()) >= total,
            timeout=10.0,
        )
    finally:
        rig.stop()

    lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
    parsed = [json.loads(line) for line in lines]  # raises on any torn line
    results = [e for e in parsed if e.get("action") == "command_result"]
    assert len(results) == 100
