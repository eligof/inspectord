"""The threaded, single-flight scan runner (design §4.4, §4.5).

A scan is a third worker shape: one expensive, fallible, minutes-long job that
must not block the worker's liveness and **must not survive the worker's
death**. So:

* the scan runs in a worker-owned daemon thread and ``step()`` is a cheap tick
  that either starts a due scan or polls the in-flight one (decision 2);
* the subprocess is spawned with ``start_new_session=True`` and every kill path
  signals the whole **process group** (decision 3) — otherwise a SIGKILLed
  worker orphans a running ``aide --check``;
* at most one scan runs at a time; a scanner that is due while a run is in
  flight emits ``scan_skipped`` rather than nothing;
* a failed scan is always reported (decision 11) — a scan that silently never
  runs looks exactly like a clean machine;
* the scanner's output is captured under a byte ceiling, and the surplus is
  *drained and discarded* rather than left in the pipe — a first ``aide --check``
  against an uninitialized database can print hundreds of megabytes.

Threading discipline: only the job thread and the two reader threads it owns
ever touch the subprocess pipes, and only the job thread ever ``wait()``s on the
process. Other threads only *send signals* and ``join()`` the job thread. That
is what keeps ``teardown()`` from racing the scan.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import socket
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from inspectord.ids import uuid7
from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event
from inspectord.workers.contract import Worker
from inspectord.workers.scanner_runner.scanners import default_adapters
from inspectord.workers.scanner_runner.scanners.base import (
    Finding,
    ScannerAdapter,
    ScanOutcome,
    sanitize_text,
)

_DEFAULT_HOSTNAME = socket.gethostname()

#: The worker's own tick — how often it checks whether anything is due.
DEFAULT_TICK_S = 60.0
#: Keeps a heavy scan off the boot path (parent spec §27.4).
DEFAULT_STARTUP_DELAY_S = 120.0
#: Decision 12 — a first-run AIDE diff can produce thousands of entries.
DEFAULT_MAX_FINDINGS_PER_RUN = 500
#: The memory sibling of the finding cap, applied to EACH of stdout and stderr.
#:
#: The finding cap bounds the *events* a run emits; it does nothing about the
#: bytes the scanner wrote, which are all buffered before the first finding is
#: parsed. 8 MiB is far more than any healthy scanner prints and far less than a
#: first-run AIDE diff.
DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
#: How much scanner output a FAILED run carries on its ``scan_completed`` event.
#:
#: `reason="scanner_error", exit_code=1` tells an operator that a scan broke but
#: not what broke: one uncompilable `.yar` file fails the whole yara run, and
#: without the scanner's own message there is no way to tell which rule file it
#: was. A few hundred characters is one such message; anything longer is either
#: a per-file error list (unbounded when sweeping a tree) or the finding set
#: itself, which belongs in `scan_finding` events. Successful runs carry none.
MAX_FAILURE_OUTPUT_CHARS = 400
#: The single retry after a failure (§4.4).
DEFAULT_RETRY_BACKOFF_S = 60.0
DEFAULT_SCAN_INTERVAL_S = 86400.0
DEFAULT_TIMEOUT_S = 3600.0
#: How long to wait between SIGTERM and SIGKILL when killing a scan on timeout.
#:
#: The full worst case on the timeout path is **three** of these — SIGTERM ->
#: 5s -> SIGKILL -> 5s (``kill_process_group``), then 5s more draining what the
#: dying group left in the pipes — so a timed-out scan can occupy its job thread
#: for ~15s past ``timeout_s``. That is deliberate and costs nothing: it happens
#: on the job thread, never on ``step()`` (which only polls) or on ``teardown()``
#: (which uses the much tighter ``SHUTDOWN_GRACE_S`` below).
KILL_GRACE_S = 5.0
#: The same, on shutdown -- deliberately much shorter.
#:
#: ``Supervisor.stop()`` budgets 5 SECONDS TOTAL for every worker, then
#: SIGKILLs. A teardown that spent 5s waiting for SIGTERM and 5s more waiting
#: for SIGKILL would be killed part-way through and orphan the very scan it was
#: trying to reap. SIGTERM -> 1.5s -> SIGKILL -> 1.5s fits inside the budget.
SHUTDOWN_GRACE_S = 1.5
#: Pipe read size. Only latency, never correctness, depends on it.
_READ_CHUNK = 64 * 1024

SpawnFn = Callable[[list[str]], "subprocess.Popen[str]"]


# --------------------------------------------------------------------------
# process-group cleanup (design decision 3)
# --------------------------------------------------------------------------


def default_spawn(argv: list[str]) -> subprocess.Popen[str]:
    """Spawn a scanner in its **own session** (design decision 3).

    ``start_new_session=True`` makes the child a session and process-group
    leader, so its pid *is* its pgid and every kill path below can take out the
    whole tree — including grandchildren the scanner forked. Without it, a
    SIGKILLed worker leaves a multi-minute scan running with nobody to reap it.

    ``argv`` is a list and ``shell`` is left false: scanner arguments include
    operator-supplied paths and must never be re-parsed by a shell.
    """
    return subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=True,
    )


class _BoundedSink:
    """Collects up to *limit* bytes of a scanner's output, discarding the rest.

    The surplus is **read and thrown away, never left unread**: a reader that
    simply stopped at the ceiling would block the scanner in ``write()`` on a
    full pipe buffer until its timeout, turning a bounded overrun into a hung
    scan. What was dropped is counted, so the degradation is reportable rather
    than silent (decision 11).

    Written by one reader thread, read by the job thread — hence the lock.
    """

    def __init__(self, limit: int) -> None:
        self._limit = max(0, limit)
        self._lock = threading.Lock()
        self._chunks: list[bytes] = []
        self._kept = 0
        self._dropped = 0

    def write(self, chunk: str | bytes) -> None:
        # Text-mode pipes hand back str; the ceiling is in bytes either way, so
        # that is what gets measured.
        data = chunk.encode("utf-8", "replace") if isinstance(chunk, str) else chunk
        with self._lock:
            room = self._limit - self._kept
            if room > 0:
                keep = data[:room]
                self._chunks.append(keep)
                self._kept += len(keep)
                data = data[len(keep) :]
            self._dropped += len(data)

    def snapshot(self) -> tuple[str, int]:
        """``(text, dropped_bytes)`` — safe to call while a reader is still running."""
        with self._lock:
            return b"".join(self._chunks).decode("utf-8", "replace"), self._dropped


def _drain_into(stream: Any, sink: _BoundedSink) -> None:
    """Read *stream* to EOF into *sink*. Never raises.

    Runs on its own daemon thread, one per pipe: reading both from this thread
    would deadlock as soon as the other pipe filled up.
    """
    try:
        with stream:
            while True:
                chunk = stream.read(_READ_CHUNK)
                if not chunk:
                    return
                sink.write(chunk)
    except Exception:
        # A closed or broken pipe just means there is nothing more to capture.
        return


def _start_reader(stream: Any, sink: _BoundedSink, name: str) -> threading.Thread | None:
    if stream is None:
        return None
    thread = threading.Thread(target=_drain_into, args=(stream, sink), name=name, daemon=True)
    thread.start()
    return thread


def _pgid_of(proc: subprocess.Popen[str]) -> int | None:
    """The process's group id, or ``None`` if it cannot be determined."""
    try:
        return os.getpgid(proc.pid)
    except Exception:
        # Already reaped, never started, or a stand-in object. Signalling the
        # direct child is the safe fallback; guessing a group id is not.
        return None


def signal_process_group(proc: subprocess.Popen[str], sig: int) -> None:
    """Send *sig* to the scan's whole process group. Never raises.

    Falls back to signalling the direct child when the group id is unavailable.
    The process may already be gone at any point here — that is normal, not an
    error.
    """
    pgid = _pgid_of(proc)
    if pgid is not None:
        try:
            os.killpg(pgid, sig)
            return
        except Exception:
            pass
    with contextlib.suppress(Exception):
        proc.send_signal(sig)


def _wait_quietly(proc: subprocess.Popen[str], timeout_s: float) -> bool:
    """Wait for *proc*; ``True`` if it exited, ``False`` on timeout. Never raises."""
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        # Nothing further we can do — treat as "not our problem any more".
        return True
    return True


def kill_process_group(proc: subprocess.Popen[str], *, grace_s: float = KILL_GRACE_S) -> None:
    """Terminate, wait, kill, wait — on the process **group**. Never raises.

    Call only from the thread that owns *proc*, so this never races the
    ``communicate()`` in the job thread.
    """
    signal_process_group(proc, signal.SIGTERM)
    if _wait_quietly(proc, grace_s):
        return
    signal_process_group(proc, signal.SIGKILL)
    _wait_quietly(proc, grace_s)


# --------------------------------------------------------------------------
# the scan job
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanResult:
    """What one finished scan produced."""

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    error: str | None = None
    #: The job thread never reported at all — only ``teardown()`` can see this,
    #: when its shutdown grace expires before the thread gets back to it.
    unreported: bool = False
    #: Bytes read off the pipes and discarded above the output ceiling, summed
    #: over stdout and stderr. Non-zero means the captured output is a prefix.
    output_dropped_bytes: int = 0


class _ScanJob:
    """One scanner subprocess, run to completion in one daemon thread."""

    def __init__(
        self,
        *,
        argv: Sequence[str],
        timeout_s: float,
        spawn: SpawnFn,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> None:
        self._argv = list(argv)
        self._timeout_s = float(timeout_s)
        self._spawn = spawn
        self._max_output_bytes = max(0, int(max_output_bytes))
        self._lock = threading.Lock()
        self._proc: subprocess.Popen[str] | None = None
        self._cancelled = False
        self._started = False
        self._done = threading.Event()
        self._result: ScanResult | None = None
        self._thread = threading.Thread(target=self._run, name="scanner-runner-scan", daemon=True)

    def start(self) -> None:
        self._started = True
        self._thread.start()

    def is_done(self) -> bool:
        return self._done.is_set()

    def result(self) -> ScanResult | None:
        return self._result

    def cancel(self, *, grace_s: float = KILL_GRACE_S) -> None:
        """Kill the scan's process group and wait for the job thread. Never raises.

        Only *signals* are sent from this thread; the wait is a ``join()`` on
        the job thread, so the subprocess is still owned by exactly one waiter.
        """
        with self._lock:
            self._cancelled = True
            proc = self._proc
        if proc is not None:
            signal_process_group(proc, signal.SIGTERM)
        if not self._started:
            return
        self._thread.join(grace_s)
        if self._thread.is_alive():
            if proc is None:
                # The thread had not spawned yet when we set the flag; it will
                # see the flag and kill the child itself.
                with self._lock:
                    proc = self._proc
            if proc is not None:
                signal_process_group(proc, signal.SIGKILL)
            self._thread.join(grace_s)

    def _finish(self, result: ScanResult) -> None:
        self._result = result
        self._done.set()

    def _run(self) -> None:
        try:
            proc = self._spawn(self._argv)
        except Exception as exc:
            # A missing / unexecutable binary must be reported as a failed
            # scan, never raised: the worker outlives any one scan.
            self._finish(ScanResult(None, "", "", error=repr(exc)))
            return

        with self._lock:
            self._proc = proc
            cancelled = self._cancelled
        if cancelled:
            # teardown() beat us to the spawn; kill what we just created.
            kill_process_group(proc)
            self._finish(ScanResult(proc.returncode, "", "", cancelled=True))
            return

        # `communicate()` cannot bound what it buffers, so the pipes are read
        # directly: one daemon reader per pipe, each capping what it keeps.
        out_sink = _BoundedSink(self._max_output_bytes)
        err_sink = _BoundedSink(self._max_output_bytes)
        readers = [
            reader
            for reader in (
                _start_reader(proc.stdout, out_sink, "scanner-runner-stdout"),
                _start_reader(proc.stderr, err_sink, "scanner-runner-stderr"),
            )
            if reader is not None
        ]

        try:
            timed_out = self._await_exit(proc, readers)
        except Exception as exc:
            kill_process_group(proc)
            self._finish(ScanResult(proc.returncode, "", "", error=repr(exc)))
            return

        stdout, dropped_out = out_sink.snapshot()
        stderr, dropped_err = err_sink.snapshot()
        with self._lock:
            cancelled = self._cancelled
        self._finish(
            ScanResult(
                proc.returncode,
                stdout,
                stderr,
                timed_out=timed_out,
                cancelled=cancelled,
                output_dropped_bytes=dropped_out + dropped_err,
            )
        )

    def _await_exit(self, proc: subprocess.Popen[str], readers: list[threading.Thread]) -> bool:
        """Wait for EOF on both pipes and then for exit. ``True`` if it timed out.

        EOF first, exit second, exactly like ``communicate()``: a scanner that
        exits while a forked grandchild still holds the pipe has not finished
        producing output yet.
        """
        deadline = time.monotonic() + self._timeout_s
        timed_out = False
        for reader in readers:
            reader.join(max(0.0, deadline - time.monotonic()))
            if reader.is_alive():
                timed_out = True
                break
        if not timed_out and not _wait_quietly(proc, max(0.0, deadline - time.monotonic())):
            timed_out = True
        if not timed_out:
            return False

        kill_process_group(proc)
        # The group is gone, so the pipes are about to hit EOF; give the readers
        # a bounded moment to notice. They are daemon threads, so even a reader
        # that never returns cannot hold the worker open.
        drain_deadline = time.monotonic() + KILL_GRACE_S
        for reader in readers:
            reader.join(max(0.0, drain_deadline - time.monotonic()))
        return True


@dataclass
class _ActiveRun:
    scanner: str
    adapter: ScannerAdapter
    run_id: str
    started_at: float
    argv: list[str]
    job: _ScanJob


# --------------------------------------------------------------------------
# the worker
# --------------------------------------------------------------------------


class ScannerRunnerWorker(Worker):
    """Runs on-disk scanners on an interval, one at a time (design §4.4).

    ``step()`` is a tick, never a scan: it finishes an in-flight run if the job
    thread is done, then starts at most one due scanner.
    """

    def __init__(
        self,
        *,
        name: str = "scanner_runner",
        adapters: Sequence[ScannerAdapter] | None = None,
        spawn: SpawnFn | None = None,
        host_name: str = _DEFAULT_HOSTNAME,
        **kwargs: Any,
    ) -> None:
        super().__init__(name=name, **kwargs)
        chosen = list(adapters) if adapters is not None else default_adapters()
        self._adapters: dict[str, ScannerAdapter] = {a.name: a for a in chosen}
        self._spawn: SpawnFn = spawn if spawn is not None else default_spawn
        self._host_name = host_name
        self._active: _ActiveRun | None = None
        self._next_due: dict[str, float] = {}
        self._retried: dict[str, bool] = {}
        # Scanners already told "a run is in flight" for their current due
        # window. Without this a 60s tick under a one-hour scan would emit 60
        # identical skip events.
        self._skip_notified: set[str] = set()
        self._scheduled = False

    # -- config ------------------------------------------------------------

    def step_interval_s(self) -> float:
        return _as_float(self.config.get("interval_s"), DEFAULT_TICK_S)

    def _scanner_config(self, name: str) -> Mapping[str, Any]:
        scanners = self.config.get("scanners")
        if not isinstance(scanners, dict):
            return {}
        entry = scanners.get(name)
        return entry if isinstance(entry, dict) else {}

    def _enabled(self, name: str) -> bool:
        return bool(self._scanner_config(name).get("enabled", False))

    def _interval_s(self, name: str) -> float:
        return _as_float(self._scanner_config(name).get("interval_s"), DEFAULT_SCAN_INTERVAL_S)

    def _timeout_s(self, name: str) -> float:
        return _as_float(self._scanner_config(name).get("timeout_s"), DEFAULT_TIMEOUT_S)

    def _max_findings(self) -> int:
        raw = self.config.get("max_findings_per_run", DEFAULT_MAX_FINDINGS_PER_RUN)
        try:
            return max(0, int(raw))
        except (TypeError, ValueError):
            return DEFAULT_MAX_FINDINGS_PER_RUN

    def _max_output_bytes(self) -> int:
        raw = self.config.get("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES)
        try:
            return max(0, int(raw))
        except (TypeError, ValueError):
            return DEFAULT_MAX_OUTPUT_BYTES

    def _retry_backoff_s(self) -> float:
        return _as_float(self.config.get("retry_backoff_s"), DEFAULT_RETRY_BACKOFF_S)

    # -- the tick ----------------------------------------------------------

    def step(self) -> None:
        now = time.monotonic()
        self._ensure_scheduled(now)

        active = self._active
        if active is not None and active.job.is_done():
            self._active = None
            self._finish_run(active, now)

        for name in sorted(self._adapters):
            if not self._enabled(name):
                continue
            if self._next_due.get(name, 0.0) > now:
                continue
            if self._active is not None:
                self._notify_in_flight(name)
                continue
            self._start_run(name, now)

    def teardown(self) -> None:
        """Kill any in-flight scan by process group and report it. Never raises."""
        active = self._active
        if active is None:
            return
        self._active = None
        with contextlib.suppress(Exception):
            active.job.cancel(grace_s=SHUTDOWN_GRACE_S)
        with contextlib.suppress(Exception):
            self._finish_run(active, time.monotonic())

    # -- scheduling --------------------------------------------------------

    def _ensure_scheduled(self, now: float) -> None:
        if self._scheduled:
            return
        delay = _as_float(self.config.get("startup_delay_s"), DEFAULT_STARTUP_DELAY_S)
        for name in self._adapters:
            self._next_due[name] = now + delay
        self._scheduled = True

    def _notify_in_flight(self, name: str) -> None:
        """Report the single-flight rejection once per due window, not per tick."""
        if name in self._skip_notified:
            return
        self._skip_notified.add(name)
        self._emit_skipped(name, "run_in_flight")

    def _start_run(self, name: str, now: float) -> None:
        adapter = self._adapters[name]
        config = self._scanner_config(name)

        if shutil.which(adapter.binary) is None:
            # Decision 14: silence here would let the user believe AIDE runs
            # nightly when the binary was never installed.
            self._skip_slot(name, "binary_not_found", now)
            return

        try:
            # A per-scanner prerequisite the runner cannot know about (YARA with
            # no rulesets shipped yet, say). An ordinary state like that must be
            # an explicit skip, not an argv that fails in a confusing way.
            reason = adapter.preflight(config)
        except Exception:
            # Adapters promise not to raise; the runner assumes they will anyway.
            reason = "preflight_error"
        if reason is not None:
            self._skip_slot(name, str(reason), now)
            return

        try:
            argv = [str(part) for part in adapter.argv(config)]
        except Exception:
            self._skip_slot(name, "argv_error", now)
            return

        run_id = str(uuid7())
        job = _ScanJob(
            argv=argv,
            timeout_s=self._timeout_s(name),
            spawn=self._spawn,
            max_output_bytes=self._max_output_bytes(),
        )
        # Claim the slot before the run begins, so the scanner is no longer
        # "due" while its own scan is in flight — otherwise every tick of a
        # multi-minute run would report it as skipped against itself.
        # _reschedule() re-bases this on the completion time.
        self._consume_slot(name, now)
        self._emit_started(name, run_id, argv)
        job.start()
        self._active = _ActiveRun(
            scanner=name,
            adapter=adapter,
            run_id=run_id,
            started_at=now,
            argv=argv,
            job=job,
        )

    def _skip_slot(self, name: str, reason: str, now: float) -> None:
        """Report a due window that never became a scan, and give up the slot.

        Clearing the retry flag is the point: nothing was attempted here, so a
        skip must not consume the retry a previous failure is still owed. (The
        run-start path deliberately leaves the flag alone — resetting it there
        would let a scanner retry forever instead of once.)
        """
        self._emit_skipped(name, reason)
        self._retried[name] = False
        self._consume_slot(name, now)

    def _consume_slot(self, name: str, now: float) -> None:
        """Push *name* to its next scheduled slot and end its skip window.

        Deliberately does NOT touch the retry flag: this is called when a run
        *starts*, and resetting the flag there would let a scanner retry
        forever instead of once.
        """
        self._next_due[name] = now + self._interval_s(name)
        self._skip_notified.discard(name)

    # -- completing a run --------------------------------------------------

    def _finish_run(self, run: _ActiveRun, now: float) -> None:
        result = run.job.result() or _UNREPORTED
        outcome, reason = self._classify(run, result)

        findings: list[Finding] = []
        if outcome is not ScanOutcome.failure:
            try:
                findings = list(run.adapter.parse(result.stdout, result.stderr))
            except Exception:
                # Adapters promise never to raise; if one does, the run is not
                # trustworthy and must be reported as failed, not as clean.
                outcome, reason = ScanOutcome.failure, "parse_error"
                findings = []

        cap = self._max_findings()
        emitted = findings[:cap]
        dropped = len(findings) - len(emitted)

        # Decision 11 is the reason this worker exists in the shape it does: the
        # run gets reported, and the scanner gets its next slot, whatever the
        # emission of the findings does. `self._active` is already cleared, so
        # the "stuck in flight forever" failure is impossible either way; what
        # this protects is `scan_completed` itself, which is the only thing that
        # distinguishes a broken scanner from a clean machine.
        self._guard(lambda: self._emit_findings(run, emitted))
        self._guard(
            lambda: self._emit_completed(
                run,
                outcome=outcome,
                reason=reason,
                result=result,
                duration_s=max(0.0, now - run.started_at),
                finding_count=len(emitted),
                findings_dropped=dropped,
            )
        )
        self._guard(lambda: self._reschedule(run.scanner, outcome, reason, now))

    def _guard(self, action: Callable[[], Any]) -> None:
        """Run *action*, recording any failure on the heartbeat instead of raising."""
        try:
            action()
        except Exception as exc:
            self._last_error = repr(exc)

    def _classify(self, run: _ActiveRun, result: ScanResult) -> tuple[ScanOutcome, str | None]:
        """Map a finished job to ``(outcome, reason)``.

        The exit status is only consulted once the job itself is known to have
        produced one — a killed or never-spawned scan has no meaningful code.
        """
        reason = _pre_exit_failure_reason(result)
        exit_code = result.exit_code
        if reason is not None or exit_code is None:
            return ScanOutcome.failure, reason or "no_exit_status"
        try:
            # Decision 10: never a `code == 0` boolean — the adapter decides,
            # and it decides from the OUTPUT as well as the code, because for
            # rkhunter exit 1 means both "found something" and "refused to run".
            outcome = run.adapter.interpret_outcome(int(exit_code), result.stdout, result.stderr)
        except Exception:
            return ScanOutcome.failure, "exit_interpretation_error"
        return outcome, "scanner_error" if outcome is ScanOutcome.failure else None

    def _reschedule(self, name: str, outcome: ScanOutcome, reason: str | None, now: float) -> None:
        # A scan the worker itself stopped is not a scanner failure, so it never
        # earns a retry — and there would be no tick left to run one anyway.
        retryable = outcome is ScanOutcome.failure and reason not in _SHUTDOWN_REASONS
        if retryable and not self._retried.get(name, False):
            # §4.4: one retry after a short backoff, then wait for the next slot.
            self._retried[name] = True
            self._next_due[name] = now + self._retry_backoff_s()
            self._skip_notified.discard(name)
            return
        self._retried[name] = False
        self._consume_slot(name, now)

    # -- events (design §4.2) ----------------------------------------------

    def _emit(self, event: Event) -> None:
        self.emit_event(event.model_dump(mode="json", exclude_none=True))

    def _emit_started(self, scanner: str, run_id: str, argv: list[str]) -> None:
        self._emit(
            build_event(
                module="scanner_runner",
                action="scan_started",
                category=["process"],
                type_=["start"],
                severity="info",
                host={"name": self._host_name},
                message=f"{scanner} scan started",
                labels=["scanner", f"scanner:{scanner}"],
                raw={"scanner": scanner, "run_id": run_id, "argv": argv},
            )
        )

    def _emit_completed(
        self,
        run: _ActiveRun,
        *,
        outcome: ScanOutcome,
        reason: str | None,
        result: ScanResult,
        duration_s: float,
        finding_count: int,
        findings_dropped: int,
    ) -> None:
        failed = outcome is ScanOutcome.failure
        message = f"{run.scanner} scan {outcome.value}"
        if reason is not None:
            message = f"{message} ({reason})"
        self._emit(
            build_event(
                module="scanner_runner",
                action="scan_completed",
                category=["process"],
                type_=["end"],
                severity="info",
                outcome="failure" if failed else "success",
                host={"name": self._host_name},
                message=message,
                labels=["scanner", f"scanner:{run.scanner}"],
                raw=_prune(
                    {
                        "scanner": run.scanner,
                        "run_id": run.run_id,
                        "scan_outcome": outcome.value,
                        "reason": reason,
                        "exit_code": result.exit_code,
                        "error": result.error,
                        "duration_s": round(duration_s, 3),
                        "finding_count": finding_count,
                        "findings_dropped": findings_dropped,
                        "truncated": findings_dropped > 0,
                        # Decision 11 again: a run whose output was clipped is
                        # a degraded run, and must never look like a whole one.
                        "output_dropped_bytes": result.output_dropped_bytes,
                        "output_truncated": result.output_dropped_bytes > 0,
                        # Why it failed, in the scanner's own words. Failures
                        # only: a successful run's output is the finding set,
                        # which is already an event per finding.
                        "output_excerpt": _failure_excerpt(result) if failed else None,
                    }
                ),
            )
        )

    def _emit_skipped(self, scanner: str, reason: str) -> None:
        adapter = self._adapters[scanner]
        self._emit(
            build_event(
                module="scanner_runner",
                action="scan_skipped",
                category=["process"],
                type_=["info"],
                severity="info",
                host={"name": self._host_name},
                message=f"{scanner} scan skipped: {reason}",
                labels=["scanner", f"scanner:{scanner}"],
                raw={"scanner": scanner, "reason": reason, "binary": adapter.binary},
            )
        )

    def _emit_findings(self, run: _ActiveRun, findings: Sequence[Finding]) -> None:
        for finding in findings:
            self._emit_finding(run, finding)

    def _emit_finding(self, run: _ActiveRun, finding: Finding) -> None:
        indicator: dict[str, Any] = {
            "type": finding.indicator_type,
            "value": finding.indicator_value,
            # The scanner, so a rule can key on which tool said so.
            "source": run.scanner,
        }
        if finding.severity is not None:
            # Decision 7: the SCANNER's severity is data; rules assign the real one.
            indicator["severity"] = finding.severity

        file_block: dict[str, Any] | None = None
        if finding.path is not None:
            file_block = {"path": finding.path}
            if finding.hashes:
                file_block["hash"] = dict(finding.hashes)

        self._emit(
            build_event(
                module="scanner_runner",
                action="scan_finding",
                category=[finding.category or "file"],
                type_=["info"],
                severity="low",
                host={"name": self._host_name},
                message=finding.message,
                labels=["scanner", f"scanner:{run.scanner}"],
                file=file_block,
                threat={"indicator": indicator},
                raw={
                    "scanner": run.scanner,
                    "run_id": run.run_id,
                    "line": finding.raw_line,
                },
            )
        )


#: Reasons that mean "the worker stopped this scan", not "the scanner failed".
_SHUTDOWN_REASONS = frozenset({"shutdown", "teardown_timeout"})

#: Stands in for a run that ``teardown()`` had to report before its job thread
#: did. Nothing failed to *spawn* here — the thread simply did not get back
#: inside SHUTDOWN_GRACE_S — so it gets its own reason rather than being filed
#: under `spawn_error`, which would send a later investigation the wrong way.
_UNREPORTED = ScanResult(
    None,
    "",
    "",
    error="the scan thread did not report before the shutdown grace expired",
    unreported=True,
)


def _pre_exit_failure_reason(result: ScanResult) -> str | None:
    """Why the scan failed before its exit status could be trusted, if it did."""
    if result.unreported:
        return "teardown_timeout"
    if result.error is not None:
        return "spawn_error"
    if result.timed_out:
        return "timeout"
    if result.cancelled:
        return "shutdown"
    return None


def _as_float(value: Any, default: float) -> float:
    """Coerce a config value to a float, falling back to *default* on garbage."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _failure_excerpt(result: ScanResult) -> str | None:
    """A short, sanitized head of a failed run's output — stderr, else stdout.

    stderr first because that is where every scanner puts the reason it could
    not run (yara's compile error, rkhunter's refusal is on stdout instead).
    The text is untrusted scanner output embedding attacker-influenceable
    filenames, so it is stripped of control characters and hard-capped; it is a
    diagnostic breadcrumb, never the finding set.
    """
    for text in (result.stderr, result.stdout):
        excerpt = " ".join(
            piece for piece in (sanitize_text(line).strip() for line in text.split("\n")) if piece
        )
        if not excerpt:
            continue
        if len(excerpt) > MAX_FAILURE_OUTPUT_CHARS:
            return excerpt[:MAX_FAILURE_OUTPUT_CHARS] + " [truncated]"
        return excerpt
    return None


def _prune(data: dict[str, Any]) -> dict[str, Any]:
    """Drop ``None`` values — ``exclude_none`` does not reach inside ``raw``."""
    return {k: v for k, v in data.items() if v is not None}
