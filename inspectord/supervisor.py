"""Supervisor — owns workers, router, journal, and storage.

Spawns each declared worker as a Python subprocess. Reads events from each
worker's stdout line by line and publishes them onto the router. Heartbeats
arrive on stderr and update worker_health.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from importlib.resources import files
from queue import Empty as QueueEmpty
from typing import Any

import yaml as _yaml

from inspectord.allowlist.file_loader import load_allowlist_file
from inspectord.config import DaemonConfig, WorkerSpec
from inspectord.enrichment import enrich
from inspectord.evidence.collector import EvidenceCollector
from inspectord.evidence.store import ForensicStore
from inspectord.journal import Journal
from inspectord.log import get
from inspectord.parsers.base import build_event
from inspectord.router import DropPolicy, EventRouter, RouterFull
from inspectord.rule_engine import RuleEngine
from inspectord.rules.python_loader import load_python_rules
from inspectord.rules.registry import Registry
from inspectord.rules.yaml_loader import load_yaml_rule_from_dict
from inspectord.schemas.alert import Alert
from inspectord.schemas.event import Event
from inspectord.state.projector import project
from inspectord.state.reconcile import current_boot_id, reconcile_processes
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations
from inspectord.workers.notifier.__main__ import NotifierWorker

log = get(__name__)

# --- worker restart policy (spec section 3.2) -------------------------------
# How often the monitor thread polls the children for death.
MONITOR_POLL_INTERVAL_S = 1.0
# Delay before the first restart; doubles per consecutive restart...
RESTART_BASE_DELAY_S = 1.0
# ...up to this cap.
RESTART_MAX_DELAY_S = 60.0
# Uptime after which a restarted worker counts as recovered and its
# consecutive-restart counter resets. Without this, a worker that crashes once
# a day would eventually be treated as crash-looping and given up on.
RESTART_HEALTHY_AFTER_S = 60.0
# Consecutive restarts that never reached RESTART_HEALTHY_AFTER_S before the
# supervisor gives up and leaves the worker dead.
RESTART_MAX_ATTEMPTS = 8


def backoff_delay(
    attempt: int,
    *,
    base: float = RESTART_BASE_DELAY_S,
    cap: float = RESTART_MAX_DELAY_S,
) -> float:
    """Delay before restart number ``attempt`` (1-based): base * 2^(n-1), capped."""
    exponent = max(0, attempt - 1)
    return min(base * (2.0**exponent), cap)


class _WorkerProc:
    def __init__(self, spec: WorkerSpec, proc: subprocess.Popen[bytes]) -> None:
        self.spec = spec
        self.proc = proc
        self.threads: list[threading.Thread] = []
        # Monotonic timestamp of this incarnation's spawn, for the healthy check.
        self.started_at = time.monotonic()
        # Consecutive restarts carried across incarnations; reset once healthy.
        self.restarts = 0
        # Monotonic deadline for the pending respawn, None when not scheduled.
        self.restart_at: float | None = None
        # True once we gave up: the worker is left dead and never polled again.
        self.exhausted = False
        # Guards against re-emitting worker_died on every tick of the corpse.
        self.died_reported = False


class Supervisor:
    def __init__(
        self,
        config: DaemonConfig,
        *,
        poll_interval_s: float = MONITOR_POLL_INTERVAL_S,
        restart_base_delay_s: float = RESTART_BASE_DELAY_S,
        restart_max_delay_s: float = RESTART_MAX_DELAY_S,
        restart_healthy_after_s: float = RESTART_HEALTHY_AFTER_S,
        restart_max_attempts: int = RESTART_MAX_ATTEMPTS,
    ) -> None:
        self._cfg = config
        self._router = EventRouter()
        self._journal = Journal(config.storage.journal_dir)
        self._db = Database(config.storage.db_path)
        self._procs: list[_WorkerProc] = []
        # Guards mutation of _procs: the monitor thread swaps entries in place
        # while stop() and callers read the list.
        self._procs_lock = threading.RLock()
        self._stop = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._poll_interval_s = poll_interval_s
        self._restart_base_delay_s = restart_base_delay_s
        self._restart_max_delay_s = restart_max_delay_s
        self._restart_healthy_after_s = restart_healthy_after_s
        self._restart_max_attempts = restart_max_attempts
        self._boot_id: str | None = None
        self._listeners: list[Callable[[Event], None]] = []
        # Build the rule engine.
        python_rules = load_python_rules("inspectord.rules.starter_pack")
        yaml_rules = []
        pkg = files("inspectord.rules.starter_pack")
        for entry in pkg.iterdir():
            if entry.name.endswith(".yaml"):
                yaml_rules.append(
                    load_yaml_rule_from_dict(
                        _yaml.safe_load(entry.read_text(encoding="utf-8")),
                        source=entry.name,
                    )
                )
        self._rule_engine = RuleEngine(
            registry=Registry(yaml_rules=yaml_rules, python_rules=python_rules),
            db_path=config.storage.db_path,
            allowlist_entries=load_allowlist_file(),
        )
        self._alert_listeners: list[Callable[[Alert], None]] = []
        self._evidence_collector: EvidenceCollector | None = None

    def start(self) -> None:
        self._db.connect()
        run_migrations(self._db)
        self._evidence_collector = EvidenceCollector(
            self._cfg.storage.db_path, ForensicStore(self._cfg.storage.evidence_dir)
        )
        # suppress(OSError) guards the /proc/sys/kernel/random/boot_id read on hosts
        # where it is unreadable (e.g. some CI sandboxes); migrations above have
        # already created process_state, so the reconcile UPDATE itself won't raise here.
        with contextlib.suppress(OSError):
            self._boot_id = current_boot_id()
            reconcile_processes(self._db, self._boot_id)
        self._subscribe_storage()
        for spec in self._cfg.workers:
            self._spawn_worker(spec)
        if self._cfg.notifier_desktop_enabled:
            self._notifier = NotifierWorker()
            self.attach_alert_listener(self._notifier.on_alert)
        # Started last: it must never see a half-built worker list.
        self._monitor_thread = threading.Thread(
            target=self._monitor, name="worker-monitor", daemon=True
        )
        self._monitor_thread.start()

    def attach_listener(self, fn: Callable[[Event], None]) -> None:
        self._listeners.append(fn)

    def attach_alert_listener(self, fn: Callable[[Alert], None]) -> None:
        self._alert_listeners.append(fn)

    def _inject_for_test(self, ev: Event) -> None:
        """Test hook: push an event through the same path workers' events take."""
        self._dispatch(ev)

    def _dispatch(self, ev: Event) -> None:
        """Enrich, run rules, fan out alerts, publish — the one path every event takes.

        Runs on whichever thread produced the event: the worker reader threads
        (alert fan-out MUST stay on them) and the worker monitor thread.
        """
        ev = enrich(ev)
        for alert in self._rule_engine.process(ev):
            if self._evidence_collector is not None:
                # MUST precede the notifier listeners (evidence first, notify second).
                self._evidence_collector.capture(alert, ev)
            for fn in list(self._alert_listeners):
                try:
                    fn(alert)
                except Exception as exc:
                    log.warning("alert listener raised: %r", exc)
        try:
            self._router.publish(ev)
        except RouterFull as exc:
            log.error("router full, dropping %s event from %s: %r", ev.action, ev.module, exc)

    def stop(self, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        # Order matters: the monitor has to be stopped BEFORE any worker is
        # terminated, or it would helpfully restart them all mid-shutdown.
        self._stop.set()
        monitor = self._monitor_thread
        if monitor is not None:
            monitor.join(timeout=min(max(0.0, deadline - time.monotonic()), 2.0))
            if monitor.is_alive():
                log.warning("worker monitor did not stop within the shutdown budget")
        # Taking the lock here also closes the last respawn window: a monitor
        # caught mid-respawn holds it, so the snapshot below sees the new proc.
        with self._procs_lock:
            procs = list(self._procs)
        for wp in procs:
            with contextlib.suppress(Exception):
                wp.proc.terminate()
        for wp in procs:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                wp.proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                wp.proc.kill()
            for t in wp.threads:
                t.join(timeout=1.0)
        self._journal.close()
        self._db.close()

    def _subscribe_storage(self) -> None:
        store_sub = self._router.subscribe(
            name="store",
            queue_size=4096,
            drop_policy=DropPolicy.drop_oldest_non_critical,
        )
        threading.Thread(target=self._drain, args=(store_sub,), daemon=True).start()

    def _drain(self, sub) -> None:  # type: ignore[no-untyped-def]
        while not self._stop.is_set():
            try:
                ev = sub.get_nowait()
            except QueueEmpty:
                time.sleep(0.01)
                continue
            self._persist(ev)
            for fn in list(self._listeners):
                try:
                    fn(ev)
                except Exception as exc:
                    log.warning("listener raised: %r", exc)

    def _persist(self, ev: Event) -> None:
        payload = ev.model_dump_json()
        self._journal.append(json.loads(payload))
        self._db.execute(
            "INSERT INTO events_enriched "
            "(event_id, ts, kind, module, action, severity, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [ev.event_id, ev.ts, ev.kind.value, ev.module, ev.action, ev.severity.value, payload],
        )
        project(ev, self._db, boot_id=self._boot_id)

    def _spawn_worker(self, spec: WorkerSpec) -> None:
        with self._procs_lock:
            self._procs.append(self._start_worker_proc(spec))

    def _start_worker_proc(self, spec: WorkerSpec) -> _WorkerProc:
        """Spawn one worker process with its own pair of fresh reader threads."""
        cmd = [sys.executable, "-m", spec.module]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert proc.stdin is not None
        # A worker that dies before reading its config breaks the pipe; that is
        # the monitor's problem to solve (restart), not a reason to fail here.
        with contextlib.suppress(BrokenPipeError):
            proc.stdin.write((json.dumps(spec.config) + "\n").encode("utf-8"))
            proc.stdin.flush()
        proc.stdin.close()
        wp = _WorkerProc(spec, proc)
        wp.threads.append(threading.Thread(target=self._read_stdout, args=(wp,), daemon=True))
        wp.threads.append(threading.Thread(target=self._read_stderr, args=(wp,), daemon=True))
        for t in wp.threads:
            t.start()
        return wp

    # --- worker monitor (spec §3.2) -----------------------------------------

    def _monitor(self) -> None:
        """Poll the children ~every poll_interval_s and restart the dead ones."""
        while not self._stop.wait(self._poll_interval_s):
            try:
                self._monitor_tick()
            except Exception as exc:  # the monitor must outlive any single failure
                log.error("worker monitor tick failed: %r", exc)

    def _monitor_tick(self) -> None:
        now = time.monotonic()
        with self._procs_lock:
            snapshot = list(enumerate(self._procs))
        for index, wp in snapshot:
            if self._stop.is_set():
                return
            if wp.exhausted:
                continue
            rc = wp.proc.poll()
            if rc is None:
                # Alive: a worker that has stayed up long enough is recovered,
                # so the next crash starts its backoff from scratch. Without
                # this a worker crashing once a day would eventually exhaust.
                if wp.restarts and now - wp.started_at >= self._restart_healthy_after_s:
                    log.info("worker %s healthy again; restart backoff reset", wp.spec.name)
                    wp.restarts = 0
                continue
            self._handle_dead_worker(index, wp, rc, now)

    def _handle_dead_worker(self, index: int, wp: _WorkerProc, rc: int, now: float) -> None:
        if not wp.died_reported:
            wp.died_reported = True
            # Reap first so the worker's final events reach the router before
            # worker_died does, and so the reader threads never outlive the child.
            self._reap(wp)
            log.warning("worker %s died with exit code %d", wp.spec.name, rc)
            self._emit_supervisor_event(
                action="worker_died",
                severity="medium",
                type_=["end"],
                message=f"worker {wp.spec.name} exited with code {rc}",
                raw={
                    "worker": wp.spec.name,
                    "exit_code": rc,
                    # A negative returncode is -SIGNUM (killed, not exited).
                    "signal": -rc if rc < 0 else None,
                    "restarts": wp.restarts,
                },
            )
        if wp.restarts >= self._restart_max_attempts:
            wp.exhausted = True
            log.error(
                "worker %s is permanently down after %d restarts",
                wp.spec.name,
                wp.restarts,
            )
            self._emit_supervisor_event(
                action="worker_restart_exhausted",
                severity="high",
                type_=["error"],
                message=(
                    f"worker {wp.spec.name} stayed down after {wp.restarts} restarts; "
                    "its telemetry is missing until inspectord is restarted"
                ),
                raw={"worker": wp.spec.name, "attempts": wp.restarts},
            )
            return
        attempt = wp.restarts + 1
        delay = backoff_delay(
            attempt, base=self._restart_base_delay_s, cap=self._restart_max_delay_s
        )
        if wp.restart_at is None:
            wp.restart_at = now + delay
        if now < wp.restart_at:
            return
        self._respawn(index, wp, attempt=attempt, delay=delay)

    def _respawn(self, index: int, old: _WorkerProc, *, attempt: int, delay: float) -> None:
        # The attempt is counted before the spawn, so a spawn that fails still
        # backs off (and can still exhaust) instead of retrying every tick.
        old.restarts = attempt
        old.restart_at = None
        with self._procs_lock:
            if self._stop.is_set():
                return
            try:
                new = self._start_worker_proc(old.spec)
            except Exception as exc:
                log.error("failed to respawn worker %s: %r", old.spec.name, exc)
                return
            new.restarts = attempt
            self._procs[index] = new
        log.info("restarted worker %s (attempt %d after %.2fs)", old.spec.name, attempt, delay)
        self._emit_supervisor_event(
            action="worker_restarted",
            severity="info",
            type_=["start"],
            message=f"restarted worker {old.spec.name} (attempt {attempt}, {delay:g}s backoff)",
            raw={"worker": old.spec.name, "attempt": attempt, "backoff_s": delay},
        )

    def _reap(self, wp: _WorkerProc) -> None:
        """Join a dead child's reader threads and close its pipes — no leaks, no double-read."""
        stuck = False
        for t in wp.threads:
            if t is not threading.current_thread():
                t.join(timeout=1.0)
                if t.is_alive():
                    stuck = True
                    log.warning("reader thread for %s did not exit at EOF", wp.spec.name)
        if stuck:
            # Closing a pipe out from under a thread still blocked in readline
            # would kill that thread with a ValueError; leave the fds to stop().
            return
        for stream in (wp.proc.stdin, wp.proc.stdout, wp.proc.stderr):
            if stream is not None:
                with contextlib.suppress(Exception):
                    stream.close()

    def _emit_supervisor_event(
        self,
        *,
        action: str,
        severity: str,
        type_: list[str],
        message: str,
        raw: dict[str, Any],
    ) -> None:
        try:
            self._dispatch(
                build_event(
                    module="supervisor",
                    action=action,
                    category=["process"],
                    type_=type_,
                    severity=severity,
                    message=message,
                    raw=raw,
                )
            )
        except Exception as exc:
            log.error("failed to emit supervisor %s event: %r", action, exc)

    def _read_stdout(self, wp: _WorkerProc) -> None:
        assert wp.proc.stdout is not None
        for line in iter(wp.proc.stdout.readline, b""):
            if self._stop.is_set():
                return
            stripped = line.rstrip(b"\n")
            if not stripped:
                continue
            try:
                payload = json.loads(stripped.decode("utf-8"))
                ev = Event.model_validate(payload)
                ev = enrich(ev)
                for alert in self._rule_engine.process(ev):
                    if self._evidence_collector is not None:
                        # MUST precede the notifier listeners (evidence first, notify second).
                        self._evidence_collector.capture(alert, ev)
                    for fn in list(self._alert_listeners):
                        try:
                            fn(alert)
                        except Exception as exc:
                            log.warning("alert listener raised: %r", exc)
                self._router.publish(ev)
            except Exception as exc:
                log.error("worker %s emitted invalid event: %r", wp.spec.name, exc)

    def _read_stderr(self, wp: _WorkerProc) -> None:
        assert wp.proc.stderr is not None
        for line in iter(wp.proc.stderr.readline, b""):
            if self._stop.is_set():
                return
            stripped = line.rstrip(b"\n")
            if not stripped:
                continue
            try:
                hb = json.loads(stripped.decode("utf-8"))
            except Exception:
                continue
            self._record_heartbeat(wp.spec.name, hb)

    def _record_heartbeat(self, name: str, hb: dict[str, Any]) -> None:
        try:
            self._db.execute(
                "INSERT INTO worker_health "
                "(worker, ts, events_processed, queue_depth, last_error, uptime_s) "
                "VALUES (?, to_timestamp(?), ?, ?, ?, ?)",
                [
                    name,
                    float(hb.get("ts", time.time())),
                    int(hb.get("events_processed", 0)),
                    int(hb.get("queue_depth", 0)),
                    hb.get("last_error"),
                    float(hb.get("uptime_s", 0.0)),
                ],
            )
        except Exception as exc:
            log.warning("failed to record heartbeat for %s: %r", name, exc)
