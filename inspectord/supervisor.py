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
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from importlib.resources import files
from queue import Empty as QueueEmpty
from typing import Any
from uuid import uuid4

import yaml as _yaml

from inspectord.allowlist.file_loader import load_allowlist_file
from inspectord.anomaly.detector import AnomalyDetector
from inspectord.anomaly.first_sighting import FirstSightingTracker
from inspectord.audit.log import (
    append_audit,
    newest_anchor,
    set_failure_listener,
    verify_audit_chain,
)
from inspectord.config import DaemonConfig, WorkerSpec
from inspectord.enrichment import enrich
from inspectord.evidence.collector import EvidenceCollector
from inspectord.evidence.store import ForensicStore
from inspectord.journal import Journal
from inspectord.log import get
from inspectord.parsers.base import build_event
from inspectord.retention.engine import run_retention
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
from inspectord.storage.events import insert_event
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

# --- persistence resilience -------------------------------------------------
# Persistence health is judged over a rolling window of the last N outcomes
# rather than a consecutive streak. A streak counter that a single success
# resets never fires on a *partial* outage -- a systematic 9-fail/1-success
# pattern, or any sustained ~50% loss, silently drops most of the telemetry
# while the user-facing alert path says nothing.
PERSIST_FAILURE_WINDOW = 20
# Failures within that window before the supervisor stops treating them as bad
# luck (a duplicate event_id, a transient DuckDB conflict) and tells the user
# that persistence is failing. A one-off failure never gets near it.
PERSIST_FAILURE_ALERT_THRESHOLD = 10
# Minimum seconds between two persistence_failing events.
PERSIST_ALERT_COOLDOWN_S = 300.0

# --- worker command channel (worker-command-channel design §5) ---------------
# Default wait for a worker's command_result before answering "timeout".
COMMAND_TIMEOUT_S = 10.0
# Assert-grade bound on concurrently in-flight commands per worker. Unreachable
# in single-user practice (documented as such): every pending entry is removed
# in a `finally`, so only 32 simultaneous waiters could ever hit it.
MAX_INFLIGHT_COMMANDS_PER_WORKER = 32

# --- audit chain maintenance (spec 2026-08-25-audit-log-design §6a/§7) ------
# How often the supervisor anchors the audit head into the journal (as an
# audit_head event) and verifies the whole chain. Daily: verify walks every
# row, and the anchor only needs to be newer than the last plausible tamper
# window, not fresh to the minute.
AUDIT_TICK_INTERVAL_S = 86400.0

# --- retention (spec 2026-08-26-retention-design §6) -------------------------
# How often the retention pruners run. Daily, and ordered strictly AFTER the
# audit tick in the same monitor tick: the fresh anchor is emitted before
# retention can touch the events table.
RETENTION_TICK_INTERVAL_S = 86400.0


class PersistFailed(Exception):
    """A _persist failure, tagged with the stage that broke.

    _persist appends to the journal first and independently of the database, so
    a DuckDB failure (disk full, PRIMARY KEY conflict) still leaves the event in
    the journal while a journal failure loses it outright. The stage is what
    lets the outage report say which of the two is actually down instead of
    asserting both are.
    """

    def __init__(self, stage: str, cause: BaseException) -> None:
        super().__init__(f"{stage}: {cause!r}")
        self.stage = stage
        self.cause = cause


def _persistence_outage_detail(stage: str | None) -> str:
    """What is actually lost, given which stage of _persist failed."""
    if stage == "journal":
        return "neither the journal nor the database is recording events"
    if stage == "database":
        return "the database is not recording events (the journal still has them)"
    return "events are not being recorded"


def backoff_delay(
    attempt: int,
    *,
    base: float = RESTART_BASE_DELAY_S,
    cap: float = RESTART_MAX_DELAY_S,
) -> float:
    """Delay before restart number ``attempt`` (1-based): base * 2^(n-1), capped."""
    exponent = max(0, attempt - 1)
    return min(base * (2.0**exponent), cap)


class _PendingCommand:
    """One in-flight command awaiting its command_result. First fulfillment wins."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        # What the sender sees if nobody fulfills before its wait expires.
        self.result: dict[str, Any] = {"status": "timeout"}

    def fulfill(self, result: dict[str, Any]) -> None:
        with self._lock:
            if self._event.is_set():
                return  # already fulfilled; a later worker_died/late result loses
            self.result = result
            self._event.set()

    def wait(self, timeout_s: float) -> bool:
        return self._event.wait(timeout_s)


class _WorkerProc:
    def __init__(self, spec: WorkerSpec, proc: subprocess.Popen[bytes]) -> None:
        self.spec = spec
        self.proc = proc
        self.threads: list[threading.Thread] = []
        # Serializes command writes to this incarnation's stdin (design §5).
        self.stdin_lock = threading.Lock()
        # Per-INCARNATION pending map, keyed by request_id: fulfillment identity
        # is the pipe (only _read_stdout(self) consults it), so a hostile worker
        # can never fulfill another worker's requests and a respawned
        # incarnation structurally starts empty.
        self.pending: dict[str, _PendingCommand] = {}
        self.pending_lock = threading.Lock()
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
        audit_tick_interval_s: float = AUDIT_TICK_INTERVAL_S,
        retention_tick_interval_s: float = RETENTION_TICK_INTERVAL_S,
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
        self._audit_tick_interval_s = audit_tick_interval_s
        # None -> the audit tick runs on the first monitor tick after start.
        self._last_audit_tick_mono: float | None = None
        self._retention_tick_interval_s = retention_tick_interval_s
        # None -> the retention tick runs on the first monitor tick after start.
        self._last_retention_tick_mono: float | None = None
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
        self._first_sighting: FirstSightingTracker | None = None
        self._anomaly_detector: AnomalyDetector | None = None
        if config.anomaly.enabled:
            self._first_sighting = FirstSightingTracker()
            # The detector must never aggregate its own signals (spec §2.1).
            anomaly_sub = self._router.subscribe(
                name="anomaly",
                queue_size=4096,
                drop_policy=DropPolicy.drop_oldest_non_critical,
                filter_fn=lambda ev: ev.module != "anomaly_detector",
            )
            self._anomaly_detector = AnomalyDetector(
                db=self._db,
                tracker=self._first_sighting,
                config=config.anomaly,
                subscription=anomaly_sub,
                emit=self._dispatch,
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
        if self._first_sighting is not None:
            self._first_sighting.load(self._db)
        # Fail-open audit appends escalate through the supervisor's event path.
        set_failure_listener(self._report_audit_log_failing)
        if self._anomaly_detector is not None:
            self._anomaly_detector.load_checkpoints()
            self._anomaly_detector.start()
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
        (alert fan-out MUST stay on them) and the worker monitor thread. Never
        raises: both callers are loops that must survive one bad event.

        Publishing is deliberately *not* guarded by the alert path. The rule
        engine can fail on a live system (e.g. two workers racing on the same
        dedup_key), and losing the event itself — unstored, unprojected,
        invisible — is far worse than losing the alert it would have raised.
        """
        try:
            ev = enrich(ev)
            if self._first_sighting is not None:
                self._first_sighting.observe(ev)
            self._run_alert_path(ev)
        except Exception as exc:
            log.error(
                "alert path failed for %s event from %s (publishing anyway): %r",
                ev.action,
                ev.module,
                exc,
            )
        try:
            self._router.publish(ev)
        except RouterFull as exc:
            log.error("router full, dropping %s event from %s: %r", ev.action, ev.module, exc)
        except Exception as exc:
            log.error("failed to publish %s event from %s: %r", ev.action, ev.module, exc)

    def _run_alert_path(self, ev: Event) -> None:
        """Run the rules and fan the alerts out on the *calling* thread.

        Staying on the caller's thread is load-bearing: the evidence collector
        captures under the worker fan-out thread and MUST run before the
        notifier listeners see the alert.
        """
        for alert in self._rule_engine.process(ev):
            if self._evidence_collector is not None:
                # MUST precede the notifier listeners (evidence first, notify second).
                self._evidence_collector.capture(alert, ev)
            for fn in list(self._alert_listeners):
                try:
                    fn(alert)
                except Exception as exc:
                    log.warning("alert listener raised: %r", exc)

    def stop(self, timeout: float = 5.0) -> None:
        """Shut everything down within roughly ``timeout`` seconds.

        Every blocking step below is clamped to what is left of the budget, so
        a stuck reader thread or a monitor caught mid-respawn delays shutdown
        but cannot hang it.
        """
        deadline = time.monotonic() + timeout

        def remaining() -> float:
            return max(0.0, deadline - time.monotonic())

        # Order matters: the monitor has to be stopped BEFORE any worker is
        # terminated, or it would helpfully restart them all mid-shutdown.
        self._stop.set()
        # Immediately after setting _stop: every in-flight command is answered
        # now, not after its own timeout — a blocked IPC thread must not outlive
        # the daemon. list() is atomic; send_worker_command fast-fails once
        # _stop is set, so entries cannot keep accumulating behind this sweep.
        for wp in list(self._procs):
            self._fail_pending(wp, {"status": "worker_unavailable", "detail": "shutting_down"})
        monitor = self._monitor_thread
        if monitor is not None:
            monitor.join(timeout=min(remaining(), 2.0))
            if monitor.is_alive():
                log.warning("worker monitor did not stop within the shutdown budget")
        # Taking the lock here also closes the last respawn window: a monitor
        # caught mid-respawn holds it, so the snapshot below sees the new proc.
        # If it cannot be taken in time we snapshot anyway -- list() is atomic,
        # and _respawn kills its own child when it finds _stop set after the
        # spawn, so a proc that lands after this snapshot still gets cleaned up.
        locked = self._procs_lock.acquire(timeout=remaining()) if remaining() else False
        try:
            procs = list(self._procs)
        finally:
            if locked:
                self._procs_lock.release()
        if not locked:
            log.warning("shutdown budget expired waiting for the worker list lock")
        for wp in procs:
            with contextlib.suppress(Exception):
                wp.proc.terminate()
        for wp in procs:
            try:
                wp.proc.wait(timeout=remaining())
            except subprocess.TimeoutExpired:
                wp.proc.kill()
            for t in wp.threads:
                t.join(timeout=remaining())
        # After the workers (no more observe() traffic can queue sightings) and
        # before _db.close(): stop() runs the final first-sighting flush.
        if self._anomaly_detector is not None:
            self._anomaly_detector.stop(timeout=remaining())
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
        """Persist every routed event; the only thread that writes the event store.

        (The anomaly detector thread writes its own disjoint tables --
        first_seen and metric_baseline -- on its own per-thread cursor.)

        _persist raises for ordinary reasons -- events_enriched.event_id is a
        PRIMARY KEY so a duplicate id conflicts, journal I/O fails, the disk
        fills, DuckDB hits a transaction conflict. Letting any of those escape
        would kill this thread, and with it every subsequent write to the
        database and the journal, silently: the daemon keeps running, workers
        keep emitting, and nothing is ever stored again.

        Health is tracked over the last PERSIST_FAILURE_WINDOW outcomes, not as
        a consecutive streak, so a sustained *partial* outage -- half the events
        failing, or nine in every ten -- is reported instead of being reset to
        zero by the occasional success.
        """
        # True == that event failed to persist. maxlen makes this the last N.
        outcomes: deque[bool] = deque(maxlen=PERSIST_FAILURE_WINDOW)
        last_alert_at: float | None = None
        while not self._stop.is_set():
            try:
                ev = sub.get_nowait()
            except QueueEmpty:
                time.sleep(0.01)
                continue
            try:
                self._persist(ev)
            except Exception as exc:
                outcomes.append(True)
                failures = sum(outcomes)
                log.error(
                    "failed to persist %s event %s from %s (%d of the last %d failed): %r",
                    ev.action,
                    ev.event_id,
                    ev.module,
                    failures,
                    len(outcomes),
                    exc,
                )
                now = time.monotonic()
                cooled = last_alert_at is None or now - last_alert_at >= PERSIST_ALERT_COOLDOWN_S
                if failures >= PERSIST_FAILURE_ALERT_THRESHOLD and cooled:
                    window = len(outcomes)
                    # Both guards matter. The report is itself an event: it goes
                    # back through the router into this loop and fails to persist
                    # like everything else. Clearing the window means the next
                    # report needs a fresh THRESHOLD failures -- of which the
                    # report's own is at most one -- so it cannot sustain itself,
                    # and the cooldown bounds how often a busy event stream can
                    # re-trigger it while the outage continues.
                    outcomes.clear()
                    last_alert_at = now
                    self._report_persistence_down(failures, window, exc)
            else:
                outcomes.append(False)
            for fn in list(self._listeners):
                try:
                    fn(ev)
                except Exception as exc:
                    log.warning("listener raised: %r", exc)

    def _report_persistence_down(self, failures: int, window: int, exc: BaseException) -> None:
        """Surface a persistence outage as an event instead of a log line nobody reads.

        The event cannot be stored either -- persistence is what is broken --
        but it still reaches the alert path and the live listeners (IPC, tray),
        which is the whole point: a monitor that has silently stopped recording
        is exactly the blind spot the user needs told about.
        """
        stage = exc.stage if isinstance(exc, PersistFailed) else None
        self._emit_supervisor_event(
            action="persistence_failing",
            severity="high",
            type_=["error"],
            message=(
                f"failed to persist {failures} of the last {window} events; "
                f"{_persistence_outage_detail(stage)}"
            ),
            raw={"failures": failures, "window": window, "stage": stage, "error": repr(exc)},
        )

    def _persist(self, ev: Event) -> None:
        payload = ev.model_dump_json()
        record = json.loads(payload)
        try:
            self._journal.append(record)
        except Exception as exc:
            raise PersistFailed("journal", exc) from exc
        # The journal already holds the event from here on: a failure below
        # costs the database row and the projection, not the record itself.
        try:
            insert_event(self._db, ev, payload)
            project(ev, self._db, boot_id=self._boot_id)
        except Exception as exc:
            raise PersistFailed("database", exc) from exc

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
        # stdin stays OPEN for ALL workers: it is the command channel
        # (worker-command-channel design §1). Workers that never read past the
        # config line are unaffected; _reap's close is the incarnation-end of
        # the channel.
        wp = _WorkerProc(spec, proc)
        wp.threads.append(threading.Thread(target=self._read_stdout, args=(wp,), daemon=True))
        wp.threads.append(threading.Thread(target=self._read_stderr, args=(wp,), daemon=True))
        for t in wp.threads:
            t.start()
        return wp

    # --- worker command channel (worker-command-channel design §5) ----------

    def send_worker_command(
        self,
        worker_name: str,
        command: str,
        args: dict[str, Any] | None = None,
        *,
        timeout_s: float = COMMAND_TIMEOUT_S,
    ) -> dict[str, Any]:
        """Send one command to a running worker and wait for its result.

        Returns the worker's ``{"status": "accepted"|"rejected", "detail"}``,
        or ``{"status": "timeout"}`` (the command may still run),
        ``{"status": "worker_died"}``, or ``{"status": "worker_unavailable",
        "detail": ...}``. Trigger-only, at-most-once: ``accepted`` means "will
        run at the next loop iteration", never "done".

        Lock discipline: ``_procs_lock`` only for the name lookup, the
        per-worker stdin lock only for serialize+write+flush, and the response
        wait holds NO supervisor lock.
        """
        if self._stop.is_set():
            return {"status": "worker_unavailable", "detail": "shutting_down"}
        with self._procs_lock:
            wp = next((p for p in self._procs if p.spec.name == worker_name), None)
        if wp is None:
            return {"status": "worker_unavailable", "detail": f"no such worker: {worker_name}"}

        request_id = uuid4().hex
        line = (
            json.dumps(
                {"command": command, "args": args or {}, "request_id": request_id},
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        entry = _PendingCommand()
        with wp.pending_lock:
            if len(wp.pending) >= MAX_INFLIGHT_COMMANDS_PER_WORKER:
                return {"status": "worker_unavailable", "detail": "too many in-flight commands"}
            wp.pending[request_id] = entry
        try:
            # Registered before stop()'s sweep could run? Re-check so an entry
            # added after the sweep cannot sit out its full timeout.
            if self._stop.is_set():
                return {"status": "worker_unavailable", "detail": "shutting_down"}
            try:
                with wp.stdin_lock:
                    stdin = wp.proc.stdin
                    if stdin is None:
                        raise BrokenPipeError("worker stdin was not captured")
                    stdin.write(line)
                    stdin.flush()
            except (BrokenPipeError, ValueError, OSError) as exc:
                # Every write-failure shape — broken pipe, a reaped/closed file
                # (ValueError), any OSError — means this incarnation cannot be
                # commanded; the monitor owns recovery.
                log.warning("cannot send %s to worker %s: %r", command, worker_name, exc)
                return {"status": "worker_unavailable", "detail": "worker stdin unwritable"}
            # The wait holds no lock; a wedged worker wedges only this caller.
            entry.wait(timeout_s)
            return dict(entry.result)
        finally:
            # Whatever the outcome — fulfilled, timeout, write failure — the
            # entry is removed here, so a wedged worker cannot wedge the channel.
            with wp.pending_lock:
                wp.pending.pop(request_id, None)

    def _fulfill_command_result(self, wp: _WorkerProc, ev: Event) -> None:
        """Fulfill a pending send from this worker's own command_result.

        Consults ONLY ``wp``'s pending map: the fulfillment identity is the
        pipe the event arrived on, so a hostile or buggy worker can never
        fulfill another worker's requests.
        """
        if ev.action != "command_result" or not isinstance(ev.raw, dict):
            return
        request_id = ev.raw.get("request_id")
        if not isinstance(request_id, str):
            return
        with wp.pending_lock:
            entry = wp.pending.get(request_id)
        if entry is None:
            # Late (post-timeout) or unknown: dispatched as an ordinary event
            # by the caller, never fulfills anything.
            log.info(
                "late or unknown command_result from worker %s (request_id=%s)",
                wp.spec.name,
                request_id,
            )
            return
        status = ev.raw.get("status")
        entry.fulfill(
            {
                "status": "accepted" if status == "accepted" else "rejected",
                "detail": str(ev.raw.get("detail", "")),
            }
        )

    def _fail_pending(self, wp: _WorkerProc, result: dict[str, Any]) -> None:
        """Fulfill every pending entry of one incarnation with *result*."""
        with wp.pending_lock:
            entries = list(wp.pending.values())
            wp.pending.clear()
        for entry in entries:
            entry.fulfill(dict(result))

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
        if (
            self._last_audit_tick_mono is None
            or now - self._last_audit_tick_mono >= self._audit_tick_interval_s
        ):
            self._last_audit_tick_mono = now
            self._audit_tick()
        # Strictly AFTER the audit tick (retention spec §6): the fresh anchor
        # is emitted before retention can touch the events table. The marker
        # is set BEFORE the run so a failing run waits a full interval.
        if self._cfg.retention.enabled and (
            self._last_retention_tick_mono is None
            or now - self._last_retention_tick_mono >= self._retention_tick_interval_s
        ):
            self._last_retention_tick_mono = now
            self._retention_tick()

    def _audit_tick(self) -> None:
        """Daily: verify the chain against the newest anchor, then re-anchor.

        The anchor rides the normal event path, so it lands in the journal —
        outside the database an attacker with DB access can rewrite — which is
        what lets verify catch suffix truncation (spec §6a). Ordering matters:
        verify runs FIRST, with the newest anchor, and a failed verify
        suppresses the fresh anchor — anchoring a truncated head would bless
        the shortened chain and launder the tamper. _db access happens on the
        monitor thread; Database is thread-safe via thread-local cursors.
        """
        try:
            verification = verify_audit_chain(self._db, anchor=newest_anchor(self._db))
            if not verification.ok:
                self._emit_supervisor_event(
                    action="audit_chain_broken",
                    severity="high",
                    type_=["error"],
                    message=(
                        f"audit chain verification FAILED at seq "
                        f"{verification.first_bad_seq} ({verification.reason})"
                    ),
                    raw=verification.as_dict(),
                )
                return  # a broken chain must not be re-anchored
            head = self._db.query(
                "SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if head is not None:
                self._emit_supervisor_event(
                    action="audit_head",
                    severity="info",
                    type_=["info"],
                    message=f"audit chain head seq={head[0]}",
                    raw={"seq": head[0], "row_hash": head[1]},
                )
        except Exception as exc:
            log.error("audit tick failed: %r", exc)

    def _retention_tick(self) -> None:
        """Daily: run the retention pruners; audit deletions, surface errors.

        Retention spec §6. Real deletions produce exactly ONE audit row per
        run (a no-op run writes nothing); a run with errors emits a
        medium-severity ``retention_failed`` supervisor event — retention
        failure is a maintenance problem, not an intrusion signal, and a
        persistently failing run repeats the event daily, which is the
        desired nagging. The whole body catches like ``_audit_tick``: the
        monitor thread must outlive any single failure.
        """
        try:
            collector = self._evidence_collector
            report = run_retention(
                self._db,
                cfg=self._cfg.retention,
                journal_dir=self._cfg.storage.journal_dir,
                evidence_root=self._cfg.storage.evidence_dir,
                now=datetime.now(UTC),
                capture_lock=collector.capture_lock if collector is not None else None,
            )
            if report.any_deletions:
                details: dict[str, Any] = {
                    "events_deleted": report.events_deleted,
                    "journal_files_deleted": report.journal_files_deleted,
                    "alerts_deleted": report.alerts_deleted,
                    "evidence_blobs_deleted": report.evidence_blobs_deleted,
                    "pruned_shas": report.pruned_shas[:50],
                    "skipped_files": report.skipped_files,
                    "quota_overage_bytes": report.quota_overage_bytes,
                }
                if len(report.pruned_shas) > 50:
                    details["more"] = len(report.pruned_shas) - 50
                append_audit(
                    self._cfg.storage.db_path,
                    actor="auto:retention",
                    action="retention_pruned",
                    target="retention:daily",
                    details=details,
                )
            if report.errors:
                log.error("retention run had errors: %s", "; ".join(report.errors))
                message = "; ".join(report.errors[:5])
                if len(report.errors) > 5:
                    message += f" and {len(report.errors) - 5} more"
                self._emit_supervisor_event(
                    action="retention_failed",
                    severity="medium",
                    type_=["error"],
                    message=message,
                    raw={"errors": report.errors[:20]},
                )
        except Exception as exc:
            log.error("retention tick failed: %r", exc)

    def _report_audit_log_failing(self, failures: int, window: int) -> None:
        self._emit_supervisor_event(
            action="audit_log_failing",
            severity="high",
            type_=["error"],
            message=f"failed to write {failures} of the last {window} audit rows",
            raw={"failures": failures, "window": window},
        )

    def _handle_dead_worker(self, index: int, wp: _WorkerProc, rc: int, now: float) -> None:
        if not wp.died_reported:
            wp.died_reported = True
            # Reap first so the worker's final events reach the router before
            # worker_died does, and so the reader threads never outlive the child.
            self._reap(wp)
            # After _reap (any final command_result has been read), before any
            # respawn: the incarnation's pending senders learn their worker died
            # at monitor-poll latency instead of sitting out their timeouts.
            self._fail_pending(wp, {"status": "worker_died"})
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
            if self._stop.is_set():
                # stop() raced past the pre-spawn check above and may already
                # have snapshotted the worker list: kill our own child rather
                # than leave it running past shutdown.
                with contextlib.suppress(Exception):
                    new.proc.terminate()
                log.info("discarded respawn of worker %s: shutting down", old.spec.name)
                return
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
            # would kill that thread with a ValueError, so leave the fds alone.
            # stop() will not pick them up either: a respawn replaces this
            # _WorkerProc in _procs and the shutdown snapshot only sees the
            # current generation. They are released when the straggler thread
            # finally returns and drops the last reference to the dead Popen.
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
            except Exception as exc:
                log.error("worker %s emitted invalid event: %r", wp.spec.name, exc)
                continue
            # Fulfillment first, then the ordinary dispatch: command_result
            # events also land in events_enriched like everything else.
            self._fulfill_command_result(wp, ev)
            # Same path the monitor's own events take, on this reader thread.
            self._dispatch(ev)

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
