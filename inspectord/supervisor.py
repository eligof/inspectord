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
from queue import Empty as QueueEmpty
from typing import Any

from inspectord.config import DaemonConfig, WorkerSpec
from inspectord.journal import Journal
from inspectord.log import get
from inspectord.router import DropPolicy, EventRouter
from inspectord.schemas.event import Event
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations

log = get(__name__)


class _WorkerProc:
    def __init__(self, spec: WorkerSpec, proc: subprocess.Popen[bytes]) -> None:
        self.spec = spec
        self.proc = proc
        self.threads: list[threading.Thread] = []


class Supervisor:
    def __init__(self, config: DaemonConfig) -> None:
        self._cfg = config
        self._router = EventRouter()
        self._journal = Journal(config.storage.journal_dir)
        self._db = Database(config.storage.db_path)
        self._procs: list[_WorkerProc] = []
        self._stop = threading.Event()
        self._listeners: list[Callable[[Event], None]] = []

    def start(self) -> None:
        self._db.connect()
        run_migrations(self._db)
        self._subscribe_storage()
        for spec in self._cfg.workers:
            self._spawn_worker(spec)

    def attach_listener(self, fn: Callable[[Event], None]) -> None:
        self._listeners.append(fn)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        deadline = time.monotonic() + timeout
        for wp in self._procs:
            with contextlib.suppress(Exception):
                wp.proc.terminate()
        for wp in self._procs:
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

    def _spawn_worker(self, spec: WorkerSpec) -> None:
        cmd = [sys.executable, "-m", spec.module]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(spec.config) + "\n").encode("utf-8"))
        proc.stdin.flush()
        proc.stdin.close()
        wp = _WorkerProc(spec, proc)
        wp.threads.append(threading.Thread(target=self._read_stdout, args=(wp,), daemon=True))
        wp.threads.append(threading.Thread(target=self._read_stderr, args=(wp,), daemon=True))
        for t in wp.threads:
            t.start()
        self._procs.append(wp)

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
