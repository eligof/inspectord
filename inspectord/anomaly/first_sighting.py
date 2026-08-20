"""First-sighting tracker (spec 2026-08-20-anomaly-detector-design.md §3).

``observe()`` runs synchronously on the supervisor's dispatch path for every
event: an in-memory seen-set lookup, no I/O. On a miss it stamps
``baseline.first_sighting = True`` on the event and queues a ``first_seen``
row; the anomaly detector thread flushes the queue each tick.

``Event.first_seen`` (snapshot catch-up) is deliberately NOT consulted here:
catch-up events populate the seen-set like any other, and the rule engine's
existing catch-up skip keeps them from alerting.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import NamedTuple

from inspectord.schemas.event import Event
from inspectord.storage.db import Database


class SightingKey(NamedTuple):
    category: str
    entity_kind: str
    entity_key: str


def _process_start_key(ev: Event) -> list[SightingKey]:
    proc = ev.process or {}
    ident = (proc.get("hash") or {}).get("sha256") or proc.get("executable")
    # Unenriched events (no /proc by the time we looked) carry neither; a
    # binary we cannot identify is not a sighting.
    if ident:
        return [SightingKey("process", "binary", str(ident))]
    return []


def _outbound_connection_key(ev: Event) -> list[SightingKey]:
    name = (ev.process or {}).get("name")
    dst = ev.destination or {}
    ip, port = dst.get("ip"), dst.get("port")
    if name and ip and port is not None:
        return [SightingKey("network", "proc_dest", f"{name}->{ip}:{port}")]
    return []


def _ssh_login_key(ev: Event) -> list[SightingKey]:
    ip = (ev.source or {}).get("ip")
    return [SightingKey("authentication", "login_ip", str(ip))] if ip else []


def _kmod_key(ev: Event) -> list[SightingKey]:
    name = (ev.raw or {}).get("module_name")
    return [SightingKey("driver", "kmod", str(name))] if name else []


def _suid_key(ev: Event) -> list[SightingKey]:
    f = ev.file or {}
    if f.get("setuid") is True and f.get("path"):
        return [SightingKey("file", "suid", str(f["path"]))]
    return []


def sighting_keys(ev: Event) -> list[SightingKey]:
    """Derive the sighting keys an event represents (spec §3, five starter cases)."""
    if ev.action == "process_start":
        return _process_start_key(ev)
    if ev.action == "outbound_connection":
        return _outbound_connection_key(ev)
    if ev.action == "ssh_login_succeeded":
        return _ssh_login_key(ev)
    if ev.action == "kmod_loaded":
        return _kmod_key(ev)
    if ev.module == "fim_watcher" and ev.action in ("file_created", "file_attributes_changed"):
        return _suid_key(ev)
    return []


class FirstSightingTracker:
    """Thread-safe: observe() runs on worker fan-out threads, flush() on the
    anomaly detector thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: set[SightingKey] = set()
        self._pending: list[tuple[SightingKey, datetime, str]] = []

    def load(self, db: Database) -> int:
        rows = db.query("SELECT category, entity_kind, entity_key FROM first_seen").fetchall()
        with self._lock:
            self._seen = {SightingKey(str(c), str(k), str(key)) for c, k, key in rows}
            return len(self._seen)

    def observe(self, ev: Event) -> None:
        keys = sighting_keys(ev)
        if not keys:
            return
        fresh = False
        with self._lock:
            for key in keys:
                if key in self._seen:
                    continue
                self._seen.add(key)
                self._pending.append((key, ev.ts, ev.event_id))
                fresh = True
        if fresh:
            baseline = dict(ev.baseline or {})
            baseline["first_sighting"] = True
            ev.baseline = baseline

    def flush(self, db: Database) -> int:
        """Persist queued rows. Raises on DB failure — the caller's tick wrapper
        logs it; the rows are gone, and a re-sighting after a crash is absorbed
        by INSERT OR IGNORE + alert dedup."""
        with self._lock:
            pending, self._pending = self._pending, []
        for key, ts, event_id in pending:
            db.execute(
                "INSERT OR IGNORE INTO first_seen "
                "(category, entity_kind, entity_key, first_seen_at, event_id) "
                "VALUES (?, ?, ?, ?, ?)",
                [key.category, key.entity_kind, key.entity_key, ts, event_id],
            )
        return len(pending)

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)
