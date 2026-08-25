"""Auto-capture evidence on high-severity alerts, before notify (spec §3.6).

Runs in-process on the supervisor's worker fan-out thread. All capture is under one lock
(concurrent worker threads), best-effort, and hard-bounded so it can never hang or DoS the
event pipeline.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inspectord.audit.log import append_audit
from inspectord.cases import store as cases_store
from inspectord.evidence.capture import _MAX_FILE_BYTES, read_capture
from inspectord.evidence.netsnapshot import network_snapshot
from inspectord.evidence.store import ForensicStore
from inspectord.schemas.alert import Alert
from inspectord.schemas.event import Event, Severity
from inspectord.storage.db import Database

log = logging.getLogger(__name__)

_TRIGGER = {Severity.high, Severity.critical}
_MAX_FILES = 16
_MAX_TOTAL_BYTES = 128 * 1024 * 1024
_CAPTURE_DEADLINE_S = 5.0
# _MAX_FILE_BYTES is single-sourced from capture.py so the per-file cap and the `truncated`
# flag derived from it can never drift apart.


def implicated_paths(alert: Alert, event: Event) -> list[str]:
    paths: list[str] = []
    for p in ((event.file or {}).get("path"), (event.persistence or {}).get("source_path")):
        if isinstance(p, str) and p:
            paths.append(p)
    for ent in alert.entities:
        if ent.kind == "file" and ent.key:
            paths.append(ent.key)
    seen: set[str] = set()
    deduped: list[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped


class EvidenceCollector:
    def __init__(self, db_path: Path, store: ForensicStore) -> None:
        self._db_path = db_path
        self._store = store
        self._lock = threading.Lock()

    def capture(self, alert: Alert, event: Event) -> None:
        if alert.severity not in _TRIGGER:
            return
        with self._lock:
            try:
                self._capture(alert, event)
            except Exception:  # never propagate into the fan-out
                log.exception("evidence capture failed for alert %s", alert.alert_id)

    def _insert(
        self,
        db: Database,
        case_id: str,
        kind: str,
        sha: str,
        original_path: str,
        meta: dict[str, Any],
    ) -> None:
        db.execute(
            "INSERT INTO case_evidence (case_id, kind, sha256, original_path, captured_at, "
            "meta_json) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            [case_id, kind, sha, original_path, datetime.now(tz=UTC), json.dumps(meta)],
        )

    def _capture(self, alert: Alert, event: Event) -> None:
        with Database(self._db_path) as db:
            if db.query("SELECT 1 FROM case_alert WHERE alert_id = ?", [alert.alert_id]).fetchall():
                return  # already captured (idempotent; the lock makes check+create atomic)
            case_id = cases_store.open_case(db, alert_id=alert.alert_id, title=alert.rendered.short)
            # open_case has committed: the auto-case exists even if capture below fails.
            append_audit(
                self._db_path,
                actor="auto:evidence_collector",
                action="case_opened",
                target=f"case:{case_id}",
                details={"auto": True, "alert_id": alert.alert_id},
            )
            aid = alert.alert_id  # provenance: every blob records the triggering alert (§3.6)
            net_ok = bundle_ok = False
            # 1) network snapshot first (cheap, always bounded)
            try:
                snap = network_snapshot()
                sha = self._store.put(json.dumps(snap).encode())
                self._insert(
                    db,
                    case_id,
                    "net_state",
                    sha,
                    "",
                    {
                        "socket_count": len(snap["sockets"]),
                        "truncated": snap["truncated"],
                        "alert_id": aid,
                    },
                )
                net_ok = True
            except Exception:
                log.exception("evidence: net snapshot failed")
            # 2) in-memory event bundle
            try:
                blob = json.dumps(event.model_dump(mode="json", exclude_none=True)).encode()
                sha = self._store.put(blob)
                self._insert(
                    db,
                    case_id,
                    "event_bundle",
                    sha,
                    "",
                    {"event_id": event.event_id, "alert_id": aid},
                )
                bundle_ok = True
            except Exception:
                log.exception("evidence: event bundle failed")
            # 3) implicated files (hard-bounded)
            n_files, total, partial = 0, 0, False
            deadline = time.monotonic() + _CAPTURE_DEADLINE_S
            for path in implicated_paths(alert, event):
                if (
                    n_files >= _MAX_FILES
                    or total >= _MAX_TOTAL_BYTES
                    or time.monotonic() > deadline
                ):
                    partial = True
                    break
                try:
                    data = read_capture(path, max_bytes=_MAX_FILE_BYTES)
                    if data is None:
                        continue
                    sha = self._store.put(data)
                    self._insert(
                        db,
                        case_id,
                        "file",
                        sha,
                        path,
                        {
                            "size": len(data),
                            "truncated": len(data) >= _MAX_FILE_BYTES,
                            "alert_id": aid,
                        },
                    )
                    n_files += 1
                    total += len(data)
                except Exception:
                    log.exception("evidence: file capture failed for %r", path)
            # Summarize only what actually landed (net/bundle capture is best-effort).
            parts = [f"{n_files} file(s)"]
            if net_ok:
                parts.append("net snapshot")
            if bundle_ok:
                parts.append("event bundle")
            summary = "captured " + ", ".join(parts)
            if partial:
                summary += " (partial — bounds hit)"
            cases_store.append_timeline(db, case_id=case_id, kind="evidence_captured", text=summary)
