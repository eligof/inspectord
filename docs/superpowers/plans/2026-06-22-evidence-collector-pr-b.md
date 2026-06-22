# Evidence collector PR-B (collector + wiring + panel) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. TDD throughout. PR-A (forensic store, `read_capture`, `network_snapshot`, migration 0007, `evidence_dir`) is merged.

**Goal:** Wire the evidence collector — on a `{high, critical}` alert, BEFORE notify, idempotently auto-create a Case and capture a network snapshot + event bundle + implicated files into the forensic store, shown in a Case-detail Evidence section.

**Architecture:** An in-process `EvidenceCollector` the supervisor calls **directly in both alert fan-out sites** (`_read_stdout` line ~194 and `_inject_for_test` line ~104), passing the **live `Event`** (the triggering event is not yet in `events_enriched`). All capture runs under one `threading.Lock` (worker threads fan out concurrently), best-effort and hard-bounded.

**Tech Stack:** Python 3.14, the PR-A evidence units, the cases store, DuckDB, pytest.

**Spec:** `docs/superpowers/specs/2026-06-22-evidence-collector-design.md` — §2 (threading), §3.5 implicated_paths, §3.6 collector, §5 wiring, §6 panel, §9 DB concurrency, §4.2 coverage.

**Gates:** `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` · `.venv/bin/ruff check inspectord inspectorctl tests` · `.venv/bin/ruff format --check inspectord inspectorctl tests` · `.venv/bin/mypy inspectord`

**Branch:** `feat/evidence-collector` (checked out; spec + plan ride along).

**Key facts:**
- `Severity` (`inspectord/schemas/event.py:22`) has `info/low/medium/high/critical`. Gate = `alert.severity in {Severity.high, Severity.critical}`. `Alert` has `alert_id`, `event_ids`, `entities` (`EntityRef.kind`/`.key`), `severity`, `rendered.short`.
- `cases.store`: `open_case(db, *, alert_id, title=None) -> str`, private `_append_event(db, case_id, ts, seq, kind, text)`, `_case_exists`, `get_case(db, *, case_id) -> dict|None` (returns case/alerts/timeline).
- PR-A units: `from inspectord.evidence.store import ForensicStore`, `from inspectord.evidence.capture import read_capture`, `from inspectord.evidence.netsnapshot import network_snapshot`.
- `case_evidence(case_id, kind, sha256, original_path NOT NULL DEFAULT '', captured_at, meta_json)`.
- Two fan-out sites in `supervisor.py` (`_read_stdout` ~194, `_inject_for_test` ~104) share the `for alert in rule_engine.process(ev): for fn in alert_listeners: fn(alert)` shape.

---

## Task 1: cases store — `append_timeline` + `get_case` returns `evidence`

**Files:** Modify `inspectord/cases/store.py`, `inspectord/cases/ipc_handlers.py`; Test `tests/cases/test_store.py`, `tests/cases/test_ipc_handlers.py`.

- [ ] **Step 1: Write failing tests** in `tests/cases/test_store.py`:
  - `append_timeline(db, case_id=c, kind="evidence_captured", text="x")` adds a `case_event` row with that kind (open a case first; assert via `get_case(...)["timeline"]`); no-op on a missing case.
  - `get_case` now returns an `evidence` key: seed a `case_evidence` row (raw INSERT) for the case → `get_case(...)["evidence"]` is a list with `{kind, sha256, original_path, captured_at, meta}` (meta = decoded `meta_json` dict or `{}`); a case with no evidence → `evidence == []`.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** in `inspectord/cases/store.py`:
```python
def append_timeline(db: Database, *, case_id: str, kind: str, text: str | None = None) -> None:
    """Append a case_event of a custom kind (e.g. 'evidence_captured'). No-op if case missing."""
    if not _case_exists(db, case_id):
        return
    _append_event(db, case_id, datetime.now(tz=UTC), 0, kind, text)
```
  In `get_case`, after building `timeline`, add an evidence query + key:
```python
    erows = db.query(
        "SELECT kind, sha256, original_path, captured_at, meta_json "
        "FROM case_evidence WHERE case_id = ? ORDER BY captured_at, kind, sha256",
        [case_id],
    ).fetchall()
    evidence = [
        {"kind": e[0], "sha256": e[1], "original_path": e[2], "captured_at": e[3],
         "meta": json.loads(e[4]) if e[4] else {}}
        for e in erows
    ]
```
  and add `"evidence": evidence` to the returned dict. (`import json` if not already imported.)
- [ ] **Step 4: Update `handle_get_case`** (`inspectord/cases/ipc_handlers.py`) to ISO-render the evidence rows' `captured_at` (mirror how it renders alert `ts`/timeline `ts`): after the existing loops, `for ev in case["evidence"]: ev["captured_at"] = _iso(ev["captured_at"])`. Add a test in `tests/cases/test_ipc_handlers.py` asserting `handle_get_case` returns evidence with an ISO-string `captured_at`.
- [ ] **Step 5: Run tests + gates — expect pass.** Commit. `feat(cases): append_timeline + evidence in get_case`.

---

## Task 2: `implicated_paths` + `EvidenceCollector`

**Files:** Create `inspectord/evidence/collector.py`; Test `tests/evidence/test_collector.py`.

- [ ] **Step 1: Write failing tests** `tests/evidence/test_collector.py`. Helpers: a migrated `db_path` (`run_migrations`), a `_seed_alert(db_path, alert_id, severity, short)` (raw INSERT into `alerts`, mirror `tests/cases/test_store.py`), a small `Alert`/`Event` builder, and a `ForensicStore(tmp_path/"ev")`. Cover:
  - **severity gate**: `capture(low_alert, ev)` writes nothing (no case, no evidence).
  - **idempotent under concurrency**: two threads call `capture(high_alert, ev)` with the same `alert_id` → exactly one case, and the case linked once (assert via `case_alert` count == 1). (Exercise the lock.)
  - **net + event_bundle always captured**: `capture(high_alert, ev)` with no implicated files → a case exists with a `net_state` row and an `event_bundle` row in `case_evidence`.
  - **file capture**: an event whose `file.path` is a readable tmp file → a `file` row with `original_path` set and the blob in the store; a missing/denied path is skipped (best-effort) without aborting net/bundle/case.
  - **bounds**: with `max_files=1`, two implicated readable files → only one `file` row + the timeline summary notes a partial capture (assert the `evidence_captured` event text contains "partial").
  - **timeline**: an `evidence_captured` case_event exists after capture.
  - `implicated_paths(alert, event)` unit: union of `event.file["path"]`, `event.persistence["source_path"]`, and `alert.entities` kind=="file" key; de-duped; empty when none.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** `inspectord/evidence/collector.py`:
```python
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

from inspectord.cases import store as cases_store
from inspectord.evidence.capture import read_capture
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
_MAX_FILE_BYTES = 32 * 1024 * 1024


def implicated_paths(alert: Alert, event: Event) -> list[str]:
    paths: list[str] = []
    for p in ((event.file or {}).get("path"), (event.persistence or {}).get("source_path")):
        if isinstance(p, str) and p:
            paths.append(p)
    for ent in alert.entities:
        if ent.kind == "file" and ent.key:
            paths.append(ent.key)
    seen: set[str] = set()
    return [p for p in paths if not (p in seen or seen.add(p))]


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

    def _insert(self, db: Database, case_id: str, kind: str, sha: str,
                original_path: str, meta: dict[str, Any]) -> None:
        db.execute(
            "INSERT INTO case_evidence (case_id, kind, sha256, original_path, captured_at, "
            "meta_json) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            [case_id, kind, sha, original_path, datetime.now(tz=UTC), json.dumps(meta)],
        )

    def _capture(self, alert: Alert, event: Event) -> None:
        with Database(self._db_path) as db:
            if db.query(
                "SELECT 1 FROM case_alert WHERE alert_id = ?", [alert.alert_id]
            ).fetchall():
                return  # already captured (idempotent; the lock makes check+create atomic)
            case_id = cases_store.open_case(
                db, alert_id=alert.alert_id, title=alert.rendered.short
            )
            captured: list[str] = []
            # 1) network snapshot first (cheap, always bounded)
            try:
                snap = network_snapshot()
                sha = self._store.put(json.dumps(snap).encode())
                self._insert(db, case_id, "net_state", sha, "",
                             {"socket_count": len(snap["sockets"]), "truncated": snap["truncated"]})
                captured.append("net")
            except Exception:
                log.exception("evidence: net snapshot failed")
            # 2) in-memory event bundle
            try:
                blob = json.dumps(event.model_dump(mode="json", exclude_none=True)).encode()
                sha = self._store.put(blob)
                self._insert(db, case_id, "event_bundle", sha, "", {"event_id": event.event_id})
                captured.append("bundle")
            except Exception:
                log.exception("evidence: event bundle failed")
            # 3) implicated files (hard-bounded)
            n_files, total, partial = 0, 0, False
            deadline = time.monotonic() + _CAPTURE_DEADLINE_S
            for path in implicated_paths(alert, event):
                if n_files >= _MAX_FILES or total >= _MAX_TOTAL_BYTES or time.monotonic() > deadline:
                    partial = True
                    break
                try:
                    data = read_capture(path, max_bytes=_MAX_FILE_BYTES)
                    if data is None:
                        continue
                    sha = self._store.put(data)
                    self._insert(db, case_id, "file", sha, path,
                                 {"size": len(data), "truncated": len(data) >= _MAX_FILE_BYTES})
                    n_files += 1
                    total += len(data)
                    captured.append("file")
                except Exception:
                    log.exception("evidence: file capture failed for %r", path)
            summary = f"captured {n_files} file(s), net snapshot, event bundle"
            if partial:
                summary += " (partial — bounds hit)"
            cases_store.append_timeline(db, case_id=case_id, kind="evidence_captured", text=summary)
```
- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit.** `feat(evidence): EvidenceCollector + implicated_paths`.

---

## Task 3: Supervisor wiring + integration test (the DB-concurrency proof)

**Files:** Modify `inspectord/supervisor.py`; Test `tests/test_supervisor.py`.

- [ ] **Step 1: Write a failing supervisor integration test** in `tests/test_supervisor.py` (mirror the existing `_inject_for_test` tests): build a `Supervisor(dev_config(base=tmp_path))`, `start()` it (no workers), and inject an event that fires a **high-severity rule** so a high alert is produced — the simplest is a `fim_watcher` `file_modified` on `/etc/sudoers` (fires `persistence.sudoers_modified`, severity high). Then assert: a row exists in `cases` (a case was auto-created), and `case_evidence` has ≥1 row for that case (net_state + event_bundle always succeed) — **proving the collector ran on the fan-out thread AND its own `Database(db_path)` connection works concurrently with the supervisor's open `self._db`**. Poll briefly (the existing tests poll). Stop the supervisor in `finally`.
```python
def test_supervisor_captures_evidence_on_high_alert(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    cfg.workers = []
    sup = Supervisor(cfg)
    sup.start()
    try:
        ev = Event(ts=datetime(2026, 6, 22, tzinfo=UTC), event_id="ev-1", kind=EventKind.event,
                   category=["file"], type=["change"], action="file_modified",
                   severity=Severity.info, module="fim_watcher", file={"path": "/etc/sudoers"})
        sup._inject_for_test(ev)
        deadline = time.monotonic() + 3.0
        ev_rows: list = []
        while time.monotonic() < deadline:
            with Database(cfg.storage.db_path) as db:
                cases = db.query("SELECT case_id FROM cases").fetchall()
                if cases:
                    ev_rows = db.query("SELECT kind FROM case_evidence").fetchall()
                    if ev_rows:
                        break
            time.sleep(0.05)
        assert ev_rows, "expected case_evidence rows from the high-sev alert"
        kinds = {r[0] for r in ev_rows}
        assert "net_state" in kinds and "event_bundle" in kinds
    finally:
        sup.stop(timeout=5.0)
```
  **NOTE (de-risked):** concurrent read-write `Database(db_path)` connections were verified to coexist with an open `self._db` (a second connection inserts fine), so this test should pass. The collector also `log.exception`s any failure — if the test unexpectedly shows no evidence rows, check the captured logs: a DuckDB lock/IO error would mean the second connection failed, in which case STOP and report BLOCKED (fallback: pass `self._db` into the collector under the lock). Do not silently work around it.
- [ ] **Step 2: Run — expect failure** (collector not wired).
- [ ] **Step 3: Implement the wiring** in `inspectord/supervisor.py`:
  - `__init__`: add `self._evidence_collector: EvidenceCollector | None = None` (import `EvidenceCollector`, `ForensicStore`).
  - In `start()` (after `run_migrations`): `self._evidence_collector = EvidenceCollector(self._cfg.storage.db_path, ForensicStore(self._cfg.storage.evidence_dir))`.
  - In BOTH fan-out sites (`_inject_for_test` and `_read_stdout`), insert the capture call BEFORE the `for fn in alert_listeners` loop:
```python
                for alert in self._rule_engine.process(ev):
                    if self._evidence_collector is not None:
                        self._evidence_collector.capture(alert, ev)  # evidence BEFORE notify
                    for fn in list(self._alert_listeners):
                        try:
                            fn(alert)
                        except Exception as exc:
                            log.warning("alert listener raised: %r", exc)
```
  Add a code comment at the capture call: `# MUST precede the notifier listeners (evidence first, notify second).`
- [ ] **Step 4: Run the integration test + full suite — expect pass.** (If the DB-concurrency test fails, see the BLOCKED note above.)
- [ ] **Step 5: Commit.** `feat(supervisor): wire evidence collector before notify`.

---

## Task 4: Web — Case-detail Evidence section

**Files:** Modify `inspectorctl/web/templates/case_detail.html`; Test `tests/web/test_cases.py`.

- [ ] **Step 1: Write a failing test** in `tests/web/test_cases.py`: extend the `_get_case` mock's CASE dict with an `evidence` list, e.g. `[{"kind": "file", "sha256": "abc123…", "original_path": "/etc/sudoers", "captured_at": "2026-06-22T00:00:00", "meta": {"size": 42}}]`; assert `GET /cases/c1` renders an "Evidence" heading, the `original_path`, and the (truncated) sha; and that a malicious `original_path` `"<script>x</script>"` is HTML-escaped.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** — add an Evidence section to `case_detail.html` after the Timeline section:
```html
<h2>Evidence</h2>
{% if case.evidence %}
<table>
  <thead><tr><th>Kind</th><th>Source</th><th>Captured</th><th>Info</th><th>SHA-256</th></tr></thead>
  <tbody>
    {% for e in case.evidence %}
    <tr>
      <td>{{ e.kind }}</td>
      <td class="mono">{{ e.original_path or '—' }}</td>
      <td class="mono muted">{{ e.captured_at }}</td>
      <td class="mono muted">{{ e.meta.size if e.meta.size is defined else (e.meta.socket_count if e.meta.socket_count is defined else '') }}</td>
      <td class="mono muted">{{ e.sha256[:16] }}…</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
<p class="muted">Preserved — retrieval via export coming soon.</p>
{% else %}
<div class="empty">No evidence captured.</div>
{% endif %}
```
  (All autoescaped — no `| safe`. `case.evidence` comes through `get_case` → `handle_get_case` → the web `call`.)
- [ ] **Step 4: Run the web test + ALL gates — expect pass.** Commit. `feat(web): Case-detail Evidence section`.

---

## Self-review checklist (before handoff)
- [ ] Spec §3.5 implicated_paths (file.path + persistence.source_path + file entities) → Task 2. ✓
- [ ] Spec §3.6 collector (severity gate, lock-atomic idempotency, open_case reuse, net→bundle→files order, bounds + partial, append_timeline, best-effort) → Task 2. ✓
- [ ] Spec §5 wiring (capture before notify in BOTH fan-out sites, take live ev) → Task 3. ✓
- [ ] Spec §9 DB concurrency proven by the supervisor integration test (own connection vs self._db) — with the BLOCKED fallback documented. ✓
- [ ] Spec §6 panel (Evidence section, receipt label, autoescaped) → Task 4. ✓
- [ ] Out of scope: process-tree/env, windowed bundle, export/retrieval, audit_log, GC.
- [ ] Signature consistency: `EvidenceCollector(db_path, store).capture(alert, event)`; `implicated_paths(alert, event) -> list[str]`; `cases_store.append_timeline(db, *, case_id, kind, text=None)`; `get_case(...)["evidence"]`.
