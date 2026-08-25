# Audit Log PR1 (daemon) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hash-chained `audit_log` table + writer/verifier + wiring of every mutating
surface + journal head-anchoring + periodic verify + IPC read methods, per
`docs/superpowers/specs/2026-08-25-audit-log-design.md` (PR1 of 2).

**Architecture:** New `inspectord/audit/` package. `log.py` owns ONE module-level
`Database` connection + `threading.Lock`; `append_audit` does read-max→hash→INSERT
inside the lock (fail-open with rolling-window escalation), `verify_audit_chain` walks
one snapshot. Handlers call `append_audit(db_path, ...)` after success. The supervisor
emits a daily `audit_head` anchor event and runs a daily verify. Startup probes the
table's existence fatally.

**Tech Stack:** Python 3.13, DuckDB, sha256, pytest.

**Gates (before every commit):**
`.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` ·
`.venv/bin/python -m pytest -m "integration" -q` ·
`.venv/bin/ruff check inspectord inspectorctl tests` ·
`.venv/bin/ruff format --check inspectord inspectorctl tests` · `.venv/bin/mypy inspectord`

**Verified facts (do not re-derive):**
- Next free migration number is **0011** (0008 scan_run, 0009 hunt_query, 0010 anomaly).
- `journal.ZERO_HASH` exists (`inspectord/journal.py`).
- DuckDB `TIMESTAMP` returns NAIVE datetimes (`pkg_helper.py` documents it); insert
  naive UTC, hash `isoformat(sep="T", timespec="microseconds")`.
- `Database` supports `with Database(path) as db`, `.connect()`, `.query().fetchone()/
  .fetchall()`, `.execute()`; thread-local cursors inside (safe cross-thread).
- Handlers take `(*, params, db_path)` and are registered via `Method(...)` lambdas in
  `_ipc_methods` (`inspectord/__main__.py`).
- Mutating handlers to wire: alerts ack/resolve/suppress
  (`inspectord/alerts/ipc_handlers.py:75-96`), cases open/attach/note/close +
  export_case_zip/download_evidence (`inspectord/cases/ipc_handlers.py`),
  capture_baseline (`inspectord/state/ipc_handlers.py`), hunt save/delete
  (`inspectord/hunt/ipc_handlers.py:227,286`), plan_dependency_install
  (`inspectord/dependencies/ipc_handlers.py`), dep applier
  (`inspectord/dependencies/applier.py`), EvidenceCollector auto-case
  (`inspectord/evidence/collector.py`).
- Supervisor event helper: `Supervisor._emit_supervisor_event(action=..., severity=...,
  type_=..., message=..., raw=...)` (`supervisor.py:601`); periodic home:
  `_monitor_tick` (`supervisor.py:479`, runs ~1 Hz); persistence-failing pattern at
  `supervisor.py:385-425`.
- `events_enriched` columns: event_id, ts, kind, module, action, severity, payload_json.
- Handlers must call `append_audit` AFTER their own success and OUTSIDE any open
  transaction of their own connection (append uses its own connection anyway).

---

### Task 1: Migration + chained writer core

**Files:**
- Create: `inspectord/storage/migrations_data/0011_audit_log.sql`,
  `inspectord/audit/__init__.py` (empty), `inspectord/audit/log.py`
- Test: `tests/audit/__init__.py` (empty), `tests/audit/test_log.py`

- [ ] **Step 1: Migration file** `0011_audit_log.sql`:

```sql
-- Hash-chained audit log (spec 2026-08-25-audit-log-design §3).
CREATE TABLE IF NOT EXISTS audit_log (
    seq          BIGINT PRIMARY KEY,
    ts           TIMESTAMP NOT NULL,
    actor        VARCHAR NOT NULL,
    action       VARCHAR NOT NULL,
    target       VARCHAR,
    details_json VARCHAR NOT NULL,
    prev_hash    VARCHAR NOT NULL,
    row_hash     VARCHAR NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts);
```

- [ ] **Step 2: Failing tests** (`tests/audit/test_log.py`):

```python
"""Tests for the hash-chained audit log writer (spec 2026-08-25 §3/§6)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path

from inspectord.audit.log import append_audit, reset_for_tests
from inspectord.journal import ZERO_HASH
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


def _rows(db_path: Path):
    with Database(db_path) as db:
        return db.query(
            "SELECT seq, ts, actor, action, target, details_json, prev_hash, row_hash "
            "FROM audit_log ORDER BY seq"
        ).fetchall()


def setup_function(_fn) -> None:
    reset_for_tests()  # drop the module connection + counters between tests


def test_genesis_row(tmp_path):
    db_path = _fresh(tmp_path)
    seq = append_audit(db_path, actor="user:local", action="alert_acked",
                       target="alert:a1", details={})
    assert seq == 1
    rows = _rows(db_path)
    assert len(rows) == 1
    assert rows[0][6] == ZERO_HASH  # prev_hash
    assert len(rows[0][7]) == 64


def test_chain_links(tmp_path):
    db_path = _fresh(tmp_path)
    for i in range(3):
        append_audit(db_path, actor="user:local", action="case_opened",
                     target=f"case:{i}", details={"title": "t"})
    rows = _rows(db_path)
    assert [r[0] for r in rows] == [1, 2, 3]
    assert rows[1][6] == rows[0][7]
    assert rows[2][6] == rows[1][7]


def test_ts_round_trip_hash_recomputes(tmp_path):
    # Both a sub-second and a zero-microsecond ts must verify after DB re-read.
    from inspectord.audit.log import _row_hash_from_stored

    db_path = _fresh(tmp_path)
    append_audit(db_path, actor="user:local", action="a", target=None, details={})
    append_audit(db_path, actor="user:local", action="b", target="x", details={"k": 1},
                 _ts=datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC))  # zero microseconds
    for seq, ts, actor, action, target, details_json, prev_hash, row_hash in _rows(db_path):
        assert _row_hash_from_stored(
            seq=seq, ts=ts, actor=actor, action=action, target=target,
            details_json=details_json, prev_hash=prev_hash,
        ) == row_hash


def test_reopen_continues_chain(tmp_path):
    db_path = _fresh(tmp_path)
    append_audit(db_path, actor="user:local", action="a", target=None, details={})
    reset_for_tests()  # simulate daemon restart (new module connection)
    append_audit(db_path, actor="user:local", action="b", target=None, details={})
    rows = _rows(db_path)
    assert [r[0] for r in rows] == [1, 2]
    assert rows[1][6] == rows[0][7]


def test_concurrent_appends_dense_and_linked(tmp_path):
    db_path = _fresh(tmp_path)
    n = 24

    def w(i: int) -> None:
        append_audit(db_path, actor="user:local", action="hunt_query_saved",
                     target=f"hunt:{i}", details={})

    threads = [threading.Thread(target=w, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rows = _rows(db_path)
    assert [r[0] for r in rows] == list(range(1, n + 1))
    for a, b in zip(rows, rows[1:], strict=False):
        assert b[6] == a[7]


def test_unserializable_details_does_not_raise(tmp_path):
    db_path = _fresh(tmp_path)
    seq = append_audit(db_path, actor="user:local", action="a", target=None,
                       details={"path": Path("/etc")})  # not JSON-serializable natively
    assert seq == 1  # default=str kicked in, row written
```

- [ ] **Step 3: Run to verify failure** — `.venv/bin/python -m pytest tests/audit/ -v`:
`ModuleNotFoundError: inspectord.audit`.

- [ ] **Step 4: Implement `inspectord/audit/log.py`:**

```python
"""Hash-chained audit log (spec 2026-08-25-audit-log-design).

Append-only at the application layer. Each row's ``prev_hash`` is the previous
row's ``row_hash``; genesis uses ``journal.ZERO_HASH``. The chain detects
tampering with WRITTEN rows (interior edits/deletes/inserts). It cannot detect
fail-open drops (rows never written) or suffix truncation newer than the last
``audit_head`` journal anchor — see spec §8 for the honest threat model.

Concurrency: one module-owned Database connection + one module lock. Writers
never pass their own connection (a caller mid-transaction would break the
read-max-then-insert protocol). Daemon-process-only: helper processes must not
write audit_log; the seq PRIMARY KEY makes a cross-process double-append fail
loudly instead of forking the chain. No retry — a retry must re-enter the lock
and recompute seq/prev_hash.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inspectord.journal import ZERO_HASH
from inspectord.log import get
from inspectord.storage.db import Database

log = get(__name__)

# Rolling-window escalation, mirroring supervisor persistence_failing.
FAILURE_WINDOW = 20
FAILURE_ALERT_THRESHOLD = 5
FAILURE_COOLDOWN_S = 300.0

_lock = threading.Lock()
_db: Database | None = None
_db_path: Path | None = None
_outcomes: deque[bool] = deque(maxlen=FAILURE_WINDOW)
_last_alert_mono: float | None = None
_failure_listener: Callable[[int, int], None] | None = None


def set_failure_listener(cb: Callable[[int, int], None] | None) -> None:
    """Register a callback(failures, window) fired past the failure threshold."""
    global _failure_listener
    _failure_listener = cb


def reset_for_tests() -> None:
    """Drop module state (connection, counters). Test helper only."""
    global _db, _db_path, _last_alert_mono
    with _lock:
        if _db is not None:
            _db.close()
        _db = None
        _db_path = None
        _outcomes.clear()
        _last_alert_mono = None


def _conn(db_path: Path) -> Database:
    global _db, _db_path
    if _db is None or _db_path != db_path:
        if _db is not None:
            _db.close()
        _db = Database(db_path)
        _db.connect()
        _db_path = db_path
    return _db


def _canon_ts(ts: datetime) -> str:
    return ts.isoformat(sep="T", timespec="microseconds")


def _row_hash_from_stored(
    *, seq: int, ts: datetime, actor: str, action: str, target: str | None,
    details_json: str, prev_hash: str,
) -> str:
    payload = json.dumps(
        {"seq": seq, "ts": _canon_ts(ts), "actor": actor, "action": action,
         "target": target, "details": details_json, "prev_hash": prev_hash},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit(
    db_path: Path,
    *,
    actor: str,
    action: str,
    target: str | None,
    details: dict[str, Any],
    _ts: datetime | None = None,
) -> int | None:
    """Append one chained row. Returns seq, or None on a swallowed failure.

    Fail-open (spec §6): a failure here never propagates to the wrapped
    action, and the dropped row is UNDETECTABLE by verify — no seq is
    consumed. Failures escalate via the registered failure listener.
    """
    global _last_alert_mono
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"),
                              default=str)
    ts = (_ts or datetime.now(UTC)).replace(tzinfo=None)
    try:
        with _lock:
            db = _conn(db_path)
            head = db.query(
                "SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq = 1 if head is None else head[0] + 1
            prev_hash = ZERO_HASH if head is None else head[1]
            row_hash = _row_hash_from_stored(
                seq=seq, ts=ts, actor=actor, action=action, target=target,
                details_json=details_json, prev_hash=prev_hash,
            )
            db.execute(
                "INSERT INTO audit_log (seq, ts, actor, action, target, "
                "details_json, prev_hash, row_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [seq, ts, actor, action, target, details_json, prev_hash, row_hash],
            )
    except Exception as exc:
        log.error("audit append failed for %s %s: %r", action, target, exc)
        fire = False
        with _lock:
            _outcomes.append(False)
            failures = sum(1 for ok in _outcomes if not ok)
            now = time.monotonic()
            if failures >= FAILURE_ALERT_THRESHOLD and (
                _last_alert_mono is None or now - _last_alert_mono >= FAILURE_COOLDOWN_S
            ):
                _last_alert_mono = now
                fire = True
        if fire and _failure_listener is not None:
            _failure_listener(failures, FAILURE_WINDOW)
        return None
    with _lock:
        _outcomes.append(True)
    return seq
```

- [ ] **Step 5: Run tests** — `pytest tests/audit/ -v`: PASS.
- [ ] **Step 6: Full gates.** PASS.
- [ ] **Step 7: Commit**

```bash
git add inspectord/storage/migrations_data/0011_audit_log.sql inspectord/audit/ tests/audit/
git commit -m "feat(audit): migration 0011 + hash-chained append_audit"
```

---

### Task 2: verify_audit_chain

**Files:**
- Modify: `inspectord/audit/log.py`
- Test: `tests/audit/test_verify.py`

- [ ] **Step 1: Failing tests:**

```python
"""Tamper-detection tests for verify_audit_chain (spec §6/§8/§9)."""

from __future__ import annotations

from pathlib import Path

from inspectord.audit.log import append_audit, reset_for_tests, verify_audit_chain
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _fresh(tmp_path: Path) -> Path:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    db.close()
    return tmp_path / "t.duckdb"


def _seed(db_path: Path, n: int = 5) -> None:
    for i in range(n):
        append_audit(db_path, actor="user:local", action="case_opened",
                     target=f"case:{i}", details={"i": i})


def setup_function(_fn) -> None:
    reset_for_tests()


def test_clean_chain_ok(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path)
    with Database(db_path) as db:
        v = verify_audit_chain(db)
    assert v.ok and v.rows == 5 and v.first_bad_seq is None
    assert v.last_good is not None and v.last_good["seq"] == 5


def test_empty_table_ok_zero_rows(tmp_path):
    db_path = _fresh(tmp_path)
    with Database(db_path) as db:
        v = verify_audit_chain(db)
    assert v.ok and v.rows == 0


def test_edited_row_detected(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path)
    with Database(db_path) as db:
        db.execute("UPDATE audit_log SET actor='auto:evil' WHERE seq=3")
        v = verify_audit_chain(db)
    assert not v.ok and v.first_bad_seq == 3 and v.reason == "row_hash_mismatch"
    assert v.last_good is not None and v.last_good["seq"] == 2
    assert v.first_bad is not None and v.first_bad["seq"] == 3


def test_interior_delete_detected(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path)
    with Database(db_path) as db:
        db.execute("DELETE FROM audit_log WHERE seq=3")
        v = verify_audit_chain(db)
    assert not v.ok and v.first_bad_seq == 4 and v.reason == "seq_gap"


def test_inserted_row_detected(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path, 2)
    with Database(db_path) as db:
        # Forge a row 3 with a bogus hash pair.
        db.execute(
            "INSERT INTO audit_log VALUES (3, TIMESTAMP '2026-08-25 12:00:00', "
            "'user:local', 'x', NULL, '{}', 'f'||repeat('0',63), 'a'||repeat('0',63))"
        )
        v = verify_audit_chain(db)
    assert not v.ok and v.first_bad_seq == 3


def test_tail_truncation_clean_without_anchor_flagged_with_anchor(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path)
    with Database(db_path) as db:
        head = db.query(
            "SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        db.execute("DELETE FROM audit_log WHERE seq > 3")
        clean = verify_audit_chain(db)
        anchored = verify_audit_chain(db, anchor=(head[0], head[1]))
    assert clean.ok  # honest limitation: no anchor -> truncation invisible
    assert not clean.anchor_checked
    assert not anchored.ok and anchored.reason == "anchor_mismatch"
    assert anchored.anchor_checked


def test_wipe_to_empty_flagged_with_anchor(tmp_path):
    db_path = _fresh(tmp_path)
    _seed(db_path, 2)
    with Database(db_path) as db:
        head = db.query(
            "SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        db.execute("DELETE FROM audit_log")
        v = verify_audit_chain(db, anchor=(head[0], head[1]))
    assert not v.ok and v.reason == "anchor_mismatch"
```

- [ ] **Step 2: Verify failure** — ImportError on `verify_audit_chain`.

- [ ] **Step 3: Implement** (append to `inspectord/audit/log.py`):

```python
@dataclass
class AuditVerification:
    ok: bool
    rows: int
    first_bad_seq: int | None
    reason: str | None
    anchor_checked: bool
    last_good: dict[str, Any] | None
    first_bad: dict[str, Any] | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "rows": self.rows, "first_bad_seq": self.first_bad_seq,
            "reason": self.reason, "anchor_checked": self.anchor_checked,
            "last_good": self.last_good, "first_bad": self.first_bad,
        }


def _row_brief(row: tuple[Any, ...]) -> dict[str, Any]:
    return {"seq": row[0], "ts": _canon_ts(row[1]), "action": row[3]}


def verify_audit_chain(
    db: Database, *, anchor: tuple[int, str] | None = None
) -> AuditVerification:
    """Walk the whole chain in ONE snapshot query (spec §7).

    ``anchor`` is (seq, row_hash) from the newest ``audit_head`` journal
    anchor, when available: the anchored row must exist with that hash, which
    is what catches suffix truncation / full wipes (spec §6a).
    """
    rows = db.query(
        "SELECT seq, ts, actor, action, target, details_json, prev_hash, row_hash "
        "FROM audit_log ORDER BY seq"
    ).fetchall()

    def fail(bad_idx: int, reason: str) -> AuditVerification:
        return AuditVerification(
            ok=False, rows=len(rows), first_bad_seq=rows[bad_idx][0], reason=reason,
            anchor_checked=anchor is not None,
            last_good=_row_brief(rows[bad_idx - 1]) if bad_idx > 0 else None,
            first_bad=_row_brief(rows[bad_idx]),
        )

    prev_hash = ZERO_HASH
    expected_seq = 1
    for i, row in enumerate(rows):
        seq, ts, actor, action, target, details_json, row_prev, row_hash = row
        if seq != expected_seq:
            return fail(i, "seq_gap")
        if row_prev != prev_hash:
            return fail(i, "prev_hash_mismatch")
        if _row_hash_from_stored(
            seq=seq, ts=ts, actor=actor, action=action, target=target,
            details_json=details_json, prev_hash=row_prev,
        ) != row_hash:
            return fail(i, "row_hash_mismatch")
        prev_hash = row_hash
        expected_seq += 1

    result = AuditVerification(
        ok=True, rows=len(rows), first_bad_seq=None, reason=None,
        anchor_checked=anchor is not None,
        last_good=_row_brief(rows[-1]) if rows else None, first_bad=None,
    )
    if anchor is not None:
        a_seq, a_hash = anchor
        match = next((r for r in rows if r[0] == a_seq), None)
        if match is None or match[7] != a_hash:
            return AuditVerification(
                ok=False, rows=len(rows), first_bad_seq=a_seq,
                reason="anchor_mismatch", anchor_checked=True,
                last_good=None, first_bad=None,
            )
    return result
```

- [ ] **Step 4: Tests + full gates.** PASS.
- [ ] **Step 5: Commit** — `feat(audit): chain verification with journal-anchor check`

---

### Task 3: Wiring — handlers, evidence collector, dep applier

**Files:**
- Modify: `inspectord/alerts/ipc_handlers.py`, `inspectord/cases/ipc_handlers.py`,
  `inspectord/state/ipc_handlers.py`, `inspectord/hunt/ipc_handlers.py`,
  `inspectord/dependencies/ipc_handlers.py`, `inspectord/dependencies/applier.py`,
  `inspectord/evidence/collector.py`
- Test: `tests/audit/test_wiring.py`

- [ ] **Step 1: Failing tests** — one per surface. Pattern (write ALL of them; read
each handler first to build a valid success call — reuse each handler's existing test
file's seeding helpers where they exist):

```python
"""Every mutating surface writes its audit row (spec §5 catalog)."""
# For each: perform a SUCCESSFUL action via the handler, then assert the newest
# audit_log row has the cataloged action/target/actor. Example for ack_alert:

def test_ack_alert_audited(tmp_path):
    db_path = _fresh(tmp_path)
    _seed_alert(db_path, "a1")          # mirror tests/test_ipc_alerts.py seeding
    handle_ack_alert(params={"alert_id": "a1"}, db_path=db_path)
    row = _newest_audit(db_path)
    assert (row["action"], row["target"], row["actor"]) == (
        "alert_acked", "alert:a1", "user:local")

# And equivalents for: resolve_alert, suppress_alert, open_case, attach_alert,
# add_note, close_case, export_case_zip (details has "bytes"), download_evidence
# (details has "sha256"), capture_baseline (target "baseline:<kind>"),
# save_hunt_query, delete_hunt_query, plan_dependency_install
# (action dep_plan_created), and EvidenceCollector auto-case (actor
# "auto:evidence_collector", details {"auto": true, ...} — mirror the
# collector's existing test setup in tests/evidence/).
# Also one NEGATIVE test: a FAILED action (e.g. attach to a nonexistent case, or
# whatever failure mode the handler has) writes NO audit row.
```

- [ ] **Step 2: Verify failures.**

- [ ] **Step 3: Implement.** In each handler, after the success path is certain, add:

```python
from inspectord.audit.log import append_audit
...
    append_audit(db_path, actor="user:local", action="alert_acked",
                 target=f"alert:{alert_id}", details={})
```

- Actions/targets/details EXACTLY per the spec §5 catalog.
- `EvidenceCollector`: actor `auto:evidence_collector`, details
  `{"auto": True, "alert_id": ...}`; the collector knows its db_path (check its ctor).
- `applier.py`: one `dep_plan_applied` row beside its existing dep_audit write, actor
  `user:local` (the apply arrives via IPC).
- Fail-open means these calls can never break the handler — no try needed at call sites.

- [ ] **Step 4: Tests + full gates.** PASS.
- [ ] **Step 5: Commit** — `feat(audit): wire all mutating surfaces + evidence-egress reads`

---

### Task 4: Supervisor — anchors, periodic verify, failure listener; startup probe

**Files:**
- Modify: `inspectord/supervisor.py`, `inspectord/__main__.py`
- Modify: `inspectord/audit/log.py` (add `assert_audit_table`)
- Test: `tests/audit/test_supervisor_integration.py` (or extend the existing
  supervisor test file if its fixtures fit better — check `tests/` for the
  supervisor test module first)

- [ ] **Step 1: Failing tests:**

```python
def test_assert_audit_table_raises_when_missing(tmp_path):
    # DB without migrations
    db = Database(tmp_path / "bare.duckdb"); db.connect(); db.close()
    with pytest.raises(RuntimeError, match="audit_log"):
        assert_audit_table(tmp_path / "bare.duckdb")


def test_assert_audit_table_ok_after_migrations(tmp_path):
    db_path = _fresh(tmp_path)
    assert_audit_table(db_path)  # no raise


def test_audit_tick_emits_anchor_and_runs_verify(...):
    # Instantiate Supervisor with the test config used by existing supervisor
    # tests; pass audit_tick_interval_s=0; seed 2 audit rows; run one
    # _monitor_tick; assert an audit_head event was dispatched with
    # raw={"seq": 2, "row_hash": <64-hex>}; tamper a row; run another tick;
    # assert an audit_chain_broken high-severity event.


def test_failure_listener_emits_audit_log_failing(...):
    # Register supervisor's listener; force FAILURE_ALERT_THRESHOLD failures
    # (monkeypatch audit.log._conn to raise); assert one audit_log_failing high
    # event, and cooldown suppresses a second burst.
```

(Adapt to the real supervisor test fixtures — read them first; the assertions above
are the contract.)

- [ ] **Step 2: Verify failures.**

- [ ] **Step 3: Implement.**

`inspectord/audit/log.py`:

```python
def assert_audit_table(db_path: Path) -> None:
    """Startup probe (spec §6): a missing table is fatal, not fail-open fodder."""
    with Database(db_path) as db:
        try:
            db.query("SELECT seq FROM audit_log LIMIT 1").fetchall()
        except Exception as exc:
            raise RuntimeError(
                "audit_log table missing or unreadable - migration drift; "
                "refusing to run with audit fail-open masking it"
            ) from exc
```

`inspectord/supervisor.py`:
- Constant `AUDIT_TICK_INTERVAL_S = 86400.0` beside the other policy constants; ctor
  param `audit_tick_interval_s: float = AUDIT_TICK_INTERVAL_S` (mirroring the restart
  tunables); instance attr `self._last_audit_tick_mono: float | None = None` (None →
  run on the first tick after start).
- In `_monitor_tick`, after the existing work:

```python
        if (self._last_audit_tick_mono is None
                or now - self._last_audit_tick_mono >= self._audit_tick_interval_s):
            self._last_audit_tick_mono = now
            self._audit_tick()
```

```python
    def _audit_tick(self) -> None:
        """Daily: anchor the audit head into the journal + verify the chain."""
        try:
            head = self._db.query(
                "SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if head is not None:
                self._emit_supervisor_event(
                    action="audit_head", severity="info", type_=["info"],
                    message=f"audit chain head seq={head[0]}",
                    raw={"seq": head[0], "row_hash": head[1]},
                )
            verification = verify_audit_chain(self._db, anchor=None)
            if not verification.ok:
                self._emit_supervisor_event(
                    action="audit_chain_broken", severity="high", type_=["error"],
                    message=(
                        f"audit chain verification FAILED at seq "
                        f"{verification.first_bad_seq} ({verification.reason})"
                    ),
                    raw=verification.as_dict(),
                )
        except Exception as exc:
            log.error("audit tick failed: %r", exc)
```

  (`self._db` access happens on the monitor thread — `Database` is thread-safe via
  thread-local cursors per the #127 fix.)
- In `Supervisor.start()` (mirror where other wiring happens), register:

```python
        set_failure_listener(self._report_audit_log_failing)
```

```python
    def _report_audit_log_failing(self, failures: int, window: int) -> None:
        self._emit_supervisor_event(
            action="audit_log_failing", severity="high", type_=["error"],
            message=f"failed to write {failures} of the last {window} audit rows",
            raw={"failures": failures, "window": window},
        )
```

`inspectord/__main__.py`: right after migrations run at daemon startup (find the
`run_migrations` call), add `assert_audit_table(cfg.storage.db_path)`.

- [ ] **Step 4: Tests + full gates (unit AND integration).** PASS.
- [ ] **Step 5: Commit** — `feat(audit): daily head anchor + periodic verify + failure escalation + startup probe`

---

### Task 5: IPC methods

**Files:**
- Create: `inspectord/audit/ipc_handlers.py`
- Modify: `inspectord/__main__.py` (2 `Method` entries, mutates=False)
- Test: `tests/audit/test_ipc_handlers.py`

- [ ] **Step 1: Failing tests:**

```python
def test_list_shape_and_order(tmp_path):
    db_path = _fresh(tmp_path)
    for i in range(3):
        append_audit(db_path, actor="user:local", action="a", target=f"t:{i}", details={})
    out = handle_list_audit_log(params={}, db_path=db_path)
    assert out["ok"] and out["schema_version"] == "1.0.0"
    assert [r["seq"] for r in out["rows"]] == [3, 2, 1]  # newest first
    assert out["rows"][0]["details"] == {}


def test_list_limit_clamped(tmp_path):
    db_path = _fresh(tmp_path)
    out = handle_list_audit_log(params={"limit": 99999}, db_path=db_path)
    assert out["ok"]  # clamped to 500, not rejected


def test_verify_clean_and_anchor_lookup(tmp_path):
    db_path = _fresh(tmp_path)
    append_audit(db_path, actor="user:local", action="a", target=None, details={})
    out = handle_verify_audit_log(params={}, db_path=db_path)
    assert out["ok"] and out["verification"]["ok"] is True
    assert out["verification"]["anchor_checked"] is False  # no anchor event seeded


def test_verify_uses_newest_audit_head_event(tmp_path):
    db_path = _fresh(tmp_path)
    append_audit(db_path, actor="user:local", action="a", target=None, details={})
    _seed_audit_head_event(db_path, seq=1)   # capture real row_hash BEFORE the wipe
    with Database(db_path) as db:
        db.execute("DELETE FROM audit_log")  # wipe
    out = handle_verify_audit_log(params={}, db_path=db_path)
    assert out["verification"]["ok"] is False
    assert out["verification"]["reason"] == "anchor_mismatch"
```

`_seed_audit_head_event` inserts into `events_enriched` a row with
`module='supervisor', action='audit_head'` whose `payload_json` contains
`{"raw": {"seq": ..., "row_hash": <the real row_hash>}}`.

- [ ] **Step 2: Verify failure.**

- [ ] **Step 3: Implement `inspectord/audit/ipc_handlers.py`:**

```python
"""IPC handlers for the audit log (spec §7). Read-only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from inspectord.audit.log import verify_audit_chain
from inspectord.storage.db import Database

_SCHEMA_VERSION = "1.0.0"
_MAX_LIMIT = 500


def handle_list_audit_log(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    try:
        limit = int(params.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(_MAX_LIMIT, limit))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT seq, ts, actor, action, target, details_json "
            "FROM audit_log ORDER BY seq DESC LIMIT ?",
            [limit],
        ).fetchall()
    out = []
    for seq, ts, actor, action, target, details_json in rows:
        try:
            details = json.loads(details_json)
        except (TypeError, ValueError):
            details = None
        out.append({"seq": seq, "ts": ts.isoformat(), "actor": actor,
                    "action": action, "target": target, "details": details})
    return {"schema_version": _SCHEMA_VERSION, "ok": True, "rows": out}


def _newest_anchor(db: Database) -> tuple[int, str] | None:
    row = db.query(
        "SELECT payload_json FROM events_enriched "
        "WHERE module = 'supervisor' AND action = 'audit_head' "
        "ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    try:
        raw = json.loads(row[0]).get("raw") or {}
        return int(raw["seq"]), str(raw["row_hash"])
    except (TypeError, ValueError, KeyError):
        return None


def handle_verify_audit_log(*, params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    with Database(db_path) as db:
        verification = verify_audit_chain(db, anchor=_newest_anchor(db))
    return {"schema_version": _SCHEMA_VERSION, "ok": True,
            "verification": verification.as_dict()}
```

Register both in `_ipc_methods` (mutates=False), mirroring neighbors; extend the
registration-coverage test using the `_ipc_methods(None, dev_config(base=tmp_path))`
pattern in `tests/hunt/test_ipc_handlers.py`.

- [ ] **Step 4: Tests + full gates (unit AND integration).** PASS.
- [ ] **Step 5: Commit** — `feat(audit): list_audit_log + verify_audit_log IPC`

---

### Task 6: Ship PR1

- [ ] Full gates once more (unit + integration + ruff check + format + mypy).
- [ ] `git push -u origin audit-log`
- [ ] `gh pr create` — title `feat(audit): hash-chained audit log — core + wiring (PR1)`;
  body links the spec, notes concilium review happened in-session but the spec remains
  human-unreviewed, calls out fail-open as the decision to look at; standard footer.
- [ ] CI wait: use a Monitor poll loop (NOT `gh pr checks --watch` in background — it
  gets killed at ~10 min), then `gh pr merge <N> --squash --delete-branch`,
  `git checkout main && git pull --ff-only`.
