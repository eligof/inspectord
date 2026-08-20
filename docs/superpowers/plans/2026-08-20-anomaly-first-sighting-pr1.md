# Anomaly detector PR1 — first-sighting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the `inspectord/anomaly/` package with the first-sighting stage: `first_seen` persistence, `baseline.first_sighting` stamping in the supervisor dispatch path, an anomaly maintenance thread, and five first-sighting starter rules.

**Architecture:** Per `docs/superpowers/specs/2026-08-20-anomaly-detector-design.md` §2–3: `FirstSightingTracker` is a synchronous O(1) stage in `Supervisor._dispatch` (in-memory seen-set, no I/O on the hot path); an `AnomalyDetector` thread (skeleton in this PR — PR2 adds statistics) flushes pending `first_seen` rows each tick. Starter-pack YAML rules keyed on `baseline.first_sighting == true` turn stamps into alerts through the existing pipeline.

**Tech Stack:** Python 3.12, pydantic, DuckDB, pytest. Pure Python — no Rust changes.

**Commands** (from repo root):
- Tests: `.venv/bin/python -m pytest -m "not integration and not ebpf_load"`
- Lint: `.venv/bin/ruff check inspectord tests && .venv/bin/ruff format --check inspectord tests`
- Types: `.venv/bin/mypy inspectord`

**Branch:** `anomaly-first-sighting`, cut from `main` **after spec PR #140 merges**.

---

### Task 0: Branch

(This plan is already on `main` — it landed with the spec in PR #140.)

- [ ] **Step 1:** `git checkout main && git pull && git checkout -b anomaly-first-sighting`

---

### Task 1: Migration 0010 — `first_seen` + `metric_baseline`

**Files:**
- Create: `inspectord/storage/migrations_data/0010_anomaly.sql`
- Test: `tests/test_anomaly_migration.py`

- [ ] **Step 1: Write the failing test**

```python
"""Tests for migration 0010 — first_seen, metric_baseline."""

from __future__ import annotations

from pathlib import Path

from inspectord.storage.db import Database
from inspectord.storage.migrations import current_schema_version, run_migrations


def _tables(db: Database) -> set[str]:
    return {
        r[0]
        for r in db.query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchall()
    }


def test_migration_creates_anomaly_tables(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    assert current_schema_version(db) >= 10
    tables = _tables(db)
    for needed in ("first_seen", "metric_baseline"):
        assert needed in tables, f"missing table {needed}"
    db.close()


def test_first_seen_columns_and_pk(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {
        r[0]
        for r in db.query(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'first_seen'"
        ).fetchall()
    }
    assert cols == {"category", "entity_kind", "entity_key", "first_seen_at", "event_id"}
    # The composite PK makes INSERT OR IGNORE the dedup mechanism for re-flushes.
    db.execute(
        "INSERT INTO first_seen VALUES ('process', 'binary', '/usr/bin/xz', now(), 'e1')"
    )
    db.execute(
        "INSERT OR IGNORE INTO first_seen VALUES ('process', 'binary', '/usr/bin/xz', now(), 'e2')"
    )
    rows = db.query("SELECT count(*) FROM first_seen").fetchall()
    assert rows[0][0] == 1
    db.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_anomaly_migration.py -v`
Expected: FAIL — `assert current_schema_version(db) >= 10` (version is 9).

- [ ] **Step 3: Write the migration**

`inspectord/storage/migrations_data/0010_anomaly.sql`:

```sql
-- Anomaly detector (spec 2026-08-20-anomaly-detector-design.md §7).

CREATE TABLE IF NOT EXISTS first_seen (
    category      TEXT NOT NULL,
    entity_kind   TEXT NOT NULL,
    entity_key    TEXT NOT NULL,
    first_seen_at TIMESTAMP NOT NULL,
    event_id      TEXT NOT NULL,
    PRIMARY KEY (category, entity_kind, entity_key)
);

-- Checkpoint of in-memory rolling state; never the source of truth at runtime.
CREATE TABLE IF NOT EXISTS metric_baseline (
    metric_kind  TEXT NOT NULL,
    entity_key   TEXT NOT NULL,
    window_name  TEXT NOT NULL,
    state_json   TEXT NOT NULL,
    updated_at   TIMESTAMP NOT NULL,
    PRIMARY KEY (metric_kind, entity_key, window_name)
);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_anomaly_migration.py -v`
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/storage/migrations_data/0010_anomaly.sql tests/test_anomaly_migration.py
git commit -m "feat(storage): migration 0010 — first_seen + metric_baseline tables"
```

---

### Task 2: `AnomalyConfig`

**Files:**
- Modify: `inspectord/config.py` (add `AnomalyConfig` class after `IpcConfig`; add field to `DaemonConfig`)
- Test: `tests/test_config_anomaly.py`

- [ ] **Step 1: Write the failing test**

```python
"""AnomalyConfig defaults and wiring."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import AnomalyConfig, DaemonConfig, dev_config


def test_anomaly_config_defaults() -> None:
    cfg = AnomalyConfig()
    assert cfg.enabled is True
    assert cfg.tick_s == 60.0
    assert cfg.z_threshold == 3.0
    assert cfg.min_samples == 50
    assert cfg.checkpoint_interval_s == 300.0
    assert cfg.max_entities_per_metric == 512


def test_daemon_config_defaults_anomaly_section(tmp_path: Path) -> None:
    # A config with no [anomaly] section still validates and is enabled.
    cfg = DaemonConfig.model_validate(
        {
            "version": "1.0.0",
            "storage": {
                "db_path": str(tmp_path / "d.duckdb"),
                "journal_dir": str(tmp_path / "j"),
            },
            "ipc": {"socket_path": str(tmp_path / "s.sock")},
        }
    )
    assert cfg.anomaly.enabled is True


def test_dev_config_has_anomaly(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    assert cfg.anomaly.enabled is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_config_anomaly.py -v`
Expected: FAIL — `ImportError: cannot import name 'AnomalyConfig'`.

- [ ] **Step 3: Implement**

In `inspectord/config.py`, after `IpcConfig`:

```python
class AnomalyConfig(BaseModel):
    """Anomaly detector settings (spec 2026-08-20-anomaly-detector-design.md §8)."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    tick_s: float = 60.0
    z_threshold: float = 3.0
    min_samples: int = 50
    checkpoint_interval_s: float = 300.0
    max_entities_per_metric: int = 512
    # beaconing (PR3)
    beacon_min_events: int = 12
    beacon_min_interval_s: float = 5.0
    beacon_max_interval_s: float = 3600.0
    beacon_max_cv: float = 0.1
    # entity/resource baselines (PR4)
    resource_tick_s: float = 30.0
    sustained_factor: float = 5.0
    sustained_ticks: int = 6
```

Add to `DaemonConfig`:

```python
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
```

(No `dev_config()` change needed — the default factory covers it.)

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_config_anomaly.py tests/test_config_example.py -v`
Expected: PASS (the example-config test must still pass — the new field is optional).

- [ ] **Step 5: Commit**

```bash
git add inspectord/config.py tests/test_config_anomaly.py
git commit -m "feat(config): AnomalyConfig section with spec §8 defaults"
```

---

### Task 3: `FirstSightingTracker` — seen-set, stamping, flush

**Files:**
- Create: `inspectord/anomaly/__init__.py` (docstring only: `"""Anomaly detection (spec §12)."""`)
- Create: `inspectord/anomaly/first_sighting.py`
- Test: `tests/anomaly/__init__.py` (empty), `tests/anomaly/test_first_sighting.py`

The tracker is called from multiple worker fan-out threads (`_dispatch`) and one flush thread, so the seen-set and pending list are lock-guarded. `observe()` never touches the database.

- [ ] **Step 1: Write the failing tests**

`tests/anomaly/test_first_sighting.py`:

```python
"""FirstSightingTracker unit tests."""

from __future__ import annotations

from pathlib import Path

from inspectord.anomaly.first_sighting import FirstSightingTracker, SightingKey, sighting_keys
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _proc_start(sha: str = "abc123", exe: str = "/usr/bin/xz"):
    return build_event(
        module="process_collector",
        action="process_start",
        category=["process"],
        type_=["start"],
        severity="info",
        process={"pid": 1, "name": "xz", "executable": exe, "hash": {"sha256": sha}},
    )


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    return db


def test_first_observation_stamps_and_queues() -> None:
    t = FirstSightingTracker()
    ev = _proc_start()
    t.observe(ev)
    assert ev.baseline is not None and ev.baseline["first_sighting"] is True
    assert t.pending_count() == 1


def test_second_observation_does_not_stamp() -> None:
    t = FirstSightingTracker()
    t.observe(_proc_start())
    ev2 = _proc_start()
    t.observe(ev2)
    assert ev2.baseline is None
    assert t.pending_count() == 1


def test_catchup_events_populate_silently_but_still_stamp() -> None:
    # Snapshot catch-up (Event.first_seen=True) is skipped by the rule engine,
    # so stamping it costs nothing and keeps observe() uniform.
    t = FirstSightingTracker()
    ev = _proc_start()
    ev.first_seen = True
    t.observe(ev)
    assert t.pending_count() == 1
    live = _proc_start()
    t.observe(live)
    assert live.baseline is None  # already seen via catch-up


def test_event_without_sighting_key_untouched() -> None:
    t = FirstSightingTracker()
    ev = build_event(
        module="healthcheck", action="tick", category=["host"], type_=["info"], severity="info"
    )
    t.observe(ev)
    assert ev.baseline is None
    assert t.pending_count() == 0


def test_flush_persists_and_load_restores(tmp_path: Path) -> None:
    db = _db(tmp_path)
    t = FirstSightingTracker()
    t.observe(_proc_start())
    assert t.flush(db) == 1
    assert t.pending_count() == 0
    rows = db.query(
        "SELECT category, entity_kind, entity_key FROM first_seen"
    ).fetchall()
    assert rows == [("process", "binary", "abc123")]

    t2 = FirstSightingTracker()
    assert t2.load(db) == 1
    ev = _proc_start()
    t2.observe(ev)
    assert ev.baseline is None  # restored from table, not re-sighted
    db.close()


def test_flush_survives_duplicate_rows(tmp_path: Path) -> None:
    # A crash between stamp and flush re-marks the sighting next run; the
    # PRIMARY KEY + INSERT OR IGNORE absorbs the duplicate row.
    db = _db(tmp_path)
    t = FirstSightingTracker()
    t.observe(_proc_start())
    t.flush(db)
    t2 = FirstSightingTracker()  # fresh, did not load()
    t2.observe(_proc_start())
    assert t2.flush(db) == 1
    rows = db.query("SELECT count(*) FROM first_seen").fetchall()
    assert rows[0][0] == 1
    db.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/anomaly/test_first_sighting.py -v`
Expected: FAIL — `ModuleNotFoundError: inspectord.anomaly`.

- [ ] **Step 3: Implement**

`inspectord/anomaly/first_sighting.py`:

```python
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


def sighting_keys(ev: Event) -> list[SightingKey]:
    """Derive the sighting keys an event represents (spec §3, five starter cases)."""
    if ev.action == "process_start":
        proc = ev.process or {}
        ident = (proc.get("hash") or {}).get("sha256") or proc.get("executable")
        # Unenriched events (no /proc by the time we looked) carry neither; a
        # binary we cannot identify is not a sighting.
        if ident:
            return [SightingKey("process", "binary", str(ident))]
        return []
    if ev.action == "outbound_connection":
        name = (ev.process or {}).get("name")
        dst = ev.destination or {}
        ip, port = dst.get("ip"), dst.get("port")
        if name and ip and port is not None:
            return [SightingKey("network", "proc_dest", f"{name}->{ip}:{port}")]
        return []
    if ev.action == "ssh_login_succeeded":
        ip = (ev.source or {}).get("ip")
        return [SightingKey("authentication", "login_ip", str(ip))] if ip else []
    if ev.action == "kmod_loaded":
        name = (ev.raw or {}).get("module_name")
        return [SightingKey("driver", "kmod", str(name))] if name else []
    if ev.module == "fim_watcher" and ev.action in ("file_created", "file_attributes_changed"):
        f = ev.file or {}
        if f.get("setuid") is True and f.get("path"):
            return [SightingKey("file", "suid", str(f["path"]))]
        return []
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
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/anomaly/test_first_sighting.py -v`
Expected: 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/anomaly/ tests/anomaly/
git commit -m "feat(anomaly): FirstSightingTracker — seen-set, stamping, batched flush"
```

---

### Task 4: Sighting-key extraction — remaining trigger shapes

**Files:**
- Test: `tests/anomaly/test_sighting_keys.py` (extraction is already implemented in Task 3; this task locks the five shapes + negatives under test)

- [ ] **Step 1: Write the tests**

```python
"""sighting_keys() extraction for the five starter cases (spec §3)."""

from __future__ import annotations

from inspectord.anomaly.first_sighting import SightingKey, sighting_keys
from inspectord.parsers.base import build_event


def test_binary_prefers_hash_over_path() -> None:
    ev = build_event(
        module="process_collector", action="process_start", category=["process"],
        type_=["start"], severity="info",
        process={"pid": 1, "name": "xz", "executable": "/usr/bin/xz",
                 "hash": {"sha256": "deadbeef"}},
    )
    assert sighting_keys(ev) == [SightingKey("process", "binary", "deadbeef")]


def test_binary_falls_back_to_executable_then_skips() -> None:
    ev = build_event(
        module="process_collector", action="process_start", category=["process"],
        type_=["start"], severity="info",
        process={"pid": 1, "name": "xz", "executable": "/usr/bin/xz"},
    )
    assert sighting_keys(ev) == [SightingKey("process", "binary", "/usr/bin/xz")]
    bare = build_event(
        module="process_collector", action="process_start", category=["process"],
        type_=["start"], severity="info", process={"pid": 1, "name": "kworker/0:1"},
    )
    assert sighting_keys(bare) == []


def test_outbound_dest_key() -> None:
    ev = build_event(
        module="outbound_connection_tracker", action="outbound_connection",
        category=["network"], type_=["connection", "start"], severity="info",
        process={"pid": 2, "name": "curl"},
        destination={"ip": "203.0.113.9", "port": 443},
    )
    assert sighting_keys(ev) == [
        SightingKey("network", "proc_dest", "curl->203.0.113.9:443")
    ]


def test_outbound_ipv6_worker_matches_by_action() -> None:
    ev = build_event(
        module="outbound_connection_tracker6", action="outbound_connection",
        category=["network"], type_=["connection", "start"], severity="info",
        process={"pid": 2, "name": "curl"},
        destination={"ip": "2001:db8::9", "port": 443},
    )
    assert sighting_keys(ev)[0].entity_key == "curl->2001:db8::9:443"


def test_login_ip_key() -> None:
    ev = build_event(
        module="log_tailer", action="ssh_login_succeeded", category=["authentication"],
        type_=["start"], severity="info", outcome="success",
        user={"name": "eli"}, source={"ip": "198.51.100.7", "port": 50000},
    )
    assert sighting_keys(ev) == [
        SightingKey("authentication", "login_ip", "198.51.100.7")
    ]


def test_failed_login_is_not_a_sighting() -> None:
    ev = build_event(
        module="log_tailer", action="ssh_login_failed", category=["authentication"],
        type_=["start"], severity="low", outcome="failure",
        source={"ip": "198.51.100.7"},
    )
    assert sighting_keys(ev) == []


def test_kmod_key_from_raw() -> None:
    ev = build_event(
        module="kmod_watcher", action="kmod_loaded", category=["driver"],
        type_=["installation"], severity="info",
        raw={"source": "/proc/modules", "module_name": "nft_ct"},
    )
    assert sighting_keys(ev) == [SightingKey("driver", "kmod", "nft_ct")]


def test_suid_key_requires_setuid_true() -> None:
    suid = build_event(
        module="fim_watcher", action="file_created", category=["file"],
        type_=["creation"], severity="info",
        file={"path": "/usr/local/bin/backdoor", "setuid": True},
    )
    assert sighting_keys(suid) == [
        SightingKey("file", "suid", "/usr/local/bin/backdoor")
    ]
    plain = build_event(
        module="fim_watcher", action="file_created", category=["file"],
        type_=["creation"], severity="info",
        file={"path": "/tmp/x", "setuid": False},
    )
    assert sighting_keys(plain) == []
```

- [ ] **Step 2: Run tests**

Run: `.venv/bin/python -m pytest tests/anomaly/test_sighting_keys.py -v`
Expected: all PASS (implementation landed in Task 3). If any FAIL, fix `sighting_keys()` — the tests are the contract.

- [ ] **Step 3: Commit**

```bash
git add tests/anomaly/test_sighting_keys.py
git commit -m "test(anomaly): lock the five sighting-key extraction shapes"
```

---

### Task 5: `AnomalyDetector` skeleton — maintenance thread

**Files:**
- Create: `inspectord/anomaly/detector.py`
- Test: `tests/anomaly/test_detector.py`

PR1 scope: the thread exists and flushes the tracker each tick; PR2 extends `_tick` with statistical aggregation. Tick failures log and never kill the loop.

- [ ] **Step 1: Write the failing tests**

```python
"""AnomalyDetector skeleton tests."""

from __future__ import annotations

import time
from pathlib import Path

from inspectord.anomaly.detector import AnomalyDetector
from inspectord.anomaly.first_sighting import FirstSightingTracker
from inspectord.config import AnomalyConfig
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _tracker_with_pending() -> FirstSightingTracker:
    t = FirstSightingTracker()
    ev = build_event(
        module="kmod_watcher", action="kmod_loaded", category=["driver"],
        type_=["installation"], severity="info",
        raw={"module_name": "nft_ct"},
    )
    t.observe(ev)
    return t


def test_tick_flushes_pending(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    tracker = _tracker_with_pending()
    det = AnomalyDetector(db=db, tracker=tracker, config=AnomalyConfig(tick_s=0.05))
    det.start()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and tracker.pending_count():
        time.sleep(0.02)
    det.stop(timeout=2.0)
    assert tracker.pending_count() == 0
    assert db.query("SELECT count(*) FROM first_seen").fetchall()[0][0] == 1
    db.close()


def test_tick_failure_does_not_kill_thread(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()  # run_migrations deliberately NOT run: flush will raise
    tracker = _tracker_with_pending()
    det = AnomalyDetector(db=db, tracker=tracker, config=AnomalyConfig(tick_s=0.05))
    det.start()
    time.sleep(0.3)
    assert det.is_alive()
    run_migrations(db)  # heal the DB; stop()'s final flush now succeeds
    tracker.observe(
        build_event(
            module="kmod_watcher", action="kmod_loaded", category=["driver"],
            type_=["installation"], severity="info", raw={"module_name": "vfat"},
        )
    )
    det.stop(timeout=2.0)
    assert not det.is_alive()
    db.close()


def test_stop_performs_final_flush(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    tracker = _tracker_with_pending()
    # Huge tick: the loop never fires; only stop()'s final flush can persist.
    det = AnomalyDetector(db=db, tracker=tracker, config=AnomalyConfig(tick_s=3600.0))
    det.start()
    det.stop(timeout=2.0)
    assert db.query("SELECT count(*) FROM first_seen").fetchall()[0][0] == 1
    db.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/anomaly/test_detector.py -v`
Expected: FAIL — `ModuleNotFoundError: inspectord.anomaly.detector`.

- [ ] **Step 3: Implement**

`inspectord/anomaly/detector.py`:

```python
"""Anomaly detector thread (spec 2026-08-20-anomaly-detector-design.md §2).

PR1 skeleton: owns the maintenance thread and flushes the first-sighting
queue each tick. PR2 adds the statistical aggregators to ``_tick``.
"""

from __future__ import annotations

import contextlib
import threading

from inspectord.anomaly.first_sighting import FirstSightingTracker
from inspectord.config import AnomalyConfig
from inspectord.log import get
from inspectord.storage.db import Database

log = get(__name__)


class AnomalyDetector:
    def __init__(
        self, *, db: Database, tracker: FirstSightingTracker, config: AnomalyConfig
    ) -> None:
        self._db = db
        self._tracker = tracker
        self._cfg = config
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="anomaly-detector", daemon=True)
        self._thread.start()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        while not self._stop.wait(self._cfg.tick_s):
            self._tick()

    def _tick(self) -> None:
        try:
            self._tracker.flush(self._db)
        except Exception as exc:
            # One bad tick must never kill the thread; pending rows are gone,
            # and a re-sighting after restart is absorbed by dedup.
            log.error("anomaly tick failed: %r", exc)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        # Best-effort final flush so a clean shutdown loses nothing.
        with contextlib.suppress(Exception):
            self._tracker.flush(self._db)
```

(Logger accessor verified: `inspectord.log.get`, same as `supervisor.py`.)

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/anomaly/test_detector.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/anomaly/detector.py tests/anomaly/test_detector.py
git commit -m "feat(anomaly): AnomalyDetector maintenance thread — tick flushes first sightings"
```

---

### Task 6: Five first-sighting starter rules

**Files:**
- Create: `inspectord/rules/starter_pack/anomaly_first_binary_execution.yaml`
- Create: `inspectord/rules/starter_pack/anomaly_first_outbound_dest.yaml`
- Create: `inspectord/rules/starter_pack/anomaly_first_login_ip.yaml`
- Create: `inspectord/rules/starter_pack/anomaly_first_kmod_load.yaml`
- Create: `inspectord/rules/starter_pack/anomaly_first_suid_file.yaml`
- Test: `tests/rules/starter_pack/test_anomaly_first_sighting_rules.py`

Severities per spec §3: binary/dest/login = **low** (notifier routes low to no sinks — log-only, satisfies main-spec §21.4); kmod/SUID = **medium** (rare, high-signal, does popup). The supervisor auto-loads every `*.yaml` in `starter_pack`, so dropping the files in registers them.

- [ ] **Step 1: Write the failing tests**

```python
"""First-sighting starter rules (anomaly.first_*)."""

from __future__ import annotations

from importlib.resources import files

import yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict


def _rule(name: str):
    text = files("inspectord.rules.starter_pack").joinpath(name).read_text(encoding="utf-8")
    return load_yaml_rule_from_dict(yaml.safe_load(text), source=name)


def _stamped(ev):
    ev.baseline = {**(ev.baseline or {}), "first_sighting": True}
    return ev


def _proc_start():
    return build_event(
        module="process_collector", action="process_start", category=["process"],
        type_=["start"], severity="info",
        process={"pid": 1, "name": "xz", "executable": "/usr/bin/xz"},
    )


def test_first_binary_execution_fires_only_when_stamped() -> None:
    rule = _rule("anomaly_first_binary_execution.yaml")
    assert rule.severity == "low"
    assert not evaluate_yaml_rule(rule, EvalContext(event=_proc_start()))
    matches = evaluate_yaml_rule(rule, EvalContext(event=_stamped(_proc_start())))
    assert len(matches) == 1
    assert matches[0].rule_id == "anomaly.first_binary_execution"
    assert matches[0].category == "anomaly"


def test_first_outbound_dest_fires() -> None:
    rule = _rule("anomaly_first_outbound_dest.yaml")
    assert rule.severity == "low"
    ev = _stamped(
        build_event(
            module="outbound_connection_tracker", action="outbound_connection",
            category=["network"], type_=["connection", "start"], severity="info",
            process={"pid": 2, "name": "curl"},
            destination={"ip": "203.0.113.9", "port": 443},
        )
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev))


def test_first_login_ip_fires() -> None:
    rule = _rule("anomaly_first_login_ip.yaml")
    assert rule.severity == "low"
    ev = _stamped(
        build_event(
            module="log_tailer", action="ssh_login_succeeded",
            category=["authentication"], type_=["start"], severity="info",
            outcome="success", user={"name": "eli"}, source={"ip": "198.51.100.7"},
        )
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev))


def test_first_kmod_load_fires_at_medium() -> None:
    rule = _rule("anomaly_first_kmod_load.yaml")
    assert rule.severity == "medium"
    ev = _stamped(
        build_event(
            module="kmod_watcher", action="kmod_loaded", category=["driver"],
            type_=["installation"], severity="info", raw={"module_name": "nft_ct"},
        )
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev))


def test_first_suid_file_fires_at_medium() -> None:
    rule = _rule("anomaly_first_suid_file.yaml")
    assert rule.severity == "medium"
    ev = _stamped(
        build_event(
            module="fim_watcher", action="file_created", category=["file"],
            type_=["creation"], severity="info",
            file={"path": "/usr/local/bin/backdoor", "setuid": True},
        )
    )
    assert evaluate_yaml_rule(rule, EvalContext(event=ev))
    # setuid gate: a stamped fim event without the bit must not fire.
    plain = _stamped(
        build_event(
            module="fim_watcher", action="file_created", category=["file"],
            type_=["creation"], severity="info",
            file={"path": "/tmp/x", "setuid": False},
        )
    )
    assert not evaluate_yaml_rule(rule, EvalContext(event=plain))


def test_unstamped_events_never_fire_any_rule() -> None:
    names = [
        "anomaly_first_binary_execution.yaml",
        "anomaly_first_outbound_dest.yaml",
        "anomaly_first_login_ip.yaml",
        "anomaly_first_kmod_load.yaml",
        "anomaly_first_suid_file.yaml",
    ]
    ev = _proc_start()
    for name in names:
        assert not evaluate_yaml_rule(_rule(name), EvalContext(event=ev)), name
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/rules/starter_pack/test_anomaly_first_sighting_rules.py -v`
Expected: FAIL — `FileNotFoundError` on the yaml files.

- [ ] **Step 3: Write the five rules**

`anomaly_first_binary_execution.yaml`:

```yaml
version: 1.0.0
id: anomaly.first_binary_execution
name: "first execution of a binary"
severity: low
category: anomaly
why: |
  This binary (identified by SHA-256 when enrichment could hash it, otherwise
  by executable path) has never been seen executing on this host before. On a
  compromised machine, the attacker's tooling is by definition new here; on a
  healthy machine, so is every freshly installed or updated program. That is
  why this rule is `low`: it is a triage breadcrumb, recorded but never
  notified (the notifier routes `low` to no sinks). A young install will
  produce a stream of these while the first-seen table warms up.
false_positives:
  - "Every package install or upgrade produces new binaries (new hashes), each firing once."
  - "Anything run for the first time since inspectord was installed — the table only knows what it has watched."
detect:
  any_of:
    - event.action == "process_start" AND baseline.first_sighting == true
short: "first execution: {process.name}"
detail: "First observed execution of {process.executable} (sha256 {process.hash.sha256}). Command line: {process.command_line}"
labels: [anomaly, first-sighting]
```

`anomaly_first_outbound_dest.yaml`:

```yaml
version: 1.0.0
id: anomaly.first_outbound_dest
name: "first outbound destination for a process"
severity: low
category: anomaly
why: |
  This process name has never been observed connecting to this destination
  ip:port before. Malware that phones home shows up as a process talking to
  somewhere it never talked to before — but so does a browser opening any new
  site, which is why this is `low` and log-only. Its value is in triage: when
  some other alert implicates a process, its first-contact history is already
  recorded here.
false_positives:
  - "Any program whose destinations naturally vary — browsers, package mirrors chosen round-robin, CDN-backed updaters — fires constantly."
  - "The key is per process *name*, so two different binaries sharing a name share a history."
detect:
  any_of:
    - event.action == "outbound_connection" AND baseline.first_sighting == true
short: "first outbound: {process.name} -> {destination.ip}:{destination.port}"
detail: "First observed connection from {process.name} to {destination.ip}:{destination.port} (transport {network.transport})."
labels: [anomaly, first-sighting, network]
```

`anomaly_first_login_ip.yaml`:

```yaml
version: 1.0.0
id: anomaly.first_login_ip
name: "first SSH login from an IP"
severity: low
category: anomaly
why: |
  A successful SSH login arrived from a source IP that has never successfully
  logged in before. On a personal machine the set of legitimate login sources
  is small and stable, so a new one is worth a breadcrumb — but DHCP churn,
  VPNs, and mobile networks all rotate addresses, so this stays `low` and
  log-only rather than notifying.
false_positives:
  - "Your own address rotating: DHCP renewal, VPN exit change, logging in from a phone hotspot."
  - "IPv6 privacy extensions rotate the source address by design."
detect:
  any_of:
    - event.action == "ssh_login_succeeded" AND baseline.first_sighting == true
short: "first login from {source.ip} ({user.name})"
detail: "First successful SSH login from {source.ip} for user {user.name}."
labels: [anomaly, first-sighting, authentication]
```

`anomaly_first_kmod_load.yaml`:

```yaml
version: 1.0.0
id: anomaly.first_kmod_load
name: "first load of a kernel module"
severity: medium
category: anomaly
why: |
  A kernel module was loaded that has never been loaded on this host before.
  Kernel modules run with full kernel privilege and are the classic rootkit
  vehicle; on a stable machine the set of modules in use settles quickly, so
  a first-timer is rare and worth a desktop notification — hence `medium`
  rather than the log-only `low` used by chattier first sightings. Correlate
  with proc.kernel_module_loaded_unknown, which fires on the *loader*.
false_positives:
  - "New hardware or first use of a feature: a USB peripheral, a filesystem type first mounted, a netfilter match first referenced."
  - "The first days after install, while the module set is still being learned."
detect:
  any_of:
    - event.action == "kmod_loaded" AND baseline.first_sighting == true
short: "first load of kernel module {raw.module_name}"
detail: "Kernel module {raw.module_name} was loaded for the first time on this host."
labels: [anomaly, first-sighting, kmod]
```

`anomaly_first_suid_file.yaml`:

```yaml
version: 1.0.0
id: anomaly.first_suid_file
name: "first sighting of a SUID file"
severity: medium
category: anomaly
why: |
  FIM observed a file with the setuid bit at a path never recorded as SUID
  before. SUID binaries are permanent privilege-escalation surface; new ones
  are rare on a stable system and overwhelmingly arrive via package manager.
  This complements persistence.new_suid_file (severity high, fires on the
  create/chmod event itself): this rule is the *first-seen* angle, keyed on
  the path's history rather than the single change event.
false_positives:
  - "Package installs and updates legitimately add SUID binaries (verify with pacman -Qo <path>)."
detect:
  any_of:
    - event.module == "fim_watcher" AND baseline.first_sighting == true AND file.setuid == true
short: "first SUID sighting: {file.path}"
detail: "First sighting of setuid file {file.path} (owner {file.owner})."
labels: [anomaly, first-sighting, suid, persistence]
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/rules/starter_pack/test_anomaly_first_sighting_rules.py tests/rules -v`
Expected: new tests PASS; the whole `tests/rules` tree stays green (registry/loader tests may enumerate the pack — if a count assertion exists, update it).

- [ ] **Step 5: Commit**

```bash
git add inspectord/rules/starter_pack/anomaly_first_*.yaml tests/rules/starter_pack/test_anomaly_first_sighting_rules.py
git commit -m "feat(rules): five anomaly.first_* first-sighting starter rules"
```

---

### Task 7: Supervisor wiring + integration test

**Files:**
- Modify: `inspectord/supervisor.py` (imports; `__init__` after `self._rule_engine = RuleEngine(...)` ~line 176; `start()` after the boot-id/reconcile block ~line 190; `_dispatch()` ~line 226; `stop()` before `self._journal.close()` ~line 305)
- Test: `tests/test_supervisor_anomaly.py`

- [ ] **Step 1: Write the failing test**

```python
"""End-to-end: first sighting stamps, alerts once, persists, survives restart."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config
from inspectord.parsers.base import build_event
from inspectord.storage.db import Database
from inspectord.supervisor import Supervisor


def _kmod_event(name: str = "evilmod"):
    return build_event(
        module="kmod_watcher", action="kmod_loaded", category=["driver"],
        type_=["installation"], severity="info",
        raw={"source": "/proc/modules", "module_name": name},
    )


def _quiet_cfg(tmp_path: Path):
    cfg = dev_config(base=tmp_path)
    # No workers: this test injects events directly.
    return cfg.model_copy(update={"workers": []})


def test_first_sighting_alerts_once_and_persists(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    sup = Supervisor(cfg)
    alerts = []
    sup.attach_alert_listener(alerts.append)
    sup.start()
    try:
        sup._inject_for_test(_kmod_event())
        sup._inject_for_test(_kmod_event())  # second sighting: no stamp, no alert
        first = [a for a in alerts if a.rule.id == "anomaly.first_kmod_load"]
        assert len(first) == 1
        assert first[0].severity.value == "medium"
    finally:
        sup.stop(timeout=10.0)

    # stop() flushed the pending row.
    db = Database(cfg.storage.db_path)
    db.connect()
    rows = db.query(
        "SELECT entity_key FROM first_seen WHERE entity_kind = 'kmod'"
    ).fetchall()
    assert rows == [("evilmod",)]
    db.close()

    # A fresh supervisor loads the table: same module is no longer a sighting.
    sup2 = Supervisor(_quiet_cfg(tmp_path))
    alerts2 = []
    sup2.attach_alert_listener(alerts2.append)
    sup2.start()
    try:
        sup2._inject_for_test(_kmod_event())
        assert not [a for a in alerts2 if a.rule.id == "anomaly.first_kmod_load"]
    finally:
        sup2.stop(timeout=10.0)


def test_catchup_event_populates_without_alerting(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    sup = Supervisor(cfg)
    alerts = []
    sup.attach_alert_listener(alerts.append)
    sup.start()
    try:
        catchup = _kmod_event("vfat")
        catchup.first_seen = True  # snapshot catch-up re-emission
        sup._inject_for_test(catchup)
        assert not alerts  # rule engine skips catch-up events
        live = _kmod_event("vfat")
        sup._inject_for_test(live)
        assert not [a for a in alerts if a.rule.id == "anomaly.first_kmod_load"]
    finally:
        sup.stop(timeout=10.0)


def test_disabled_anomaly_never_stamps(tmp_path: Path) -> None:
    cfg = _quiet_cfg(tmp_path)
    cfg = cfg.model_copy(update={"anomaly": cfg.anomaly.model_copy(update={"enabled": False})})
    sup = Supervisor(cfg)
    alerts = []
    sup.attach_alert_listener(alerts.append)
    sup.start()
    try:
        sup._inject_for_test(_kmod_event())
        assert not [a for a in alerts if a.rule.id == "anomaly.first_kmod_load"]
    finally:
        sup.stop(timeout=10.0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_supervisor_anomaly.py -v`
Expected: FAIL — no stamping happens, so `anomaly.first_kmod_load` never fires (`len(first) == 1` is 0).

- [ ] **Step 3: Wire the supervisor**

Imports:

```python
from inspectord.anomaly.detector import AnomalyDetector
from inspectord.anomaly.first_sighting import FirstSightingTracker
```

In `__init__`, after `self._rule_engine = RuleEngine(...)`:

```python
        self._first_sighting: FirstSightingTracker | None = None
        self._anomaly_detector: AnomalyDetector | None = None
        if config.anomaly.enabled:
            self._first_sighting = FirstSightingTracker()
            self._anomaly_detector = AnomalyDetector(
                db=self._db, tracker=self._first_sighting, config=config.anomaly
            )
```

In `start()`, after the boot-id/reconcile `with contextlib.suppress(OSError):` block (migrations have run by then):

```python
        if self._first_sighting is not None:
            self._first_sighting.load(self._db)
        if self._anomaly_detector is not None:
            self._anomaly_detector.start()
```

In `_dispatch()`, inside the existing try, between `enrich` and the alert path:

```python
        try:
            ev = enrich(ev)
            if self._first_sighting is not None:
                self._first_sighting.observe(ev)
            self._run_alert_path(ev)
```

In `stop()`, immediately before `self._journal.close()` (the DB must still be open for the final flush):

```python
        if self._anomaly_detector is not None:
            self._anomaly_detector.stop(timeout=remaining())
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_supervisor_anomaly.py tests/test_supervisor.py -v`
Expected: all PASS (existing supervisor tests must stay green).

- [ ] **Step 5: Commit**

```bash
git add inspectord/supervisor.py tests/test_supervisor_anomaly.py
git commit -m "feat(supervisor): wire first-sighting stage + anomaly detector thread"
```

---

### Task 8: Main-spec §12.2 amendment note

**Files:**
- Modify: `docs/superpowers/specs/2026-05-24-local-inspection-design.md` (§12.2 bullet list, around line 772)

- [ ] **Step 1:** Append one bullet to the §12.2 list:

```markdown
* *Amended 2026-08-20:* the first-sighting marker is `baseline.first_sighting`, **not** `event.first_seen` — that flag means snapshot catch-up re-emission in the implementation. See `2026-08-20-anomaly-detector-design.md` §3.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-05-24-local-inspection-design.md
git commit -m "docs(specs): note §12.2 first-sighting marker amendment"
```

---

### Task 9: Full gates + PR

- [ ] **Step 1:** `.venv/bin/python -m pytest -m "not integration and not ebpf_load"` — all pass.
- [ ] **Step 2:** `.venv/bin/ruff check inspectord tests && .venv/bin/ruff format --check inspectord tests` — clean. (If format complains, run `.venv/bin/ruff format inspectord tests` and re-commit.)
- [ ] **Step 3:** `.venv/bin/mypy inspectord` — clean.
- [ ] **Step 4:** Push and open the PR:

```bash
git push -u origin anomaly-first-sighting
gh pr create --title "feat(anomaly): first-sighting detection (PR1)" --body "$(cat <<'EOF'
## Summary
- New `inspectord/anomaly/` package (PR1 of 4, per docs/superpowers/specs/2026-08-20-anomaly-detector-design.md)
- Migration 0010: `first_seen` + `metric_baseline` tables
- `FirstSightingTracker`: O(1) synchronous stage in the supervisor dispatch path stamps `baseline.first_sighting`; rows flushed off the hot path by the new anomaly maintenance thread
- `AnomalyConfig` section (spec §8 defaults)
- Five `anomaly.first_*` starter rules — binary/dest/login at `low` (log-only per main-spec §21.4), kmod/SUID at `medium`
- Amends main-spec §12.2: marker is `baseline.first_sighting`; `Event.first_seen` keeps its catch-up meaning

## Test plan
- [ ] Unit: migration, config, tracker, extraction shapes, detector thread, five rules
- [ ] Integration: inject → stamp → alert once → persist → survives restart; catch-up populates silently; disabled config inert
- [ ] CI: lint-and-test, CodeQL, cargo-audit, dependency-review green

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 5:** Wait for CI green, then `gh pr merge --squash --delete-branch`.

---

## Self-review notes

- **Spec coverage (design doc §§ relevant to PR1):** §2 hot-path placement → Task 7; §2.3 package layout (PR1 files) → Tasks 3, 5; §3 tracker + extraction + severities → Tasks 3, 4, 6; §7 migration → Task 1; §8 config → Task 2; §9 error handling (tick wrapper, no hot-path I/O, dispatch guard) → Tasks 3, 5, 7; §10 PR1 test list → Tasks 1–7; §11 delivery → Tasks 0, 9. `metric_baseline` is created now but first written in PR2 — intentional, keeps PR2 free of migrations.
- **Known judgment calls baked in:** binary key prefers sha256 over path; extraction matches by `action` so both outbound trackers (v4/v6) are covered; catch-up events are stamped (uniform code) but silenced by the rule engine's existing skip; `AnomalyDetector.stop()` does a best-effort final flush and the supervisor stops it before closing the DB.
