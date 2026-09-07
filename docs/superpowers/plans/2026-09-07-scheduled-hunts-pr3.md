# Scheduled hunts (PR3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A saved hunt query can be scheduled (`interval` + `severity`); a daemon-side `HuntScheduler` thread runs it over newly *ingested* events only and routes matches through the rule → alert pipeline. Spec: `docs/superpowers/specs/2026-09-07-hunt-followups-design.md` §4 — read it alongside this plan; it carries the rationale (concilium-reviewed) for every constraint below.

**Architecture:** ingest-sequence watermark (never event `ts`), one summary event per matching run, transition-only failure emission, per-rule dedup window, CLI-only mutating surface, everything audited + daemon-validated.

**Tech Stack:** Python 3.14, DuckDB, pydantic, typer/rich, FastAPI/Jinja2, pytest.

**Branch:** `scheduled-hunts` off up-to-date `main`.

**Gates before push** (after every task where noted, and all five at the end):
```sh
.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q
.venv/bin/python -m pytest -m "integration" -q
.venv/bin/ruff check inspectord inspectorctl tests
.venv/bin/ruff format --check inspectord inspectorctl tests
.venv/bin/mypy inspectord
```

Run `.venv/bin/ruff format inspectord inspectorctl tests` before every commit.

---

### Task 1: migration 0013 — `ingest_seq` + hunt_query schedule columns

**Files:**
- Create: `inspectord/storage/migrations_data/0013_scheduled_hunts.sql`
- Modify: `inspectord/storage/events.py` (the single `INSERT INTO events_enriched` site — verify with `grep -rn "INSERT INTO events_enriched" inspectord/` that it is still the only writer)
- Test: `tests/test_scheduled_hunts_migration.py` (mirror `tests/test_hunt_query_migration.py` style)

- [ ] **Step 1: Write the failing tests**

```python
def test_migration_0013_is_idempotent(tmp_path):
    # open db, run_migrations twice (delete the schema_version row for 0013
    # between runs to force re-application, mirroring how the existing
    # migration test exercises idempotence — read that test first), no raise

def test_events_get_monotonic_ingest_seq(tmp_path):
    # run_migrations; insert two events via storage.events.insert_event;
    # SELECT ingest_seq ORDER BY ingest_seq → two non-null, strictly increasing

def test_preexisting_rows_have_null_ingest_seq_and_are_excluded_from_max(tmp_path):
    # insert a row with explicit NULL ingest_seq (raw SQL), one via insert_event;
    # SELECT MAX(ingest_seq) → the real one; NULL row never satisfies ingest_seq > 0

def test_hunt_query_gains_schedule_columns(tmp_path):
    # PRAGMA table_info / DESCRIBE hunt_query → schedule_interval_s,
    # schedule_severity, watermark_seq, last_run_at, last_status present
```

- [ ] **Step 2: Run, verify fail** — `.venv/bin/python -m pytest tests/test_scheduled_hunts_migration.py -q` → FAIL (missing column).

- [ ] **Step 3: Implement**

`0013_scheduled_hunts.sql` (every statement idempotent — the runner is not transactional, a crash mid-file re-applies the whole file; spec §4.2):

```sql
-- Migration 0013 — scheduled hunts (hunt-followups design §4.2). Additive.
--
-- ingest_seq is the ground the scheduled-hunt watermark stands on: assigned at
-- INSERT (explicitly, in storage/events.py — no column DEFAULT, so behavior is
-- identical on every DuckDB version), monotonic, no clocks, not derivable from
-- event content. Pre-existing rows keep NULL: they are pre-watermark for every
-- schedule that will ever exist, and NULL never satisfies `ingest_seq > ?`.
CREATE SEQUENCE IF NOT EXISTS event_ingest_seq;
ALTER TABLE events_enriched ADD COLUMN IF NOT EXISTS ingest_seq BIGINT;

ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS schedule_interval_s INTEGER;
ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS schedule_severity VARCHAR;
ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS watermark_seq BIGINT;
ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS last_run_at TIMESTAMP;
ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS last_status VARCHAR;

CREATE INDEX IF NOT EXISTS events_ingest_seq_idx ON events_enriched (ingest_seq);
```

`inspectord/storage/events.py` — extend the INSERT to assign the sequence at write time:

```python
_INSERT = (
    "INSERT INTO events_enriched "
    "(event_id, ts, kind, module, action, severity, payload_json, ingest_seq) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, nextval('event_ingest_seq'))"
)
```

(If `ALTER ... ADD COLUMN IF NOT EXISTS` turns out unsupported by the venv's DuckDB, STOP and report BLOCKED — do not improvise a different idempotence mechanism.)

- [ ] **Step 4: Run, verify pass** — the new test file AND the full unit marker run (every existing insert-path test must still pass).
- [ ] **Step 5: Commit** — `feat(storage): migration 0013 — event ingest_seq + hunt schedule columns`

---

### Task 2: `Event.hunt` namespace + compiler ingest bound

**Files:**
- Modify: `inspectord/schemas/event.py`, `inspectord/parsers/base.py` (`build_event`), `inspectord/hunt/compiler.py`, `inspectord/hunt/execute.py` (only if the SQL text is assembled there — follow where `since`/`until` land)
- Test: `tests/hunt/test_compiler.py` (mirror existing bound tests), plus the schema round-trip test file that covers `Event.vulnerability` (grep for it and add `hunt` beside it)

- [ ] **Step 1: Failing tests**

```python
def test_compile_with_ingest_bounds_emits_placeholders():
    q = compile_hunt_query("process.name == 'x'", ingest_bounds=(10, 20))
    assert "ingest_seq > ?" in q.sql and "ingest_seq <= ?" in q.sql
    assert 10 in q.params and 20 in q.params
    assert "10" not in q.sql and "20" not in q.sql  # parameterized, never formatted

def test_compile_ingest_bounds_with_hostile_expression_stays_parameterized():
    # expression containing quotes/']; DROP' style literals still compiles to
    # placeholder-only SQL (mirror the existing injection tests' style)

def test_event_hunt_namespace_round_trips():
    ev = build_event(module="hunt_scheduler", action="hunt_match", category=["hunt"],
                     type_=["info"], severity="medium", kind="signal",
                     hunt={"name": "q1", "severity": "medium", "match_count": 3})
    assert Event.model_validate_json(ev.model_dump_json()).hunt == {...}
```

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement**

`event.py`: add `hunt: dict[str, Any] | None = None` beside `vulnerability`. `parsers/base.py`: add the `hunt: dict[str, Any] | None = None` kwarg and pass through (mirror `vulnerability` exactly).

`compiler.py`: `compile_hunt_query(..., ingest_bounds: tuple[int, int] | None = None)`. Where the since/until predicates are appended with bound params, append when set:

```python
    if ingest_bounds is not None:
        low, high = ingest_bounds
        where_parts.append("(ingest_seq > ? AND ingest_seq <= ?)")
        params.extend([low, high])
```

(Adapt names to the module's actual builder — read how `since` does it and do the identical thing; strict `>` on the low bound is deliberate, spec §4.3.)

- [ ] **Step 4: Run, verify pass** (compiler + differential + schema suites).
- [ ] **Step 5: Commit** — `feat(hunt): Event.hunt namespace + parameterized ingest_seq bounds in the compiler`

---

### Task 3: store — schedule state operations

**Files:**
- Modify: `inspectord/hunt/store.py`
- Test: `tests/hunt/test_store.py`

- [ ] **Step 1: Failing tests** — behaviors (write them in the file's existing style):
  - `schedule_query` first time → `watermark_seq` = the `max_ingest_seq` passed in; interval/severity stored.
  - `schedule_query` on already-scheduled name (change severity) → watermark UNCHANGED.
  - re-schedule after `unschedule_query` → preserved watermark kept (NOT reset).
  - `unschedule_query` → clears `schedule_interval_s` + `schedule_severity` ONLY (watermark, last_run_at, last_status survive).
  - `schedule_query` validation: interval < 300 raises `HuntBoundsError`; severity outside low/medium/high raises `HuntRequestError`; unknown name raises `HuntQueryNotFound`.
  - `record_run` guarded UPDATE: returns True and stamps watermark/last_run_at/last_status when still scheduled; returns False and writes NOTHING when the row was unscheduled meanwhile; status-only failure stamp leaves watermark untouched (pass `watermark_seq=None`).
  - `due_queries(db, now=...)`: never-run scheduled query is due; one run 10s ago with 300s interval is not; ordering by name.
  - `delete_query` still returns the row; `save_query(replace=True)` preserves all five schedule columns.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** in `store.py`:

```python
SCHEDULE_MIN_INTERVAL_S = 300
SCHEDULE_SEVERITIES = ("low", "medium", "high")


@dataclass(frozen=True)
class ScheduledQuery:
    """One scheduled saved query, as the scheduler consumes it."""

    name: str
    expression: str
    interval_s: int
    severity: str
    watermark_seq: int | None
    last_run_at: datetime | None
    last_status: str | None


def schedule_query(
    db: Database, *, name: str, interval_s: int, severity: str, max_ingest_seq: int
) -> ScheduledQuery:
    """Schedule `name`. A fresh schedule starts its watermark at NOW's max
    ingest_seq — never a catch-up scan (spec §4.3: the catch-up run was an
    alert-suppression primitive). A preserved watermark from an earlier
    schedule is kept, so an off→on gap IS scanned."""
    if interval_s < SCHEDULE_MIN_INTERVAL_S:
        raise HuntBoundsError(
            f"schedule interval is {interval_s}s; the floor is {SCHEDULE_MIN_INTERVAL_S}s"
        )
    if severity not in SCHEDULE_SEVERITIES:
        raise HuntRequestError(
            f"schedule severity must be one of {', '.join(SCHEDULE_SEVERITIES)}, got {severity!r}"
        )
    existing = get_query(db, name)  # validates name
    if existing is None:
        raise HuntQueryNotFound(f"no saved query named {name!r}")
    db.execute(
        "UPDATE hunt_query SET schedule_interval_s = ?, schedule_severity = ?, "
        "watermark_seq = COALESCE(watermark_seq, ?) WHERE name = ?",
        [interval_s, severity, max_ingest_seq, name],
    )
    ...  # re-read and return the ScheduledQuery


def unschedule_query(db: Database, *, name: str) -> ScheduledQuery: ...
    # UPDATE ... SET schedule_interval_s = NULL, schedule_severity = NULL WHERE name = ?
    # raises HuntQueryNotFound on unknown name; returns prior state for the CLI to print


def due_queries(db: Database, *, now: datetime) -> list[ScheduledQuery]: ...
    # WHERE schedule_interval_s IS NOT NULL AND
    #   (last_run_at IS NULL OR last_run_at + interval (seconds) <= now) ORDER BY name
    # (compute the cutoff in Python per row or in SQL with to_seconds/INTERVAL —
    #  whichever DuckDB expresses cleanly; timestamps naive UTC both sides)


def record_run(
    db: Database, *, name: str, watermark_seq: int | None, status: str, now: datetime
) -> bool:
    """Guarded run-result stamp. False = schedule changed under the run;
    the caller must discard the run's result (spec §4.3 item 4)."""
    ...  # single UPDATE ... WHERE name = ? AND schedule_interval_s IS NOT NULL;
    ...  # SET last_run_at, last_status, and watermark_seq only when not None;
    ...  # return rowcount > 0 (DuckDB: use `db.execute(...); SELECT changes()` —
    ...  # or re-SELECT to confirm; pick what Database exposes and test it)
```

Extend `HuntQuery` + `_COLUMNS` + `_row_to_query` with the five new columns (new fields default `None` so existing constructors stay valid), and make `list_queries` carry them.

- [ ] **Step 4: Run, verify pass** (whole `tests/hunt/` + unit marker).
- [ ] **Step 5: Commit** — `feat(hunt): schedule state operations in the saved-query store`

---

### Task 4: `HuntScheduler`

**Files:**
- Create: `inspectord/hunt/scheduler.py`
- Test: `tests/hunt/test_scheduler.py`

- [ ] **Step 1: Failing tests** — drive the scheduler synchronously by calling its
  `tick(now=...)` method directly (design the loop so the thread is a thin
  `while not stop: tick(); wait()` — tests never sleep). Behaviors:
  - due query with matches → exactly ONE emitted event: `module="hunt_scheduler"`,
    `action="hunt_match"`, `kind=signal`, event severity = schedule severity,
    `hunt` payload has `name/severity/match_count/sample_event_ids(≤20)/window_upper_seq/run_duration_s/truncated/pruned_gap`.
  - zero matches → NO event, watermark still advances to upper.
  - `upper <= watermark` or empty table → no SELECT, no watermark write.
  - late-persisted event (old `ts`, fresh `ingest_seq`, inserted after a prior
    run) IS matched by the next run — **the concilium-BLOCKING regression test**.
  - truncated run (insert MAX_LIMIT+1 matching events) → `truncated=True`,
    watermark still advances.
  - failure (schedule a query, then monkeypatch `run_hunt_query` to raise
    `HuntExecutionError`) → `hunt_run_failed` emitted ONCE (transition), second
    failing tick emits nothing, `last_status == "failed:execution"`; watermark
    unchanged; after success the streak resets.
  - backoff: 3 consecutive failures → not due again before `max(interval, 3600)`s.
  - unschedule between SELECT and stamp (simulate via `record_run` returning
    False — monkeypatch or unschedule inside the emit callable) → no emission.
  - an unexpected exception inside one query's run is contained: tick completes,
    other due queries still run (#127 lesson).
  - `pruned_gap`: watermark below `MIN(ingest_seq) - 1` of surviving rows →
    emission carries `pruned_gap: True`.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** `inspectord/hunt/scheduler.py`:

```python
"""HuntScheduler — scheduled saved hunts (hunt-followups design §4).

A supervisor-owned thread, mirroring AnomalyDetector's shape: daemon=True,
the supervisor's shared Database (per-thread cursor contract, storage/db.py),
an injected emit callable, a wake Event for prompt shutdown. The loop guard is
the #127 lesson: no exception may kill this thread — and liveness is surfaced
via last_tick_at because containment without detection is half that lesson.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from typing import Any, Callable

from inspectord.hunt import store
from inspectord.hunt.compiler import compile_hunt_query
from inspectord.hunt.errors import HuntError
from inspectord.hunt.execute import run_hunt_query
from inspectord.log import get
from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event
from inspectord.storage.db import Database

log = get(__name__)

_TICK_S = 60.0
_SAMPLE_MAX = 20
_SOFT_BUDGET_S = 30.0
_FAILURE_BACKOFF_AFTER = 3
_FAILURE_BACKOFF_S = 3600


class HuntScheduler:
    def __init__(self, *, db: Database, emit: Callable[[Event], None]) -> None:
        self._db = db
        self._emit = emit
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._failure_streaks: dict[str, int] = {}
        self.last_tick_at: datetime | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="hunt-scheduler", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick(now=datetime.now(tz=UTC))
            except Exception as exc:  # the #127 guard: the loop never dies
                log.error("hunt scheduler tick failed: %r", exc)
            self._stop.wait(_TICK_S)

    def tick(self, *, now: datetime) -> None:
        self.last_tick_at = now
        for query in store.due_queries(self._db, now=now):
            if self._stop.is_set():
                return
            if self._in_backoff(query, now=now):
                continue
            try:
                self._run_one(query, now=now)
            except Exception as exc:
                log.error("scheduled hunt %s failed unexpectedly: %r", query.name, exc)
                self._record_failure(query, kind="internal", now=now)

    # _run_one:
    #   upper = SELECT MAX(ingest_seq) FROM events_enriched  (via self._db.query)
    #   if upper is None or (query.watermark_seq is not None and upper <= query.watermark_seq): return
    #   watermark = query.watermark_seq or 0  # NULL watermark cannot happen for a
    #       scheduled row (schedule_query always sets it) — treat 0 defensively
    #   pruned_gap = (SELECT MIN(ingest_seq) FROM events_enriched WHERE ingest_seq IS NOT NULL)
    #       > watermark + 1   # bounded claim; NULL-safe
    #   started = time.monotonic()
    #   compiled = compile_hunt_query(query.expression, ingest_bounds=(watermark, upper),
    #                                 since=<epoch floor — pass an explicit very-old since
    #                                 datetime(1970,1,1,tzinfo=UTC) so the default recent
    #                                 window never hides older-ts-but-new-ingest rows>)
    #   result = run_hunt_query(self._db, compiled)          # HuntError → _record_failure(kind=error_kind)
    #   duration = time.monotonic() - started
    #   if duration > _SOFT_BUDGET_S: log.warning(...)
    #   if not store.record_run(self._db, name=query.name, watermark_seq=upper,
    #                           status="ok", now=now): return   # schedule changed mid-run: discard
    #   self._failure_streaks.pop(query.name, None)
    #   if result.rows: self._emit(self._match_event(query, result, upper=upper,
    #                                                duration=duration, pruned_gap=pruned_gap, now=now))
    #
    # _record_failure(query, *, kind, now):
    #   transition = not (query.last_status or "").startswith("failed")
    #   store.record_run(self._db, name=query.name, watermark_seq=None,
    #                    status=f"failed:{kind}", now=now)
    #   self._failure_streaks[query.name] = self._failure_streaks.get(query.name, 0) + 1
    #   if transition: self._emit(build_event(module="hunt_scheduler",
    #       action="hunt_run_failed", kind="signal", category=["hunt"], type_=["error"],
    #       severity=query.severity, ts=now,
    #       hunt={"name": query.name, "severity": query.severity, "error_kind": kind}))
    #
    # _match_event: build_event(module="hunt_scheduler", action="hunt_match",
    #   kind="signal", category=["hunt"], type_=["info"], severity=query.severity, ts=now,
    #   message=f"scheduled hunt {query.name}: {len(result.rows)} new match(es)",
    #   hunt={"name": query.name, "severity": query.severity,
    #         "match_count": len(result.rows),
    #         "sample_event_ids": [r.event_id for r in result.rows[:_SAMPLE_MAX]],
    #         "window_upper_seq": upper, "run_duration_s": round(duration, 3),
    #         "truncated": result.truncated, "pruned_gap": pruned_gap})
    # NOTE: the expression is deliberately NOT in the payload (spec §4.4 — it may
    # legitimately contain the hostile bytes it hunts for).
```

Turn every `# comment block` above into real code — the shapes and constants are the contract; severity strings map through `build_event(severity=...)` which already validates via the enum. The failure-streak map is in-memory by design (a restart resets backoff; `last_status` in the DB carries transition state across restarts — derive `transition` from the DB row, not the map).

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(hunt): HuntScheduler — watermarked scheduled hunts with transition-only failure signaling`

---

### Task 5: per-rule dedup window + non-open bump semantics

**Files:**
- Modify: `inspectord/alerts/dedup.py`, `inspectord/rule_engine.py`, `inspectord/rules/yaml_loader.py` (YamlRule + loader + Match), `inspectord/rules/base.py` (only if `Match` lives there — grep `class Match`)
- Test: `tests/alerts/` dedup tests + rule_engine tests (find them: `grep -rln "DedupEngine\|dedup_window" tests/`)

- [ ] **Step 1: Failing tests** — behaviors:
  - `DedupEngine.persist(alert, window_s=86400.0)` merges with a 2h-old open alert of the same key (would NOT merge under the 600s default); default unchanged when the override is None.
  - bump of an alert with status `acked`: dedup_count/last_seen_at advance, `rendered_short`/`rendered_detail`/`payload_json` NOT overwritten, and the returned tuple flags it as not-notifiable.
  - bump of an `open` alert: unchanged behavior, notifiable.
  - `RuleEngine.process` does NOT return the non-open bumped alert (so supervisor fan-out — notifier AND evidence collector — never sees it); DOES return open bumps and new alerts.
  - YAML rule with `dedup_window_s: 86400` parses; absent → None; non-numeric → YamlRuleError.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement**
  - `dedup.py`: `persist(self, alert, *, window_s: float | None = None) -> tuple[Alert, bool, bool]` — returns `(final_alert, was_new, notifiable)`. Read `status` in the SELECT; when the existing row's status != `"open"`, the UPDATE sets only `dedup_count` and `last_seen_at`, and `notifiable=False`. New alerts and open bumps: `notifiable=True`. Window: `timedelta(seconds=window_s)` when given, else `self._window`.
  - `Match`: add `dedup_window_s: float | None = None`. `YamlRule`: add the field; loader parses `data.get("dedup_window_s")` (float, positive, else `YamlRuleError`); `evaluate_yaml_rule` passes it into `Match`.
  - `rule_engine.py`: `persisted, _was_new, notifiable = self._dedup.persist(candidate, window_s=match.dedup_window_s)`; append to `out` only when `notifiable`.
  - Python rules construct `Match` too — grep `Match(` across `inspectord/rules/` and starter-pack `.py` rules; the new field has a default so no call-site changes, but confirm.

- [ ] **Step 4: Run, verify pass** (full unit marker run — alert-path tests are widespread).
- [ ] **Step 5: Commit** — `feat(alerts): per-rule dedup window; non-open dedup bumps stop notifying and stop rewriting text`

---

### Task 6: starter rules + `_primary_entity_for` hunt branch

**Files:**
- Create: `inspectord/rules/starter_pack/hunt_scheduled_match_high.yaml`, `hunt_scheduled_match.yaml`, `hunt_scheduled_match_low.yaml`, `hunt_scheduled_run_failed.yaml`
- Modify: `inspectord/rules/yaml_loader.py` (`_primary_entity_for`), the starter-pack registry/loader list (grep how existing `vuln_*.yaml` get registered — likely auto-globbed)
- Test: `tests/rules/` starter-pack tests (find the vuln rules' tests and mirror)

- [ ] **Step 1: Failing tests** — behaviors:
  - each severity rule fires only for its `hunt.severity` AND `module == "hunt_scheduler"` AND `action == "hunt_match"`; an identical payload with `module="synthetic_emitter"` fires nothing (forgery pin).
  - `hunt_scheduled_run_failed` fires on `hunt_run_failed` from `hunt_scheduler`.
  - dedup key: two `hunt_match` events for query `q1` → `("hunt", "q1")` entity, same dedup_key; the hunt branch precedes the process branch (event with BOTH `hunt` and `process` blocks → `hunt` wins).
  - rendered messages for a hostile-expression query contain no ESC byte (templates interpolate `{hunt.name}`/`{hunt.match_count}` only — name charset is already safe by store validation).
  - all four rules carry `dedup_window_s: 86400`.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement**

`hunt_scheduled_match.yaml` (the other two severities differ only in `id`, `severity`, and the `hunt.severity` literal; write all three out):

```yaml
version: 1.0.0
id: hunt.scheduled_match
name: "scheduled hunt matched new events"
severity: medium
category: hunt
dedup_window_s: 86400
why: |
  A hunt query you saved and scheduled matched events that arrived since its
  last run. You wrote the query; this alert is it doing its job. The matched
  event ids ride in the alert payload — open /hunt and run the saved query
  interactively to investigate.
false_positives:
  - "The query is broader than intended — refine the expression and save --replace."
detect:
  any_of:
    - event.module == "hunt_scheduler" AND event.action == "hunt_match" AND hunt.severity == "medium"
short: "scheduled hunt {hunt.name}: {hunt.match_count} new match(es)"
detail: "Scheduled hunt {hunt.name} matched {hunt.match_count} newly ingested event(s). Sample event ids are in the alert payload; run the saved query in /hunt to see them."
labels: [hunt, scheduled]
```

`hunt_scheduled_run_failed.yaml`: severity medium, `detect`: `event.module == "hunt_scheduler" AND event.action == "hunt_run_failed"`, short `"scheduled hunt {hunt.name} is failing ({hunt.error_kind})"`, same `dedup_window_s: 86400`, why-text: a broken standing detection is itself a monitoring gap; fires once per failure streak (emission is transition-only).

`_primary_entity_for` — insert BEFORE the process branch:

```python
    if event.module == "hunt_scheduler" and event.hunt and "name" in event.hunt:
        # One alert per scheduled query, keyed on the (charset-validated) saved
        # name; module-pinned so no other event source can steal the identity.
        return "hunt", str(event.hunt["name"])
```

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(rules): hunt.scheduled_match tier rules + hunt dedup entity`

---

### Task 7: IPC — schedule/unschedule methods, limiter, audit enrichment, scheduled_ok gate

**Files:**
- Modify: `inspectord/hunt/ipc_handlers.py`, `inspectord/__main__.py`
- Test: `tests/hunt/test_ipc_handlers.py`

- [ ] **Step 1: Failing tests** — behaviors:
  - `handle_schedule_hunt_query` happy path: `{name, interval_s, severity}` → ok:True, schedule visible via `handle_list_hunt_queries` (which now carries schedule fields); audit row `hunt_query_scheduled` with details `{interval_s, severity, watermark_preserved: bool}`.
  - validation errors (floor/enum/unknown name) → `ok:False` request/bounds error, NO audit row, NO write.
  - `handle_unschedule_hunt_query` → ok:True, audit `hunt_query_unscheduled` with details `{interval_s, severity}` (what was destroyed).
  - rate limit: 13th mutating hunt call inside a minute → `ok:False, error_kind="rate_limited"`; first rejection audited, second not (mirror `_SlidingWindowLimiter` contract in `ipc_commands.py`).
  - `handle_save_hunt_query` on a SCHEDULED name without `scheduled_ok: true` → refused (`error_kind="scheduled"`), with it → replaced AND schedule+watermark preserved; audit details now `{replaced, was_scheduled, old_expression_sha256, new_expression_sha256}`.
  - `handle_delete_hunt_query` on a scheduled name: same gate; audit details `{expression_sha256, was_scheduled, schedule_interval_s}`.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement**
  - New `HuntScheduledError` in `inspectord/hunt/errors.py` mapped to kind `"scheduled"`; `"rate_limited"` kind emitted directly.
  - Module-level limiter shared by save/delete/schedule/unschedule (import or replicate `_SlidingWindowLimiter` from `ipc_commands.py` — IMPORT it; if it is private, promote it to a small shared module `inspectord/ratelimit.py` if one exists — check, `inspectord/ratelimit.py` already exists, read it first, it may BE the limiter).
  - `handle_schedule_hunt_query`: parse + validate via `store.schedule_query` (daemon-side enforcement); `max_ingest_seq` = `SELECT COALESCE(MAX(ingest_seq), 0) FROM events_enriched`; audit AFTER success, actor `user:local`, target `f"hunt:{name}"`.
  - `handle_unschedule_hunt_query`: via `store.unschedule_query`; audit after.
  - save/delete: look up schedule state first; gate on `params.get("scheduled_ok") is True`; enrich the existing `append_audit` calls' `details` (sha256 via `hashlib.sha256(expr.encode()).hexdigest()`).
  - `__main__.py`: register both methods `mutates=True` beside the existing hunt methods (mirror the save/delete registration lambdas).
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(hunt): schedule/unschedule IPC — validated, rate-limited, audited (save/delete enriched + scheduled_ok gate)`

---

### Task 8: supervisor wiring + status liveness

**Files:**
- Modify: `inspectord/supervisor.py`, `inspectord/__main__.py` (status handler)
- Test: the supervisor integration/unit tests that cover AnomalyDetector wiring (grep `AnomalyDetector` in tests/) + status handler test

- [ ] **Step 1: Failing tests**
  - supervisor start → `HuntScheduler` constructed with the shared `self._db` and `emit=self._dispatch`, started; stop() stops it inside the budget (mirror the anomaly-detector wiring test).
  - status IPC response carries `hunt_scheduler: {"alive": true, "last_tick_at": <iso|null>}`.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement**
  - `supervisor.py`: construct `self._hunt_scheduler = HuntScheduler(db=self._db, emit=self._dispatch)` unconditionally (no config knob — zero scheduled queries = no-op ticks), `start()` after the anomaly detector starts, `stop()` beside it in the shutdown sequence (respect the remaining-budget clamping pattern already there). Expose it as an attribute for the status handler.
  - `__main__.py` status handler: add the block from `supervisor._hunt_scheduler` (`alive` + `last_tick_at` ISO or None).

- [ ] **Step 4: Run, verify pass** (unit + integration markers — the daemon fixture boots the real supervisor).
- [ ] **Step 5: Commit** — `feat(daemon): wire HuntScheduler into the supervisor with status liveness`

---

### Task 9: CLI — `hunt schedule` + list columns

**Files:**
- Modify: `inspectorctl/cli/hunt.py`
- Test: `tests/test_cli_hunt.py`

- [ ] **Step 1: Failing tests** — behaviors:
  - `hunt schedule q1 --every 15m` → calls `schedule_hunt_query` with `{"name": "q1", "interval_s": 900, "severity": "medium"}`; `--severity high` passes through; `--every 2m` rejected CLIENT-side (floor message) without an IPC call — but note in the test that the daemon re-validates.
  - `hunt schedule q1 --off` → calls `unschedule_hunt_query {"name": "q1"}`.
  - `--every` and `--off` together → error.
  - `hunt list` renders interval/severity/last-run/last-status columns and an `overdue` marker when `last_run_at + interval < now`; unscheduled rows show `-`.
  - `hunt save --replace` on a scheduled query passes `scheduled_ok` only with a new `--scheduled-ok` flag; `hunt delete` likewise; the daemon's `"scheduled"` rejection renders its message + a hint to re-run with `--scheduled-ok`.
  - all daemon-derived strings escaped (existing house pattern).

  Reuse `_DURATION_RE`/`to_iso` conventions: parse `--every` with the existing `_DURATION_RE` into seconds (new tiny helper `to_seconds`), floor check `>= 300`.

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** — one `schedule` command (`--every`, `--severity`, `--off`, mutually-exclusive validation), extend `list_cmd` table, add `--scheduled-ok` to save/delete. Match the file's output-style rules (loud REPLACED-style messages for schedule changes: scheduling prints what now stands, `--off` prints what was destroyed).
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(cli): inspectorctl hunt schedule/--off + schedule columns in hunt list`

---

### Task 10: web — read-only schedule display

**Files:**
- Modify: `inspectorctl/web/routes/hunt.py`, `inspectorctl/web/templates/hunt.html`
- Test: `tests/web/test_hunt.py`

- [ ] **Step 1: Failing tests** — saved-query list shows interval/severity/last-status when present (fake `list_hunt_queries` response with schedule fields); a `failed:execution` status renders with the warning css class; hostile description/name content stays escaped (extend the existing escaping test's fake data).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** — pass the fields through the route's `saved` list (they arrive in the IPC response from Task 7's `_query_dict` extension — extend `_query_dict` in `ipc_handlers.py` there if Task 7 did not already; verify), render extra columns in the saved-queries table; NO mutating controls (spec §4.6: the web stays read-only for hunt).
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(web): show hunt schedule state read-only on /hunt`

---

### Task 11: full gates, push, PR

- [ ] **Step 1: All five gates green** (unit, integration, ruff check, format --check, mypy).
- [ ] **Step 2:** `git push -u origin scheduled-hunts`; `gh pr create --title "feat(hunt): scheduled hunts (PR3)"` — body: what/why, spec §4 pointer, concilium note, test summary. Watch CI via Monitor, squash-merge, sync main.

---

## Self-review checklist for the executor
- Watermark NEVER compares event `ts` (only `ingest_seq`); the compiled `since` for scheduled runs is the 1970 floor so the default window cannot hide old-ts/new-ingest rows.
- No emission path includes the expression in `Event.hunt`.
- `record_run` guard tested for the unschedule-mid-run race.
- Every mutating hunt IPC method rate-limited AND audited; rejections before writes.
- Type thread-through: `ScheduledQuery` vs `HuntQuery` field names consistent across store/scheduler/handlers/CLI.
