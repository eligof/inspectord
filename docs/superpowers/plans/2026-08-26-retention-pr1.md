# Retention v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Age-based pruning of events/journal/alerts/evidence with §10.4 critical-data
protection, per `docs/superpowers/specs/2026-08-26-retention-design.md`. Single PR.

**Architecture:** `inspectord/retention/engine.py` holds four pruners +
`run_retention` orchestrator returning `RetentionReport`; a daily supervisor
`_retention_tick` (strictly after `_audit_tick`) runs it, writes one
`retention_pruned` audit row on real deletions, emits `retention_failed` on errors.
The evidence pruner runs under `EvidenceCollector`'s capture lock.

**Tech Stack:** Python 3.13, DuckDB, pytest.

**Gates (before every commit):**
`.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` ·
`.venv/bin/python -m pytest -m "integration" -q` ·
`.venv/bin/ruff check inspectord inspectorctl tests` ·
`.venv/bin/ruff format --check inspectord inspectorctl tests` · `.venv/bin/mypy inspectord`

**Verified facts:**
- The spec (§3–§6) is authoritative for ALL semantics: config fields/validators,
  protection rules, per-pruner SQL, tombstone stamping, tick ordering, audit/event
  shapes. Read it in full before starting; where this plan and the spec disagree, the
  spec wins.
- `EvidenceCollector.__init__(db_path, store)` has `self._lock = threading.Lock()`
  (`inspectord/evidence/collector.py:58`) — expose it via a `capture_lock` property.
- Supervisor: `self._cfg.storage.{db_path, journal_dir, evidence_dir}`; audit-tick
  pattern at `supervisor.py:151/168/514` (ctor param + `_last_*_mono` + hook in
  `_monitor_tick`); `_emit_supervisor_event`; `append_audit` fail-open.
- Journal files: `YYYY-MM-DD.jsonl.gz` (`journal.py:41`), rotation date =
  `datetime.now(UTC).date()`.
- Config precedent: `AnomalyConfig` in `inspectord/config.py:37` + `anomaly` field on
  `DaemonConfig` — mirror for `RetentionConfig`/`retention`.
- Alerts: `last_seen_at` NOT NULL (0003); cases: `cases.status`, `case_alert`
  (0006); `case_evidence.meta_json` VARCHAR nullable (0007).
- Audit test hygiene: call `inspectord.audit.log.reset_for_tests()` in
  `setup_function` of any test file that touches `append_audit`.

---

### Task 1: RetentionConfig

**Files:**
- Modify: `inspectord/config.py`
- Test: `tests/test_config_retention.py` (mirror `tests/test_config_anomaly.py` style)

- [ ] Failing tests: defaults (30/30/500/7/365/365/100_000, enabled True); validators
reject `events_days=0`, `journal_quota_mb=5`, `events_max_rows_per_run=100`; TOML
round-trip through the config loader sets fields; `extra="forbid"` rejects unknown
keys.
- [ ] Implement `RetentionConfig` exactly per spec §3 + `retention: RetentionConfig =
Field(default_factory=RetentionConfig)` on `DaemonConfig` (use pydantic `Field(ge=...)`
constraints: `*_days ge=1`, `journal_quota_mb ge=10`, `events_max_rows_per_run
ge=1000`).
- [ ] Gates. Commit: `feat(retention): RetentionConfig`

---

### Task 2: Engine — report, events, journal, alerts pruners

**Files:**
- Create: `inspectord/retention/__init__.py` (empty), `inspectord/retention/engine.py`
- Test: `tests/retention/__init__.py`, `tests/retention/test_engine.py`

- [ ] Failing tests (seed via `run_migrations` + `insert_event`/raw INSERTs; `NOW =
datetime(2026, 8, 26, 12, 0, tzinfo=UTC)`):
  - events: out-of-window deleted, in-window survives; **newest `audit_head` event
    survives even when ancient** (seed a supervisor/audit_head event 90 days old as
    the only anchor); chunking: seed 25 old rows, `events_max_rows_per_run=10` →
    first run deletes 10 and reports it, three runs drain.
  - journal (tmp dir of fake `.gz` files with dated names + junk name): age pass
    deletes old, keeps today (today = `now.date()` UTC), keeps critical-day files
    (seed a critical alert on that date), junk name → `skipped_files` not deleted not
    error; quota pass: floor holds (files younger than `journal_quota_floor_days`
    survive a tiny quota), oldest-first eviction, stops at list exhaustion with
    residual overage reported.
  - alerts: old `last_seen_at` non-critical deleted; **old `ts` + fresh
    `last_seen_at` survives**; critical survives; attached-to-open-case survives;
    attached-to-closed-case old alert deleted.
  - `now` must be tz-aware: naive `now` raises `ValueError`.
- [ ] Implement per spec §5.1–§5.3 exactly: `RetentionReport` dataclass
  (`events_deleted, journal_files_deleted, alerts_deleted, evidence_blobs_deleted,
  pruned_shas, skipped_files, errors`, plus `quota_overage_bytes: int = 0` and an
  `any_deletions` property), `prune_events(db, *, now, days, max_rows)`,
  `prune_journal_files(db, journal_dir, *, now, days, quota_mb, floor_days)`
  (critical-day set from the alerts table), `prune_alerts(db, *, now, days)`. Each
  guarded by the orchestrator (Task 3), not internally.
- [ ] Gates. Commit: `feat(retention): events/journal/alerts pruners`

---

### Task 3: Engine — evidence pruner, checkpoint, orchestrator

**Files:**
- Modify: `inspectord/retention/engine.py`, `inspectord/evidence/collector.py`
- Test: `tests/retention/test_engine.py` (append), `tests/retention/test_evidence_pruner.py`

- [ ] Failing tests:
  - `EvidenceCollector.capture_lock` property returns its lock.
  - evidence: closed-non-critical old blob deleted, tombstone `meta_json` gains
    `pruned_at`/`pruned_by`, sha in `pruned_shas`; open-case blob survives;
    critical-case blob survives; younger `case_evidence` row for same sha → survives;
    already-stamped tombstone not re-candidate (second run: zero counts); missing
    blob file → stamped, NOT counted; `.tmp-old` file older than 1 day swept,
    fresh `.tmp` kept; two-thread test: pruner blocks while capture lock held.
  - orchestrator: `enabled` handled by caller (supervisor) — `run_retention` always
    runs; one-surface-fails-others-run (drop the alerts table before the run →
    `errors` non-empty, events still pruned); CHECKPOINT executed when any DB count >
    0 (assert via a real mechanism — monkeypatch-count the execute call or observe
    file-size behavior; must be a genuine assertion); naive-`now` ValueError.
- [ ] Implement per spec §5.4–§5.5: `prune_evidence(db, evidence_root, *, now, days,
  capture_lock)` (whole body under `capture_lock` when given, else a no-op lock);
  candidate query excludes rows whose `meta_json` already carries `"pruned_at"`;
  re-check younger row before unlink; stamp via read-merge-UPDATE of `meta_json`;
  `run_retention(db, *, cfg, journal_dir, evidence_root, now, capture_lock=None)`
  wiring all five steps with per-surface try/except into `errors`.
- [ ] Gates. Commit: `feat(retention): evidence pruner + checkpoint + orchestrator`

---

### Task 4: Supervisor tick + wiring

**Files:**
- Modify: `inspectord/supervisor.py`
- Test: `tests/retention/test_supervisor_tick.py` (mirror
  `tests/audit/test_supervisor_integration.py`'s unstarted-Supervisor +
  `_monitor_tick()` pattern)

- [ ] Failing tests:
  - `RETENTION_TICK_INTERVAL_S = 86400.0` constant + ctor param
    `retention_tick_interval_s`; with interval 0 and `retention.enabled=True`, one
    `_monitor_tick()` runs retention (seed one prunable event → gone) and writes ONE
    `retention_pruned` audit row (actor `auto:retention`, target `retention:daily`,
    details carry counts) — and a second tick with nothing to prune writes NO second
    row.
  - `retention.enabled=False` → nothing pruned, no row.
  - Ordering: retention tick runs after the audit tick in the same `_monitor_tick`
    (assert via emitted-event order: the `audit_head` event is dispatched before the
    events pruner deletes anything).
  - Injected error (chmod-away `evidence_root` or drop a table) → medium
    `retention_failed` event; message truncation: >5 errors → "and N more" suffix
    (or assert the ≤5 exact-join path — cover one branch precisely).
  - Marker-before-run: a raising run does not re-run on the immediately-next tick
    (interval respected).
- [ ] Implement: constant + ctor param + `self._last_retention_tick_mono` (None →
  first tick); hook in `_monitor_tick` AFTER the audit-tick block;
  `_retention_tick()` builds `now = datetime.now(UTC)`, calls
  `run_retention(self._db, cfg=self._cfg.retention,
  journal_dir=self._cfg.storage.journal_dir,
  evidence_root=self._cfg.storage.evidence_dir, now=now,
  capture_lock=<the collector's capture_lock if the supervisor holds an
  EvidenceCollector reference (constructed ~line 215 — keep a reference if it doesn't
  already), else None>)`; on `report.any_deletions` →
  `append_audit(self._cfg.storage.db_path, actor="auto:retention",
  action="retention_pruned", target="retention:daily", details=<counts +
  pruned_shas[:50] + {"more": n} when truncated + skipped_files + overage>)`; on
  `report.errors` → `_emit_supervisor_event(action="retention_failed",
  severity="medium", type_=["error"], message=first-5-joined + (" and N more" if
  more), raw={"errors": report.errors[:20]})`. Whole body in try/except like
  `_audit_tick`; only run when `self._cfg.retention.enabled`.
- [ ] Gates (unit AND integration). Commit: `feat(retention): daily supervisor tick + audit/event wiring`

---

### Task 5: Ship

- [ ] Full gates once more.
- [ ] `git push -u origin retention`; `gh pr create` — title
  `feat(retention): age-based pruning with critical-data protection`; body: spec link,
  concilium note (5 lenses, findings folded; still human-unreviewed), the §4
  protection rules summary, accepted residual risks (attach-to-closed permanent
  window, orphan-blob leak); standard footer.
- [ ] Monitor poll loop for CI (NOT background `gh pr checks --watch`), then
  `gh pr merge <N> --squash --delete-branch`, `git checkout main && git pull --ff-only`.
