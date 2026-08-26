# Retention & rotation v1 — design

Date: 2026-08-26 (v2 — concilium verdicts folded: 4 REVISE + 1 READY across 5 lenses;
2 BLOCKING + 6 MAJOR findings all addressed)
Parent spec: `2026-05-24-local-inspection-design.md` §10.4 (retention & rotation), §23
(config), profile disk budgets (minimal 500 MB / standard 2 GB).
Status: **autonomously drafted, NOT human-reviewed** (concilium-reviewed in-session).
The §4 protection rules and the §5.2 journal-quota interpretation are the decisions
most worth a human look.

## 1. Goal

Bound the daemon's disk growth: age-based pruning of the four unbounded surfaces
(enriched events, journal files, alerts, forensic evidence blobs), §10.4's protection
rule — critical alerts and their evidence are NEVER auto-pruned — enforced
structurally, a flood-resistant quota backstop for the journal dir, and every
destructive run audit-logged with attributable per-blob provenance.

## 2. Scope

### In (v1)

- `RetentionConfig` on `DaemonConfig` (§3).
- `inspectord/retention/engine.py`: four pruners + `run_retention` orchestrator →
  `RetentionReport` (§5).
- Daily supervisor tick, ordered strictly AFTER the audit tick (§6).
- Journal quota backstop with critical-day exemption + age floor (§5.2).
- Tombstone provenance stamping + per-blob audit detail (§5.4).
- `CHECKPOINT` after DB pruning (§5.5).

### Out (deliberate)

| Cut | Why |
| --- | --- |
| `audit_log` pruning | Chain-aware GC needs re-anchoring; deferred by the audit-log spec §2. |
| Profile-aware defaults (§10.4 "defaults profile-aware") | `DaemonConfig` has no profile machinery yet; v1 ships standard-profile constants. The future profile slice must wire minimal-profile defaults (7-day retention, journal quota well under 500 MB) into `RetentionConfig`. |
| Entity-state / first_seen / metric_baseline / rule_stats / dep_audit pruning | Bounded by system size or tiny write rates. Future per-table knobs. |
| `cases` / `case_event` pruning | User-curated record; deletion is a user action. |
| Whole-storage-dir quota | v1 quota covers the journal dir only; a global cap needs cross-surface eviction priorities. |
| Web/Settings UI | Config-file only (parent §23 TOML). |
| Orphan evidence blobs (blob present, no `case_evidence` row — crash between `put()` and INSERT) | Accepted leak: the window is milliseconds wide and each occurrence is one file. Revisit if it ever shows up in practice. `.tmp-*` debris IS swept (§5.4). |
| Hunt data-horizon banner | §5.1 notes the interaction; surfacing "results cover data since <date>" in the hunt UI is a one-line follow-up in the web tier, out of this daemon-only PR. |

**Space-reclamation facts** (verified empirically on this project's DuckDB): after
DELETE, freed blocks are reused only once a CHECKPOINT runs; the file then plateaus at
peak size rather than shrinking. DuckDB's `VACUUM` reclaims nothing — if the plateau
ever proves too high, the remedy is copy-to-new-file compaction, not VACUUM.

**Forward-compat note (case reopen):** closed is currently terminal. When
reopen-after-close ships (cases spec deferred item), the reopen flow must surface
which attached alerts/evidence were already retained out (tombstones + the case
detail's pruned-alert placeholders make this cheap), so the loss is visible at reopen
time.

## 3. Config

```python
class RetentionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    events_days: int = 30          # events_enriched rows
    events_max_rows_per_run: int = 100_000   # chunked-delete budget per daily run
    journal_days: int = 30         # daily .jsonl.gz files
    journal_quota_mb: int = 500    # MiB; quota backstop on the journal dir
    journal_quota_floor_days: int = 7   # quota pass never deletes files younger than this
    alerts_days: int = 365         # non-critical alerts, by last_seen_at
    evidence_days: int = 365       # forensic blobs (subject to §4 protection)
```

All `*_days` ≥ 1, `journal_quota_mb` ≥ 10 (MiB — `quota_bytes = journal_quota_mb *
2**20`), `events_max_rows_per_run` ≥ 1000. `journal_quota_mb = 500` is a v1-chosen
sub-budget of the parent's 2 GB standard-profile whole-storage cap (which is cut),
leaving headroom for the DuckDB file and evidence blobs.

## 4. Protection rules (what is never auto-pruned)

1. **Critical alerts** — `severity = 'critical'` exempt regardless of age.
2. **Evidence of open or critical cases** — a blob is prunable only if EVERY case
   referencing it is closed AND none has a critical alert attached (§5.4 mechanics,
   including the race defenses).
3. **Today's journal file** — never deleted; **journal files for days on which a
   critical alert fired** — never deleted by the quota pass NOR the age pass (parent
   §10.4's "non-critical" qualifier, interpreted per-day via
   `SELECT DISTINCT CAST(ts AS DATE) FROM alerts WHERE severity='critical'`).
4. **Alerts attached to open cases** — kept regardless of age. Attached-to-closed
   non-critical alerts prune normally (the case detail already renders a placeholder
   for pruned alerts; export lists them as missing).
5. **The newest `audit_head` anchor event** — structurally exempt from the events
   pruner (one-row subquery exclusion). Protects the tamper-detection anchor across
   daemon outages longer than `events_days` and while a broken chain is suppressing
   re-anchoring.

Residual risk, accepted and documented: `attach_alert` (IPC) accepts closed cases, so
a critical alert attached to a long-closed case AFTER its evidence was pruned finds
the blob gone — the §4.2 check runs at tick time and cannot see the future. The
racing variant (attach concurrent with the tick) is closed by the capture-lock
serialization in §5.4.

## 5. Pruners — `inspectord/retention/engine.py`

`run_retention(db, *, cfg, journal_dir, evidence_root, now, capture_lock=None) ->
RetentionReport`. `now` MUST be timezone-aware UTC (`datetime.now(UTC)`); "today" =
`now.date()` in UTC — exactly the Journal's rotation date; all SQL cutoffs derive from
this `now` (naive-UTC conversion at the query boundary, matching the DB convention).
`RetentionReport`: per-surface counts, `pruned_shas: list[str]`,
`skipped_files: list[str]` (unparseable names — reported in audit details, NOT
errors), `errors: list[str]`. Each pruner independently guarded; a
`TransactionException` from concurrent persist-loop writes lands in `errors` like any
other failure and the remaining surfaces still run.

### 5.1 Events (chunked)

Delete rows `ts < now - events_days`, EXCEPT the newest `audit_head` row (§4.5), in
chunks bounded by `events_max_rows_per_run` per run (LIMIT-subquery loop). A run that
exhausts its budget stops; the backlog drains over subsequent daily runs — this
bounds the first prune after a months-off outage instead of issuing one giant DELETE
on the monitor thread at startup. Note: hunt queries reaching past `events_days`
silently cover only the surviving window (banner is a cut, §2).

### 5.2 Journal files

Files `YYYY-MM-DD.jsonl.gz` in `journal_dir`; unparseable names → `skipped_files`,
never deleted. Protected set: today + critical-alert days (§4.3).
- Age pass: delete unprotected files older than `journal_days`.
- Quota pass: if remaining `.jsonl.gz` bytes still exceed the quota, delete
  unprotected files oldest-first — but never files younger than
  `journal_quota_floor_days` (a log flood cannot compress history to zero: bounded by
  the floor, an intruder can at most evict files older than 7 days, and never
  critical-alert days). Stop when under quota OR the deletable list is exhausted;
  residual overage is reported in the audit details, not an error.
- Caveat: deleting a file the `Journal` still holds open (yesterday's, pre-rotation)
  unlinks the name while the daemon keeps writing the orphaned inode until rotation —
  harmless (space frees at rotation), noted here so nobody "fixes" it.

### 5.3 Alerts

Prune on **recency, not first-seen** — dedup keeps one row alive across re-firings by
updating `last_seen_at` while `ts` stays at the first firing:

```sql
DELETE FROM alerts
WHERE last_seen_at < now - alerts_days
  AND severity != 'critical'
  AND alert_id NOT IN (
      SELECT ca.alert_id FROM case_alert ca
      JOIN cases c ON c.case_id = ca.case_id WHERE c.status = 'open')
```

### 5.4 Evidence blobs

Runs entirely under the EvidenceCollector's capture lock (passed in as
`capture_lock`; supervisor wires it) — `ForensicStore.put` is idempotent-by-existence,
so an unserialized pruner could unlink a blob that a concurrent capture just deduped
against, leaving a brand-new critical case with no evidence. Captures are rare and the
pruner is daily; contention is negligible.

Candidates: DISTINCT sha256 among `case_evidence` rows with `captured_at < now -
evidence_days` whose `meta_json` does NOT already carry a `pruned_at` marker. Prune
iff: no younger `case_evidence` row for the sha, every referencing case closed, no
referencing case has a critical alert. Immediately before unlink, re-check for a
younger row (belt-and-braces inside the lock). On successful unlink:
- merge `{"pruned_at": <iso>, "pruned_by": "auto:retention"}` into each tombstone
  row's `meta_json` — a missing blob WITHOUT this marker is itself an indicator of
  tampering; the marker also removes the sha from future candidate scans;
- append the sha to `RetentionReport.pruned_shas`.
Already-missing file: stamp the tombstone the same way but count nothing (no phantom
daily counts). `case_evidence` rows are never deleted. Also swept here: `.tmp-*`
files under `evidence_root` older than one day (crashed `put()` debris).

### 5.5 Checkpoint

After the DB pruners, when any DB-surface count > 0: best-effort `CHECKPOINT`
(failure → `errors`). Without it, freed blocks are not reusable and the file grows
past its plateau.

## 6. Scheduling, audit, failure surfacing

- Supervisor `_retention_tick`, daily, from `_monitor_tick`, **strictly after
  `_audit_tick` in the same tick** (the fresh anchor is emitted before retention can
  touch the events table; combined with §4.5 the anchor survives regardless).
  Ctor-injectable interval; marker set BEFORE the run (a failing run waits a full
  interval, not one poll); the tick body catches all exceptions like `_audit_tick`.
  Runs only when `cfg.retention.enabled`.
- Deleted anything (real deletions — counts and `pruned_shas` from actual work): ONE
  audit row, actor `auto:retention`, action `retention_pruned`, target
  `retention:daily`, details = counts + `pruned_shas` (capped at 50 + `"more": n`) +
  `skipped_files` + residual quota overage. A no-op run writes no row.
- `errors` non-empty → medium-severity `retention_failed` supervisor event; message
  carries the first 5 errors + "and N more" (full list to the log). Severity stays
  medium deliberately — retention failure is a maintenance problem, not an intrusion
  signal; a persistently failing run repeats the event daily, which is the desired
  nagging.
- First run on a fresh install: fires ~1s after start, prunes nothing, writes
  nothing — quiet by design.

## 7. Testing

TDD. Per pruner: in/out-of-window; every §4 rule (critical alert survives; open-case
alert survives; open-case/critical-case evidence survives; closed-non-critical old
evidence deleted with tombstone stamped `pruned_at`; second run over stamped
tombstones = zero counts, no audit row; missing blob stamped but uncounted; newest
audit_head survives even when ancient; critical-day journal file survives age AND
quota passes; today survives; quota floor holds under a simulated flood; unparseable
name → skipped_files, not errors; deduped alert with old ts + fresh last_seen_at
survives). Events chunking: budget-bounded run resumes next run. UTC: local-naive
`now` is rejected (assert/raise) or converted — pin one behavior and test it.
Concurrency: evidence pruner blocks while capture lock held (two-thread test);
retention runs while the persist loop inserts (no lost surfaces; conflict → errors).
Orchestrator: `enabled=False` no-op; one-surface-fails-others-run; checkpoint invoked
when counts > 0. Supervisor: ordering after audit tick; audit row only when counts >
0; `retention_failed` on injected error; marker-before-run.

## 8. Delivery

Single PR (pure Python): config + engine + supervisor tick + EvidenceCollector lock
exposure + tests. If it runs long, §5.4 evidence pruning is the designated split
point (its protection logic is the largest test surface and is inert for a year at
default settings).
