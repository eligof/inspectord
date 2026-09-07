# Hunt follow-ups: data-horizon banner, `scanners run` CLI, scheduled hunts

- **Status**: v2 — concilium-reviewed (3-lens Workflow: unanimous REVISE, 3 BLOCKING +
  7 MAJOR + 12 MINOR; all folded below). Autonomously drafted; not yet human-reviewed.
- **Date**: 2026-09-07
- **Parent spec**: `2026-05-24-local-inspection-design.md` §2.2 (Hunt panel), §24 (CLI verbs)
- **Sibling specs**: `2026-08-20-hunt-design.md` (the shipped hunt engine/panel),
  `2026-08-26-retention-design.md` (which deferred the horizon banner),
  `2026-08-27-worker-command-channel-design.md` (the trigger channel PR2 reuses)

## 1. What this is

Three follow-ups left dangling around Hunt after the panel program shipped:

1. **Data-horizon banner** (deferred by the retention spec): after retention pruning, a hunt
   query reaching past `events_days` silently covers only the surviving window — an empty
   result is indistinguishable from a clean history. Surface the truncation on `/hunt`.
2. **`inspectorctl scanners run <name>`** (parent §24 promise): the web Run-now buttons
   (#156) exist; the CLI verb does not. Add it over the same `run_worker_command` IPC.
3. **Scheduled hunts**: a saved hunt query can be given a per-query interval and severity;
   the daemon runs it periodically over *newly ingested events only* and routes matches
   through the normal rule → alert pipeline. This turns Hunt from a purely interactive
   tool into a standing detection the user authors in the query grammar they already know.

One PR per item. PR1 and PR2 are small and mechanically reviewable; PR3 is the feature.

## 2. PR1 — data-horizon banner

**Daemon.** `run_hunt_query`'s success response gains one field: `data_horizon` — the
ISO-rendered `MIN(ts)` over the `events_enriched` table, `null` when the table is empty.
`MIN(ts)` (the *actual* oldest surviving row) is deliberately chosen over the retention
config cutoff (`now - events_days`): during a chunked backlog drain after downtime, real
data older than the cutoff still exists and the banner must not claim it doesn't; before
retention has ever pruned, the horizon is honestly "since first install". The value is
computed inside the existing handler with the same DB handle, once per query run (not per
listed query). It is a *second statement*, not one transaction with the query SELECT — a
daily retention prune committing between the two can skew the banner by one prune cycle;
accepted (concilium ops-MINOR), the error is bounded and rare.

Two honesty caveats the implementation must respect (concilium):

- **The banner must not over-claim.** With default config, `MIN(ts)` is ~30 days back
  while the default query window is 7 days — "results cover data since \<MIN(ts)\>"
  would claim coverage the query never scanned. The panel/CLI render the *effective*
  lower bound `max(since, data_horizon)`, and the horizon-specific warning line appears
  **only when `data_horizon > since`** ("your window reaches past the surviving data;
  results only cover since \<horizon\>"). Otherwise the existing window line already
  tells the truth and no extra banner renders. `data_horizon` itself is returned in the
  IPC response unconditionally; the conditional is presentation.
- `data_horizon = null` renders "no events in the store" — not "no events recorded
  yet": with persistence down, events ARE being recorded into the journal and the
  handler cannot know recording state.
- `ts` for log-derived events comes from log content, so one backdated line can drag
  `MIN(ts)` arbitrarily far back and overstate coverage. Advisory value; documented
  limitation (single-user box, and the failure direction is over- not under-claiming
  after this section's `max(since, horizon)` rule).

**CLI.** `inspectorctl events search` / `hunt run` print the same effective-coverage
line to stderr after results, same conditional.

No new IPC method, no schema change.

## 3. PR2 — `inspectorctl scanners run <name>`

New CLI module `inspectorctl/cli/scanners.py` with one verb:

```
inspectorctl scanners run <name>      # aide | rkhunter | yara | vuln
```

- `aide`/`rkhunter`/`yara` → `run_worker_command` with
  `{"worker": "scanner_runner", "command": "run_scanner", "args": {"name": <name>}}` —
  exactly the params the web Run-now button sends; mirror
  `inspectorctl/web/routes/scanners.py:45` (and `routes/vulnerabilities.py` for vuln),
  do not re-derive. (v1 of this spec said `args: {"scanner": ...}` — wrong; the worker
  reads `args.get("name")`. Concilium-corrected.)
- `vuln` → `{"worker": "vuln_scanner", "command": "rescan"}`.
- Names outside the closed set are rejected client-side with the list of valid names —
  but the daemon's allowlist remains the enforcement point; the client check is UX only.
- Output: the daemon's accepted/rejected outcome verbatim, including the rejection
  reason (`not_allowlisted`, rate-limit, worker-not-running). Exit code 0 only on
  accepted. Trigger-only at-most-once semantics are printed once
  ("triggered; watch /scanners or the events feed for the result") — the CLI does NOT
  wait for the `command_result` event; that is the channel's design.

Audit, allowlist and the 12/min rate limit all live daemon-side and apply unchanged.
Parent §24's `scanners schedule list/set` verbs remain out of scope (interval scheduling
lives in config; a runtime schedule-mutation surface is a different feature).

## 4. PR3 — scheduled hunts

### 4.1 Shape

`HuntScheduler`: a daemon-side thread owned by the supervisor, mirroring
`AnomalyDetector` (`threading.Thread(daemon=True)`, the supervisor's **shared
`Database` via its per-thread cursor** — not a second connection; injected
`emit: Callable[[Event], None]`; `start()`/`stop()` with a wake `threading.Event`).
Wired in `supervisor.py` beside the anomaly detector. **Not** a worker subprocess:
DuckDB is single-writer, the hunt store and events live in the daemon's DB, and a
second process could not even read them while the daemon holds the write handle.

The loop ticks every 60 s: pick queries whose `schedule_interval_s` is set and whose
next-due time has passed, run them **serially** in `name` order (hunts are ad-hoc SQL;
two heavy regexes in parallel on a personal box is self-inflicted load), each under the
existing compiled-query row cap. A run whose wall time exceeds a soft budget (30 s)
logs it and stamps the duration into the run's emission — a chronically slow standing
hunt must be visible, not just slow.

**Liveness is observable** (the AnomalyDetector blind spot is not copied): the `status`
IPC response gains a `hunt_scheduler` block — `{alive, last_tick_at}` — surfaced on the
health panel; `inspectorctl hunt list` derives and shows overdue-ness (next-due from
`schedule_interval_s` + `last_run_at` vs now). A dead scheduler thread must be visible
without reading logs — silent stop of standing detections is the #127 incident shape
one layer up.

### 4.2 Schema (migration 0013, additive, idempotent)

Every statement must be re-runnable: the migration runner is not transactional, so a
crash mid-file re-applies the whole file on next boot. All existing migrations are
idempotent by construction; 0013 keeps that property with `IF NOT EXISTS` on every
statement (verified supported by the project's DuckDB for both forms below).

**`events_enriched` gains an ingestion sequence** — the ground the watermark stands on:

```sql
CREATE SEQUENCE IF NOT EXISTS event_ingest_seq;
ALTER TABLE events_enriched ADD COLUMN IF NOT EXISTS
    ingest_seq BIGINT DEFAULT nextval('event_ingest_seq');
```

Existing rows take whatever backfill value the ALTER assigns (all are pre-watermark for
every schedule that will ever exist, so the exact values are irrelevant); new rows get
monotonically increasing values from the insert path. The implementation plan must
verify the `_persist` INSERT uses an explicit column list so the DEFAULT applies (or
set the column explicitly).

`ALTER TABLE hunt_query ADD COLUMN IF NOT EXISTS` ×5:

| column | type | meaning |
|---|---|---|
| `schedule_interval_s` | INTEGER | NULL = not scheduled (the default for every existing and new query) |
| `schedule_severity` | VARCHAR | one of low/medium/high; NULL until scheduled |
| `watermark_seq` | BIGINT | newest `ingest_seq` already covered; NULL only when never scheduled |
| `last_run_at` | TIMESTAMP | last completed run (success or failure), naive UTC |
| `last_status` | VARCHAR | `'ok'` or `'failed:<error_kind>'`; NULL until first run |

### 4.3 Watermark semantics — only newly *ingested* events

**The watermark is an ingest-sequence number, not an event timestamp.** v1 of this spec
watermarked on event `ts` and was rejected by concilium as BLOCKING twice over: `ts` is
capture-time while arrival in `events_enriched` is asynchronous (router → bounded queue
→ `_drain` → `_persist`), so any event still in that pipeline when a run's SELECT
executes would have been skipped by every future run — silently, under completely
normal operation (bursts, backlog drain after downtime). Worse, log-derived events take
`ts` from log *content*, so a backdated log line would evade every standing detection.
`ingest_seq` is assigned at INSERT, is monotonic, involves no clocks (no tz-mixing, no
backward-NTP-step edge), and cannot be influenced by event content.

Each run:

1. Captures `upper = SELECT MAX(ingest_seq) FROM events_enriched` once at run start.
   `upper IS NULL` (empty table) or `upper <= watermark_seq` → skip: no SELECT, no
   event, no watermark write.
2. Executes the saved expression with an **additional compiled predicate**
   `ingest_seq > :watermark AND ingest_seq <= :upper`, injected via a new
   parameterized bound in `compile_hunt_query` (same `_Binder` path as the ad-hoc
   `since` bound — never by string-formatting the stored expression; a test must
   assert the *placeholder*, not the value, appears in the SQL text).
3. On success, advances `watermark_seq = upper` — even when the run matched nothing,
   and even when the run was `truncated` (row cap hit): the uncounted remainder of a
   truncated window is deliberately not re-scanned; `truncated=True` on the alerting
   event is the signal to go look interactively. On failure the watermark does NOT
   advance; the window is retried.
4. The watermark UPDATE is guarded: `... WHERE name = :name AND schedule_interval_s IS
   NOT NULL`; zero rows updated means the schedule was removed or the row deleted
   mid-run — the run's result is discarded (no emission), closing the
   `--off`-while-running race.

**No catch-up run, no `first_seen` suppression.** Scheduling a query (first time) sets
`watermark_seq = MAX(ingest_seq)` at schedule time: the standing detection covers from
that moment forward, with zero rows scanned and **zero suppressed matches** — "what
does this match historically" is what the interactive panel is for. v1's
first-run-with-`first_seen` design let `--off` → re-schedule compose into "suppress the
whole recent window for this detection" (concilium BLOCKING-class); it is gone.
Consequences, stated explicitly:

- `--off` **preserves** `watermark_seq`. Re-scheduling resumes from the preserved
  watermark, so the off-gap IS scanned on the next run (bounded by the row cap +
  `truncated`). Only `delete` destroys the watermark.
- Re-running `schedule` on an already-scheduled query (interval/severity change)
  never touches the watermark.
- **Retention interaction**: a watermark held back long enough (persistent failure,
  long `--off`) can point below the retention horizon; rows in the un-scanned gap may
  already be pruned. At run start, if the oldest surviving `ingest_seq` exceeds
  `watermark_seq + 1`'s era (detected cheaply: `MIN(ingest_seq)` > watermark + 1 is
  not reliable across the ALTER backfill — the plan picks the concrete check), the
  run's emission carries `pruned_gap: true`. The gap is unknowable, not silent.

### 4.4 Emission

Per query-run **with at least one match**, exactly ONE summary event (never one event
per matching row — a query matching 10 k new events must not become 10 k events):

- `module="hunt_scheduler"`, `action="hunt_match"`, `kind="signal"`,
  event `severity` = the query's `schedule_severity`.
- New `Event.hunt` payload namespace (schema change + `build_event` kwarg — the
  `extra=forbid` convention established by `Event.vulnerability`):
  `{name, severity, match_count, sample_event_ids: [...max 20], window_upper_seq,
  run_duration_s, truncated: bool, pruned_gap: bool}`.
  `severity` is duplicated into the payload because the per-tier rules match on it
  (v1 omitted it and all three rules were dead as specified — concilium MAJOR).
  **`expression` is deliberately NOT in the payload**: a saved expression may
  legitimately contain the hostile bytes it hunts for (ESC, newlines); the panel/CLI
  show it from the saved query via the existing text-only paths, and rule templates
  never interpolate it.
- A truncated run sets `truncated=True`; `match_count` reports only counted rows.

**Failure runs.** `last_status` (§4.2) tracks per-query failure state across restarts.
On an ok→failed **transition**, the run emits `action="hunt_run_failed"` with the same
`Event.hunt` namespace (`name`, `severity`, plus `error_kind`) — the namespace must be
present or dedup falls to the per-event fallback and every failure is a fresh alert.
While a query **stays** failed, subsequent failures update `last_run_at`/`last_status`
and log, but do NOT re-emit — 288 identical events/day/query is flood, not signal; the
visible failure state lives in `hunt list` / the panel (§4.6) and the standing alert.
A failed→ok transition emits nothing (the next `hunt_match`, if any, speaks for
itself). Consecutive failures also back the retry off: after 3 consecutive failures
the query retries at `max(interval, 1h)` until a success — an unfixable regex must not
rescan an ever-growing window at the 5-minute floor forever.

A run with zero matches emits nothing (the interactive panel is the place to confirm a
hunt runs clean; a nightly "nothing happened" event per query is noise).

### 4.5 Alerting

Starter-pack rules, vuln-precedent per-tier pattern (rule severity is static in the
YAML DSL). **All four rules pin `event.module == "hunt_scheduler"`** — one conjunct of
forgery defense-in-depth, per the scanner-parser lesson:

- `hunt.scheduled_match_high` (high) — `event.module == "hunt_scheduler" AND event.action == "hunt_match" AND hunt.severity == "high"`
- `hunt.scheduled_match` (medium) — same with `hunt.severity == "medium"`
- `hunt.scheduled_match_low` (low) — same with `hunt.severity == "low"`
- `hunt.scheduled_run_failed` (medium) — `event.module == "hunt_scheduler" AND event.action == "hunt_run_failed"`; a broken standing detection is itself a monitoring
  gap. Fires on transition only, because emission is transition-only (§4.4).

Rule message templates interpolate `{hunt.name}` and `{hunt.match_count}` only — never
the expression (§4.4). A test asserts the rendered alert message for a
hostile-literal expression contains no ESC byte.

**Dedup** keys on the query `name` via a new `hunt` branch in `_primary_entity_for` →
`("hunt", <query name>)` — gated on `event.module == "hunt_scheduler"` AND the payload
namespace, inserted **before** the process branch (without a branch, YAML rules get no
dedup at all — the vuln_scanner lesson).

**Dedup window** (concilium BLOCKING): the global dedup window is 600 s, smaller than
every sane hunt interval, so as specified in v1 *every* matching run would open a fresh
alert → desktop notification per interval, forever. PR3 therefore plumbs an optional
per-rule `dedup_window_s` through the YAML loader → `DedupEngine` (default = current
600 s, so no other rule changes behavior), and the hunt rules set it to `86400` (one
day). A standing match at any interval ≤1 d holds ONE alert whose `last_seen_at`
advances; a match recurring after >1 d quiet re-surfaces as a fresh alert —
deliberately, that is re-notification of a returned condition.

**Ack semantics, stated deliberately**: a dedup *bump* of an alert whose status is not
`open` must not fan out to the notifier (today it does — the bump path ignores
status). PR3 makes the supervisor's fan-out skip non-open bumped alerts. An acked
standing hunt match therefore stays quiet until either it goes quiet for the dedup
window and returns (fresh alert), or the user unacks. Bumps never overwrite an acked
alert's rendered text either — the bump only advances `last_seen_at`/count fields.

### 4.6 Control surface (CLI only)

```
inspectorctl hunt schedule <name> --every <15m|1h|1d|...> [--severity low|medium|high]
inspectorctl hunt schedule <name> --off
inspectorctl hunt list          # gains: interval, severity, last run, last status, overdue
```

- `--every` reuses the CLI's existing duration shorthand parser; default severity
  `medium`.
- **Daemon-side enforcement** (the CLI checks are UX only, same house rule as §3):
  `schedule_hunt_query` validates `interval_s >= 300`, `severity ∈ {low, medium,
  high}`, and that `name` exists — rejecting as request errors before any write or
  audit row. The new mutating hunt methods share a sliding-window rate limiter
  (mirror `_SlidingWindowLimiter`, 12/min) — they each write an audit row, and
  attacker-drivable append-only audit growth is exactly what the command channel's
  limiter exists to bound; `save_hunt_query`/`delete_hunt_query` join the same
  limiter, closing the same pre-existing gap.
- Two new **mutating** IPC methods `schedule_hunt_query` / `unschedule_hunt_query`
  (`mutates=True`), both **audited** (they create/destroy a standing alert-generating
  detection — same class of act as ack/close). The web keeps zero mutating hunt
  methods; `/hunt`'s saved-query list displays schedule state read-only (interval,
  severity, last run, **last status** — a failing query renders visibly failed).
- **The expression is the detection** (concilium MAJOR): `save_hunt_query` with
  `replace=True` rewrites what a standing detection matches; `delete_hunt_query`
  destroys it. Both, when the target row is currently scheduled, require an explicit
  `scheduled_ok: true` IPC param (CLI: `--scheduled-ok`) or are rejected — mirroring
  the existing replace-refuse-by-default pattern. Save-replace **preserves**
  `watermark_seq` and the schedule columns. And the audit details for save/delete stop
  being empty: save records `{replaced, was_scheduled, old_expression_sha256,
  new_expression_sha256}`; delete records `{expression_sha256, was_scheduled,
  schedule_interval_s}`. The trail must distinguish "edited an idle saved query" from
  "gutted a standing detection".

### 4.7 Bounds and failure containment

- Serial execution; a tick that finds N due queries runs them in `name` order.
- Per-run row cap = the compiler's existing `MAX_LIMIT`; no new knob. Soft 30 s
  duration budget → logged + stamped in the emission (§4.1).
- Failure backoff after 3 consecutive failures (§4.4).
- The scheduler thread guards its loop the way `_drain` now does: no exception may
  kill the thread (the silent-failure lesson, #127) — and because containment without
  detection is half the lesson, liveness is surfaced per §4.1. Any unexpected
  exception → log + failure handling per §4.4 if a query was in flight, then continue.
- `stop()` sets the stop event, calls `interrupt()` on the in-flight cursor if the
  DuckDB API offers it (plan verifies; otherwise the SELECT finishes on the daemon
  thread and process exit reaps it — `daemon=True`), and joins within the
  supervisor's existing shutdown budget. The stop event is checked between queries
  and again before the watermark write, so an interrupted run never half-advances.

### 4.8 Out of scope (v3 of hunt, not now)

Web scheduling UI; per-match events; cron expressions (plain intervals only); jitter;
run-history table (`last_run_at`/`last_status` only); triggering a scheduled hunt via
the worker command channel (ad-hoc `run_hunt_query` IPC already covers "run it now");
aggregation in the grammar; alerting on match-count *changes* (a match-count delta
grammar is a second grammar); reworking dedup-bump semantics beyond the two changes in
§4.5 (skip-notify on non-open, no text overwrite).

## 5. Testing

- **PR1**: handler unit test (horizon present/None/ISO shape); panel render test
  (warning only when `horizon > since`, effective-coverage line, "no events in the
  store" branch, escaping); CLI stderr line test.
- **PR2**: verb → IPC params mapping per scanner name (asserting the `name` key —
  the key the worker actually reads); invalid-name UX rejection; daemon rejection
  passthrough + exit codes. No daemon changes, so no daemon tests.
- **PR3**:
  - *Watermark*: advance on success incl. zero-match and truncated runs; hold on
    failure; skip when `upper <= watermark`; **late-persist test** — insert an event
    with old `ts` but fresh `ingest_seq` into an already-run window and assert the
    next run matches it (the v1 BLOCKING regression test); guarded-UPDATE race
    (`--off` mid-run → result discarded); `--off` preserves watermark, re-schedule
    resumes from it; schedule-time watermark = MAX(ingest_seq), no catch-up emission.
  - *Predicate*: parameterized seq bound (placeholder in SQL text, hostile saved
    expression cannot break out).
  - *Emission*: one event per matching run; `match_count`/sample cap/`truncated`/
    `pruned_gap`; zero-match silence; failure **transition-only** emission +
    `last_status` persistence across restart; backoff after 3 failures.
  - *Alerting*: all four rules fire (incl. `hunt.severity` present in payload);
    module pinning (same payload from another module does not fire); dedup key
    stability; per-rule dedup window honored; non-open bump does not notify and does
    not rewrite rendered text; no-ESC-byte alert message for hostile expression.
  - *Control*: daemon-side validation (interval floor, severity enum, unknown name);
    `scheduled_ok` gate on replace/delete of a scheduled query; audit rows with the
    §4.6 detail payloads; rate limiter on all mutating hunt methods.
  - *Infra*: migration idempotence (run 0013 twice); `ingest_seq` monotonicity via
    the real `_persist` path; scheduler thread exception containment; `status`
    liveness block; shutdown mid-run.

## 6. Slices

- **PR1** — horizon banner (daemon field + web + CLI line). No migration.
- **PR2** — `inspectorctl scanners run`. Pure client.
- **PR3** — scheduled hunts: migration 0013 (`ingest_seq` + hunt_query columns),
  `Event.hunt`, compiler seq-bound, `HuntScheduler` + supervisor wiring + status
  liveness, 2 IPC methods + validation + rate limit + audit-detail enrichment for
  save/delete, CLI `hunt schedule` + `hunt list` columns, 4 starter rules +
  `_primary_entity_for` branch, per-rule `dedup_window_s` + non-open-bump notify fix,
  `/hunt` read-only schedule display. Single PR (pure Python; the 2-PR split is for
  eBPF collectors only) — but it is the largest single PR in this program; the plan
  should slice tasks so the dedup/notifier changes land as their own reviewed task.
