# Hunt follow-ups: data-horizon banner, `scanners run` CLI, scheduled hunts

- **Status**: draft (autonomously brainstormed with user; scheduled-hunts portion pending
  concilium review)
- **Date**: 2026-09-07
- **Parent spec**: `2026-05-24-local-inspection-design.md` §2.2 (Hunt panel), §24 (CLI verbs)
- **Sibling specs**: `2026-08-20-hunt-design.md` (the shipped hunt engine/panel),
  `2026-08-26-retention-design.md` (which deferred the horizon banner),
  `2026-08-27-worker-command-channel-design.md` (the trigger channel PR2 reuses)

## 1. What this is

Three follow-ups left dangling around Hunt after the panel program shipped:

1. **Data-horizon banner** (deferred by the retention spec): after retention pruning, a hunt
   query reaching past `events_days` silently covers only the surviving window — an empty
   result is indistinguishable from a clean history. Surface "results cover data since
   \<date\>" on `/hunt`.
2. **`inspectorctl scanners run <name>`** (parent §24 promise): the web Run-now buttons
   (#156) exist; the CLI verb does not. Add it over the same `run_worker_command` IPC.
3. **Scheduled hunts**: a saved hunt query can be given a per-query interval and severity;
   the daemon runs it periodically over *new events only* and routes matches through the
   normal rule → alert pipeline. This turns Hunt from a purely interactive tool into a
   standing detection the user authors in the query grammar they already know.

One PR per item. PR1 and PR2 are small and mechanically reviewable; PR3 is the feature.

## 2. PR1 — data-horizon banner

**Daemon.** `run_hunt_query`'s success response gains one field: `data_horizon` — the
ISO-rendered `MIN(ts)` over the `events_enriched` table, `null` when the table is empty.
`MIN(ts)` (the *actual* oldest surviving row) is deliberately chosen over the retention
config cutoff (`now - events_days`): during a chunked backlog drain after downtime, real
data older than the cutoff still exists and the banner must not claim it doesn't; before
retention has ever pruned, the horizon is honestly "since first install". The value is
computed inside the existing handler with the same DB handle, once per query run (not per
listed query).

**Web.** `/hunt` renders the banner beside the results header:
`results cover data since <data_horizon>` — only when a result is present, and only from
the daemon's reported value (house rule: bounds are reported, never inferred; hunt route
docstring). `data_horizon = null` renders "no events recorded yet" instead of hiding the
banner, because an empty store is exactly when the user most needs to know why results
are empty.

**CLI.** `inspectorctl events search` / `hunt run` print the same line to stderr after
results, so terminal investigations get the same honesty as the panel.

No new IPC method, no schema change.

## 3. PR2 — `inspectorctl scanners run <name>`

New CLI module `inspectorctl/cli/scanners.py` with one verb:

```
inspectorctl scanners run <name>      # aide | rkhunter | yara | vuln
```

- `aide`/`rkhunter`/`yara` → `run_worker_command` with
  `{"worker": "scanner_runner", "command": "run_scanner", "args": {"scanner": <name>}}` —
  exactly the params the web Run-now button sends (mirror
  `inspectorctl/web/worker_commands.py`, do not re-derive).
- `vuln` → `{"worker": "vuln_scanner", "command": "rescan"}`.
- Names outside the closed set are rejected client-side with the list of valid names —
  but the daemon's allowlist remains the enforcement point; the client check is UX only.
- Output: the daemon's accepted/rejected outcome verbatim, including the rejection
  reason (`not_allowlisted`, rate-limit, worker-not-running). Exit code 0 only on
  accepted. Trigger-only at-most-once semantics are printed once
  ("triggered; watch /scanners or the events feed for the result") — the CLI does NOT
  wait for the `command_result` event; that is the channel's design (§ worker-command
  spec: trigger-only).

Audit, allowlist and the 12/min rate limit all live daemon-side and apply unchanged.
Parent §24's `scanners schedule list/set` verbs remain out of scope (interval scheduling
lives in config; a runtime schedule-mutation surface is a different feature).

## 4. PR3 — scheduled hunts

### 4.1 Shape

`HuntScheduler`: a daemon-side thread owned by the supervisor, mirroring
`AnomalyDetector` (own `threading.Thread`, own `Database` handle, injected
`emit: Callable[[Event], None]`, `start()`/`stop()` with a wake `threading.Event`).
Wired in `supervisor.py` beside the anomaly detector. **Not** a worker subprocess:
DuckDB is single-writer, the hunt store and events live in the daemon's DB, and a
second process could not even read them while the daemon holds the write handle.

The loop ticks every 60 s: pick queries whose `schedule_interval_s` is set and whose
next-due time has passed, run them **serially** (one at a time — hunts are ad-hoc SQL;
two heavy regexes in parallel on a personal box is self-inflicted load), each under the
existing compiled-query row cap.

### 4.2 Schema (migration 0013, additive)

`ALTER TABLE hunt_query ADD COLUMN`:

| column | type | meaning |
|---|---|---|
| `schedule_interval_s` | INTEGER | NULL = not scheduled (the default for every existing and new query) |
| `schedule_severity` | VARCHAR | one of low/medium/high; NULL until scheduled |
| `watermark_ts` | TIMESTAMP | newest event `ts` already covered; NULL = never run |
| `last_run_at` | TIMESTAMP | last completed run (success or failure), for the panel/CLI to show |

Naive-UTC timestamps, store-what-you-compare (DuckDB strips tz — audit-log lesson).

### 4.3 Watermark semantics — only new events

Each run executes the saved expression with an **additional compiled predicate**
`ts > watermark_ts AND ts <= run_upper_bound` where `run_upper_bound` is captured once
at run start (`now`). On success the watermark advances to `run_upper_bound` — not to
`MAX(ts)` of matches, so a quiet window still advances and a standing non-match never
re-scans history. A failed run does NOT advance the watermark (the window is retried
next tick, so a transient DB error cannot silently skip events).

**First run after scheduling** (`watermark_ts` NULL): the run covers the default recent
window and emits its summary event with `first_seen=True` — the RuleEngine's existing
global baseline suppression drops it before rule eval, so scheduling a query with
standing matches does not instantly flood alerts; the panel/CLI still see the event.
The watermark then advances normally.

The time-bound predicate is injected via the compiler's existing parameterized-SQL path
(the same mechanism as the ad-hoc `since` bound) — never by string-formatting the stored
expression.

### 4.4 Emission

Per query-run **with at least one match**, exactly ONE summary event (never one event
per matching row — a query matching 10 k new events must not become 10 k events):

- `module="hunt_scheduler"`, `action="hunt_match"`, `kind="signal"`,
  `severity` = the query's `schedule_severity`.
- New `Event.hunt` payload namespace (schema change + `build_event` kwarg — the
  `extra=forbid` convention established by `Event.vulnerability`):
  `{name, expression, match_count, sample_event_ids: [...max 20], window_start,
  window_end, truncated: bool}`.
- A matching run that hit the row cap sets `truncated=True` and `match_count` reports
  only the counted rows — the event must not claim a total it did not compute.

A run that **fails** (compile drift on a stored row, DB error, row-cap-zero weirdness)
always emits `action="hunt_run_failed"` with the error kind — house convention: a
failed check that emits nothing is indistinguishable from a clean pass. Repeated
failures do not stop the schedule; the query keeps its slot and keeps failing loudly
(dedup below keeps the alert singular).

A run with zero matches emits nothing (the interactive panel is the place to confirm a
hunt runs clean; a nightly "nothing happened" event per query is noise).

### 4.5 Alerting

Starter-pack rules, vuln-precedent per-tier pattern (rule severity is static in the
YAML DSL):

- `hunt.scheduled_match_high` (high) — `event.action == "hunt_match" AND hunt.severity == "high"`
- `hunt.scheduled_match` (medium) — `... AND hunt.severity == "medium"`
- `hunt.scheduled_match_low` (low) — `... AND hunt.severity == "low"`
- `hunt.scheduled_run_failed` (medium) — `event.action == "hunt_run_failed"`; a broken
  standing detection is itself a monitoring gap.

Dedup keys on the query `name` via a new `hunt` branch in `_primary_entity_for` →
`("hunt", <query name>)` — without that branch YAML rules get no dedup at all (the
vuln_scanner lesson). A query matching on every interval therefore holds ONE alert
whose `last_seen_at` advances, and `hunt_run_failed` for a persistently broken query
stays a single alert. Allowlist/dryrun/ack machinery applies unchanged — the entire
point of routing through the rule engine.

### 4.6 Control surface (CLI only)

```
inspectorctl hunt schedule <name> --every <15m|1h|1d|...> [--severity low|medium|high]
inspectorctl hunt schedule <name> --off
inspectorctl hunt list          # gains schedule columns (interval, severity, last run)
```

- `--every` reuses the CLI's existing duration shorthand parser; floor 5 m (a 10 s hunt
  loop is a footgun), default severity `medium`.
- Scheduling an unsaved name is an error; `--off` clears all four columns' scheduling
  state except `last_run_at`.
- Two new **mutating** IPC methods `schedule_hunt_query` / `unschedule_hunt_query`
  (`mutates=True`), both **audited** (they create/destroy a standing alert-generating
  detection — same class of act as ack/close). The web keeps zero mutating hunt
  methods (established stance: no CSRF token, wrong front door); `/hunt`'s saved-query
  list may *display* schedule state read-only.

### 4.7 Bounds and failure containment

- Serial execution; a tick that finds N due queries runs them in `name` order.
- Per-run row cap = the compiler's existing `MAX_LIMIT`; no new knob.
- The scheduler thread guards its loop the way `_drain` now does: no exception may kill
  the thread (the silent-failure lesson, #127). Any unexpected exception → log +
  `hunt_run_failed` emission if a query was in flight, then continue.
- `stop()` joins within the supervisor's existing shutdown budget; a hunt query mid-run
  is abandoned (read-only — safe), watermark un-advanced.

### 4.8 Out of scope (v3 of hunt, not now)

Web scheduling UI; per-match events; cron expressions (plain intervals only); jitter;
run-history table (last_run_at only); triggering a scheduled hunt via the worker
command channel (ad-hoc `run_hunt_query` IPC already covers "run it now");
aggregation in the grammar; alerting on match-count *changes* (a match-count delta
grammar is a second grammar).

## 5. Testing

- **PR1**: handler unit test (horizon present/None/ISO shape); panel render test
  (banner shown with result, "no events" branch, escaping); CLI stderr line test.
- **PR2**: verb → IPC params mapping per scanner name; invalid-name UX rejection;
  daemon rejection passthrough + exit codes. No daemon changes, so no daemon tests.
- **PR3**: watermark advance on success / hold on failure / first-run `first_seen`;
  parameterized time-bound injection (no string-formatting of expressions — test with
  a hostile saved expression); one-event-per-run with `match_count`/sample cap/
  `truncated`; zero-match silence; `hunt_run_failed` on compile drift and DB error;
  dedup-key stability per query name; scheduler-thread exception containment; the
  three severity rules + failure rule fire correctly; schedule/unschedule IPC
  round-trip incl. audit rows; migration idempotence.

## 6. Slices

- **PR1** — horizon banner (daemon field + web + CLI line). No migration.
- **PR2** — `inspectorctl scanners run`. Pure client.
- **PR3** — scheduled hunts: migration 0013, `Event.hunt`, `HuntScheduler`, supervisor
  wiring, 2 IPC methods + audit, CLI `hunt schedule`, 4 starter rules, `/hunt`
  read-only schedule display. Single PR (pure Python, one worker-shaped unit —
  the 2-PR split is for eBPF collectors only).
