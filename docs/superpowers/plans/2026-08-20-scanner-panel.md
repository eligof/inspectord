# scanner panel — the `scan_run` state table + Antivirus/Scanners panel

| Field | Value |
| --- | --- |
| Date | 2026-08-20 |
| Branch | `scanner-panel` |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` §2.2 ("Antivirus / scanners — last run, status, findings; schedule") |
| Design doc | `docs/superpowers/specs/2026-08-19-scanner-runner-design.md` §4.2 (event shapes), §3 decision 6, §6 ("Later: the `scan_run` state table + Antivirus panel") |
| Slice | The deferred panel slice. `scanner_runner` (PR1–PR3) already ships and is enabled. |

## 1. Problem

`scanner_runner` emits `scan_started` / `scan_completed` / `scan_skipped` / `scan_finding`
and the `av.*` rules alert on findings, but there is no materialized scanner state. Answering
"did AIDE run last night, and did it find anything?" today means reading `events_enriched`.

Design decision 6 deliberately kept findings as events and deferred the `scan_run` table so
the collector and the panel stay independently reviewable. This is that slice — and it keeps
decision 6 intact: **findings remain events**; only the per-run *lifecycle* is materialized.

## 2. What gets built

1. Migration `0008_scan_run.sql` — the `scan_run` table.
2. A `scanner_runner` branch in `inspectord/state/projector.py`.
3. Two read-only IPC handlers in `inspectord/state/ipc_handlers.py`, wired in `__main__.py`.
4. A `/scanners` panel (route + shell + HTMX feed template + nav link).

## 3. The `scan_run` table

```sql
CREATE TABLE IF NOT EXISTS scan_run (
    run_id           VARCHAR PRIMARY KEY,
    scanner          VARCHAR NOT NULL,
    status           VARCHAR NOT NULL,   -- running | success | failure | skipped
    reason           VARCHAR,            -- failure reason or skip reason
    exit_code        INTEGER,
    duration_s       DOUBLE,
    finding_count    INTEGER,
    findings_dropped INTEGER,
    truncated        BOOLEAN,
    output_truncated BOOLEAN,
    output_excerpt   VARCHAR,            -- failures only; bounded by the runner
    started_at       TIMESTAMP NOT NULL,
    completed_at     TIMESTAMP,
    last_event_id    VARCHAR
);
CREATE INDEX IF NOT EXISTS scan_run_scanner_idx ON scan_run (scanner, started_at);
```

`status` collapses the event's `outcome` (`success`/`failure`) and the skip case into one
column; "clean vs findings" stays derivable from `finding_count`, so no second enum.

### Keying

`run_id` comes from `raw.run_id`, which `scan_started`, `scan_completed` and `scan_finding`
all carry. **`scan_skipped` carries no `run_id`** (it is not a run — nothing was spawned), so
a skip row is keyed `skip:<event_id>`. `event_id` is a uuid7, so skips never collide and
never overwrite a real run.

### Event ordering — the decision that matters

`scan_started` and `scan_completed` are separate events minutes apart, and a daemon restart
mid-scan means a `scan_started` may never get its `scan_completed` (design §4.4 records that
the in-flight marker is memory-only).

- **`scan_started`** inserts `status='running'`, `started_at=ts`. On conflict it updates only
  `scanner`, `started_at`, `last_event_id` — **never `status`** — so a `scan_started` that
  somehow lands after its `scan_completed` cannot resurrect a finished run.
- **`scan_completed`** upserts the full terminal row. On conflict it updates everything
  **except `started_at`**, preserving the real start time. If no `scan_started` row exists
  (missed event), it inserts one with `started_at = ts - duration_s`.
- Projection is therefore order-independent in both directions.

**A run that never completed stays `status='running'` in the table**, and the *read* path
derives a fifth, display-only state: a row still `running` whose `started_at` is older than
`incomplete_after_s` is reported as **`interrupted`**. It is never reported as `success`
(only a real `scan_completed` writes that) and never as "running forever" (the age bound
flips it). Default bound: **7200 s** — twice the longest default per-scan timeout (`aide`,
3600 s). A live worker always emits `scan_completed` even on timeout (`reason="timeout"`),
so a run still `running` past that bound can only mean the daemon died mid-scan.

**Skipped vs never ran**: a skipped run has a row (`status='skipped'`) with the runner's
reason (`binary_not_found`, `config_missing`, `database_missing`, `run_in_flight`, …). A
scanner that never ran has **no row at all** and simply does not appear in the panel; the
empty state says so explicitly. The state table has no knowledge of the configured scanner
set (that lives in worker config, unreachable over IPC — design §5.1), so it cannot invent a
"never ran" row, and will not pretend to.

`scan_finding` is **not** projected: `scan_completed.finding_count` is the authoritative
count and incrementing a counter per finding would double-count on any replay. Findings stay
events (decision 6) and the panel reads them from `events_enriched`.

## 4. IPC handlers

Both read-only, both in `inspectord/state/ipc_handlers.py`, following the existing pattern.

- `list_scan_runs(params: {incomplete_after_s?, limit?})` → `{"schema_version", "scanners": [...]}`
  — the **latest run per scanner** (one row each), with the derived `state` field
  (`success` | `failure` | `skipped` | `running` | `interrupted`).
- `list_scan_findings(params: {run_ids?, limit?, scan_limit?})` → `{"schema_version", "findings": [...]}`
  — recent `scan_finding` events from `events_enriched`, optionally restricted to the given
  run ids, decoded in Python (no JSON SQL) and capped.

## 5. The panel — `/scanners`

Nav label "Scanners" (parent §2.2's row is "Antivirus / scanners"). Shell + HTMX feed at
`/scanners/feed`, exactly like `/persistence`.

Per scanner: **Last run** (started_at), **State** badge, **Duration**, **Findings**, and a
**Detail** column that carries the *reason* — so a user sees *why* AIDE is producing nothing:

| state | Detail column |
| --- | --- |
| `success` | truncation note when `truncated`, else blank |
| `failure` | `reason`, `exit_code`, and the bounded `output_excerpt` (as escaped text) |
| `skipped` | `reason` (e.g. "binary_not_found") |
| `running` | "in progress" |
| `interrupted` | "no scan_completed — the daemon stopped mid-scan" |

Below it, a bounded findings list for the latest runs: scanner, indicator type/value, path,
message.

### Escaping

Everything on this page is scanner-derived and **a filename can forge a report line** — the
residual bound the adapters' docstrings record is that `threat.indicator.value`, the finding
message and `file.path` can be attacker-chosen text (see `scanners/aide.py`,
`scanners/rkhunter.py`, `scanners/yara.py` module docstrings). So:

- Jinja2 autoescaping only; **no `|safe`, no `|e(...)` bypass, no raw output rendered as
  markup anywhere** — `output_excerpt` goes into a `<pre>` as escaped text.
- A short muted note on the page states the bound honestly: scanner output is untrusted
  input; a filename can forge a report line, so a finding's path, rule name and message may
  be attacker-chosen. Shown verbatim as text, never interpreted.
- XSS test following `tests/web/test_persistence.py::test_persistence_feed_escapes_details`:
  assert the raw payload is absent **and** the escaped form is present (so a silently
  dropped field cannot pass), driven through a finding whose `path` contains HTML, plus a
  failure `output_excerpt` and `reason` containing HTML.

## 6. Tests (TDD, test first for each piece)

- `tests/test_scan_run_migration.py` — table + columns exist.
- `tests/state/test_projector.py` — complete run (started→completed, success); failed run
  (reason/exit_code/output_excerpt); skipped run (`skip:` key, distinct from any run);
  run that never completed (stays `running`); completed-before-started ordering; completed
  with no started row.
- `tests/state/test_ipc_handlers.py` — latest-per-scanner selection; `interrupted` derivation
  at the age bound; skipped row surfaced with its reason; empty DB.
- `tests/web/test_scanners.py` — shell renders; feed renders each of the five states;
  empty state; daemon unreachable; **XSS test**.

## 7. Explicitly not in this slice

- **Schedule display** (parent §2.2 also asks for "schedule"). The schedule lives in the
  worker's stdin config and there is no IPC→worker channel (design §5.1), so the daemon
  cannot report it without inventing that channel. Deferred with the on-demand-run CLI.
- **On-demand run button** — same missing channel (design §5, deviation 1).
- A "never ran" row for a configured-but-silent scanner — needs the same channel to know the
  configured set.
- Retention/pruning of `scan_run` — no state table in this repo prunes today; out of scope.

## 8. Commits

1. plan
2. migration 0008 + its test
3. projector branch + tests
4. IPC handlers + wiring + tests
5. web panel + templates + nav + tests
