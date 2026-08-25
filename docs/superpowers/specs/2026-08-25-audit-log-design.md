# Hash-chained audit log — design

Date: 2026-08-25 (v2 — concilium REVISE verdict folded; 5 lenses, 3 BLOCKING + 10 MAJOR
findings all addressed below)
Parent spec: `2026-05-24-local-inspection-design.md` §20.4 (hash-chained audit log), §703
(component table), §632 (alert state-transition logging), §674/§177 (pending-actions
audit), §830 (case operations), §1728 (dep_manager actions).
Status: **autonomously drafted, NOT human-reviewed** (concilium-reviewed in-session).
The fail-open decision (§6) and the success-only completeness contract (§1) are the
calls most worth a human look.

## 1. Goal — and the honest completeness contract

One append-only, tamper-evident record of administrative actions taken through
inspectord: who did what, to which object, when — with a SHA-256 hash chain so
tampering with *written* rows is detectable. Prerequisite for Phase-3 quarantine
(parent §674).

**This log records successful actions only.** Failed/denied attempts surface as IPC
errors and are not persisted in v1 (revisit when a deny-capable surface — polkit,
pending actions — exists; `details_json` accommodates `*_failed` rows without schema
change). The audit write happens after the action commits and is not atomic with it; a
crash between the two loses that one audit row. These limits are stated here rather than
implied away.

## 2. Scope

### In (v1)

- `audit_log` DuckDB table (**migration 0011** — 0008–0010 are taken) +
  `inspectord/audit/` module: chained `append_audit(...)` writer,
  `verify_audit_chain(...)` checker.
- Wiring for every mutating IPC surface **plus the two evidence-egress reads**
  (case export, evidence download) — catalog in §5.
- Journal head-anchoring (§6a) so tail-truncation is not silently clean.
- Daily periodic chain verify emitting a high-severity event on breakage (§7).
- Read-only IPC: `list_audit_log`, `verify_audit_log`.
- `/audit` web panel (PR2).

### Out (deliberate)

| Cut | Why |
| --- | --- |
| Reusing `journal.py`'s `Journal` class as the audit store | Journal restarts its chain at ZERO_HASH per daily file, so deleting a whole day's file is undetectable; audit needs one dense chain from seq 1. Parent §703 also names audit_log a DuckDB table, and the panel/quarantine need SQL. |
| Migrating `dep_audit` into `audit_log` | 10 domain columns + existing consumers. v1 dual-writes **plan-level summary rows only** (`dep_plan_created`/`dep_plan_applied`); per-step actions (dropin_written, verify_*, service_*, backups) remain dep_audit-only until an eventual merge. |
| Allowlist mutations | The allowlist is file-driven in v1 — no daemon-mediated mutation surface exists; file edits are covered by fim_watcher. When the allowlist UI / pending action (parent §674) lands, its handlers must call `append_audit`. |
| Reason notes on alert transitions (parent §632) | The ack/resolve/suppress handlers take only `alert_id` today; no reason param exists to record. `details_json` already accommodates `{"reason": ...}` — add when the handlers grow the param. |
| Signing / HMAC | A secret on the same box buys nothing against root; hardware/remote anchoring conflicts with the no-egress stance. Residual risk in §8. |
| `case_event` replacement | Stays as UI-facing narrative; audit rows are written alongside. |
| Rules/config file-edit auditing | fim_watcher covers files; audit_log records daemon-mediated actions only. |
| Retention/GC | Append-only means append-only; chain-aware GC (re-anchoring) comes with forensic-store GC later. |

**Future wiring note:** config reload, pending-action approve/reject, and
watchdog/supervisor self-actions (parent §177, §20.3) must call `append_audit` when
those surfaces are built; no schema change needed.

## 3. Table (migration `0011_audit_log.sql`)

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    seq          BIGINT PRIMARY KEY,      -- app-assigned, dense, monotonic from 1
    ts           TIMESTAMP NOT NULL,      -- naive UTC (DuckDB strips tz on read)
    actor        VARCHAR NOT NULL,        -- §4
    action       VARCHAR NOT NULL,
    target       VARCHAR,
    details_json VARCHAR NOT NULL,        -- '{}' if none; hashed VERBATIM as stored
    prev_hash    VARCHAR NOT NULL,        -- 64-hex; 64 zeroes for seq 1
    row_hash     VARCHAR NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts);
```

(No `(action, ts)` index — no v1 consumer filters by action.)

**Canonical serialization — store what you hash, hash what you store.** DuckDB
`TIMESTAMP` returns naive datetimes (tz stripped — documented in `pkg_helper.py`), so
the hashed `ts` string is pinned to the naive-UTC form as DuckDB returns it:

```python
ts_naive = datetime.now(UTC).replace(tzinfo=None)         # what gets INSERTed
ts_canon = ts_naive.isoformat(sep="T", timespec="microseconds")  # what gets hashed
row_hash = sha256(json.dumps(
    {"seq": seq, "ts": ts_canon, "actor": actor, "action": action,
     "target": target, "details": details_json, "prev_hash": prev_hash},
    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
```

`timespec="microseconds"` pins zero-microsecond values to a stable form. Verify
recomputes with the SAME formatter from the row as returned, and uses the stored
`details_json` string verbatim (never re-serializes a parsed dict). §9 mandates a
round-trip test with sub-second and zero-microsecond timestamps. Genesis `prev_hash` =
`journal.ZERO_HASH`.

## 4. Actor model

The IPC socket is single-user (0660) and unauthenticated; actors are honest labels:

- `user:local` — actions arriving via IPC.
- `auto:<module>` — daemon-initiated (e.g. `auto:evidence_collector`).

Parent §632's `eli@local` is an illustration, not a contract.

## 5. Wired actions (v1 catalog)

| Source | Action | Target | Details |
| --- | --- | --- | --- |
| `handle_ack_alert` / `resolve` / `suppress` | `alert_acked` / `alert_resolved` / `alert_suppressed` | `alert:<id>` | `{}` |
| `handle_open_case` | `case_opened` | `case:<id>` | `{"title": ...}` |
| `handle_attach_alert` | `case_alert_attached` | `case:<id>` | `{"alert_id": ...}` |
| `handle_add_note` | `case_note_added` | `case:<id>` | `{}` (text stays in case_event) |
| `handle_close_case` | `case_closed` | `case:<id>` | `{}` |
| `handle_export_case_zip` | `case_exported` | `case:<id>` | `{"bytes": n}` |
| `handle_download_evidence` | `evidence_downloaded` | `case:<id>` | `{"sha256": ...}` |
| `handle_capture_baseline` | `baseline_captured` | `baseline:<kind>` | `{"entries": n}` |
| `handle_save_hunt_query` / `delete` | `hunt_query_saved` / `hunt_query_deleted` | `hunt:<name>` | `{}` |
| `EvidenceCollector` auto-case | `case_opened` | `case:<id>` | `{"auto": true, "alert_id": ...}`; actor `auto:evidence_collector` |
| `handle_plan_dependency_install` | `dep_plan_created` | `dep:<name>` | `{"plan_id": ...}` |
| dep applier (beside its dep_audit write) | `dep_plan_applied` | `dep:<name>` | `{"plan_id": ...}` |

Placement: audit call in the IPC handler / daemon-side caller, not the store layer.
Written after the action succeeds (see §1's contract).

## 6. Writer — `inspectord/audit/log.py`

- `append_audit(db_path, *, actor, action, target, details) -> int | None` (seq, or
  None on swallowed failure).
- **Module-owned connection.** `append_audit` does NOT take a caller connection: a
  caller mid-transaction (cases/store.py and anomaly/detector.py both use explicit
  BEGIN…COMMIT) would break the read-max-then-insert protocol. The module lazily opens
  ONE dedicated `Database(db_path)` guarded by the same module-level `threading.Lock`
  that serializes appends: one connection, one lock, invariant self-contained. Inside
  the lock: read `seq, row_hash` of the max row (single query), compute, INSERT,
  auto-commit before the lock releases.
- **Daemon-process-only, enforced by convention + PK backstop.** `threading.Lock` gives
  no cross-process exclusion. All v1 writers run in the daemon process (IPC handler
  threads, supervisor fan-out thread, dep applier inside its handler). Helper processes
  (e.g. `pkg_helper`, the one existing out-of-process DB writer) must never write
  audit_log — their actions are audited by the daemon-side caller. If a second process
  ever appends, the `seq` PRIMARY KEY makes the collision fail loudly rather than fork
  the chain.
- **No retry.** Any future retry must re-enter the lock and recompute seq/prev_hash. A
  commit-then-raise (interrupt after COMMIT) can make an ERROR log a false positive —
  reconciliation trusts the table, not the log.
- **Failure mode: fail-open, honestly stated.** If the append fails, the wrapped action
  still succeeds and the audit row is **silently and undetectably absent** — no seq is
  consumed, so the chain stays dense and verify cannot see the gap. The chain detects
  tampering with rows that were written, never the absence of rows that were never
  written. Compensations, not detection:
  - `details` serialization uses `json.dumps(default=str)` so a bad payload cannot
    raise pre-INSERT.
  - Failures are counted over a rolling window and escalate to a high-severity
    `audit_log_failing` health event via the same pattern as the supervisor's
    `persistence_failing` (window/threshold/cooldown) — an ERROR log line nobody reads
    is not surfacing.
  - **Startup probe:** the daemon probes `audit_log` existence once at boot and treats
    a missing table (migration drift) as fatal, so schema problems cannot masquerade as
    an endless string of swallowed per-action failures.
  Fail-open remains a deliberate single-user-console tradeoff (blocking alert-ack on a
  DB hiccup hurts more than an audit gap) and is flagged for human review; fail-closed
  is a per-call-site one-liner.

### 6a. Journal head-anchoring (tail-truncation detection)

A predecessor-only chain cannot detect suffix truncation: deleting the newest K rows —
or the whole table — leaves a dense, verifying chain. To bound that hole without a
secret: the supervisor emits a daily `audit_head` state event carrying
`{seq, row_hash}` of the current chain head. Events flow into the hash-chained journal
(§20.5) and `events_enriched`, so rolling the audit table back past an anchor is
detectable by comparing the newest anchor against the table (verify does this when
anchor data is available; `verify_audit_log` reports `anchor_checked: bool`).
The daily supervisor check runs verify WITH the newest anchor BEFORE emitting the
fresh `audit_head`, so the day-old anchor gets one chance to catch a truncation
before it is superseded.
Truncation within the last day remains undetectable — stated in §8.

## 7. IPC, periodic verify, web

- `list_audit_log` (mutates=False): `{limit?}` only — default 100, hard cap 500, newest
  first by `seq DESC`. No offset/total/action filter (no consumer; keyset `before_seq`
  is the future extension if ever needed).
- `verify_audit_log` (mutates=False): runs the full check on one DuckDB snapshot
  (single query materializes all rows — cost is milliseconds at tens of rows/day).
  Returns `{ok, rows, first_bad_seq, reason, anchor_checked, last_good: {seq, ts,
  action} | null, first_bad: {seq, ts, action} | null}` — enough to bound a damage
  window, not just point at a number.
- **Periodic verify:** the daemon runs `verify_audit_chain` daily (same scheduling home
  as the `audit_head` anchor emission); on `ok=False` it emits a high-severity
  `audit_chain_broken` event through the normal alert path. Tampering does not wait for
  a human to click Verify. A failed verify suppresses that tick's re-anchoring — a
  fresh anchor over a truncated head would launder the tamper into a clean verify.
- `/audit` panel (PR2): table (ts, actor, action, target, details), "Verify chain"
  POST-redirect control. On a detected break the panel states that rows ≥
  `first_bad_seq` are untrusted, shows the last-good/first-bad rows, and points at the
  event journal and backups for cross-checking. Recovery from a break is manual and
  documented (restore DB from backup, or accept the annotated break); v1 ships no
  re-anchor operation.

## 8. Threat model honesty

Detects: **interior** tampering with written rows — edits, deletions, and insertions
that break a surviving successor's linkage — plus suffix truncation older than the most
recent `audit_head` anchor (§6a). Does NOT detect: truncation newer than the last
anchor; fail-open drops (§6 — rows never written); a chain-aware root attacker who
rewrites the chain and the journal anchors together; actions taken outside the daemon.
Verify on an empty table reports `ok=True, rows=0` — but an anchor with `seq > 0`
flags a wipe. The verify result means "chain consistent", never "history authentic".

## 9. Testing

TDD. Unit: append (genesis, N rows), verify clean; verify detects edited / interior-
deleted / inserted row and non-dense seq; **ts round-trip** (sub-second AND
zero-microsecond rows verify after DB re-read); reopen test (append, new `Database`
instance, append more, chain ok); concurrency (N threads → dense seq, valid chain);
fail-open (induced INSERT failure → caller unaffected, failure counted); unserializable
details does not raise; anchor comparison (truncated table + newer anchor → flagged).
Wiring: one test per audited handler (action/target/actor row lands). IPC shape tests.
Startup probe test. Web (PR2): render, verify control, break-state text, XSS.

## 10. Delivery

PR1: migration 0011 + `inspectord/audit/` + wiring + anchor & periodic verify +
startup probe + IPC methods + tests.
PR2: `/audit` web panel.
