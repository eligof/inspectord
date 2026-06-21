# Cases panel (manual cases v1) — design

| Field | Value |
| --- | --- |
| Date | 2026-06-21 |
| Status | Approved (brainstorming) + concilium-reviewed 2026-06-21 — ready for implementation plan |
| Spec section refs | §2.2 (panels: Cases), §7.5 (Case record), §13 (evidence & cases), §13.4 (export), §13.5 (chain of custody), §16 (IPC), §20.4 (audit_log) |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` |

## 1. Purpose & context

This is **sub-project 3 (Cases)** — the 7th and final §2.2 System/Integrity panel. The full
Cases vision (parent spec §13) is large: an `evidence_collector` that auto-captures evidence
*before* notifying on high-severity alerts, a forensic store, ZIP export with a rendered
narrative, and a hash-chained chain-of-custody. **That is too big for one implementation plan,
so it is decomposed.** This spec covers only **v1: manual cases** — the data model +
user-curated case management + the panel. The heavy forensic slices are explicitly deferred
(§9).

Unlike sub-projects 1–2, **Cases is not entity-state**: a case is a user-curated bundle, not
state derived from the event stream, so it does NOT use the projector / materialized-state
machinery. It gets its own small module.

> **A concilium (multi-lens design review) on 2026-06-21 returned READY-WITH-EDITS** — all
> lenses approved the scope and architecture. The edits below are folded in. The strongest
> cross-lens finding (raised independently by three lenses): the first draft mislabeled the
> `case_event` table a "§13.5 chain-of-custody log," but it is a plain mutable table with no
> hash chain — real custody in the parent spec is the hash-chained `audit_log` (§20.4), which
> **does not exist in code yet**. v1 does NOT claim tamper-evidence (see §1.1, §3).

### Design decisions (locked during brainstorming + concilium 2026-06-21)

| Decision | Choice | Rationale |
| --- | --- | --- |
| v1 scope | **Manual cases only** | Deliver a usable, visible Cases panel fast; defer the heavy/sensitive auto-evidence-capture + export to later slices. |
| Creation flow | **Open-from-alert + attach-from-alert** | A case is born from an alert under investigation (parent spec §139). Both "Open case" and "Attach to existing case" are actions on the **alert detail page** (you act on the alert you're looking at), not a type-an-alert-id form. |
| What a case links (v1) | **Alerts + notes** | Alerts already exist (`alerts` table). Entities/incidents/evidence linking deferred. |
| Notes + activity model | **One append-only `case_event` activity log** | Notes and case activity are the same shape — a timestamped ordered log that powers the detail-view timeline. **NOT a tamper-evident chain-of-custody** (see §1.1). |
| Architecture | **Standalone `inspectord/cases/` module** | Cases are curated, not projected; keep them separate from `inspectord/state/` (the projector). |

### 1.1 What v1 does NOT guarantee (honesty note)

The `case_event` table is an ordered **activity / notes log**, not a tamper-evident
chain-of-custody. It is a plain DuckDB table the daemon can UPDATE/DELETE; "append-only" is a
convention of the store API, not an enforced or cryptographically-verifiable property.
True chain-of-custody (parent spec §13.5 / §20.4: a hash-chained `audit_log` with `prev_hash`,
like `journal.py` already does for events) is **deferred to the evidence/export slice** along
with the `evidence_collector`. Likewise, linked alerts are **live references** (by
`alert_id`), not snapshots — if an alert is later resolved, mutated, or pruned, the case's view
of it changes accordingly. v1 is a curation/triage aid, not a sealed forensic record.

## 2. Architecture

```
Alert detail page  ──"Open case"(POST)─────► open_case (IPC, mutates) ─┐
                   ──"Attach to case"(POST)─► attach_alert (IPC, mutates)│
                                                                         ▼
inspectord/cases/store.py  ◄── cases/ipc_handlers.py ──► cases / case_alert / case_event
   (CRUD + timeline + assembly, DB-only)        │           (LEFT-join alerts for detail)
                                                ▼
            inspectorctl-web /cases (+ /cases/{id})  ◄── list_cases / get_case (IPC, read)
```

- `inspectord/cases/store.py` — pure DuckDB CRUD over a `Database` (DB-only, no `db_path`;
  mirrors `inspectord/state/baseline.py`'s `capture_baseline(kind, db)` shape). Generates
  `case_id` via the existing helper **`inspectord.ids.uuid7`** (no new dependency). Every
  mutating op appends a `case_event` row.
- `inspectord/cases/ipc_handlers.py` — keyword-only handlers `(*, params, db_path)` mirroring
  `inspectord/state/ipc_handlers.py`. Each handler wraps the store call:
  `with Database(db_path) as db: ... = store.fn(db, ...)` (exactly how `handle_capture_baseline`
  wraps `baseline.capture_baseline`). Defines its **own local `_iso`** (a 1-line copy, NOT an
  import of the module-private `_iso` in `state/ipc_handlers.py` — keeps the module standalone).
- **Single `now` per op:** each mutating store function captures one
  `datetime.now(tz=UTC)` and binds it to both the `cases`/`case_alert` row and its
  `case_event` row(s), so timeline ordering is coherent. (DuckDB returns naive datetimes;
  render via `_iso`.)

## 3. Storage — migration `0006_cases.sql`

Additive; `IF NOT EXISTS`. No foreign keys (consistent with the rest of the schema).

```sql
CREATE TABLE IF NOT EXISTS cases (
    case_id     VARCHAR PRIMARY KEY,
    title       VARCHAR NOT NULL,
    status      VARCHAR NOT NULL DEFAULT 'open',   -- open | closed
    opened_at   TIMESTAMP NOT NULL,
    closed_at   TIMESTAMP
);

CREATE TABLE IF NOT EXISTS case_alert (
    case_id     VARCHAR NOT NULL,
    alert_id    VARCHAR NOT NULL,
    attached_at TIMESTAMP NOT NULL,
    PRIMARY KEY (case_id, alert_id)
);

-- append-only case ACTIVITY / NOTES log (NOT a tamper-evident chain-of-custody — see §1.1).
-- seq orders events written within the same op (same ts); real custody is the deferred audit_log.
CREATE TABLE IF NOT EXISTS case_event (
    case_id     VARCHAR NOT NULL,
    ts          TIMESTAMP NOT NULL,
    seq         INTEGER NOT NULL,   -- per-(case,ts) tiebreak so 'opened' precedes 'alert_attached'
    kind        VARCHAR NOT NULL,   -- opened | alert_attached | note | closed
    text        VARCHAR             -- note body, or the attached alert_id, etc.
);

CREATE INDEX IF NOT EXISTS case_alert_case_idx ON case_alert (case_id);
CREATE INDEX IF NOT EXISTS case_event_case_idx ON case_event (case_id, ts, seq);
```

## 4. `store.py` — operations

All take a `Database` (`db`). `db.execute()` returns `None` (no rowcount), so existence/idempotency
is decided by a **pre-check `SELECT`** (the pattern `alerts/ipc_handlers.py::_transition` uses),
never by an INSERT result. `_MAX_TEXT = 16384`: `add_note` text and `open_case` title are
bounded (truncate) before storage — the IPC server reads the whole request into memory and does
no param validation, so cap to avoid self-DoS.

| Function | Behaviour |
| --- | --- |
| `open_case(db, *, alert_id, title=None) -> str` | **Atomic** (see below): mint `case_id` via `uuid7`; capture one `now`. Insert `cases` (status `open`, `opened_at=now`). Title defaults to the alert's `rendered_short` (`SELECT rendered_short FROM alerts WHERE alert_id=?`); fall back to `f"Case {case_id[:8]}"` if the alert is missing. Call the internal `attach_alert` logic on the **same `db`**. Append `opened` (seq 0) then `alert_attached` (seq 1) `case_event` rows sharing `now`. Returns `case_id`. |
| `attach_alert(db, *, case_id, alert_id)` | No-op if the case doesn't exist (pre-check `SELECT 1 FROM cases`). Pre-check `SELECT 1 FROM case_alert WHERE case_id=? AND alert_id=?`; if already linked, no-op (no duplicate row, no duplicate event). Else insert `case_alert` + append one `alert_attached` event. |
| `add_note(db, *, case_id, text)` | No-op if case missing. Append a `note` event with bounded `text`. Allowed on closed cases (annotate-after-close is intentional; see §6). |
| `close_case(db, *, case_id)` | No-op if case missing. Set `status='closed'`, `closed_at=now`; append `closed` event. Idempotent (closing a closed case is a no-op, no duplicate event). |
| `list_cases(db) -> list[dict]` | each: `case_id, title, status, opened_at, closed_at, alert_count` where `alert_count = COUNT(*) FROM case_alert` for the case (counts **links**, so it always equals the detail alert-row count — see below); newest `opened_at` first. |
| `get_case(db, *, case_id) -> dict | None` | `None` if the case row is absent. Else: `case` fields + `alerts` (**LEFT JOIN** `case_alert`→`alerts` ordered by `attached_at`: a link whose alert is missing/pruned still appears as a placeholder row carrying `alert_id` with null `rule_id/severity/status/rendered_short/ts`, so `len(alerts) == alert_count`) + `timeline` (`case_event` ordered by `ts, seq`). |

**Atomicity:** `open_case` runs its multiple writes inside one transaction on the single `db`
connection — `db.execute("BEGIN TRANSACTION")` … `db.execute("COMMIT")`, with
`db.execute("ROLLBACK")` on exception — so a mid-sequence failure never leaves a case row with
no `opened` event or link (DuckDB otherwise auto-commits per statement).

All input (note text, ids, title) is parameterized; no raw SQL interpolation.

## 5. IPC methods (`inspectord/__main__.py`)

Register handlers from `inspectord/cases/ipc_handlers.py`:

| Method | Params | Mutates | Returns |
| --- | --- | --- | --- |
| `open_case` | `alert_id`, `title?` | yes | `{"schema_version":"1.0.0","case_id": …}` |
| `attach_alert` | `case_id`, `alert_id` | yes | `{"schema_version":"1.0.0","ok": true}` |
| `add_note` | `case_id`, `text` | yes | `{"schema_version":"1.0.0","ok": true}` |
| `close_case` | `case_id` | yes | `{"schema_version":"1.0.0","ok": true}` |
| `list_cases` | — | no | `{"schema_version":"1.0.0","cases":[…]}` |
| `get_case` | `case_id` | no | `{"schema_version":"1.0.0","case": {…} | null}` |

Unknown `case_id` on the mutating methods is a silent no-op (returns `{"ok": true}`) — no authz
layer is needed; the IPC socket is already uid-gated and single-user. Timestamps render as ISO
via the local `_iso`.

## 6. Web panel (`inspectorctl/web/`)

**Security posture (inherit, do not expand):** these are the first user-form-driven *mutating*
POST routes. The web app is **bound to 127.0.0.1 only, with no auth/CSRF/TLS in v1** (already
documented in `inspectorctl/web/__init__.py`, and the capture-baseline POST set the precedent).
Localhost drive-by CSRF is a **knowingly-accepted residual risk** deferred to the hardening
slice — do NOT pull CSRF tokens into this PR.

- **Alert detail** (`inspectorctl/web/routes/alerts.py`, template `alert_detail.html`): two new
  actions next to the existing ack/resolve/suppress buttons:
  - **"Open case"** → `POST /alerts/{alert_id}/open-case` → calls `open_case({"alert_id": alert_id})`,
    reads `result["case_id"]`, `RedirectResponse("/cases/{case_id}", 303)`. Cannot reuse
    `_mutate` (which redirects to a static path and discards the body). On `WebIpcError` →
    `HTTPException(502)` (matching the existing alert mutations).
  - **"Attach to case"** → a small form listing **open** cases (from `list_cases`) →
    `POST /alerts/{alert_id}/attach-case` (field `case_id`) → `attach_alert(...)` →
    redirect back to `/alerts/{alert_id}` (303); `HTTPException(502)` on `WebIpcError`.
- **`inspectorctl/web/routes/cases.py`**:
  - `GET /cases` → `cases.html`: list (title, status, alert count, opened_at), each links to
    the detail. Empty-state "No cases yet." `WebIpcError` → daemon-unreachable banner.
  - `GET /cases/{case_id}` → `case_detail.html`: title + status; **Alerts** section (linked
    alerts, each linking to `/alerts/{alert_id}`; placeholder rows for pruned alerts show the
    id only); **Timeline** section (the `case_event` rows: ts + kind + text); an **add-note**
    form (`POST /cases/{case_id}/notes`) and a **Close** button (`POST /cases/{case_id}/close`)
    shown when the case is open. 404 if `get_case` returns null. (No attach form here — attach
    happens from the alert detail page.)
  - The two POST routes call the matching IPC method and redirect back to `/cases/{case_id}`
    (303); `HTTPException(502)` on `WebIpcError`.
- Register the router in `app.py`; add `nav_link("/cases", "Cases", current_path)` to
  `base.html` after Persistence.
- **Escaping:** note text, title, and alert-derived strings (`rendered_short`) render
  **autoescaped (no `| safe`)**; §8 mandates a `<script>`-in-note escaping test.

This panel is **not** an htmx auto-refreshing feed (unlike the inventory panels) — cases change
on user action, so plain request/redirect navigation is used.

Closing a case is a **reversible status flag**, not a seal: `add_note` still works on a closed
case (annotate after closing). Reopen and delete are deferred (§9), so in practice close is
one-way in v1.

## 7. PR breakdown

Two PRs (the established backend-then-web split):

- **PR8 — cases store + IPC**: migration `0006_cases.sql`, `inspectord/cases/store.py`,
  `inspectord/cases/ipc_handlers.py`, daemon registration of the six methods, unit tests. No
  web.
- **PR9 — Cases web panel**: alert-detail "Open case" + "Attach to case" actions + `/cases`
  list + `/cases/{id}` detail (add-note / close) + router/nav wiring, web tests.

## 8. Testing (TDD throughout)

- **store** — `open_case` creates the case, links the alert, writes `opened`(seq 0)+
  `alert_attached`(seq 1) timeline rows sharing one ts, and defaults the title from the alert's
  `rendered_short` (and falls back when the alert is absent); the whole op is atomic; `attach_alert`
  is idempotent (re-attach adds no duplicate link or event) and no-ops on a missing case;
  `add_note` appends (and still works on a closed case); `add_note`/title truncate at `_MAX_TEXT`;
  `close_case` sets status/closed_at + event, idempotent; `list_cases` ordering + `alert_count`
  equals the link count; `get_case` assembles case+alerts+timeline, returns `None` for a missing
  id, and a **pruned/dangling alert link still appears as a placeholder row so `alert_count`
  matches the alert-list length**.
- **migration** — `tests/test_cases_migration.py`: tables + columns exist (mirror
  `test_persistence_state_migration.py`).
- **IPC handlers** — each method's params/return shape; ISO timestamps; `get_case` null case;
  unknown-case mutating no-op.
- **web** — alert-detail "Open case" POSTs and redirects to the new case; "Attach to case"
  lists open cases and POSTs `attach_alert`; `/cases` list renders + empty state +
  daemon-unreachable; `/cases/{id}` detail renders alerts + timeline; add-note / close POSTs
  call the right IPC method and redirect; **a note containing `<script>` is HTML-escaped**.

## 9. Out of scope (deferred Cases slices)

- **`evidence_collector`** — auto-capture on ≥high-severity alerts (hash+copy implicated
  files, process-tree snapshot, network-state snapshot, ±5 min event bundle) *before* notify
  (parent spec §13.1–13.2); the forensic store (§10.3); `case_evidence` rows.
- **Tamper-evident chain-of-custody** — a hash-chained `audit_log` (§13.5 / §20.4) replacing
  the plain `case_event` log for custody guarantees; alert **snapshotting** into the case so a
  pruned/mutated alert no longer changes the record. (Both belong with the evidence slice.)
- **ZIP export** (`export_case_zip`) with `case.json` / `events/*.jsonl` / `alerts/*.json` /
  `evidence/<sha256>` / `narrative.md` / `audit.log` (parent spec §13.4). Note: case notes are
  potentially-sensitive free text — redaction belongs in the export slice's scope.
- **Incident / entity linking**, the Incidents panel, quarantine integration.
- **Reopen-after-close, case deletion**; multi-user/auth/CSRF (single-user localhost host).
