# Case ZIP export + evidence download — design

| Field | Value |
| --- | --- |
| Date | 2026-06-23 |
| Status | Approved (brainstorming) — ready for implementation plan |
| Spec section refs | §13.4 (case ZIP export format), §13.5 (chain of custody), §672 (`export_case_zip`), §16 (IPC) |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` |
| Builds on | manual Cases (#107–108), evidence collector (#110–111) |

## 1. Purpose & context

The Case detail panel preserves evidence and shows "retrieval via export coming soon." This
makes it real: a **whole-case ZIP export** and a **per-evidence-blob download**, so a user can
archive a case or hand it to a security professional. Implements parent spec §13.4 (the ZIP
format) + §672 (`export_case_zip`).

### The load-bearing constraint: transport

The web dashboard (`inspectorctl.web.create_app(*, socket_path)`) is a **pure IPC client** — it
has no filesystem, DB, or forensic-store access; it only talks to the daemon over a
**line-delimited-JSON Unix socket**. The forensic store is **root-only** (`0700`), so only the
daemon can read evidence blobs. Therefore export/download **bytes must travel over IPC as
base64** in the JSON response: the daemon (root) reads the store, builds the artifact in memory,
base64-encodes it; the web decodes and returns it as an HTTP `Response`. This is memory-heavy, so
it is **hard size-capped** (`_MAX_EXPORT_BYTES`, 64 MiB) — over the cap, the daemon refuses and
the UI tells the user to retrieve from the on-disk store.

### Design decisions (locked during brainstorming 2026-06-23)

| Decision | Choice | Rationale |
| --- | --- | --- |
| v1 features | **Whole-case ZIP export + per-blob download** | The ZIP is the shareable archive; per-blob download for quick single-artifact access. |
| Transport | **base64-over-IPC, daemon-built, size-capped (64 MiB)** | The web is a pure IPC client; the store is root-only; line-delimited JSON can't carry raw binary. |
| Where built | **Daemon-side `inspectord/cases/export.py`** | Only the daemon can read the store. |
| Custody | **Each export/download appends a `case_event`** (`exported` / `evidence_downloaded`) | §13.5: "every operation on a case … is logged." (The `case_event` log is the existing not-yet-tamper-evident trail; real hash-chained custody stays deferred.) |
| Path safety | **`download_evidence` only serves a `sha` present in THIS case's `case_evidence`** | Never an arbitrary store path; `sha` validated as hex. |

## 2. Components

### 2.1 `inspectord/cases/export.py` (daemon-side, pure over `db` + `ForensicStore`)

- `build_case_zip(db, store, case_id) -> bytes` — `None`-guard: raise `CaseNotFound` if the case
  is absent. Assemble a ZIP **in memory** (`io.BytesIO` + `zipfile.ZipFile`) containing:
  - `case.json` — the `cases_store.get_case(db, case_id)` record (case + alerts + timeline +
    evidence manifest), JSON, timestamps ISO.
  - `alerts/<alert_id>.json` — each linked alert's full record (`SELECT payload_json FROM alerts
    WHERE alert_id = ?` for each `case_alert`).
  - `evidence/<sha>` — each `case_evidence` blob's bytes from `store.path_for(sha)` (skip a
    missing blob, note it in the manifest/narrative).
  - `narrative.md` — a template-rendered human summary: title, status, opened/closed, the linked
    alerts (rule + severity + short), the timeline (ts + kind + text), and the evidence list
    (kind + original_path + sha + size). Plain-text builder (no Jinja needed); a few lines.
  - **Size cap**: track the running total of blob bytes; if it would exceed `_MAX_EXPORT_BYTES`
    (64 MiB), raise `ExportTooLarge` before finishing (the caller turns this into a friendly
    error). Returns the ZIP bytes.
- `read_evidence_blob(db, store, case_id, sha) -> tuple[bytes, str, str]` — validate `sha` is
  hex and exists in `case_evidence` **for this `case_id`** (else raise `EvidenceNotFound`); read
  the blob from the store; return `(data, filename, media_type)`. `filename` = basename of
  `original_path` for `kind=file` (fallback `<sha[:12]>.bin`), `<sha[:12]>-<kind>.json` for
  `net_state`/`event_bundle`. `media_type` = `application/json` for net/bundle, else
  `application/octet-stream`. Enforce `_MAX_EXPORT_BYTES` on the single blob too.

### 2.2 IPC handlers (`inspectord/cases/ipc_handlers.py`, registered in `__main__.py`)

Both `mutates=False` (UX: no permission prompt; the custody `case_event` append is an internal
side-effect, not the method's "mutation"). Each opens `with Database(db_path) as db:` + a
`ForensicStore(evidence_dir)`. **They need `evidence_dir`** — pass it into the handler lambdas
from `cfg.storage.evidence_dir` (alongside `db_path`).

- `export_case_zip(case_id) -> {filename, content_b64}` — `build_case_zip` → base64; append
  `cases_store.append_timeline(db, case_id, kind="exported", text="case exported as ZIP")`. On
  `CaseNotFound` → `{ "error": "not found" }`; on `ExportTooLarge` → `{ "error": "too_large" }`.
- `download_evidence(case_id, sha) -> {filename, media_type, content_b64}` — `read_evidence_blob`
  → base64; append `append_timeline(... kind="evidence_downloaded", text=f"downloaded {sha[:12]}")`.
  On not-found → `{ "error": "not found" }`; over-cap → `{ "error": "too_large" }`.

### 2.3 Web (`inspectorctl/web/routes/cases.py` + `case_detail.html`)

- `GET /cases/{case_id}/export` → `call("export_case_zip", {case_id})`; on `error` →
  `HTTPException(404 or 502)` / a friendly message for `too_large`; else
  `Response(base64.b64decode(content_b64), media_type="application/zip", headers={
  "Content-Disposition": f'attachment; filename="case-{case_id[:8]}.zip"'})`.
- `GET /cases/{case_id}/evidence/{sha}` → `call("download_evidence", {case_id, sha})`; decode →
  `Response(bytes, media_type=resp["media_type"], Content-Disposition attachment filename=...)`.
  404 on not-found.
- `case_detail.html`: replace "retrieval via export coming soon." with an **Export ZIP** link
  (`/cases/{id}/export`) and a **Download** link per evidence row (`/cases/{id}/evidence/{sha}`).

## 3. Cross-cutting

- **Size cap** bounds the base64-over-IPC memory on both the daemon (build) and web (decode)
  sides; over the cap the UI says "too large for browser download — retrieve from the on-disk
  forensic store." `_MAX_EXPORT_BYTES = 64 MiB`.
- **Path/sha safety**: `download_evidence` serves only a sha tied to this case's evidence rows;
  `sha` is validated `^[0-9a-f]{64}$`. No path traversal — the store path is derived from the
  validated sha, never from user input.
- **Privacy / posture**: this serves potentially-sensitive captured file contents over the
  **localhost-only, no-auth** UI (the established v1 posture). A knowing residual risk; the
  evidence already lives at rest. Export/download are logged to the case timeline (custody).
- **Custody events are GET side-effects** — intentional per §13.5 (access *is* a custody event);
  the `case_event` trail is the existing plain (not tamper-evident) log.

## 4. Out of scope (deferred)
Hash-chained tamper-evident `audit_log` (the `case_event` trail stays plain); process-tree/env
capture; export retention/GC (exports are built in-memory, not persisted, so no GC needed here);
streaming/chunked transport for >64 MiB cases (use on-disk retrieval); incidents; the
`exported_at` field on the case record (the `exported` timeline event suffices for v1).

## 5. PR breakdown (2 PRs)
- **PR1 — export builder + IPC**: `inspectord/cases/export.py` (`build_case_zip`,
  `read_evidence_blob`, the exceptions, the cap, the narrative), the two IPC handlers + wiring
  (passing `evidence_dir`). Unit tests (zip contents, missing-blob skip, size cap, sha
  validation, custody event) + handler tests (base64 round-trip, error shapes).
- **PR2 — web download/export**: the two web routes (binary `Response`, `Content-Disposition`,
  error handling) + the Case-detail Export/Download links + tests (zip bytes returned with the
  right headers; a `too_large`/not-found error path; a `sha` that isn't in the case → 404).

## 6. Testing (TDD)
- **export.py** — `build_case_zip` produces a ZIP whose namelist includes `case.json`,
  `alerts/<id>.json`, `evidence/<sha>`, `narrative.md`; `case.json` parses and contains the case;
  a missing store blob is skipped (noted), not fatal; the size cap raises `ExportTooLarge`;
  `CaseNotFound` on a bad id. `read_evidence_blob` returns the bytes + right filename/media_type;
  a sha not in the case raises `EvidenceNotFound`; a non-hex sha is rejected.
- **IPC handlers** — `export_case_zip` returns base64 that decodes to a valid ZIP + appends an
  `exported` case_event; `download_evidence` round-trips a blob + appends `evidence_downloaded`;
  error shapes for not-found / too_large.
- **web** — `GET /export` returns `application/zip` bytes with the attachment header and the
  decoded ZIP is valid; `GET /evidence/{sha}` returns the blob with the right media_type;
  not-found → 404; the Case-detail page shows Export + per-row Download links.
