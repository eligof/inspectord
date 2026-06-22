# Evidence collector v1 (file + network + event-bundle capture) — design

| Field | Value |
| --- | --- |
| Date | 2026-06-22 |
| Status | Approved (brainstorming) + concilium-reviewed (REVISE→revised) 2026-06-22 — ready for plan |
| Spec section refs | §13 (evidence & cases), §13.1–13.2, §7.5 (Case.evidence), §10.3 (forensic store), §693–694 |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` |
| Builds on | `docs/superpowers/specs/2026-06-21-cases-panel-design.md` (manual Cases — reused) |

## 1. Purpose & context

The manual Cases panel (PRs #107–#108) lets a user curate cases from alerts. This adds the
**`evidence_collector`** — the parent spec's "evidence first, notify second" (§13.2): on a
high-severity alert, **preserve evidence before the user is notified**, so a self-deleting
payload or an exiting process is captured before it "runs away."

The full §13.1 collector captures five artifact types of wildly different complexity and
sensitivity. **This is decomposed; v1 captures the foundation + three low-risk artifacts:
implicated files, a network-state snapshot, and a minimal event bundle.** The privacy-sensitive
process-tree-with-env/fds capture, the ±5-min windowed event bundle, and ZIP export are
deferred (§10).

> **A concilium (5-lens review) on 2026-06-22 returned REVISE.** The scope cut and foundation
> were endorsed; the capture mechanism was rebuilt around verified-in-code findings. **The
> load-bearing correction (all five lenses): alert listeners fire on each worker's
> `_read_stdout` thread (supervisor.py:194), not a single `_drain` thread.** Consequences,
> all folded in below: (a) the triggering event is NOT yet in `events_enriched` when the
> collector runs (that write happens later on `_drain` via `_persist`), so the collector
> takes the **live `Event` in-memory**, not a DB lookup; (b) multiple worker threads fan out
> concurrently, so idempotency needs a **lock**; (c) a blocking/slow capture stalls a worker's
> whole event stream, so reads are **non-blocking, symlink-safe, and hard-bounded**.

### Design decisions (locked: brainstorming + concilium 2026-06-22)

| Decision | Choice | Rationale |
| --- | --- | --- |
| v1 artifacts | **Implicated files + network snapshot + minimal event bundle** | Files = "catch it before deletion"; net = cheap moment-in-time; event bundle pulled in because several high-sev rules yield no file path (§4.2), so files-only would capture nothing for them. |
| Where it runs | **In-process; the supervisor calls it directly in the alert fan-out** | Not a generic alert-listener (those take only `Alert`); the collector needs the **live triggering `Event`**, which the fan-out has in hand. |
| Before-notify | **Supervisor calls `collector.capture(alert, event)` before the notifier listeners** | Guarantees evidence-first without changing the `alert_listener` protocol. |
| Concurrency | **A single `threading.Lock` serializes all captures** | Worker `_read_stdout` threads fan out concurrently; the lock makes the idempotency check+create atomic and bounds concurrent disk/DB pressure (captures are rare). |
| Trigger | **`severity in {high, critical}`** | §13.1 "≥ high"; membership avoids enum-ordering assumptions. `critical` is forward-looking (no starter rule emits it yet). |
| Auto-case model | **One idempotent case per distinct `alert_id`** | Dedup keeps `alert_id` stable; reuses `cases.store.open_case`. |
| Forensic store | **Content-addressed blobs, atomically `0600`** | De-dups identical content; `case_evidence` rows are the manifest. |
| Capture failure | **Best-effort per artifact, hard-bounded** | A failure logs + continues; bounded so it can never hang or DoS the worker thread. |

## 2. Architecture & threading (corrected)

```
_read_stdout (per worker thread)  AND  _inject_for_test:
    for alert in rule_engine.process(ev):          # ev = the LIVE triggering event
        if evidence_collector: evidence_collector.capture(alert, ev)   ← BEFORE notify; bounded
        for fn in alert_listeners: fn(alert)        # notifier etc.
    router.publish(ev)                              # → _drain → _persist (events_enriched) LATER
```

The collector is held as `self._evidence_collector` on the supervisor and invoked directly
(not via `attach_alert_listener`) so it receives the live `Event`. Both fan-out sites
(`_read_stdout` line ~194 and `_inject_for_test` line ~105) call it. All of `capture()` runs
under one shared `threading.Lock` (concurrent worker threads + the supervisor's own DB use).

## 3. Components

### 3.1 Forensic store — `inspectord/evidence/store.py`

`ForensicStore(root: Path)`:
- `put(data: bytes) -> str` — `sha = sha256(data).hexdigest()`; dest `root/<sha[:2]>/<sha>`.
  If dest exists, return `sha` (idempotent, no rewrite). Else: create the shard dir with
  `os.makedirs(dir, mode=0o700, exist_ok=True)`; write **atomically and never world-readable**
  — `fd = os.open(tmp, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0o600)` in the same dir, write,
  `os.fsync`, `os.close`, `os.replace(tmp, dest)`. Returns `sha`. (A pre-existing-umask
  write-then-chmod is NOT acceptable — there must be no readable window.)
- `path_for(sha) -> Path`. Root: `/var/lib/inspectord/evidence` (prod) / `<base>/evidence`
  (dev), via a new `evidence_dir` storage-config field.
- Store-write/mkdir failures are raised to the caller, which treats them best-effort (§3.6).

### 3.2 `case_evidence` table — migration `0007_case_evidence.sql`

```sql
CREATE TABLE IF NOT EXISTS case_evidence (
    case_id       VARCHAR NOT NULL,
    kind          VARCHAR NOT NULL,   -- file | net_state | event_bundle
    sha256        VARCHAR NOT NULL,   -- content-addressed blob
    original_path VARCHAR,            -- source path for kind=file; NULL otherwise
    captured_at   TIMESTAMP NOT NULL,
    meta_json     VARCHAR,            -- {size, truncated, socket_count, alert_id, ...}
    PRIMARY KEY (case_id, kind, sha256, original_path)
);
CREATE INDEX IF NOT EXISTS case_evidence_case_idx ON case_evidence (case_id);
```

`original_path` is in the PK so two distinct paths with identical content are two rows (you
keep "which paths held this blob"). Inserts use `ON CONFLICT DO NOTHING` (a re-capture is a
clean no-op, not a swallowed error). DuckDB's NULL-in-PK: `original_path` is `''` (not NULL)
for non-file kinds so the PK is well-defined.

### 3.3 Safe file capture — `inspectord/evidence/capture.py::read_capture(path) -> bytes | None`

The single most safety-critical unit. The path is attacker-influenced, the daemon is root.
- **Path gate first** (reject → return None, record the refusal): require an **absolute** path,
  reject any `..` component, `os.path.realpath` it, and reject if the resolved path is under a
  **sensitive-prefix deny-list** (`/proc`, `/sys`, `/dev`, `~/.ssh`, `/root/.ssh`, `/etc/shadow`,
  `/etc/gshadow`, private-key-ish suffixes). This stops the confused-deputy "copy any file into
  the store" exfil primitive.
- **fd-based, non-following, non-blocking open**:
  `fd = os.open(path, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)`. `O_NOFOLLOW` refuses an
  attacker symlink at the final component; `O_NONBLOCK` means opening a writer-less FIFO does
  not hang and reads return `EAGAIN` instead of blocking.
- **fstat THAT fd** (never re-stat by path): require `S_ISREG`, else close + return None.
- **Read at most `_MAX_FILE_BYTES + 1` from the fd** (default 32 MiB); if it exceeds, keep the
  first `_MAX_FILE_BYTES` and mark `truncated=True`. Enforce the cap on the *read*, not the
  pre-stat size (TOCTOU-safe). Always read from the already-open fd — never re-open by path.
- All `OSError`/`BlockingIOError` → return None (best-effort skip), logged.

### 3.4 Network snapshot — `inspectord/evidence/netsnapshot.py`

`network_snapshot(proc_net_dir=Path("/proc/net")) -> dict` — a **new** parser (the existing
`parse_listeners` filters to LISTEN and never decodes the remote address) that **reuses the
`listening_socket_snapshotter.source` `_decode_*` hex helpers**. Reads
`/proc/net/{tcp,tcp6,udp,udp6}`, **bounded** (cap bytes read per proto file and/or parsed rows,
set `truncated=True` if hit), decoding all states with local+remote addr+port+state. Returns
`{"captured_at": iso, "truncated": bool, "sockets": [...]}`. No subprocess; never raises.

### 3.5 Implicated paths — `implicated_paths(alert, event) -> list[str]`

From the **live event** (not the DB): union, de-duplicated, of `event.file["path"]`,
`event.persistence["source_path"]` (the high-sev `authorized_keys`/cron rules set this, not
`file.path`), and `alert.entities` where `kind == "file"` (the YAML loader emits a **bare
path**, no `file:` prefix — verified). Returns the raw candidate list; the path gate (§3.3)
filters at read time.

### 3.6 `EvidenceCollector` — `inspectord/evidence/collector.py`

`EvidenceCollector(db_path, store)` with `capture(alert, event) -> None`, all under
`self._lock`:
1. If `alert.severity` not in `{high, critical}` → return.
2. Open a `Database(db_path)` (the established IPC-handler pattern — the IPC handlers already
   open their own connection concurrently with the running supervisor; §9 documents/tests this
   is safe). **Idempotent guard**: `SELECT 1 FROM case_alert WHERE alert_id = ?` → if present,
   return (the lock makes check+create atomic across worker threads).
3. `case_id = cases.store.open_case(db, alert_id=alert.alert_id, title=alert.rendered.short)`.
4. **Network snapshot FIRST** (cheap, always-bounded) → `store.put` → `case_evidence`
   (`kind='net_state'`, `meta={socket_count, truncated}`). Doing net before files means a
   file-volume stall never costs the net snapshot.
5. **Event bundle** → `store.put(json.dumps(event.model_dump(mode="json", exclude_none=True)))`
   → `case_evidence` (`kind='event_bundle'`). Near-zero cost; salvages no-file alerts.
6. **File capture** (bounded loop): for each implicated path, up to `_MAX_FILES` (default 16)
   and a per-alert total-bytes budget (`_MAX_TOTAL_BYTES`, default 128 MiB) and an overall
   soft deadline (`_CAPTURE_DEADLINE_S`, default ~5 s): `data = read_capture(path)` (§3.3);
   if not None, `store.put(data)` → `case_evidence` (`kind='file'`, `original_path`,
   `meta={size, truncated}`). When a bound is hit, stop and mark the timeline summary
   "partial capture".
7. Append a `cases` timeline event via a new `cases.store.append_timeline(db, *, case_id,
   kind='evidence_captured', text=summary)` (a thin public wrapper over the private
   `_append_event` — the store today only exposes `add_note`/kind=`note`). Summary records
   counts + any partial/refused note.
8. Every step's exceptions are caught + logged; one artifact failing never aborts the others
   or the case.

`meta_json` always records `alert_id` and `captured_at`-vs-`alert.ts` so a blob's provenance
is explicit: it is a **best-effort post-detection read, not a point-in-time image** (the file
may have been swapped before capture).

## 4. Coverage honesty (what v1 actually captures)

### 4.1 Threading reality
The collector runs synchronously on the worker `_read_stdout` thread before notify. The hard
bounds (§3.3 non-blocking + size cap; §3.6 file-count/total-bytes/deadline; §3.4 bounded net)
keep the worst-case stall short and un-weaponizable. Accepted: a `>= high` capture briefly
pauses that worker's event ingestion.

### 4.2 Which alerts yield what
`build_alert` sets exactly ONE primary entity (process before file — verified). So: the
`new_suid`/`sudoers` rules yield a **file** path; the `authorized_keys`/`new_cron` rules set
`persistence.source_path` (captured as a file via §3.5); process/network-primary alerts yield
**no file** — for those the **event bundle + net snapshot** are the evidence. This is why the
event bundle is in v1.

## 5. Supervisor wiring

In `Supervisor.start()`: construct `ForensicStore(cfg.storage.evidence_dir)` +
`EvidenceCollector(cfg.storage.db_path, store)`, store as `self._evidence_collector`. In both
fan-out sites, call `self._evidence_collector.capture(alert, ev)` **before** the
`alert_listeners` loop. The collector attach is unconditional (evidence is core); a code
comment marks that it MUST precede notify. Add `evidence_dir` to the storage config.

## 6. Web — Case detail "Evidence" section

`get_case` also returns `evidence` — `case_evidence` rows ordered `ORDER BY captured_at, kind,
sha256`, `meta_json` decoded to a dict in the store layer. A Case-detail **Evidence** section:
Kind / Original path / Captured / size-or-socket-count (from meta) / `sha256` (mono, truncated),
labeled a **preservation receipt** ("Preserved — retrieval via export coming soon"). No file
download in v1. Autoescaped (paths are attacker-influenced).

## 7. PR breakdown (2 PRs)

- **PR-A — foundation units**: `store.py` (atomic-0600 content-addressed store), migration
  `0007`, `netsnapshot.py` (bounded all-states parser), `capture.py` (the symlink/TOCTOU-safe
  `read_capture` + path gate), the `evidence_dir` config field. Pure units + tests. No
  collector, no wiring.
- **PR-B — collector + wiring + panel**: `implicated_paths`, `EvidenceCollector` (lock, bounds,
  idempotency, the 3 artifact captures), `cases.store.append_timeline`, supervisor registration
  (before notify, both fan-out sites), the `case_evidence` read in `get_case`, the Case-detail
  Evidence section. Tests incl. fan-out ordering + concurrent-idempotency + end-to-end capture.

## 8. Testing (TDD)

- **store** — content-addressing/dedup, `<sha[:2]>` shard, **perms `0600` hold DURING creation**
  (no world-readable window — assert via the temp-then-rename path), dir `0700`, `path_for`.
- **read_capture** (the safety unit) — a regular file is read + size-capped (`truncated`); a
  **FIFO/symlink-to-FIFO returns None without hanging** (use a real `os.mkfifo` with no writer +
  `O_NONBLOCK`); a **symlink is refused** (`O_NOFOLLOW`); a deny-listed path (`/etc/shadow`,
  `..`, relative, `/proc/...`) is refused; an oversize file is truncated via the fd read (not
  the pre-stat size).
- **netsnapshot** — listeners + established decoded from `/proc/net` fixtures; bounded/truncated;
  unreadable proto contributes nothing, never raises.
- **implicated_paths** — union of `file.path` + `persistence.source_path` + file entities from a
  live event; de-dup; empty when none.
- **collector** — `>= high` triggers, `< high` skipped; **concurrent idempotency** (two threads,
  same `alert_id`, exactly one case — exercise the lock); net + event_bundle always captured;
  file capture from a tmp file; a missing/oversize/denied file is skipped without aborting net,
  bundle, or case; `_MAX_FILES`/total-bytes/deadline bounds stop the loop + mark partial;
  timeline `evidence_captured` event written.
- **supervisor** — `self._evidence_collector.capture` is called **before** the notifier in the
  fan-out (both `_read_stdout` and `_inject_for_test`); an injected `critical` alert (synthetic,
  since no rule emits critical) produces a case with evidence; a non-writable `evidence_dir`
  degrades gracefully (case opens, store failure logged, thread unaffected).
- **web** — Evidence section renders the rows; a malicious `original_path` is HTML-escaped.

## 9. DB concurrency

The collector opens its own `Database(db_path)` per capture under the global capture lock —
the **same pattern the IPC handlers already use** concurrently with the running supervisor
(precedent that a second connection to the DuckDB file in-process is workable). A test exercises
a capture while the supervisor's `_persist` path is active to confirm no lock error; if DuckDB
rejects the concurrent connection in practice, fall back to reusing the supervisor's `self._db`
handle guarded by the same lock. Either way, the capture lock + the bounds keep any DB wait off
the unbounded path.

## 10. Out of scope (deferred evidence slices)

- **Process-tree snapshot** — PIDs/exe/hashes/cmdline/cwd/**env/fds/mapped-libs** (most
  secret-laden + racy); its own slice with explicit privacy handling.
- **±5-min windowed event bundle** (v1 bundles only the in-hand triggering event).
- **ZIP export** + `narrative.md` + evidence file **download/retrieval UI**.
- **Hash-chained `audit_log`** (real tamper-evident chain-of-custody).
- **Forensic-store retention/GC** — blobs are content-addressed and currently live forever
  under `/var/lib` even after a case closes; v1 consciously accepts this unbounded
  secret-on-disk growth and names GC as a deferred slice.
- The `manifest.json` file; entity-window case grouping; quarantine integration.

## 11. Privacy & attack-surface summary

Blobs are atomically `0600` in a root-only (`0700`) store, local-only, content-addressed. The
path gate + `O_NOFOLLOW` + deny-list stop the root daemon from being a confused-deputy file
reader. Captured content is a best-effort post-detection read (provenance in `meta`). Process
env (the high-secret capture) and unbounded retention are deliberately out of v1. Paths/net
render autoescaped in the panel.
