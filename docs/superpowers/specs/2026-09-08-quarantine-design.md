# File quarantine + the polkit gate

- **Status**: draft (user-brainstormed 2026-09-08; pending concilium review). Autonomously
  drafted; not yet human-reviewed in written form.
- **Date**: 2026-09-08
- **Parent spec**: `2026-05-24-local-inspection-design.md` §2.2 (Quarantine panel), §9.5
  (File actions), §10.3 (forensic store), §16 (IPC auth: SO_PEERCRED + polkit)
- **User decisions (2026-09-08)**: polkit NOW (not deferred again); manual triggers only
  (no §9.5 pending-actions framework yet); web may *quarantine* but restore/delete are
  CLI-only.

## 1. What this is

The first destructive action the daemon performs on the host: isolate a file into the
forensic store and remove the original, reversibly. Because it is the first, it also
builds the **polkit gate** parent §16 promised — a real authorization boundary in front
of mutating IPC, reusable by later phases.

Two PRs: **PR1** = polkit gate + quarantine core + IPC + CLI + retention protection
(daemon-complete). **PR2** = web panel + quarantine buttons.

## 2. The polkit gate (PR1)

### 2.1 Mechanism

`inspectord/authz.py`:

```python
def check_polkit(action_id: str, peer_pid: int, *, runner=subprocess.run) -> AuthzResult
```

- Subject: `--process <pid>,<start-time>` where start-time is field 22 of
  `/proc/<pid>/stat` (parsed from AFTER the last `)` — comm can contain spaces and
  parens). The pid comes from SO_PEERCRED, which `ipc_server` already reads (it
  currently keeps only the uid; the pid will now be kept too). Pid+start-time defeats
  pid-reuse between the peercred read and the check.
- Check: `pkcheck --action-id <id> --process <pid>,<start> --allow-user-interaction`,
  `subprocess.run` with a **60 s timeout** (pkcheck blocks while the user's polkit
  agent shows the prompt; timeout/kill → deny). Exit 0 = authorized; anything else =
  denied, with pkcheck's stderr captured for the audit detail. `pkcheck` binary
  missing → deny with kind `polkit_unavailable`.
- **Fail closed everywhere**: unknown action id (policy file not installed) is an
  implicit polkit deny; that surfaces as a distinct, actionable client error
  ("polkit denied — is packaging/polkit/org.inspectord.policy installed?").
- Injectable (`runner`) so unit tests fake the subprocess; CI never needs polkit.
  One root-only `ebpf_load`-style manual test exercises the real binary
  (skipif non-root + skipif pkcheck missing) with `--allow-user-interaction`
  REPLACED by nothing (non-interactive) so it never hangs a terminal.

### 2.2 Server-level gating

`Method` gains `polkit_action: str | None = None`. `ipc_server` runs the check BEFORE
dispatching the handler for any method that declares one — handlers stay pure and
cannot forget the check. The JSON-RPC error for a denial is a `ClientFacingError`
(the user must see *why*), and every denial is audited
(`action="polkit_denied"`, target = the method name, details = `{action_id, peer_pid,
reason}`). Timeouts audit as denials with `reason="timeout"`.

Existing methods are NOT retrofitted in this spec (scope discipline; the gate is
built to make that a one-line change later).

### 2.3 Policy file

`packaging/polkit/org.inspectord.policy` — three actions:

| action id | defaults (allow_active) |
|---|---|
| `org.inspectord.quarantine` | `auth_self_keep` |
| `org.inspectord.quarantine-restore` | `auth_self_keep` |
| `org.inspectord.quarantine-delete` | `auth_self_keep` |

`auth_self_keep` = prompt for the user's own password, remember for the session —
parent §16's "prompts the user the first time and remembers grants". Install is a
documented human step: `sudo cp packaging/polkit/org.inspectord.policy
/usr/share/polkit-1/actions/`. Until installed, all three verbs fail closed with the
actionable error above. `packaging/config.example.toml` gains the recipe.

## 3. Quarantine core (PR1)

`inspectord/quarantine/` (store-adjacent module, mirrors `inspectord/cases/` shape).

### 3.1 Table (migration 0014, additive, idempotent)

```sql
CREATE TABLE IF NOT EXISTS quarantine (
    quarantine_id  VARCHAR PRIMARY KEY,   -- uuid, house id style
    sha256         VARCHAR NOT NULL,
    original_path  VARCHAR NOT NULL,
    file_mode      INTEGER NOT NULL,      -- st_mode & 0o7777
    file_uid       INTEGER NOT NULL,
    file_gid       INTEGER NOT NULL,
    size_bytes     BIGINT  NOT NULL,
    pkg_owner      VARCHAR,               -- `pacman -Qo` result or NULL
    note           VARCHAR,
    alert_id       VARCHAR,
    case_id        VARCHAR,
    status         VARCHAR NOT NULL,      -- active | restored | deleted
    quarantined_at TIMESTAMP NOT NULL,    -- naive UTC (store-what-you-compare)
    restored_at    TIMESTAMP,
    deleted_at     TIMESTAMP
);
```

### 3.2 Quarantine (isolate)

Bytes land in the existing `ForensicStore` (parent §10.3 names exactly this store for
"files preserved by … the quarantine action"; content-addressed dedup is free).

Read discipline reuses `evidence/capture.py`'s hardening (O_NOFOLLOW | O_NONBLOCK,
fstat S_ISREG, absolute-path + `..` rejection, the `_DENY_PREFIXES` deny-list —
quarantining `/etc/shadow` or anything under /proc bricks the box) with TWO deliberate
differences from evidence capture:

1. **Refusal, never truncation.** `_MAX_QUARANTINE_BYTES` (256 MiB): an over-limit
   file is REFUSED with a typed error — a truncated quarantine cannot restore, and a
   quarantine that silently dropped bytes is worse than none.
2. **Errors are loud.** Evidence capture is best-effort (returns None); quarantine is
   user-initiated and every failure mode returns a distinct typed error
   (`QuarantineDenied` (deny-list), `QuarantineTooLarge`, `QuarantineNotRegular`,
   `QuarantineNotFound`, `QuarantineIOError`).

Order of operations (each step's failure leaves the earlier steps' state, never a
half-neutralized file):

1. `fstat` on the open fd → record mode/uid/gid/size.
2. `pacman -Qo <path>` (subprocess, 5 s timeout, non-fatal on error) → `pkg_owner`.
   A package-owned file is NOT refused — the user may genuinely want to isolate a
   trojaned binary — but the ownership is recorded and echoed in the response as a
   warning ("owned by <pkg>; reinstall with pacman -S <pkg> after restore/delete").
3. Read all bytes **from the already-open fd** (no second path lookup), sha256, `ForensicStore.put`.
4. INSERT the `quarantine` row (status `active`).
5. `os.unlink(path)` — only now, and via the original (validated) path. An unlink
   failure (e.g. immutable attr) marks nothing: the row exists, the blob exists, the
   file survives; the typed error says isolation FAILED and the copy is in the store.
   Recovery guidance in the message.
6. Audit row + (when case-linked) case timeline entry.

Not handled in v1, documented in the module docstring: a running process holding the
inode keeps it alive until exit (quarantine does not kill processes — parent §9.5's
`kill` is a separate action); directories and symlink targets are refused, not
recursed; the path may be re-created afterwards (FIM/persistence collectors are the
watch on that).

### 3.3 Restore

1. Load row (must be status `active`).
2. Read blob from store; **verify sha256 matches the row** (a store bit-flip must not
   restore silently wrong bytes).
3. **Refuse if `original_path` now exists** (something re-created it — restoring on
   top would destroy that evidence and possibly hand an attacker a race). The error
   names the conflict; the user moves it aside first. No `--force`.
4. Write: open parent with O_NOFOLLOW discipline, temp file 0600 in the same
   directory, write + fsync, `fchown(uid, gid)`, `fchmod(recorded mode)`,
   `os.rename` into place.
5. Row → status `restored`, `restored_at`. **Blob stays** — it is evidence that the
   file existed in that state; only delete removes bytes.
6. Audit + case timeline.

### 3.4 Delete

Removes the quarantine's claim on the bytes. The blob is unlinked ONLY when no other
reference holds it — the store is shared with the evidence collector:

- no `case_evidence` row with this sha, AND
- no other `quarantine` row with this sha whose status ≠ `deleted`.

Otherwise the row flips to `deleted` and the blob survives under its other claims.
Deletion runs under `EvidenceCollector.capture_lock` + re-check (the retention
engine's put()-vs-unlink race pattern, §retention concilium item 3). Audit + timeline.

### 3.5 Retention interaction

`prune_evidence` gains one more protection clause: a sha referenced by any
`quarantine` row with status `active` is NEVER pruned (mirrors the open-case
exemption). `restored`/`deleted` rows do not protect. One sentence in the retention
module docstring + a test.

## 4. IPC + CLI (PR1)

Four methods:

| method | mutates | polkit_action |
|---|---|---|
| `quarantine_file` | True | `org.inspectord.quarantine` |
| `list_quarantine` | False | — |
| `restore_quarantined` | True | `org.inspectord.quarantine-restore` |
| `delete_quarantined` | True | `org.inspectord.quarantine-delete` |

- Params: `quarantine_file {path, alert_id?, case_id?, note?}`;
  `restore_quarantined {quarantine_id}`; `delete_quarantined {quarantine_id}`.
- All three mutating methods: polkit-gated at the server (§2.2), rate-limited by a
  shared `SlidingWindowLimiter` (the hunt-methods pattern), audited on success AND on
  polkit denial; typed errors as `{ok: False, error, error_kind}`.
- `alert_id`/`case_id` are validated to exist when given (a quarantine claiming a
  nonexistent alert is a false audit trail).

CLI `inspectorctl quarantine`:

```
inspectorctl quarantine file <path> [--alert ID] [--case ID] [--note TEXT]
inspectorctl quarantine list
inspectorctl quarantine restore <id>
inspectorctl quarantine delete <id>
```

Terminal callers get the polkit prompt from their desktop agent (or `pkttyagent` in a
bare TTY). Output follows the hunt-CLI rules: loud irreversibility ("original removed;
restore with …"), pkg_owner warning echoed, escaped daemon strings, distinct exit
codes for denial vs error.

## 5. Web (PR2)

- `/quarantine` panel: table of rows (path, sha short, size, status, quarantined_at,
  pkg_owner warning, alert/case links), banner plumbing for action outcomes. Pure IPC
  client, autoescaped, entity links where they exist.
- **Quarantine buttons** on alert-detail (when the alert carries a `file.path`) and
  the file entity card: POST → `quarantine_file` → the polkit agent prompts on the
  desktop (the web server is a user-session process, so the session agent handles
  it); denial/timeout renders as the standard outcome banner. POST-303 pattern like
  the Run-now buttons.
- **No restore/delete in the web** (user decision): the risk-raising verbs stay
  CLI-only, like hunt save/delete.

## 6. Testing

- **Gate**: stat-parse (comm with spaces/parens), fake-runner authorize/deny/timeout/
  missing-binary, server-level enforcement (gated method with denying runner →
  handler NEVER invoked, denial audited), non-gated methods untouched. Root-only
  real-pkcheck test, non-interactive.
- **Core**: full quarantine round-trip on tmp files (mode/uid preserved where
  runnable as non-root: fchown to self only; root-only test for foreign uid);
  deny-list refusals; oversize refusal (no partial state); unlink-failure leaves
  file + blob + row consistent; restore occupied-path refusal; restore sha-mismatch
  refusal; delete blob-sharing matrix (case_evidence hold / second quarantine hold /
  sole claim); retention protection of active shas.
- **IPC/CLI/web**: param validation, alert/case existence check, rate limit, audit
  rows (success + denial), CLI output contract, web banner + escaping + button
  presence conditions.

## 7. Out of scope

Pending-actions framework (§9.5) and rule-proposed quarantines; polkit on
pre-existing methods; process kill / service stop actions; quarantining directories;
nftables blocks; ClamAV-style auto-quarantine; web restore/delete; recursive
directory isolation; xattr/ACL preservation (mode/uid/gid only in v1 — documented).
