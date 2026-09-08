# File quarantine + the polkit gate

- **Status**: v2 — concilium-reviewed (3-lens Workflow: unanimous REVISE, 4 BLOCKING +
  9 MAJOR + 12 MINOR; all folded below). User-brainstormed 2026-09-08; not yet
  human-reviewed in written form.
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
(daemon-complete). **PR2** = web panel + quarantine button — **gated on an empirical
polkit-session prototype (§5.1)**.

## 2. The polkit gate (PR1)

### 2.1 Subject identity — captured at accept, verified at check

SO_PEERCRED is read per-connection today (uid only). The server now snapshots
**(pid, uid, start-time)** immediately after `getsockopt`, before reading any request
bytes — start-time from field 22 of `/proc/<pid>/stat`, parsed from AFTER the last
`)` (comm can contain spaces and parens). Snapshotting at accept is load-bearing:
the peer provably lives at that instant (it holds the connection open); a check-time
`/proc` read would faithfully describe whatever process *currently* owns the pid and
re-bind the authorization to a pid-reuse squatter. `check_polkit` receives the stored
pair verbatim. A `/proc` read failure at accept (ENOENT/ESRCH/parse) marks the
connection's gated calls as denied with kind `peer_gone`.

Honest residual (single-user threat model, accepted): pid+start-time closes the
window between the daemon's snapshot and polkitd's evaluation; a same-uid process was
always able to open its own connection and be its own (legitimate) subject.

### 2.2 Mechanism

`inspectord/authz.py`:

```python
def check_polkit(action_id: str, peer: PeerIdentity, *, runner=subprocess.run) -> AuthzResult
```

- `pkcheck --action-id <id> --process <pid>,<start> --allow-user-interaction
  --detail path <target>` (the detail makes the agent prompt say WHICH file, so two
  stacked prompts are distinguishable), `subprocess.run` with a **60 s timeout**
  (pkcheck blocks while the agent prompts; timeout/kill → deny).
- **Outcome taxonomy, mapped from exit code + stderr and each one tested with a fake
  runner**: `authorized` / `denied` / `agent_missing` ("Authorization requires
  authentication but no agent is available" — the SSH/headless case, instant deny,
  NOT a hang) / `action_unknown` (policy file not installed) / `polkit_unavailable`
  (pkcheck binary missing) / `timeout` / `error`. Everything but `authorized` fails
  closed; each gets a distinct, actionable client message (`agent_missing` tells the
  user "no polkit agent in this session — use a desktop terminal, or run
  pkttyagent"; `action_unknown` names the policy install command).
- **One prompt at a time**: a `threading.Semaphore(1)` bounds outstanding pkcheck
  calls; a second concurrent gated call gets an immediate typed `authz_busy` denial
  (audited). Stacked auth dialogs are prompt-fatigue training — the thing an auth
  gate must never create.
- Injectable `runner` so CI never needs polkit. One root-only manual test (skipif
  non-root or pkcheck missing) exercises the real binary WITHOUT
  `--allow-user-interaction` so it can never hang a terminal.

### 2.3 Server-level gating and pipeline order

`Method` gains `polkit_action: str | None = None` and an optional shared limiter
reference. For gated methods the server pipeline is, in ORDER:

1. request parse / param shape,
2. **rate limit** (shared `SlidingWindowLimiter` — BEFORE pkcheck, so a request
   flood can never spawn N concurrent 60 s pkcheck subprocesses or stack prompts;
   rate-limited requests are refused without touching polkit and audited per the
   limiter's first-rejection contract),
3. **polkit** (§2.2, under the semaphore),
4. handler.

Denials are surfaced with a dedicated JSON-RPC error code **-32001** whose message
carries the outcome token — machine-distinguishable from -32000 internal errors, so
the CLI's distinct exit codes need no string matching. Every non-authorized outcome
is audited: `action="polkit_denied"`, target = method name, details =
`{action_id, peer_pid, peer_uid, reason, path?}`.

Existing methods are NOT retrofitted in this spec (scope discipline; the gate makes
that a one-line change later).

### 2.4 Policy file

`packaging/polkit/org.inspectord.policy` — three actions, **all three defaults
pinned explicitly** (an unpinned `allow_any`/`allow_inactive` is an implicit value
we'd be trusting blind):

| action id | allow_any | allow_inactive | allow_active |
|---|---|---|---|
| `org.inspectord.quarantine` | no | no | `auth_self_keep` |
| `org.inspectord.quarantine-restore` | no | no | **`auth_self`** |
| `org.inspectord.quarantine-delete` | no | no | **`auth_self`** |

Restore and delete prompt **every time** (`auth_self`): they are rare, deliberate,
CLI-only verbs, and `*_keep`'s session-scoped grant would make them promptless for
ANY same-uid process during the keep window — the exact window malware would use to
`delete_quarantined` the evidence after the user's one legitimate click. Quarantine
keeps `auth_self_keep` for multi-file UX; that keep-window residual is ACCEPTED and
stated here: after one authorized quarantine, same-uid processes can quarantine
without a prompt for ~5 minutes (containment-only; restore/delete stay prompted, and
the §3.2 deny-list bounds the blast radius).

Install is a documented human step: `sudo cp packaging/polkit/org.inspectord.policy
/usr/share/polkit-1/actions/`. Until installed: `action_unknown`, fail closed,
actionable message. `packaging/config.example.toml` gains the recipe.

## 3. Quarantine core (PR1)

`inspectord/quarantine/` (mirrors `inspectord/cases/` shape). House ids = **uuid7**
(`inspectord/ids.py`).

### 3.1 Table (migration 0014, additive, idempotent)

```sql
CREATE TABLE IF NOT EXISTS quarantine (
    quarantine_id  VARCHAR PRIMARY KEY,   -- uuid7
    sha256         VARCHAR NOT NULL,
    original_path  VARCHAR NOT NULL,
    file_mode      INTEGER NOT NULL,      -- st_mode & 0o7777 (setuid bits included — see §3.3)
    file_uid       INTEGER NOT NULL,
    file_gid       INTEGER NOT NULL,
    size_bytes     BIGINT  NOT NULL,      -- bytes actually stored (not fstat's answer)
    pkg_owner      VARCHAR,
    note           VARCHAR,
    alert_id       VARCHAR,
    case_id        VARCHAR,
    status         VARCHAR NOT NULL,      -- isolating | active | failed | restored | deleted
    quarantined_at TIMESTAMP NOT NULL,    -- naive UTC
    restored_at    TIMESTAMP,
    deleted_at     TIMESTAMP
);
```

**`active` must earn its meaning** (concilium ops-BLOCKING): the row is INSERTed as
`isolating` and flips to `active` only after the unlink succeeds. Unlink failure →
`failed` (blob + row kept, loud typed error). A crash between INSERT and unlink
leaves `isolating`, which reconciliation surfaces (§3.6) — the panel can never show
"contained" for a file still sitting on disk.

### 3.2 Quarantine (isolate)

Bytes land in the existing `ForensicStore` (parent §10.3). All fd/path discipline
below exists because the target is, by threat model, a file in an
**attacker-writable directory**.

**Path resolution — no re-traversal, ever.** The parent directory is opened to a
dirfd via symlink-free resolution (`os.open(..., O_PATH)` walk component-wise with
`O_NOFOLLOW | O_DIRECTORY`, or `openat2(RESOLVE_NO_SYMLINKS)` where the plan finds
it exposed); the file is opened `O_NOFOLLOW | O_RDONLY | O_NONBLOCK` *via that
dirfd*; every later step uses the fd or the dirfd, never the path string.

**Deny-list: quarantine gets its own, a superset of evidence capture's.** Capture's
list was scoped for *reads*; quarantine adds a root *unlink*, and the daemon's own
control plane must be non-negotiable (concilium: quarantining a forensic-store blob
would dedup in `put`, then unlink the blob itself — destroying case evidence while
reporting success; quarantining the policy file would brick the gate fail-closed =
self-lockout):

- everything in `evidence/capture.py`'s `_DENY_PREFIXES`, plus
- the configured state dir (`/var/lib/inspectord` — DB, audit chain, journal,
  forensic store), the runtime/socket dir, the daemon config path,
- `/usr/share/polkit-1`.

Belt-and-braces: after hashing, refuse if the captured (st_dev, st_ino) equals the
store destination's, or the resolved path lies under the store root.

**Streaming, refusal-not-truncation** (concilium: a 256 MiB slurp peaks ~2× in RAM
against the unit's `MemoryMax=500M` — the cap itself would OOM-kill the daemon
mid-operation): `ForensicStore.put_stream(fd, max_bytes)` reads chunked from the fd,
updates sha256 incrementally, writes to the store's O_EXCL tmp file, fsyncs, renames
to the sha path — O(chunk) memory. Byte count exceeding `_MAX_QUARANTINE_BYTES`
(256 MiB) → tmp unlinked, typed `QuarantineTooLarge`; a truncated quarantine cannot
restore, so refusal is the only honest cap. `size_bytes` = bytes streamed (a file
growing mid-read is caught by the cap or recorded as streamed; concurrent-writer
races go in the module docstring's not-handled list).

Order of operations:

1. Open parent dirfd + file fd as above; `fstat(fd)` → mode/uid/gid + (st_dev,
   st_ino); refuse non-regular.
2. `LC_ALL=C pacman -Qqo <path>` (5 s timeout; quiet form — stdout is exactly the
   package name, exit 0; ANY nonzero exit or empty stdout → `pkg_owner` NULL, no
   locale-dependent parsing). Package-owned is a recorded WARNING, not a refusal.
3. `put_stream` from the fd → sha.
4. INSERT row, status **`isolating`** (steps 3–4 run under
   `EvidenceCollector.capture_lock` — `prune_evidence` runs entirely under that
   lock and `put`'s existence-dedup would otherwise race a concurrent prune into
   unlinking the just-deduped blob; the lock is obtained from the supervisor-owned
   collector, plumbed explicitly).
5. Unlink **without re-traversal**: `fstatat(dirfd, basename, AT_SYMLINK_NOFOLLOW)`
   must equal step 1's (st_dev, st_ino) — a swapped file/parent means the thing at
   the path is NOT the thing we preserved → typed error, nothing unlinked, row →
   `failed`. Match → `os.unlink(basename, dir_fd=dirfd)`. Success → row `active`.
6. **Post-unlink running-process scan** (concilium: unlinking a *running* binary —
   the common malware case — leaves it executing from the deleted inode; success
   output claiming containment would be false): scan `/proc/*/exe` for step 1's
   dev:ino; matching PIDs+comms ride in the response, and EVERY success surface
   (CLI, banner, panel row) carries "processes already running from this file are
   NOT stopped" plus the live PID list when non-empty.
7. Audit row + case timeline when case-linked.

Typed errors: `QuarantineDenied` (deny-list), `QuarantineTooLarge`,
`QuarantineNotRegular`, `QuarantineNotFound`, `QuarantineSwapped` (dev/ino
mismatch), `QuarantineIsolationFailed` (unlink error; copy IS in the store —
message says so), `QuarantineIOError`. **Every refusal of a mutating verb is
audited** (`quarantine_refused` with path, peer uid+pid, error_kind) — an attempted
quarantine of `/etc/shadow` is itself high-signal. Success audit rows carry actor
`uid:pid` identity. Audit stays fail-open here as everywhere (one sentence in the
module: a dropped audit row must not abort a user-commanded containment; the
fail-open counter/alert from the audit spec covers systemic failure).

Not handled in v1 (module docstring AND §3.2-step-6 user surfaces where relevant):
processes holding the inode; directories/symlink targets (refused, not recursed);
path re-creation afterwards (FIM watches that); concurrent writers during
streaming; xattrs/ACLs/caps (mode/uid/gid only).

### 3.3 Restore

1. Guarded status transition FIRST (concilium: read-then-act let concurrent
   restore+delete both proceed): `UPDATE quarantine SET status='restoring' WHERE
   quarantine_id=? AND status='active'` — rowcount 0 → typed "not active" error
   before anything touches disk.
2. Read blob; verify sha256 against the row (`QuarantineBlobMissing` — names
   backup/store drift — and sha-mismatch are distinct typed errors). On failure the
   row flips back to `active`.
3. Resolve the parent dirfd with the SAME symlink-free walk as §3.2 (O_NOFOLLOW
   discipline on the final component alone is worthless — intermediate components
   are where the swap happens), and re-run the §3.2 deny-list validation on
   `original_path` at restore time. Parent directory missing →
   `QuarantineRestoreNoParent` with "recreate <dir> then retry" guidance (we do not
   recreate directories; we have no recorded metadata to do it faithfully).
4. Write via the dirfd: tmp file 0600 + write + fsync + `fchown(uid, gid)` +
   `fchmod(mode)` (that order), then **atomic no-replace commit**:
   `os.link(tmp, dest_at_dirfd)` → EEXIST = typed occupied-path error (the §3.2
   check-then-rename clobber race is closed by construction; something re-created
   the path and that is evidence) → unlink tmp. No `--force`.
5. Row → `restored` (guarded from `restoring`). Blob stays; bytes are removed only
   by delete or by normal evidence retention once no protecting reference remains
   (§3.5 — this sentence is the honest version of v1's "only delete removes
   bytes").
6. **Setuid/setgid warning**: a recorded mode carrying 0o6000 bits is restored
   verbatim but LOUDLY flagged in the CLI output and the audit row — restoring a
   quarantined setuid binary is the single most dangerous act this feature can
   perform.
7. Audit + case timeline.

### 3.4 Delete

1. Guarded transition `active|restored|failed → deleting` (rowcount-checked).
2. Under `EvidenceCollector.capture_lock`, blob unlinked ONLY when no
   `case_evidence` row and no other `quarantine` row with the sha in a non-`deleted`
   status (re-checked under the lock).
3. Row → `deleted`. Audit + timeline.

### 3.5 Retention interaction

`prune_evidence` protection clause: a sha referenced by any `quarantine` row in
status `isolating`, `active`, `failed` or `restoring` is never pruned. `restored`
and `deleted` do not protect (a restored quarantine's blob follows normal evidence
retention when its other references age out). Orphan blobs from a crash between
`put_stream` and INSERT are the same accepted leak the evidence collector already
documents. One paragraph + tests in the retention module.

### 3.6 Reconciliation — a row must never lie

`list_quarantine` (and therefore CLI list + panel) computes per-row health flags:

- `isolating`/`failed` rows, or an `active` row whose `original_path` still exists:
  flagged **"isolation incomplete — file still present"** with re-run guidance
  (covers unlink failure AND crash-between-INSERT-and-unlink).
- Non-`deleted` rows whose blob is missing from the store: flagged
  **"blob missing (backup drift?)"** — visible in the list, not first discovered at
  restore time.

At daemon startup, `isolating` rows are logged as incomplete (no auto-repair in v1
— re-running the quarantine is the user's call).

## 4. IPC + CLI (PR1)

| method | mutates | polkit_action |
|---|---|---|
| `quarantine_file` | True | `org.inspectord.quarantine` |
| `list_quarantine` | False | — |
| `restore_quarantined` | True | `org.inspectord.quarantine-restore` |
| `delete_quarantined` | True | `org.inspectord.quarantine-delete` |

- Pipeline order per §2.3 (validate → rate limit → polkit → handler).
- **Per-verb rate-limit windows** (concilium: one shared window lets malware spam
  denied quarantines to lock the user out of `restore` mid-incident — restore's
  availability is a security property): `quarantine_file` 12/min;
  `restore`+`delete` share a separate 12/min window.
- `alert_id`/`case_id` validated to exist when given.
- `list_quarantine` takes `limit` (default 200, max 1000, echoed hunt-style),
  ordered `quarantined_at DESC`, rows carrying the §3.6 health flags — one query
  powers CLI and panel.

CLI `inspectorctl quarantine file|list|restore|delete` as v1, plus:

- When stdin is a TTY and no desktop agent answers, the CLI itself spawns
  `pkttyagent --process <own-pid> --fallback` for the duration of a mutating call —
  nothing else ever spawns one, and an SSH session would otherwise get an instant
  unexplained deny. The `agent_missing` outcome still exists (non-TTY callers) with
  its actionable message.
- Distinct exit codes: 0 ok, 1 error, 3 authorization denied (from the -32001
  channel), 2 usage.
- Success output: loud irreversibility, restore hint, pkg_owner warning, running-PID
  list from §3.2 step 6, setuid warning on restore.

## 5. Web (PR2)

### 5.1 Gate: the session prototype comes first

Parent §16 has the web UI as a `systemd --user` service — and processes in the user
manager are typically in **no logind session**, so polkitd can classify the subject
as session-less: `allow_active` never matches and (with §2.4's pinned `no`
defaults) every web quarantine is denied. The spec written around "the session
agent handles it" would be fiction in that deployment (concilium ops-BLOCKING).

PR2's first task is therefore an **empirical prototype on this box**: run pkcheck
against (a) a session-launched `inspectorctl web` (desktop terminal) and (b) a
`systemd --user` unit, record both results in this spec. v1 then ships the honest
subset: the quarantine button is supported for **session-launched** web servers;
the user-unit deployment gets the distinct `agent_missing`/denial banner with
guidance ("launch the dashboard from a desktop terminal to enable quarantine"). No
polkit `.rules` auto-grant file in v1 — a promptless allow would silently delete
the only human check on the web path.

### 5.2 Panel + button

- `/quarantine` panel: bounded table (path, sha-short, size, status + §3.6 health
  flags, quarantined_at, pkg_owner warning, alert/case/entity links).
- Quarantine button on alert-detail (only when the alert carries a `file.path`) and
  the file entity card. **The form carries `alert_id` (or the entity key), never a
  free-form path** — the path is resolved server-side from what the daemon already
  asserted, so the web tier never becomes an arbitrary-path proxy.
- **CSRF posture, stated**: the existing Host-allowlist + Sec-Fetch/Origin
  middleware (installed app-wide) is the browser-side control for these POSTs; its
  residual — local same-uid processes can POST directly, and quarantine's
  `auth_self_keep` window removes the prompt backstop for them — is accepted and
  recorded here (same-uid processes could equally call the IPC socket directly).
- **UX of the blocking prompt**: the button's confirm step says "your system
  password prompt will appear on the desktop — this page waits for it (up to
  60 s)". The POST redirects to `/quarantine` (row highlighted), so an abandoned
  tab still leaves the authoritative outcome one visit away.
- **Own banner contract** (the Run-now `_BANNERS` vocabulary cannot say any of
  this and its 200-char detail cap would eat the pkg warning): fixed status tokens
  `quarantined | quarantined_pkg_owned | still_running | isolation_failed |
  polkit_denied | polkit_no_agent | authz_busy | rate_limited | error`, with
  quarantine_id / pkg name / PID count carried as separate capped query params and
  composed server-side into fixed messages.
- No restore/delete in the web (user decision).

## 6. Testing

- **Gate**: stat-parse (comm with spaces/parens); accept-time snapshot (pkcheck argv
  uses the accept-time start-time, not a fresh read); fake-runner map for EVERY
  §2.2 outcome; pipeline order (rate-limited call spawns NO pkcheck; denied call
  never reaches the handler; both audited); semaphore busy-denial; -32001 channel +
  CLI exit code 3. Root-only real-pkcheck test, non-interactive.
- **Core**: dirfd round-trip; **parent-symlink-swap between open and unlink →
  `QuarantineSwapped`, nothing unlinked** (the BLOCKING regression test); inode-swap
  variant; deny-list matrix incl. store-blob and policy-file refusals; oversize
  streaming refusal (tmp cleaned, no row); memory bound (near-cap file, RSS
  observed); `isolating→active/failed` transitions incl. simulated crash row;
  running-exe scan finds a live process post-unlink; restore: guarded CAS, occupied
  path via link-EEXIST, parent-missing, blob-missing, sha-mismatch,
  parent-symlink-swap, setuid flag; delete blob-sharing matrix under the lock;
  retention protection statuses; reconciliation flags in list.
- **IPC/CLI/web**: param validation, per-verb limiters, audit rows (success +
  refusal + denial, with uid:pid), CLI exit codes + pkttyagent spawn condition, web
  banner tokens + escaping + alert_id-not-path form + middleware rejection of
  cross-origin POST, prototype results recorded.

## 7. Out of scope

Pending-actions framework (§9.5) and rule-proposed quarantines; polkit on
pre-existing methods; process kill / service stop; quarantining directories;
nftables blocks; auto-quarantine; web restore/delete; xattr/ACL/capability
preservation; directory recreation on restore; polkit `.rules` auto-grants.
