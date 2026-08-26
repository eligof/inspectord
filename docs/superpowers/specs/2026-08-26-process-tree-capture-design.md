# Process-tree/env capture — design

Date: 2026-08-26 (v2 — concilium 3-lens review, unanimous REVISE: 2 BLOCKING +
5 MAJOR + 10 MINOR findings all folded)
Parent: evidence-collector spec (`2026-06-22-evidence-collector-design.md`) deferred
slice; parent design §13.1 item 2.
Status: **autonomously drafted, NOT human-reviewed** (concilium-reviewed in-session).
The redaction policy (§4) is the decision most worth a human look.

## 1. Goal

On every auto-captured high/critical alert whose event carries a `process.pid`,
snapshot the **process ancestry chain** (implicated process → PID 1 or kernel root):
identity, exe path + sha256, command line (scrubbed), cwd, uid/euid, and (redacted)
environment — so "who spawned this?" survives the processes exiting.

## 2. Scope

### In (v1)

- `inspectord/evidence/proctree.py`: `capture_process_tree(pid, *, proc_root="/proc")
  -> dict | None`, pure/bounded/best-effort, plus the shared scrub helpers.
- Env redaction + cmdline scrub + known-prefix value backstop (§4) — one coherent
  secret policy for both surfaces.
- Collector step + `process_tree` evidence kind; `read_evidence_blob` JSON-kind
  addition; case-detail Info fallback (`meta.nodes`); export-narrative note.

### Out (deliberate)

| Cut | Why |
| --- | --- |
| Children / descendant tree | Ancestry answers the spawn-chain question; descendants live in `process_state` history. |
| Open fds / mapped libraries (parent §13.1 lists them) | Breadth explosion, low signal per byte; revisit with quarantine. |
| Raw (unredacted) env or cmdline | Both are secret-bearing; §4 policy applies to both. Raw capture is a non-goal, not a knob. |
| Pid-reuse hardening (starttime checks, openat pinning) | Capture runs ms after the alert; a raced node yields wrong-but-labeled data. Accepted. |
| Retro-capture for historical alerts | Live processes only. |

Accepted disclosure, stated for the human reviewer: variable NAMES are kept (a shared
case ZIP thereby enumerates which services the user holds credentials for, and
path-valued vars like `KUBECONFIG`/`GNUPGHOME` map where key material lives). That is
deliberate — names are forensic signal — and the ZIP narrative gains a warning line
so the exporter decides with eyes open.

## 3. Snapshot shape and walk contract

Single JSON blob, kind `process_tree` (VARCHAR kind column — no migration; 0007
comment updated):

```json
{
  "captured_at": "<iso-utc>", "root_pid": 4242, "truncated": false,
  "nodes": [{
    "pid": 4242, "ppid": 4100, "comm": "curl",
    "exe": "/usr/bin/curl", "exe_sha256": "ab...", "cwd": "/home/user",
    "cmdline": "curl -H 'Authorization: <redacted>' https://x",
    "uid": 1000, "euid": 1000,
    "env": {"PATH": "/usr/bin", "API_TOKEN": "<redacted>"},
    "env_bytes": 1832, "env_truncated": false, "env_redacted": 1,
    "errors": []
  }]
}
```

**Walk contract:**
- `/proc/<root_pid>/stat` unreadable or absent at start → return **None**: no blob,
  no `case_evidence` row. An empty `nodes` list is never emitted.
- Follow `ppid` from `/proc/<pid>/stat` (parse after the LAST `)` — comm may contain
  spaces/parens). Terminate with `truncated: false` at pid 1 (inclusive) **or when
  ppid is 0** (kernel-spawned chains: usermode helpers have ppid 2 → kthreadd →
  ppid 0; a complete kernel chain is not "truncated").
- `truncated: true` only for: depth cap (32) reached, or an ANCESTOR vanished
  mid-walk (prior nodes kept).
- Per-field reads individually guarded; failures append to the node's `errors`, the
  node is kept.
- `exe_sha256`: sha256 of `/proc/<pid>/exe` contents (readable even for deleted
  binaries — the whole point), capped at the store's `_MAX_FILE_BYTES`; over-cap or
  unreadable → field omitted + error entry. (Parent §13.1 promises hashes; v1
  delivers them.)
- `uid`/`euid`: parsed from `/proc/<pid>/status` `Uid:` line (real + effective — the
  setuid-escalation signal).
- Env read: cap + 1 bytes; more available → `env_truncated: true`; `env_bytes` =
  bytes read. Empty environ (zombies, kthreads) → `env: {}`, NO error. Split on NUL,
  discard empty fragments, skip fragments without `=` (counted in errors); when the
  read hit the cap, drop the final non-NUL-terminated fragment. "Malformed → env
  omitted" applies only to non-empty content yielding zero parseable entries.

## 4. Secret policy (env AND cmdline — one philosophy)

All rules are module constants in `proctree.py`, reviewable at a glance.

1. **Name-based env redaction** — value → `<redacted>` (`<redacted:empty>` for empty;
   NO length leak) when the variable NAME case-insensitively contains any of:
   `TOKEN, SECRET, PASS, _PWD, API_KEY, APIKEY, PRIVATE, CREDENTIAL, AUTH, SESSION,
   COOKIE, DSN, ACCESS_KEY, CONNECTION_STRING, BEARER, WEBHOOK`.
   (`PASS` subsumes PASSWORD/PASSWD/PASSPHRASE/SSHPASS/VAULT_PASS; `_PWD` catches
   MYSQL_PWD without hitting PWD/OLDPWD.)
2. **Exact-name exemptions** (checked FIRST — desktop plumbing the investigator needs
   raw): `SSH_AUTH_SOCK, XAUTHORITY, DBUS_SESSION_BUS_ADDRESS, XDG_SESSION_ID,
   XDG_SESSION_TYPE, XDG_SESSION_CLASS, XDG_SESSION_DESKTOP, SESSION_MANAGER`.
3. **URL-credential scrub** on every KEPT value and on cmdline: a substring parsing as
   `scheme://user:password@rest` keeps scheme/user/host, replaces only the password
   component with `<redacted>` (where it was exfiltrating to is signal; the password
   is not).
4. **Known-prefix backstop** on every KEPT value and on cmdline — unambiguous secret
   formats scrubbed regardless of name: `AKIA[0-9A-Z]{16}`,
   `ghp_|gho_|ghs_|github_pat_`, `glpat-`, `sk-ant-`, `sk_live_|rk_live_`,
   `xox[bpca]-`, `AIza[0-9A-Za-z_-]{35}`, `-----BEGIN[A-Z ]*PRIVATE KEY-----`, JWT
   shape (`eyJ` + two dot-separated base64url segments). Matched spans →
   `<redacted>`.
5. **cmdline scrub** (mirrors the env philosophy): redact the value after
   `Authorization:`/`Bearer`, `-u`/`--user` colon-pairs, `--password=X` /
   `password=X`, the argument following `sshpass -p` and `mysql -p<glued>`, URL
   userinfo passwords (rule 3), and `NAME=value` prefixes whose NAME matches rule 1.
   Everything else verbatim.

`env_redacted` counts redacted variables. Rationale unchanged: predictable, auditable
list-based matching over entropy heuristics; the backstop covers unambiguous formats
only, so false positives on benign values are effectively nil.

## 5. Collector integration

New step in `EvidenceCollector._capture` between the event bundle and implicated
files: if the event's `process.pid` parses to int, `capture_process_tree(pid)`;
non-None → `store.put(json.dumps(snapshot).encode())` + `_insert(db, case_id,
"process_tree", sha, "", {"root_pid": pid, "nodes": n, "truncated": t, "alert_id":
aid})`, and a `tree_ok` flag feeds the existing timeline summary ("process tree
(N nodes)"). Own try/except; never blocks later steps. Bounded by proctree's own
depth/size caps plus the collector lock (the file-capture deadline starts later and
does not cover this step — stated to match the code). No config knob; rides the
high/critical trigger.

Adjacent one-liners in this PR: `read_evidence_blob`'s JSON-kind tuple gains
`"process_tree"` (downloads as `.json`, not `.bin`); `case_detail.html` Info fallback
gains `meta.nodes`; the ZIP narrative Notes mention that process_tree evidence
contains redacted-but-structured environment data.

## 6. Testing

TDD, fake `/proc` under tmp_path. Walk: chain to pid 1; ppid-0 kernel chain →
`truncated: false`; hostile comm `)(  ) x`; depth cap; vanished ancestor (prior nodes
kept); dead root → None; zombie (empty environ → `env: {}`, no error); uid/euid from
status; exe_sha256 correct + over-cap omitted. Env: NUL parse, cap+1/env_truncated,
trailing-fragment drop, malformed-only content omitted. Redaction: every rule-1
pattern + case-insensitivity; each rule-2 exemption stays raw; URL scrub keeps
scheme/user/host; every rule-4 prefix hit; cmdline scrub cases (Authorization header,
--password=, sshpass -p, NAME=value prefix, URL userinfo) + benign cmdline verbatim;
`<redacted>` carries no length. Collector: end-to-end row + parseable blob with
redaction verified through the store; no-pid event → no row; proctree raising → other
captures land; timeline mentions the tree. Export: process_tree downloads as JSON.
Web: Info cell shows node count.

## 7. Delivery

Single PR: `proctree.py` + collector step + export/web one-liners + tests + 0007
comment.
