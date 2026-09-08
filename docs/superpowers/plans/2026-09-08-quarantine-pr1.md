# Quarantine PR1 — polkit gate + core + IPC + CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Daemon-complete file quarantine: polkit-gated IPC (`quarantine_file`/`list_quarantine`/`restore_quarantined`/`delete_quarantined`), TOCTOU-hardened isolate/restore/delete, `isolating→active/failed` lifecycle with reconciliation, retention protection, CLI verbs.

**Spec:** `docs/superpowers/specs/2026-09-08-quarantine-design.md` (v2, concilium-folded). **The spec is the contract — read it in full first.** This plan sequences it and pins the code-level shapes; where they conflict, the spec wins and the conflict gets reported.

**Tech Stack:** Python 3.14, DuckDB, pkcheck subprocess, typer/rich, pytest.

**Branch:** `quarantine` (current; spec already committed).

**Gates** (unit + integration pytest markers, ruff check, ruff format --check, mypy — the five standard commands; run all after the last task, unit-marker after each task).

---

### Task 1: authz gate (`check_polkit`) + policy file

**Files:**
- Create: `inspectord/authz.py`, `packaging/polkit/org.inspectord.policy`
- Modify: `packaging/config.example.toml` (install recipe comment)
- Test: `tests/test_authz.py`

- [ ] **Step 1: Failing tests** — cover: `proc_start_time()` parse of a stat line with comm `"(a) b)"` (split at LAST `)`, field 22 counted after it); every outcome via fake runner: exit 0 → `authorized`; exit 1 + stderr containing `no agent` phrasing → `agent_missing`; stderr naming unknown action → `action_unknown`; `FileNotFoundError` from runner → `polkit_unavailable`; `subprocess.TimeoutExpired` → `timeout`; other nonzero → `denied`; argv assertion (action id, `pid,start`, `--allow-user-interaction`, `--detail path <target>` when a target is given); semaphore: second concurrent call gets `authz_busy` immediately (thread + event choreography, no sleeps).

- [ ] **Step 2: verify fail.**

- [ ] **Step 3: Implement** `inspectord/authz.py`:

```python
"""Polkit authorization gate (quarantine design §2).

Fail closed on every path: the ONLY outcome that authorizes is pkcheck
exiting 0. Subject identity (pid + start-time) is captured by the IPC server
at connection-accept time and passed in — never re-read here, because a
check-time /proc read would describe whatever process currently owns the pid.
"""

from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass

_PKCHECK_TIMEOUT_S = 60.0
#: One interactive prompt at a time; a second concurrent gated call is denied
#: immediately (`authz_busy`) — stacked auth dialogs are prompt-fatigue training.
_PROMPT_SEMAPHORE = threading.Semaphore(1)


@dataclass(frozen=True)
class PeerIdentity:
    pid: int
    uid: int
    start_time: int  # /proc/<pid>/stat field 22, snapshotted at accept


@dataclass(frozen=True)
class AuthzResult:
    outcome: str  # authorized|denied|agent_missing|action_unknown|polkit_unavailable|timeout|authz_busy|error
    detail: str = ""

    @property
    def authorized(self) -> bool:
        return self.outcome == "authorized"


def proc_start_time(pid: int) -> int | None:
    """Field 22 of /proc/<pid>/stat, or None if unreadable (peer gone)."""
    try:
        raw = open(f"/proc/{pid}/stat", "rb").read().decode("ascii", "replace")
    except OSError:
        return None
    # comm may contain spaces and parens: fields resume after the LAST ')'.
    tail = raw.rsplit(")", 1)[-1].split()
    try:
        return int(tail[19])  # field 22 overall; tail[0] is field 3 (state)
    except (IndexError, ValueError):
        return None


def check_polkit(
    action_id: str,
    peer: PeerIdentity,
    *,
    target: str | None = None,
    runner=subprocess.run,
    interactive: bool = True,
) -> AuthzResult:
    if not _PROMPT_SEMAPHORE.acquire(blocking=False):
        return AuthzResult("authz_busy")
    try:
        argv = ["pkcheck", "--action-id", action_id,
                "--process", f"{peer.pid},{peer.start_time}"]
        if interactive:
            argv.append("--allow-user-interaction")
        if target is not None:
            argv += ["--detail", "path", target]
        try:
            proc = runner(argv, capture_output=True, text=True, timeout=_PKCHECK_TIMEOUT_S)
        except FileNotFoundError:
            return AuthzResult("polkit_unavailable", "pkcheck is not installed")
        except subprocess.TimeoutExpired:
            return AuthzResult("timeout", "no answer to the authorization prompt in 60s")
        if proc.returncode == 0:
            return AuthzResult("authorized")
        stderr = proc.stderr or ""
        if "no agent" in stderr.lower() or "not authorized" in stderr.lower() and "agent" in stderr.lower():
            return AuthzResult("agent_missing", stderr.strip())
        if "not registered" in stderr.lower() or "no action with action id" in stderr.lower():
            return AuthzResult("action_unknown", stderr.strip())
        return AuthzResult("denied", stderr.strip())
    finally:
        _PROMPT_SEMAPHORE.release()
```

(Verify the exact pkcheck stderr phrasings by running `pkcheck --action-id org.nonexistent.test --process 1,0` and `pkcheck` against a made-up action on this box; adjust the string matches to what the installed polkit actually emits, and pin them in the tests. The plan's strings are hypotheses, the box is the oracle.)

Policy file `packaging/polkit/org.inspectord.policy` — XML with the three `<action id=...>` blocks; **all three defaults pinned per spec §2.4** (`allow_any=no`, `allow_inactive=no`, `allow_active=auth_self_keep` for quarantine, `auth_self` for restore/delete). Message/description per action name the operation. Config example gains the `sudo cp` recipe comment.

- [ ] **Step 4: verify pass. Step 5: Commit** — `feat(authz): polkit gate — pkcheck subject checks with a full outcome taxonomy`

---

### Task 2: server-level gating (pipeline order + peer snapshot + -32001)

**Files:**
- Modify: `inspectord/ipc_server.py`
- Test: `tests/test_ipc_server.py` (extend the existing server tests in place)

- [ ] **Step 1: Failing tests** — a gated `Method` with a fake gate: denial → handler NOT invoked, JSON-RPC error code **-32001**, message starts with the outcome token; rate-limited call (fake limiter) → refused BEFORE the gate runs (gate never called), -32001 with `rate_limited`; authorized → handler runs; ungated methods bypass both; peer snapshot: the `PeerIdentity` passed to the gate carries the accept-time start_time (monkeypatch `proc_start_time` to a counter — assert value captured once at connect, not per call); `proc_start_time` returning None at accept → gated calls denied `peer_gone`; audit callable invoked on every non-authorized outcome with `{action_id, peer_pid, peer_uid, reason}`.

- [ ] **Step 2: verify fail.**

- [ ] **Step 3: Implement** in `ipc_server.py`:
  - `Method` gains `polkit_action: str | None = None` and `limiter: object | None = None` (the `SlidingWindowLimiter` protocol: `.check() -> tuple[bool, bool]`).
  - `IpcServer.__init__` gains `authz_check: Callable[[str, PeerIdentity, str | None], AuthzResult] | None = None` and `audit: Callable[..., object] | None = None` (both None = gated methods all fail closed with `polkit_unavailable`).
  - `_handle`: after the existing `_peer_uid` check, snapshot `PeerIdentity(pid, uid, proc_start_time(pid))` ONCE (extend `_peer_uid` to return the full struct-unpacked triple); `start_time is None` → mark identity as dead (`peer_gone`). Pass the identity into `_dispatch`.
  - `_dispatch` pipeline for `method.polkit_action is not None`: limiter first (refusal → -32001 `rate_limited`, audit per limiter's first-rejection flag), then `authz_check(action, peer, target=None)` (target plumbing arrives in Task 7 via a `polkit_target` param extractor — for now None), non-authorized → -32001 `<outcome>: <client message>` + audit. Client messages per spec §2.2 (actionable strings for `agent_missing` / `action_unknown`).

- [ ] **Step 4: verify pass (full unit marker — existing IPC tests must hold). Step 5: Commit** — `feat(ipc): server-level polkit gating — accept-time peer identity, limiter-before-prompt, -32001 channel`

---

### Task 3: migration 0014 + `ForensicStore.put_stream`

**Files:**
- Create: `inspectord/storage/migrations_data/0014_quarantine.sql`
- Modify: `inspectord/evidence/store.py`
- Test: `tests/test_quarantine_migration.py`, `tests/evidence/test_store.py` (extend)

- [ ] **Step 1: Failing tests** — migration idempotence (0013-test pattern: force re-apply); table columns present. `put_stream`: content lands identical to `put` for the same bytes (same sha, same path, 0600); dedup (existing blob → returns sha, no rewrite); over-cap fd → raises the typed size error AND the tmp file is gone AND no dest created; memory: stream a ~64 MiB file and assert peak RSS delta stays far under file size ×2 (use `resource.getrusage` before/after; generous bound, e.g. < 32 MiB delta, tmpfs-backed tmp_path).

- [ ] **Step 2: verify fail. Step 3: Implement** — 0014 SQL from spec §3.1 verbatim (`CREATE TABLE IF NOT EXISTS quarantine (...)`). `put_stream(self, fd: int, *, max_bytes: int) -> tuple[str, int]` (sha, size): chunked `os.read(fd, 1 MiB)` loop, incremental `hashlib.sha256`, write to the same O_EXCL tmp-name scheme as `put`, `bytes_read > max_bytes` → unlink tmp + raise `BlobTooLarge` (new exception in the store module); fsync; dedup check happens at rename time (`dest.exists()` → unlink tmp, return); `os.replace` otherwise. Keep `put` untouched.

- [ ] **Step 4: verify pass. Step 5: Commit** — `feat(storage): quarantine table (0014) + streaming forensic-store writes`

---

### Task 4: quarantine core — isolate

**Files:**
- Create: `inspectord/quarantine/__init__.py`, `inspectord/quarantine/errors.py`, `inspectord/quarantine/paths.py`, `inspectord/quarantine/ops.py`
- Test: `tests/quarantine/test_isolate.py` (+ `__init__.py`)

- [ ] **Step 1: Failing tests** — the spec §6 core list, isolate half:
  - happy path round-trip on a tmp file: blob in store, row `active`, original gone, mode/uid/gid/size recorded, audit row written;
  - **parent-symlink swap between open and unlink** → `QuarantineSwapped`, file untouched, row `failed` (harness: monkeypatch the `pacman -Qo` step to perform the swap — the deliberately-injectable seam);
  - inode swap (replace file during capture) → same;
  - deny-list matrix: `/proc/...`, state dir, store blob path, `/usr/share/polkit-1/...` → `QuarantineDenied`, nothing written, refusal AUDITED;
  - oversize → `QuarantineTooLarge`, no row, no blob;
  - non-regular (fifo, symlink final component, directory) → typed refusals;
  - unlink failure (monkeypatch `os.unlink` at the dirfd call to raise EPERM) → row `failed`, blob + file both present, error message names the store copy;
  - running-exe scan: `shutil.copy('/usr/bin/sleep', p)`; `Popen([str(p), '30'])`, quarantine it, assert its PID is reported; kill in teardown;
  - `pacman -Qqo` parsing: fake runner exit 0 + name → recorded; exit 1 → NULL; timeout → NULL.

- [ ] **Step 2: verify fail. Step 3: Implement**
  - `errors.py`: the spec §3.2 exception set, each carrying a stable `error_kind` string.
  - `paths.py`: `open_parent_dirfd(path) -> int` — component-wise walk from `/` using `os.open(component, O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC, dir_fd=prev)` (CPython exposes no openat2; the component walk IS the mechanism, say so in the docstring); `quarantine_deny(path_resolved) -> bool` building the superset deny-list from a `QuarantinePaths` config dataclass (state dir, socket dir, config path, `/usr/share/polkit-1`, plus `capture.py`'s `_DENY_PREFIXES` imported — promote that tuple to a public name in capture.py).
  - `ops.py` `isolate(db, store, lock, *, path, actor, alert_id=None, case_id=None, note=None, qo_runner=subprocess.run) -> IsolateResult` implementing spec §3.2's numbered order exactly: dirfd + `os.open(basename, O_NOFOLLOW|O_RDONLY|O_NONBLOCK|O_CLOEXEC, dir_fd=dirfd)`, fstat, deny-list on `os.path.realpath` BEFORE open + dev/ino store-collision check after hash; `LC_ALL=C pacman -Qqo` via `qo_runner`; `put_stream` + INSERT `isolating` under `lock`; `fstatat`-match then `os.unlink(basename, dir_fd=dirfd)`; status flip guarded UPDATE; `/proc/*/exe` scan by `os.stat(f"/proc/{pid}/exe")` dev/ino compare (PermissionError/ENOENT → skip pid); audit + timeline. Response dataclass carries `quarantine_id, sha256, pkg_owner, running_pids, warnings`.

- [ ] **Step 4: verify pass. Step 5: Commit** — `feat(quarantine): isolate — dirfd-disciplined capture, deny-list, lifecycle, running-exe scan`

---

### Task 5: restore + delete

**Files:**
- Modify: `inspectord/quarantine/ops.py`, `errors.py`
- Test: `tests/quarantine/test_restore_delete.py`

- [ ] **Step 1: Failing tests** — spec §6 restore/delete list: guarded CAS (`restore` of non-active row → typed error; two concurrent restores → one wins, loser gets not-active); occupied path via link-EEXIST (file re-created after quarantine → typed error, existing file untouched); parent-missing → `QuarantineRestoreNoParent`; blob-missing → `QuarantineBlobMissing`, row back to `active`; sha-mismatch (corrupt the blob) → typed error, row back to `active`; parent-symlink swap on restore → refused; mode/uid/gid restored (uid/gid = own, non-root runnable; mode incl. a 0o4000 bit → restored AND `setuid_warning` flag set in the result); happy round-trip content-identical; delete matrix: sole claim → blob gone; case_evidence holds sha → blob stays; second active quarantine holds sha → blob stays; row `deleted` in all three; delete under lock (assert lock held via a recording fake).

- [ ] **Step 2: verify fail. Step 3: Implement** per spec §3.3/§3.4 exactly: `restore(db, store, *, quarantine_id, actor)` — CAS to `restoring`; blob read + sha verify; deny-list re-validation; `open_parent_dirfd`; tmp 0600 write+fsync, fchown/fchmod on the open tmp fd; commit `os.link(tmp, dst, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)` → EEXIST → typed occupied error; unlink tmp; CAS `restoring→restored`. Any failure path CASes back to `active`. `delete(db, store, lock, *, quarantine_id, actor)` per §3.4.

- [ ] **Step 4: verify pass. Step 5: Commit** — `feat(quarantine): restore + delete — CAS lifecycle, no-replace commit, shared-blob accounting`

---

### Task 6: retention protection + reconciliation/list

**Files:**
- Modify: `inspectord/retention/engine.py` (`prune_evidence`), `inspectord/quarantine/ops.py` (list + flags)
- Test: `tests/retention/` evidence tests (extend), `tests/quarantine/test_list.py`

- [ ] **Step 1: Failing tests** — retention: sha held by `active` quarantine survives a prune that would otherwise take it; `restored`/`deleted` rows do NOT protect. List: bounded (limit default 200, echoed), ordered `quarantined_at DESC`; health flags: `active` row + file recreated at path → `file_still_present`; `isolating` row → `isolation_incomplete`; non-deleted row + blob removed → `blob_missing`.

- [ ] **Step 2: verify fail. Step 3: Implement** — one protection clause in `prune_evidence`'s reference query (statuses `isolating/active/failed/restoring`) + module-docstring sentence; `list_quarantine(db, store, *, limit)` computing flags (existence checks: `os.path.lexists(original_path)`, `store.path_for(sha).exists()`); startup log of `isolating` rows (a single `log.warning` per row from a small helper called at supervisor start — keep it minimal).

- [ ] **Step 4: verify pass. Step 5: Commit** — `feat(quarantine): retention protection for held blobs + reconciliation flags in list`

---

### Task 7: IPC handlers + registration

**Files:**
- Create: `inspectord/quarantine/ipc_handlers.py`
- Modify: `inspectord/__main__.py`, `inspectord/ipc_server.py` (only to finish the `polkit_target` extractor seam from Task 2)
- Test: `tests/quarantine/test_ipc_handlers.py`

- [ ] **Step 1: Failing tests** — handler-level (call handlers directly; gate is server-side and already tested): param validation (path required/absolute for quarantine_file; unknown quarantine_id; alert_id/case_id existence checks → typed request errors); success shapes `{ok, quarantine_id, sha256, pkg_owner, running_pids, warnings}`; list shape with flags + echoed limit; every mutating success and refusal audited with actor `uid:pid` (handlers receive the peer identity — Task 2's dispatch passes it to handlers of gated methods via a reserved server-injected param; assert it lands in audit rows). Registration test: the four `Method` entries exist with the right `polkit_action`s and two distinct limiters (quarantine vs restore+delete per spec §4).

- [ ] **Step 2: verify fail. Step 3: Implement** — handlers mirroring `hunt/ipc_handlers.py` conventions (`_failure`, schema_version, error-kind map from `quarantine/errors.py`); `__main__._ipc_methods` gains the four methods, wires `authz_check=check_polkit`, `audit=` partial of `append_audit`, two `SlidingWindowLimiter`s, `EvidenceCollector.capture_lock` + `ForensicStore` from the supervisor (mirror how evidence handlers get their deps); `--detail path` target: `Method` gains `polkit_target: Callable[[dict], str | None] | None`, bound at registration to `lambda params: params.get("path")` for `quarantine_file`.

- [ ] **Step 4: verify pass. Step 5: Commit** — `feat(quarantine): IPC — polkit-gated quarantine/restore/delete/list methods`

---

### Task 8: CLI

**Files:**
- Create: `inspectorctl/cli/quarantine.py`
- Modify: `inspectorctl/cli/app.py`
- Test: `tests/test_cli_quarantine.py`

- [ ] **Step 1: Failing tests** (mirror `test_cli_scanners.py`'s real-IpcServer harness) — verb→params mapping for all four; exit codes 0/1/**3** (denial: fake server answering -32001 → exit 3, message shown); success output contains restore hint + pkg warning + running-PID caution when present; setuid warning on restore; escaping; `pkttyagent` spawn: monkeypatch `subprocess.Popen` + `sys.stdin.isatty`→True and assert the agent is spawned around a mutating call and terminated after (and NOT spawned for `list` or when isatty False).

- [ ] **Step 2: verify fail. Step 3: Implement** — typer app per spec §4; `IpcError` carrying code -32001 mapped to exit 3 (check `IpcClient`'s error surface: if it hides the code, extend `IpcError` with a `code` attribute — smallest change wins); pkttyagent context manager (`Popen(["pkttyagent", "--process", str(os.getpid()), "--fallback"])`, terminate in finally; only when isatty and the binary exists). Register in `app.py`.

- [ ] **Step 4: verify pass. Step 5: Commit** — `feat(cli): inspectorctl quarantine file/list/restore/delete`

---

### Task 9: full gates, push, PR

- [ ] All five gates green. **Also run the root-only tests** if sudo pytest is available (`sudo .venv/bin/python -m pytest tests/test_authz.py -k real` — skip cleanly if the sudoers rule is gone).
- [ ] Push `quarantine`, `gh pr create --title "feat(quarantine): polkit gate + file quarantine (PR1)"` (body: spec pointer, concilium note, the human step — policy file install — called out prominently). Monitor CI, squash-merge, sync main.

---

## Executor self-review checklist
- No code path re-traverses a user-supplied path after its fd/dirfd is open (isolate unlink, restore write both via dirfd).
- Every refusal/denial of a mutating verb writes an audit row with peer uid:pid.
- Status transitions are all guarded UPDATEs; no read-then-act.
- The gate pipeline order in the server is validate → limit → polkit → handler, with tests proving limiter-before-pkcheck.
- pkcheck stderr matches verified against THIS box's polkit, not assumed.
