# Evidence collector PR-A (foundation units) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. TDD throughout: write tests first, watch fail, implement, watch pass, run gates, commit per task.

**Goal:** Build the pure foundation units for the evidence collector — the content-addressed forensic store, the `case_evidence` migration, the symlink/TOCTOU-safe file-capture reader, the bounded network-state snapshot, and the `evidence_dir` config field. No collector, no supervisor wiring (that's PR-B).

**Architecture:** Four small, independently-testable units under a new `inspectord/evidence/` package, each with one responsibility. The safety-critical one is `capture.read_capture` (a root daemon reads attacker-influenced paths) — it must never hang, follow a symlink, exceed a size cap, or read a denied path.

**Tech Stack:** Python 3.14, `os`/`stat` low-level fds, DuckDB via `Database`, pytest. No new deps.

**Spec:** `docs/superpowers/specs/2026-06-22-evidence-collector-design.md` (concilium-reviewed). PR-A = spec §7 "PR-A": §3.1 store, §3.2 migration, §3.3 read_capture, §3.4 netsnapshot, the `evidence_dir` field. Read §11 (privacy) and the §1 threading note for why the safety matters.

**Gates (run from repo root, all must pass before done):**
- `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- `.venv/bin/ruff check inspectord tests` · `.venv/bin/ruff format --check inspectord tests`
- `.venv/bin/mypy inspectord`

**Branch:** `feat/evidence-store` (already checked out; spec + this plan ride along).

**Key codebase facts:**
- `StorageConfig` (`inspectord/config.py:23`) is `extra="forbid"` — adding a field requires editing the model; give `evidence_dir` a **default** so existing configs/tests don't break. `dev_config` (line 52) builds the dev paths under `<base>/var/`.
- The `/proc/net` hex decoders to reuse: `inspectord/workers/listening_socket_snapshotter/source.py` — `_decode_ipv4(hexip)`, `_decode_ipv6(hexip)`, `_decode_local_addr(hexaddr) -> (ip, port)`. `parse_listeners` filters to LISTEN and ignores the remote address — do NOT reuse it; write a new all-states parser using the `_decode_*` helpers.
- Migrations auto-discover by `\d{4}_*.sql` filename. Migration test pattern: `tests/test_cases_migration.py` (uses `PRAGMA table_info`, column name at index 1).

---

## File structure
- Create: `inspectord/evidence/__init__.py` (empty), `inspectord/evidence/store.py`, `inspectord/evidence/capture.py`, `inspectord/evidence/netsnapshot.py`
- Create: `inspectord/storage/migrations_data/0007_case_evidence.sql`
- Modify: `inspectord/config.py` (`evidence_dir` field + dev_config)
- Test: `tests/test_case_evidence_migration.py`, `tests/evidence/__init__.py` (empty), `tests/evidence/test_store.py`, `tests/evidence/test_capture.py`, `tests/evidence/test_netsnapshot.py`, plus a `tests/` config assertion

---

## Task 1: `evidence_dir` config field + migration `0007`

**Files:** Modify `inspectord/config.py`; Create `inspectord/storage/migrations_data/0007_case_evidence.sql`; Test `tests/test_case_evidence_migration.py`, and an assertion in the existing config test (search `tests/test_config*.py`).

- [ ] **Step 1: Write the failing migration test** `tests/test_case_evidence_migration.py` (mirror `tests/test_cases_migration.py`):
```python
from pathlib import Path
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def test_case_evidence_table_created(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    cols = {r[1] for r in db.query("PRAGMA table_info('case_evidence')").fetchall()}
    assert {"case_id", "kind", "sha256", "original_path", "captured_at", "meta_json"} <= cols
    db.close()
```
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Create the migration** `0007_case_evidence.sql`:
```sql
-- Evidence artifacts preserved by the evidence_collector (spec §3.2).
-- original_path is in the PK ('' for non-file kinds) so distinct paths with identical
-- content stay distinct rows. Content lives in the forensic store, keyed by sha256.
CREATE TABLE IF NOT EXISTS case_evidence (
    case_id       VARCHAR NOT NULL,
    kind          VARCHAR NOT NULL,   -- file | net_state | event_bundle
    sha256        VARCHAR NOT NULL,
    original_path VARCHAR NOT NULL DEFAULT '',
    captured_at   TIMESTAMP NOT NULL,
    meta_json     VARCHAR,
    PRIMARY KEY (case_id, kind, sha256, original_path)
);
CREATE INDEX IF NOT EXISTS case_evidence_case_idx ON case_evidence (case_id);
```
- [ ] **Step 4: Run the migration test — expect pass.**
- [ ] **Step 5: Add `evidence_dir` config field.** In `inspectord/config.py` `StorageConfig`, add:
```python
    evidence_dir: Path = Path("/var/lib/inspectord/evidence")
```
and in `dev_config`'s `"storage"` dict add `"evidence_dir": str(base / "var" / "evidence")`. Write a quick test (in the existing config test module, or a new `tests/test_evidence_dir_config.py`):
```python
from pathlib import Path
from inspectord.config import dev_config


def test_dev_config_evidence_dir(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    assert cfg.storage.evidence_dir == tmp_path / "var" / "evidence"
```
- [ ] **Step 6: Run the config test + full suite** (the new defaulted field must not break existing `StorageConfig` construction). Confirm green.
- [ ] **Step 7: Commit.** `feat(evidence): case_evidence migration + evidence_dir config`.

---

## Task 2: `ForensicStore` — content-addressed, atomically 0600

**Files:** Create `inspectord/evidence/__init__.py` (empty), `inspectord/evidence/store.py`; Test `tests/evidence/__init__.py` (empty), `tests/evidence/test_store.py`.

- [ ] **Step 1: Write failing tests** `tests/evidence/test_store.py`:
  - `put(b"hello")` returns the sha256 hex of `b"hello"`; the blob exists at `root/<sha[:2]>/<sha>` with the exact bytes.
  - `put` is idempotent + content-addressed: putting the same bytes twice returns the same sha and leaves one file; different bytes → different sha/path.
  - **perms**: after `put`, the blob file mode is `0o600` and the shard dir mode is `0o700` (mask with `0o777`). (This is the at-rest check.)
  - **no temp left behind**: after `put`, the shard dir contains exactly one entry (the blob), no `.tmp`.
  - `path_for(sha)` returns `root/<sha[:2]>/<sha>`.
```python
import hashlib, os, stat
from pathlib import Path
from inspectord.evidence.store import ForensicStore


def test_put_is_content_addressed_and_0600(tmp_path: Path) -> None:
    store = ForensicStore(tmp_path / "ev")
    sha = store.put(b"hello")
    assert sha == hashlib.sha256(b"hello").hexdigest()
    p = store.path_for(sha)
    assert p.read_bytes() == b"hello"
    assert p == (tmp_path / "ev") / sha[:2] / sha
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700
    assert list(p.parent.iterdir()) == [p]  # no .tmp leftover


def test_put_idempotent(tmp_path: Path) -> None:
    store = ForensicStore(tmp_path / "ev")
    assert store.put(b"x") == store.put(b"x")
    assert store.put(b"y") != store.put(b"x")
```
- [ ] **Step 2: Run — expect failure** (no module).
- [ ] **Step 3: Implement** `inspectord/evidence/store.py`:
```python
"""Content-addressed forensic blob store (spec §3.1).

Blobs are written atomically with mode 0600 (no world/group-readable window) into a
0700 sharded tree: <root>/<sha[:2]>/<sha>. Idempotent: identical content is stored once.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


class ForensicStore:
    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def path_for(self, sha: str) -> Path:
        return self._root / sha[:2] / sha

    def put(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        dest = self.path_for(sha)
        if dest.exists():
            return sha
        shard = dest.parent
        os.makedirs(shard, mode=0o700, exist_ok=True)
        # makedirs honors umask on intermediate dirs; force the shard mode explicitly.
        os.chmod(shard, 0o700)
        tmp = shard / f".tmp-{sha}-{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, dest)  # atomic; dest inherits tmp's 0600
        finally:
            if tmp.exists():
                tmp.unlink()
        return sha
```
  Note: `os.open(..., 0o600)` still applies umask, so the created mode is `0o600 & ~umask`. To GUARANTEE 0o600 regardless of umask, `os.fchmod(fd, 0o600)` right after open. Add that inside the `try` before writing:
```python
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                ...
```
  (The test asserting `0o600` will catch a umask-weakened mode, so this matters.)
- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit.** `feat(evidence): content-addressed forensic store (atomic 0600)`.

---

## Task 3: `read_capture` — symlink/TOCTOU-safe, non-blocking, bounded

The safety-critical unit. The path is attacker-influenced; the daemon is root.

**Files:** Create `inspectord/evidence/capture.py`; Test `tests/evidence/test_capture.py`.

- [ ] **Step 1: Write failing tests** `tests/evidence/test_capture.py`:
  - a normal regular file → returns its bytes.
  - a file larger than the cap → returns the first `_MAX_FILE_BYTES` bytes (pass a tiny cap via a module constant override or a small fixture; assert truncation).
  - **a FIFO returns None WITHOUT HANGING**: `os.mkfifo(p)` (no writer) → `read_capture(p)` returns None promptly (the test itself would hang if the impl blocks — that's the point).
  - **a symlink is refused** (`O_NOFOLLOW`): real file + `os.symlink` to it → `read_capture(link)` returns None.
  - a relative path → None; a path containing `..` → None.
  - a denied path → None: `read_capture("/proc/self/cmdline")` returns None (under the `/proc` deny prefix).
  - a non-existent path → None (no raise).
```python
import os
from pathlib import Path
from inspectord.evidence.capture import read_capture


def test_reads_regular_file(tmp_path: Path) -> None:
    p = tmp_path / "f"
    p.write_bytes(b"data")
    assert read_capture(str(p)) == b"data"


def test_fifo_does_not_hang(tmp_path: Path) -> None:
    p = tmp_path / "fifo"
    os.mkfifo(p)
    assert read_capture(str(p)) is None  # must return, not block


def test_symlink_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"; real.write_bytes(b"x")
    link = tmp_path / "link"; os.symlink(real, link)
    assert read_capture(str(link)) is None


def test_rejects_relative_dotdot_and_denylist(tmp_path: Path) -> None:
    assert read_capture("relative/path") is None
    assert read_capture(str(tmp_path / ".." / "x")) is None
    assert read_capture("/proc/self/cmdline") is None
    assert read_capture(str(tmp_path / "nope")) is None
```
  (For the truncation test, expose `_MAX_FILE_BYTES` and read with a monkeypatched small value, OR write a >cap file — prefer monkeypatch to keep the test fast.)
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** `inspectord/evidence/capture.py`:
```python
"""Symlink/TOCTOU-safe capture of an attacker-influenced file path, as the root daemon.

Never follows a symlink, never blocks (FIFO/device), never exceeds the size cap, and
refuses sensitive paths — so a crafted implicated path cannot hang a worker thread or
exfiltrate secrets into the forensic store (spec §3.3, §11).
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

log = logging.getLogger(__name__)

_MAX_FILE_BYTES = 32 * 1024 * 1024  # 32 MiB

# Resolved-path prefixes we refuse to read into the forensic store.
_DENY_PREFIXES = (
    "/proc", "/sys", "/dev",
    "/etc/shadow", "/etc/gshadow",
    "/root/.ssh",
)


def _path_allowed(path: str) -> bool:
    if not os.path.isabs(path):
        return False
    if ".." in Path(path).parts:
        return False
    real = os.path.realpath(path)
    for deny in _DENY_PREFIXES:
        if real == deny or real.startswith(deny + "/"):
            return False
    return True


def read_capture(path: str, *, max_bytes: int = _MAX_FILE_BYTES) -> bytes | None:
    """Return up to max_bytes of the file, or None if it can't/shouldn't be captured.

    Truncates silently at max_bytes (the caller records `truncated`). Best-effort: any
    error or unsafe condition returns None.
    """
    if not _path_allowed(path):
        log.info("evidence: refused implicated path %r", path)
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        log.info("evidence: cannot open %r: %r", path, exc)
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None  # FIFO/device/dir/socket — never read
        # Read from THIS fd (never re-open by path); cap on the read, not the pre-stat size.
        chunks: list[bytes] = []
        remaining = max_bytes
        while remaining > 0:
            try:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
            except BlockingIOError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError as exc:
        log.info("evidence: read failed %r: %r", path, exc)
        return None
    finally:
        os.close(fd)
```
  (`read_capture` returns the truncated bytes; the caller compares `len(data)` against the
  on-disk size if it wants a `truncated` flag — for v1 the caller marks `truncated` when
  `len(data) == max_bytes`.)
- [ ] **Step 4: Run — expect pass.** Confirm the FIFO test returns quickly (no hang).
- [ ] **Step 5: Commit.** `feat(evidence): symlink/TOCTOU-safe file capture reader`.

---

## Task 4: `network_snapshot` — bounded all-states /proc/net parser

**Files:** Create `inspectord/evidence/netsnapshot.py`; Test `tests/evidence/test_netsnapshot.py`.

- [ ] **Step 1: Write failing tests** `tests/evidence/test_netsnapshot.py` using a fake `proc_net_dir` (write fixture files `tcp`, `tcp6`, `udp`, `udp6` with the `/proc/net` column format — header line + rows where col 1 = `local_addr` `HEXIP:HEXPORT`, col 2 = `rem_addr`, col 3 = `st`):
  - decodes both a LISTEN (`st=0A`) and an ESTABLISHED (`st=01`) row, recording `proto, local (ip,port), remote (ip,port), state`.
  - a missing proto file contributes nothing and does not raise.
  - the result has `captured_at` (ISO string), `truncated` (bool), `sockets` (list).
  - **bounded**: when a proto file exceeds the row cap, `truncated` is True and `len(sockets)` is capped (use a small `_MAX_ROWS` override).
```python
from pathlib import Path
from inspectord.evidence.netsnapshot import network_snapshot

_HEADER = "  sl  local_address rem_address   st ...\n"


def _write(d: Path, proto: str, rows: list[str]) -> None:
    (d / proto).write_text(_HEADER + "".join(f"  0: {r}\n" for r in rows))


def test_decodes_listen_and_established(tmp_path: Path) -> None:
    # 0100007F:0016 = 127.0.0.1:22 ; remote 00000000:0000 ; st 0A=listen / 01=established
    _write(tmp_path, "tcp", ["0100007F:0016 00000000:0000 0A", "0100007F:0016 0101A8C0:1F90 01"])
    snap = network_snapshot(proc_net_dir=tmp_path)
    states = {s["state"] for s in snap["sockets"]}
    assert "listen" in states and "established" in states
    assert any(s["local"] == ["127.0.0.1", 22] for s in snap["sockets"])
    assert "captured_at" in snap and snap["truncated"] is False


def test_missing_proto_file_is_skipped(tmp_path: Path) -> None:
    snap = network_snapshot(proc_net_dir=tmp_path)  # empty dir
    assert snap["sockets"] == [] and snap["truncated"] is False
```
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** `inspectord/evidence/netsnapshot.py`, reusing the `_decode_local_addr` helper from the listener source. Map the hex `st` byte to a state name (`0A`→`listen`, `01`→`established`, else the raw hex). Cap rows at `_MAX_ROWS` (default 4096) across all protos, setting `truncated=True` if hit. Read each proto file inside a `try/except OSError` (missing → skip). Never raise on a malformed row (skip it). Return `{"captured_at": datetime.now(UTC).isoformat(), "truncated": bool, "sockets": [{"proto", "local": [ip, port], "remote": [ip, port], "state"}]}`. Use `from inspectord.workers.listening_socket_snapshotter.source import _decode_local_addr`.
- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Run all gates** (full pytest, ruff, mypy). Commit. `feat(evidence): bounded /proc/net all-states snapshot`.

---

## Self-review checklist (before handoff)
- [ ] Spec §3.1 store (atomic 0600, content-addressed, idempotent) → Task 2 incl. perms + no-temp-leftover tests. ✓
- [ ] Spec §3.2 migration (PK incl. original_path, kinds) → Task 1. ✓
- [ ] Spec §3.3 read_capture (path gate, O_NOFOLLOW|O_NONBLOCK, fstat-S_ISREG, read-from-fd, cap) → Task 3 incl. **FIFO-no-hang + symlink-refused + denylist** tests. ✓
- [ ] Spec §3.4 netsnapshot (bounded, all states, reuse `_decode_*`, never raise) → Task 4. ✓
- [ ] `evidence_dir` config (defaulted so existing configs don't break) → Task 1. ✓
- [ ] Out of scope for PR-A (do NOT build): the `EvidenceCollector`, `implicated_paths`, `append_timeline`, supervisor wiring, the `get_case` extension, the web Evidence section — all PR-B.
- [ ] Signature consistency: `ForensicStore(root).put(bytes)->str` / `.path_for(sha)->Path`; `read_capture(path, *, max_bytes)->bytes|None`; `network_snapshot(proc_net_dir)->dict`.
