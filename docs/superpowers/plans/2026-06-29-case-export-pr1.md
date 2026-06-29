# Case ZIP export — PR1 (export builder + IPC) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add daemon-side `inspectord/cases/export.py` (whole-case ZIP builder + per-blob reader) and two read-only IPC methods (`export_case_zip`, `download_evidence`) that ship bytes as base64 and append a custody `case_event`.

**Architecture:** The web is a pure IPC client and the forensic store is root-only, so export/download bytes are built **daemon-side** and returned **base64-over-IPC**, hard-capped at 64 MiB of raw bytes. PR1 is the daemon half (builder + handlers + wiring); PR2 (separate plan) adds the web routes and the `IpcClient.call()` recv-loop hardening needed to carry the large payload.

**Tech Stack:** Python 3, `zipfile`/`io.BytesIO`, DuckDB via `inspectord.storage.db.Database`, `inspectord.evidence.store.ForensicStore`, pytest.

**Spec:** `docs/superpowers/specs/2026-06-23-case-export-design.md` (concilium-reviewed). This plan implements §2.1 and §2.2 only.

**Run gates before pushing** (from `CLAUDE.md`):
- `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- `.venv/bin/ruff check inspectord inspectorctl tests` · `.venv/bin/ruff format --check inspectord inspectorctl tests` · `.venv/bin/mypy inspectord`

Commit trailer on every commit: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

---

## File structure

- **Create** `inspectord/cases/export.py` — exceptions, the SHA regex + size cap, a safe blob reader, `build_case_zip`, `read_evidence_blob`, and the narrative builder. Pure over `(db, ForensicStore, ...)`; no IPC/web knowledge.
- **Modify** `inspectord/cases/ipc_handlers.py` — add `handle_export_case_zip` and `handle_download_evidence` (keyword-only `*, params, db_path, evidence_dir`).
- **Modify** `inspectord/__main__.py` — register the two new `Method`s, passing `evidence_dir=cfg.storage.evidence_dir` alongside `db_path`.
- **Create** `tests/cases/test_export.py` — unit tests for `export.py`.
- **Modify** `tests/cases/test_ipc_handlers.py` — handler tests (base64 round-trip, custody event, error shapes).

Reference signatures (verified against current code):
- `store.get_case(db, *, case_id) -> dict | None` returns `{case_id, title, status, opened_at, closed_at, alerts:[{alert_id,rule_id,severity,status,rendered_short,ts}], timeline:[{ts,seq,kind,text}], evidence:[{kind,sha256,original_path,captured_at,meta}]}` (datetimes are `datetime` objects from the store).
- `store.append_timeline(db, *, case_id, kind, text=None)` — `case_id` keyword-only.
- `ForensicStore(root).path_for(sha) -> Path` (blob at `<root>/<sha[:2]>/<sha>`).
- Alert full record: `SELECT payload_json FROM alerts WHERE alert_id = ?` (a JSON string).
- IPC error shape used across handlers: `{"schema_version": "1.0.0", "ok": False, "error": "<msg>"}`.
- Test DB helper (mirror `tests/cases/test_store.py`):
  ```python
  def _db(tmp_path):
      db = Database(tmp_path / "t.duckdb"); db.connect()
      from inspectord.storage.migrations import run_migrations
      run_migrations(db); return db
  ```

---

## Task 1: Exceptions, constants, and the safe blob reader

**Files:**
- Create: `inspectord/cases/export.py`
- Test: `tests/cases/test_export.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/cases/test_export.py
"""Tests for case ZIP export (spec §2.1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.cases import export
from inspectord.evidence.store import ForensicStore


def _store(tmp_path: Path) -> ForensicStore:
    return ForensicStore(tmp_path / "evidence")


def test_sha_re_accepts_valid_and_rejects_invalid() -> None:
    assert export._SHA_RE.match("a" * 64)
    assert not export._SHA_RE.match("A" * 64)  # uppercase rejected
    assert not export._SHA_RE.match("../../etc/passwd")
    assert not export._SHA_RE.match("a" * 63)


def test_read_blob_returns_bytes_for_stored_content(tmp_path: Path) -> None:
    store = _store(tmp_path)
    sha = store.put(b"hello evidence")
    assert export._read_blob(store, sha) == b"hello evidence"


def test_read_blob_returns_none_for_missing(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert export._read_blob(store, "b" * 64) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/cases/test_export.py -q`
Expected: FAIL — `ModuleNotFoundError`/`AttributeError` (no `inspectord.cases.export`).

- [ ] **Step 3: Write minimal implementation**

```python
# inspectord/cases/export.py
"""Daemon-side case ZIP export + per-blob reader (spec §2.1).

The web is a pure IPC client and the forensic store is root-only, so artifacts are
built here and shipped base64-over-IPC, hard-capped at _MAX_EXPORT_BYTES raw bytes.
"""

from __future__ import annotations

import io
import logging
import os
import re
import stat
import zipfile

log = logging.getLogger(__name__)

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_EXPORT_BYTES = 64 * 1024 * 1024  # cap on RAW bytes (pre-base64); ~85 MiB on the wire


class CaseExportError(Exception):
    """Base for export errors."""


class CaseNotFound(CaseExportError):
    pass


class EvidenceNotFound(CaseExportError):
    pass


class ExportTooLarge(CaseExportError):
    pass


def _read_blob(store, sha: str) -> bytes | None:
    """Read a forensic-store blob by sha. None if missing/invalid/unsafe.

    Opens with O_NOFOLLOW (defense-in-depth — the store holds regular files only) and
    reads from the fd, never re-opening by path. Caller must validate `sha` is hex first
    for any sha that did not originate as a path_for() key.
    """
    path = store.path_for(sha)
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/cases/test_export.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add inspectord/cases/export.py tests/cases/test_export.py
git commit -m "feat(cases): export module scaffold — exceptions, sha regex, safe blob reader

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `_build_narrative` — human-readable summary + Missing-evidence section

**Files:**
- Modify: `inspectord/cases/export.py`
- Test: `tests/cases/test_export.py`

- [ ] **Step 1: Write the failing test**

```python
def test_build_narrative_includes_core_fields_and_missing_section() -> None:
    case = {
        "case_id": "c1",
        "title": "sshd brute force",
        "status": "open",
        "opened_at": "2026-06-20T00:00:00+00:00",
        "closed_at": None,
        "alerts": [
            {"alert_id": "a1", "rule_id": "r1", "severity": "high", "rendered_short": "brute"}
        ],
        "timeline": [{"ts": "2026-06-20T00:00:00+00:00", "kind": "opened", "text": None}],
        "evidence": [
            {"kind": "file", "sha256": "a" * 64, "original_path": "/etc/passwd", "meta": {}}
        ],
    }
    text = export._build_narrative(case, skipped=[("b" * 64, "missing on disk")])
    assert "sshd brute force" in text
    assert "high" in text and "brute" in text
    assert "opened" in text
    assert "/etc/passwd" in text
    assert "Missing evidence" in text
    assert "b" * 64 in text
    assert "missing on disk" in text


def test_build_narrative_omits_missing_section_when_none() -> None:
    case = {
        "case_id": "c1", "title": "t", "status": "closed",
        "opened_at": "x", "closed_at": "y",
        "alerts": [], "timeline": [], "evidence": [],
    }
    text = export._build_narrative(case, skipped=[])
    assert "Missing evidence" not in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/cases/test_export.py -k narrative -q`
Expected: FAIL — `AttributeError: module ... has no attribute '_build_narrative'`.

- [ ] **Step 3: Write minimal implementation**

Append to `inspectord/cases/export.py`:

```python
def _build_narrative(case: dict, *, skipped: list[tuple[str, str]]) -> str:
    """Plain-text human summary. `skipped` = (sha, reason) for blobs not included."""
    lines: list[str] = []
    lines.append(f"# Case {case['case_id']}: {case.get('title') or '(untitled)'}")
    lines.append("")
    lines.append(f"Status: {case['status']}")
    lines.append(f"Opened: {case.get('opened_at')}")
    lines.append(f"Closed: {case.get('closed_at') or '-'}")
    lines.append("")
    lines.append("## Alerts")
    for a in case.get("alerts", []):
        lines.append(
            f"- [{a.get('severity')}] {a.get('rule_id')} ({a.get('alert_id')}): "
            f"{a.get('rendered_short') or ''}"
        )
    if not case.get("alerts"):
        lines.append("- (none)")
    lines.append("")
    lines.append("## Timeline")
    for t in case.get("timeline", []):
        lines.append(f"- {t.get('ts')} {t.get('kind')}: {t.get('text') or ''}")
    if not case.get("timeline"):
        lines.append("- (none)")
    lines.append("")
    lines.append("## Evidence")
    for e in case.get("evidence", []):
        lines.append(
            f"- {e.get('kind')} {e.get('sha256')} "
            f"{e.get('original_path') or ''}".rstrip()
        )
    if not case.get("evidence"):
        lines.append("- (none)")
    lines.append("")
    lines.append("## Notes")
    lines.append(
        "v1 export ships 4 of the 6 artifacts in parent spec §13.4: the timeline embedded in "
        "case.json stands in for audit.log (plain, not-yet-tamper-evident), and event bundles "
        "are included as evidence/<sha> blobs (kind=event_bundle), not top-level events/*.jsonl."
    )
    if skipped:
        lines.append("")
        lines.append("## Missing evidence")
        for sha, reason in skipped:
            lines.append(f"- {sha}: {reason}")
    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/cases/test_export.py -k narrative -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add inspectord/cases/export.py tests/cases/test_export.py
git commit -m "feat(cases): export narrative builder with Missing-evidence section

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `build_case_zip` — assemble the in-memory ZIP

**Files:**
- Modify: `inspectord/cases/export.py`
- Test: `tests/cases/test_export.py`

- [ ] **Step 1: Write the failing test**

```python
import io
import json
import zipfile

from inspectord.cases import store
from inspectord.storage.db import Database
from inspectord.storage.migrations import run_migrations


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "t.duckdb")
    db.connect()
    run_migrations(db)
    return db


def _seed_alert(db: Database, alert_id: str) -> None:
    db.execute(
        "INSERT INTO alerts (alert_id, rule_id, ts, severity, status, category, dedup_key, "
        "dedup_count, first_seen_at, last_seen_at, rendered_short, rendered_detail, payload_json) "
        "VALUES (?, 'r1', TIMESTAMP '2026-06-20 00:00:00', 'high', 'new', 'auth', 'dk', 1, "
        "TIMESTAMP '2026-06-20 00:00:00', TIMESTAMP '2026-06-20 00:00:00', 'short', 'detail', "
        "?)",
        [alert_id, json.dumps({"alert_id": alert_id, "rule_id": "r1"})],
    )


def _add_evidence(db: Database, case_id: str, kind: str, sha: str, path: str = "") -> None:
    db.execute(
        "INSERT INTO case_evidence (case_id, kind, sha256, original_path, captured_at, meta_json) "
        "VALUES (?, ?, ?, ?, TIMESTAMP '2026-06-20 00:00:00', '{}')",
        [case_id, kind, sha, path],
    )


def test_build_case_zip_contains_expected_members(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"captured bytes")
    _add_evidence(db, case_id, "file", sha, "/etc/passwd")

    data = export.build_case_zip(db, fstore, case_id)
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = set(zf.namelist())
    assert "case.json" in names
    assert "alerts/a1.json" in names
    assert f"evidence/{sha}" in names
    assert "narrative.md" in names
    parsed = json.loads(zf.read("case.json"))
    assert parsed["case_id"] == case_id
    assert zf.read(f"evidence/{sha}") == b"captured bytes"
    assert json.loads(zf.read("alerts/a1.json"))["alert_id"] == "a1"


def test_build_case_zip_missing_case_raises(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(export.CaseNotFound):
        export.build_case_zip(db, _store(tmp_path), "nope")


def test_build_case_zip_skips_missing_blob(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    _add_evidence(db, case_id, "file", "c" * 64, "/gone")  # no blob on disk
    data = export.build_case_zip(db, fstore, case_id)
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert f"evidence/{'c' * 64}" not in set(zf.namelist())
    assert "Missing evidence" in zf.read("narrative.md").decode()


def test_build_case_zip_skips_invalid_sha(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    _add_evidence(db, case_id, "file", "../../etc/passwd", "/x")
    data = export.build_case_zip(db, fstore, case_id)  # must not raise / traverse
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert not any(n.startswith("evidence/..") for n in zf.namelist())


def test_build_case_zip_dedupes_duplicate_sha(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"dup")
    _add_evidence(db, case_id, "file", sha, "/a")
    _add_evidence(db, case_id, "file", sha, "/b")  # same sha, different original_path
    data = export.build_case_zip(db, fstore, case_id)
    names = [n for n in zipfile.ZipFile(io.BytesIO(data)).namelist() if n.startswith("evidence/")]
    assert names.count(f"evidence/{sha}") == 1


def test_build_case_zip_size_cap_raises(tmp_path: Path, monkeypatch) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"x" * 1000)
    _add_evidence(db, case_id, "file", sha, "/big")
    monkeypatch.setattr(export, "_MAX_EXPORT_BYTES", 100)
    with pytest.raises(export.ExportTooLarge):
        export.build_case_zip(db, fstore, case_id)


def test_build_case_zip_empty_case_is_valid(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    data = export.build_case_zip(db, fstore, case_id)
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert "case.json" in zf.namelist() and "narrative.md" in zf.namelist()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/cases/test_export.py -k build_case_zip -q`
Expected: FAIL — `AttributeError: ... 'build_case_zip'`.

- [ ] **Step 3: Write minimal implementation**

Add the import for the store module at the top of `export.py` (`from inspectord.cases import store as cases_store`) and append:

```python
def _alert_record(db, alert_id: str) -> bytes:
    """Full alert record as JSON bytes (payload_json), or a placeholder for a pruned alert."""
    rows = db.query("SELECT payload_json FROM alerts WHERE alert_id = ?", [alert_id]).fetchall()
    if rows and rows[0][0]:
        return rows[0][0].encode("utf-8")
    import json as _json

    return _json.dumps({"alert_id": alert_id, "note": "alert record pruned"}).encode("utf-8")


def build_case_zip(db, store, case_id: str) -> bytes:
    """Assemble the whole-case ZIP in memory. Raises CaseNotFound / ExportTooLarge."""
    import json as _json

    case = cases_store.get_case(db, case_id=case_id)
    if case is None:
        raise CaseNotFound(case_id)
    # get_case returns datetime objects; render them ISO for JSON.
    for key in ("opened_at", "closed_at"):
        v = case.get(key)
        if hasattr(v, "isoformat"):
            case[key] = v.isoformat()
    for a in case["alerts"]:
        if hasattr(a.get("ts"), "isoformat"):
            a["ts"] = a["ts"].isoformat()
    for t in case["timeline"]:
        if hasattr(t.get("ts"), "isoformat"):
            t["ts"] = t["ts"].isoformat()
    for e in case["evidence"]:
        if hasattr(e.get("captured_at"), "isoformat"):
            e["captured_at"] = e["captured_at"].isoformat()

    skipped: list[tuple[str, str]] = []
    total = 0
    buf = io.BytesIO()
    written_shas: set[str] = set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("case.json", _json.dumps(case, indent=2, default=str))
        seen_alerts: set[str] = set()
        for a in case["alerts"]:
            aid = a["alert_id"]
            if aid in seen_alerts:
                continue
            seen_alerts.add(aid)
            zf.writestr(f"alerts/{aid}.json", _alert_record(db, aid))
        for e in case["evidence"]:
            sha = e["sha256"]
            if sha in written_shas:
                continue
            if not _SHA_RE.match(sha):
                skipped.append((sha, "invalid sha"))
                continue
            blob = _read_blob(store, sha)
            if blob is None:
                skipped.append((sha, "missing on disk"))
                continue
            total += len(blob)
            if total > _MAX_EXPORT_BYTES:
                raise ExportTooLarge(f"case {case_id} exceeds {_MAX_EXPORT_BYTES} bytes")
            zf.writestr(f"evidence/{sha}", blob)
            written_shas.add(sha)
        zf.writestr("narrative.md", _build_narrative(case, skipped=skipped))
    return buf.getvalue()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/cases/test_export.py -k build_case_zip -q`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add inspectord/cases/export.py tests/cases/test_export.py
git commit -m "feat(cases): build_case_zip — in-memory ZIP with sha validation, dedup, size cap

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `read_evidence_blob` — per-blob download with filename/media-type

**Files:**
- Modify: `inspectord/cases/export.py`
- Test: `tests/cases/test_export.py`

- [ ] **Step 1: Write the failing test**

```python
def test_read_evidence_blob_file_kind(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"file bytes")
    _add_evidence(db, case_id, "file", sha, "/etc/shadow")
    data, filename, media = export.read_evidence_blob(db, fstore, case_id, sha)
    assert data == b"file bytes"
    assert filename == "shadow"
    assert media == "application/octet-stream"


def test_read_evidence_blob_json_kind(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"{}")
    _add_evidence(db, case_id, "net_state", sha, "")
    data, filename, media = export.read_evidence_blob(db, fstore, case_id, sha)
    assert media == "application/json"
    assert filename == f"{sha[:12]}-net_state.json"


def test_read_evidence_blob_rejects_non_hex(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with pytest.raises(export.EvidenceNotFound):
        export.read_evidence_blob(db, _store(tmp_path), "c1", "NOTHEX")


def test_read_evidence_blob_sha_not_in_case(tmp_path: Path) -> None:
    db = _db(tmp_path)
    fstore = _store(tmp_path)
    _seed_alert(db, "a1")
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"orphan")  # blob exists but not linked to this case
    with pytest.raises(export.EvidenceNotFound):
        export.read_evidence_blob(db, fstore, case_id, sha)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/cases/test_export.py -k read_evidence_blob -q`
Expected: FAIL — `AttributeError: ... 'read_evidence_blob'`.

- [ ] **Step 3: Write minimal implementation**

Append to `export.py`:

```python
def _basename(path: str) -> str:
    return os.path.basename(path.rstrip("/")) or ""


def read_evidence_blob(db, store, case_id: str, sha: str) -> tuple[bytes, str, str]:
    """Return (bytes, filename, media_type) for a sha tied to THIS case. Raises on absence.

    Validates `sha` as hex BEFORE any path op, and confirms the sha is in this case's
    case_evidence rows — never serves an arbitrary store path.
    """
    if not _SHA_RE.match(sha):
        raise EvidenceNotFound(sha)
    rows = db.query(
        "SELECT kind, original_path FROM case_evidence WHERE case_id = ? AND sha256 = ? "
        "ORDER BY original_path LIMIT 1",
        [case_id, sha],
    ).fetchall()
    if not rows:
        raise EvidenceNotFound(sha)
    kind, original_path = rows[0][0], rows[0][1] or ""
    blob = _read_blob(store, sha)
    if blob is None:
        raise EvidenceNotFound(sha)
    if len(blob) > _MAX_EXPORT_BYTES:
        raise ExportTooLarge(sha)
    if kind in ("net_state", "event_bundle"):
        return blob, f"{sha[:12]}-{kind}.json", "application/json"
    filename = _basename(original_path) or f"{sha[:12]}.bin"
    return blob, filename, "application/octet-stream"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/cases/test_export.py -q`
Expected: PASS (all export tests).

- [ ] **Step 5: Commit**

```bash
git add inspectord/cases/export.py tests/cases/test_export.py
git commit -m "feat(cases): read_evidence_blob — case-scoped per-blob download

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: IPC handlers (`export_case_zip`, `download_evidence`)

**Files:**
- Modify: `inspectord/cases/ipc_handlers.py`
- Test: `tests/cases/test_ipc_handlers.py`

- [ ] **Step 1: Write the failing test**

```python
# add to tests/cases/test_ipc_handlers.py
import base64
import io
import zipfile

from inspectord.cases import ipc_handlers


def _seed_case_with_evidence(db, fstore):
    # reuse this file's existing _seed_alert / _db helpers; add evidence + a blob
    _seed_alert(db, "a1")
    from inspectord.cases import store
    case_id = store.open_case(db, alert_id="a1")
    sha = fstore.put(b"payload")
    db.execute(
        "INSERT INTO case_evidence (case_id, kind, sha256, original_path, captured_at, meta_json) "
        "VALUES (?, 'file', ?, '/etc/x', TIMESTAMP '2026-06-20 00:00:00', '{}')",
        [case_id, sha],
    )
    return case_id, sha


def test_export_case_zip_handler_round_trip_and_custody(tmp_path) -> None:
    db = _db(tmp_path)
    from inspectord.evidence.store import ForensicStore
    fstore = ForensicStore(tmp_path / "evidence")
    case_id, sha = _seed_case_with_evidence(db, fstore)
    db.close()

    resp = ipc_handlers.handle_export_case_zip(
        params={"case_id": case_id},
        db_path=tmp_path / "t.duckdb",
        evidence_dir=tmp_path / "evidence",
    )
    raw = base64.b64decode(resp["content_b64"])
    assert "case.json" in zipfile.ZipFile(io.BytesIO(raw)).namelist()
    assert resp["filename"].endswith(".zip")

    db2 = _db(tmp_path)  # reopen; migrations are idempotent
    kinds = [r[0] for r in db2.query(
        "SELECT kind FROM case_event WHERE case_id = ?", [case_id]).fetchall()]
    assert "exported" in kinds


def test_export_case_zip_handler_not_found(tmp_path) -> None:
    _db(tmp_path).close()
    resp = ipc_handlers.handle_export_case_zip(
        params={"case_id": "nope"}, db_path=tmp_path / "t.duckdb",
        evidence_dir=tmp_path / "evidence",
    )
    assert resp["ok"] is False and resp["error"] == "not found"


def test_download_evidence_handler_round_trip_and_custody(tmp_path) -> None:
    db = _db(tmp_path)
    from inspectord.evidence.store import ForensicStore
    fstore = ForensicStore(tmp_path / "evidence")
    case_id, sha = _seed_case_with_evidence(db, fstore)
    db.close()

    resp = ipc_handlers.handle_download_evidence(
        params={"case_id": case_id, "sha": sha},
        db_path=tmp_path / "t.duckdb", evidence_dir=tmp_path / "evidence",
    )
    assert base64.b64decode(resp["content_b64"]) == b"payload"
    assert resp["media_type"] == "application/octet-stream"

    db2 = _db(tmp_path)
    kinds = [r[0] for r in db2.query(
        "SELECT kind FROM case_event WHERE case_id = ?", [case_id]).fetchall()]
    assert "evidence_downloaded" in kinds


def test_download_evidence_handler_not_found(tmp_path) -> None:
    db = _db(tmp_path)
    _seed_alert(db, "a1")
    from inspectord.cases import store
    case_id = store.open_case(db, alert_id="a1")
    db.close()
    resp = ipc_handlers.handle_download_evidence(
        params={"case_id": case_id, "sha": "d" * 64},
        db_path=tmp_path / "t.duckdb", evidence_dir=tmp_path / "evidence",
    )
    assert resp["ok"] is False and resp["error"] == "not found"
```

> If `tests/cases/test_ipc_handlers.py` lacks `_db`/`_seed_alert` helpers, copy them from `tests/cases/test_store.py` (shown in the File-structure section).

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/cases/test_ipc_handlers.py -k "export_case_zip or download_evidence" -q`
Expected: FAIL — `AttributeError: ... 'handle_export_case_zip'`.

- [ ] **Step 3: Write minimal implementation**

Add to `inspectord/cases/ipc_handlers.py` (imports `base64`, `export` module, `ForensicStore`):

```python
import base64

from inspectord.cases import export
from inspectord.evidence.store import ForensicStore


def handle_export_case_zip(
    *, params: dict[str, Any], db_path: Path, evidence_dir: Path
) -> dict[str, Any]:
    case_id = str(params["case_id"])
    store_ = ForensicStore(evidence_dir)
    with Database(db_path) as db:
        try:
            data = export.build_case_zip(db, store_, case_id)
        except export.CaseNotFound:
            return {"schema_version": "1.0.0", "ok": False, "error": "not found"}
        except export.ExportTooLarge:
            return {"schema_version": "1.0.0", "ok": False, "error": "too_large"}
        store.append_timeline(db, case_id=case_id, kind="exported", text="case exported as ZIP")
    return {
        "schema_version": "1.0.0",
        "ok": True,
        "filename": f"case-{case_id[:8]}.zip",
        "content_b64": base64.b64encode(data).decode("ascii"),
    }


def handle_download_evidence(
    *, params: dict[str, Any], db_path: Path, evidence_dir: Path
) -> dict[str, Any]:
    case_id = str(params["case_id"])
    sha = str(params["sha"])
    store_ = ForensicStore(evidence_dir)
    with Database(db_path) as db:
        try:
            data, filename, media_type = export.read_evidence_blob(db, store_, case_id, sha)
        except export.EvidenceNotFound:
            return {"schema_version": "1.0.0", "ok": False, "error": "not found"}
        except export.ExportTooLarge:
            return {"schema_version": "1.0.0", "ok": False, "error": "too_large"}
        store.append_timeline(
            db, case_id=case_id, kind="evidence_downloaded", text=f"downloaded {sha[:12]}"
        )
    return {
        "schema_version": "1.0.0",
        "ok": True,
        "filename": filename,
        "media_type": media_type,
        "content_b64": base64.b64encode(data).decode("ascii"),
    }
```

> Note: `store` (the cases store module) is already imported at the top of `ipc_handlers.py` as `from inspectord.cases import store`. The new `ForensicStore` local is named `store_` to avoid shadowing it.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/cases/test_ipc_handlers.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/cases/ipc_handlers.py tests/cases/test_ipc_handlers.py
git commit -m "feat(cases): export_case_zip + download_evidence IPC handlers with custody events

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Register the two methods in the daemon

**Files:**
- Modify: `inspectord/__main__.py`

- [ ] **Step 1: Add the imports**

In the `from inspectord.cases.ipc_handlers import (...)` block, add `handle_export_case_zip` and `handle_download_evidence`:

```python
from inspectord.cases.ipc_handlers import (
    handle_add_note,
    handle_attach_alert,
    handle_close_case,
    handle_download_evidence,
    handle_export_case_zip,
    handle_get_case,
    handle_list_cases,
    handle_open_case,
)
```

- [ ] **Step 2: Register the methods**

Immediately after the `get_case` `Method(...)` entry (the last item before the closing `]` of the methods list), add:

```python
        Method(
            name="export_case_zip",
            handler=lambda params: handle_export_case_zip(
                params=params,
                db_path=cfg.storage.db_path,
                evidence_dir=cfg.storage.evidence_dir,
            ),
            mutates=False,
        ),
        Method(
            name="download_evidence",
            handler=lambda params: handle_download_evidence(
                params=params,
                db_path=cfg.storage.db_path,
                evidence_dir=cfg.storage.evidence_dir,
            ),
            mutates=False,
        ),
```

- [ ] **Step 3: Verify the daemon imports cleanly**

Run: `.venv/bin/python -c "import inspectord.__main__"`
Expected: no output, exit 0 (no `ImportError`).

- [ ] **Step 4: Commit**

```bash
git add inspectord/__main__.py
git commit -m "feat(cases): register export_case_zip + download_evidence IPC methods

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Full gate run + branch review

- [ ] **Step 1: Run the full test suite**

Run: `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
Expected: PASS (no regressions; new export + handler tests included).

- [ ] **Step 2: Lint, format, types**

Run:
```bash
.venv/bin/ruff check inspectord inspectorctl tests
.venv/bin/ruff format --check inspectord inspectorctl tests
.venv/bin/mypy inspectord
```
Expected: all clean. (If `ruff format --check` flags the new files, run `.venv/bin/ruff format inspectord/cases/export.py tests/cases/test_export.py` and amend.)

- [ ] **Step 3: Holistic branch review**

Dispatch a final spec-compliance + code-quality review over the whole branch diff (`git diff main...HEAD`) against spec §2.1/§2.2. Apply nits inline.

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin feat/case-export
gh pr create --fill
gh pr checks <N> --watch
```

---

## Self-review notes (spec coverage)

- §2.1 `build_case_zip` (case.json/alerts/evidence/narrative, sha-hex validation, O_NOFOLLOW read, dedup, missing-blob skip + Missing-evidence section, §13.4 deviation note, raw-bytes size cap mid-assembly, CaseNotFound) → Tasks 2–3.
- §2.1 `read_evidence_blob` (hex-before-path, case-scoped check, filename/media_type per kind, EvidenceNotFound, single-blob cap) → Task 4.
- §2.2 handlers (base64, custody `case_event` appended only after successful build, `{schema_version, ok, error}` shapes, `evidence_dir` threaded in, `mutates=False`) → Tasks 5–6.
- **Out of scope for PR1** (PR2, separate plan): web POST routes + `case_detail.html` buttons + the `IpcClient.call()` recv-loop hardening (linear accumulation + ~96 MiB max-response guard, spec §1).
