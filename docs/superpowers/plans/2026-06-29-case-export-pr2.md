# Case ZIP export — PR2 (web routes + IPC-client hardening) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the daemon-side export from PR1 (#113) through the web dashboard — two POST routes serving the binary ZIP / blob, the Case-detail Export + Download buttons — and harden the IPC client so it can carry the large base64 payload.

**Architecture:** The web is a pure IPC client; PR1 returns `{filename, content_b64, media_type}` over IPC. PR2 (a) fixes `IpcClient.call()`'s quadratic recv loop + adds a max-response guard so ~85 MiB base64 payloads transfer in linear time and can't grow unbounded, then (b) adds POST routes that base64-decode the daemon response into an HTTP `Response`, and (c) wires the Case-detail buttons. **Routes are POST** (matching every other web mutation) so browser prefetch can't pollute the custody trail.

**Tech Stack:** Python 3, FastAPI/Starlette `Response`, the existing `inspectorctl/web/ipc.py` `call()` adapter, `IpcServer`-backed web tests via the `ipc_factory` fixture, pytest.

**Spec:** `docs/superpowers/specs/2026-06-23-case-export-design.md` §1 (transport/IPC-client), §2.3 (web). PR1 (#113, merged) already shipped `export.py` + the `export_case_zip` / `download_evidence` IPC methods.

**Run gates before pushing** (from `CLAUDE.md`):
- `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- `.venv/bin/ruff check inspectord inspectorctl tests` · `.venv/bin/ruff format --check inspectord inspectorctl tests` · `.venv/bin/mypy inspectord`

Commit trailer on every commit: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

---

## File structure

- **Modify** `inspectorctl/ipc_client.py` — replace the `line += chunk` recv loop with a `bytearray` accumulator + `_MAX_RESPONSE_BYTES` guard.
- **Modify** `tests/test_ipc_client.py` — add a large-response reassembly test + an over-guard rejection test.
- **Modify** `inspectorctl/web/routes/cases.py` — add `POST /cases/{case_id}/export` and `POST /cases/{case_id}/evidence/{sha}` returning binary `Response`s.
- **Modify** `tests/web/test_cases.py` — route tests (zip bytes + headers; too_large; not-found; blob download; sha-not-in-case → 404).
- **Modify** `inspectorctl/web/templates/case_detail.html` — replace the "coming soon" text with an Export-ZIP POST button + a per-evidence-row Download POST button.

Verified facts (current code):
- `IpcClient.call()` (`inspectorctl/ipc_client.py:22-49`) currently: `line = b""; while not line.endswith(b"\n"): chunk = sock.recv(4096); if not chunk: break; line += chunk` then `json.loads`. `IpcError` already exists. The server frames responses as one JSON object + `"\n"` (`inspectord/ipc_server.py` `_ok`/`_err`).
- `inspectorctl/web/ipc.py`: `call(socket_path, method, params) -> Any` returns the handler's full result dict and raises `WebIpcError` on `IpcError`.
- PR1 handler success shapes: export → `{schema_version, ok: True, filename, content_b64}`; download → `{schema_version, ok: True, filename, media_type, content_b64}`. Error → `{schema_version, ok: False, error: "not found"|"too_large"}`.
- Existing routes in `cases.py`: `cases_list`/`case_detail` are GET returning templates; `case_add_note`/`case_close` are POST via `_case_mutate` → 303 redirect. Imports already include `from fastapi import APIRouter, Form, HTTPException, Request`, `from fastapi.responses import HTMLResponse, RedirectResponse`, `from inspectorctl.web.ipc import WebIpcError, call`.
- Web tests use the `ipc_factory` fixture (`tests/web/conftest.py`) — spins a real `IpcServer` with mock `Method`s over a real unix socket + a `TestClient`. So a route test exercises the REAL `IpcClient`, making the hardening genuinely covered end-to-end. Mock `Method`s are built like `Method(name=..., handler=lambda params: {...}, mutates=...)`.
- `case_detail.html`: the evidence table loops `{% for e in case.evidence %}` with `e.sha256`; line 52 is `<p class="muted">Preserved — retrieval via export coming soon.</p>`; the open-case actions block uses `<form method="post" action="/cases/{{ case.case_id }}/...">`.

---

## Task 1: Harden `IpcClient.call()` recv loop

**Files:**
- Modify: `inspectorctl/ipc_client.py`
- Test: `tests/test_ipc_client.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_ipc_client.py`:

```python
import json

import pytest

from inspectorctl.ipc_client import IpcClient, IpcError
from inspectord.ipc_server import IpcServer, Method


def _server(tmp_path, methods):
    sock_path = tmp_path / "ipc.sock"
    server = IpcServer(socket_path=sock_path, methods=methods, allowed_uids=[])
    server.start()
    return server, sock_path


def test_client_reassembles_large_multichunk_response(tmp_path) -> None:
    # A payload far bigger than the 4096-byte recv chunk must reassemble intact.
    big = "x" * (512 * 1024)  # 512 KiB string, ~128 recv chunks

    def handler(_params):
        return {"blob": big}

    server, sock_path = _server(tmp_path, [Method(name="get_big", handler=handler, mutates=False)])
    try:
        result = IpcClient(socket_path=sock_path).call("get_big")
        assert result["blob"] == big
    finally:
        server.stop()


def test_client_rejects_oversized_response(tmp_path, monkeypatch) -> None:
    import inspectorctl.ipc_client as mod

    monkeypatch.setattr(mod, "_MAX_RESPONSE_BYTES", 1024)  # tiny guard

    def handler(_params):
        return {"blob": "y" * (8 * 1024)}  # 8 KiB > guard

    server, sock_path = _server(tmp_path, [Method(name="get_big", handler=handler, mutates=False)])
    try:
        with pytest.raises(IpcError):
            IpcClient(socket_path=sock_path).call("get_big")
    finally:
        server.stop()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_ipc_client.py -k "large_multichunk or oversized" -q`
Expected: `test_client_rejects_oversized_response` FAILs (no `_MAX_RESPONSE_BYTES` attr / no guard → `AttributeError` on monkeypatch or no `IpcError` raised). (`large_multichunk` may already pass — the current code is correct, just slow; that's fine, it locks in behavior.)

- [ ] **Step 3: Implement the hardened loop**

In `inspectorctl/ipc_client.py`, add a module-level constant near the top (after the imports):

```python
# Guard on the response size. The largest legitimate response is a base64-encoded case
# export (daemon-capped at 64 MiB raw → ~85 MiB base64) plus JSON envelope; 96 MiB gives
# headroom while bounding a runaway/oversized response.
_MAX_RESPONSE_BYTES = 96 * 1024 * 1024
```

Replace the recv loop (the `line = b""` block through `resp = json.loads(line.decode("utf-8"))`) with:

```python
            buf = bytearray()
            while not buf.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk  # bytearray += is amortized O(1) (no quadratic recopy)
                if len(buf) > _MAX_RESPONSE_BYTES:
                    raise IpcError(
                        f"response exceeds {_MAX_RESPONSE_BYTES} bytes (too large for IPC)"
                    )
            resp = json.loads(bytes(buf).decode("utf-8"))
```

(Leave the rest — the `if "error" in resp` check and `return resp["result"]` — unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ipc_client.py -q`
Expected: PASS (all, including the existing `test_client_can_call_method`).

- [ ] **Step 5: Commit**

```bash
git add inspectorctl/ipc_client.py tests/test_ipc_client.py
git commit -m "fix(ipc): linear recv accumulation + max-response guard in IpcClient

The line += chunk loop was O(n^2) and unbounded; the case export ships ~85 MiB
base64 over IPC. Accumulate into a bytearray (amortized O(1)) and cap at 96 MiB.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `POST /cases/{case_id}/export` route

**Files:**
- Modify: `inspectorctl/web/routes/cases.py`
- Test: `tests/web/test_cases.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/web/test_cases.py` (top-level imports needed: `import base64`, `import io`, `import zipfile`; `Method` is already imported):

```python
def _export_ok() -> Method:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("case.json", '{"case_id": "c1"}')
    content_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return Method(
        name="export_case_zip",
        handler=lambda params: {
            "schema_version": "1.0.0",
            "ok": True,
            "filename": "case-c1.zip",
            "content_b64": content_b64,
        },
        mutates=False,
    )


def _export_error(error: str) -> Method:
    return Method(
        name="export_case_zip",
        handler=lambda params: {"schema_version": "1.0.0", "ok": False, "error": error},
        mutates=False,
    )


def test_case_export_returns_zip(ipc_factory) -> None:
    client = ipc_factory([_export_ok()])
    response = client.post("/cases/c1/export")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert 'attachment; filename="case-c1.zip"' in response.headers["content-disposition"]
    zf = zipfile.ZipFile(io.BytesIO(response.content))
    assert "case.json" in zf.namelist()


def test_case_export_not_found_404(ipc_factory) -> None:
    client = ipc_factory([_export_error("not found")])
    response = client.post("/cases/c1/export")
    assert response.status_code == 404


def test_case_export_too_large_413(ipc_factory) -> None:
    client = ipc_factory([_export_error("too_large")])
    response = client.post("/cases/c1/export")
    assert response.status_code == 413
    assert "forensic store" in response.text  # friendly retrieve-from-disk message
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/web/test_cases.py -k export -q`
Expected: FAIL — 405 Method Not Allowed (route doesn't exist yet).

- [ ] **Step 3: Implement the route**

In `inspectorctl/web/routes/cases.py`, add `import base64` at the top and `Response` to the fastapi.responses import:

```python
from fastapi.responses import HTMLResponse, RedirectResponse, Response
```

Add a shared error helper and the export route (after `case_close`):

```python
def _export_error_response(result: dict[str, Any]) -> None:
    """Translate a daemon error dict into an HTTPException. Returns None if no error."""
    if result.get("ok"):
        return None
    error = result.get("error")
    if error == "too_large":
        raise HTTPException(
            status_code=413,
            detail="export too large for browser download — retrieve from the on-disk "
            "forensic store",
        )
    raise HTTPException(status_code=404, detail=error or "not found")


@router.post("/cases/{case_id}/export")
def case_export(request: Request, case_id: str) -> Response:
    try:
        result = call(request.app.state.socket_path, "export_case_zip", {"case_id": case_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    _export_error_response(result)
    data = base64.b64decode(result["content_b64"])
    filename = result["filename"]
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/web/test_cases.py -k export -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add inspectorctl/web/routes/cases.py tests/web/test_cases.py
git commit -m "feat(web): POST /cases/{id}/export route serving the case ZIP

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `POST /cases/{case_id}/evidence/{sha}` route

**Files:**
- Modify: `inspectorctl/web/routes/cases.py`
- Test: `tests/web/test_cases.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/web/test_cases.py`:

```python
def _download_ok() -> Method:
    content_b64 = base64.b64encode(b"file bytes").decode("ascii")
    return Method(
        name="download_evidence",
        handler=lambda params: {
            "schema_version": "1.0.0",
            "ok": True,
            "filename": "sudoers",
            "media_type": "application/octet-stream",
            "content_b64": content_b64,
        },
        mutates=False,
    )


def _download_error(error: str) -> Method:
    return Method(
        name="download_evidence",
        handler=lambda params: {"schema_version": "1.0.0", "ok": False, "error": error},
        mutates=False,
    )


def test_case_evidence_download_returns_blob(ipc_factory) -> None:
    client = ipc_factory([_download_ok()])
    response = client.post("/cases/c1/evidence/" + "a" * 64)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert 'attachment; filename="sudoers"' in response.headers["content-disposition"]
    assert response.content == b"file bytes"


def test_case_evidence_download_not_in_case_404(ipc_factory) -> None:
    client = ipc_factory([_download_error("not found")])
    response = client.post("/cases/c1/evidence/" + "b" * 64)
    assert response.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/web/test_cases.py -k "evidence_download" -q`
Expected: FAIL — 405 (route missing).

- [ ] **Step 3: Implement the route**

In `inspectorctl/web/routes/cases.py`, add after `case_export`:

```python
@router.post("/cases/{case_id}/evidence/{sha}")
def case_evidence_download(request: Request, case_id: str, sha: str) -> Response:
    try:
        result = call(
            request.app.state.socket_path,
            "download_evidence",
            {"case_id": case_id, "sha": sha},
        )
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    _export_error_response(result)
    data = base64.b64decode(result["content_b64"])
    return Response(
        content=data,
        media_type=result["media_type"],
        headers={"Content-Disposition": f'attachment; filename="{result["filename"]}"'},
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/web/test_cases.py -k "evidence_download" -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add inspectorctl/web/routes/cases.py tests/web/test_cases.py
git commit -m "feat(web): POST /cases/{id}/evidence/{sha} blob download route

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Case-detail Export + per-row Download buttons

**Files:**
- Modify: `inspectorctl/web/templates/case_detail.html`
- Test: `tests/web/test_cases.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/web/test_cases.py`:

```python
def test_case_detail_shows_export_and_download_links(ipc_factory) -> None:
    client = ipc_factory([_get_case(CASE)])
    response = client.get("/cases/c1")
    assert response.status_code == 200
    # Export button posts to the export route
    assert 'action="/cases/c1/export"' in response.text
    # Per-evidence-row download button posts to the evidence route with the sha
    assert f'action="/cases/c1/evidence/{CASE["evidence"][0]["sha256"]}"' in response.text
    # The old placeholder text is gone
    assert "coming soon" not in response.text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/web/test_cases.py -k "export_and_download_links" -q`
Expected: FAIL — assertion error ("coming soon" still present / no export action).

- [ ] **Step 3: Implement the template change**

In `inspectorctl/web/templates/case_detail.html`:

(a) Add a Download column header — change the evidence `<thead>` row (line 39) to:

```html
  <thead><tr><th>Kind</th><th>Source</th><th>Captured</th><th>Info</th><th>SHA-256</th><th></th></tr></thead>
```

(b) Add a Download cell to each evidence row — after the `sha256` `<td>` (line 47), before `</tr>`:

```html
      <td>
        <form method="post" action="/cases/{{ case.case_id }}/evidence/{{ e.sha256 }}">
          <button type="submit">Download</button>
        </form>
      </td>
```

(c) Replace the placeholder paragraph (line 52) with the Export button:

```html
<form method="post" action="/cases/{{ case.case_id }}/export">
  <button type="submit">Export case as ZIP</button>
</form>
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/web/test_cases.py -q`
Expected: PASS (all cases-web tests, including the existing render/escape/404 ones).

- [ ] **Step 5: Commit**

```bash
git add inspectorctl/web/templates/case_detail.html tests/web/test_cases.py
git commit -m "feat(web): Case-detail Export + per-evidence Download buttons

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Full gate run + branch review

- [ ] **Step 1: Run the full test suite**

Run: `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
Expected: PASS (no regressions; new IPC-client + web tests included).

- [ ] **Step 2: Lint, format, types**

Run:
```bash
.venv/bin/ruff check inspectord inspectorctl tests
.venv/bin/ruff format --check inspectord inspectorctl tests
.venv/bin/mypy inspectord
```
Expected: all clean. (`mypy` targets `inspectord`; if you want, also spot-check `inspectorctl/ipc_client.py` and `inspectorctl/web/routes/cases.py` compile via the test run. Run `ruff format` on any new files it flags and amend.)

- [ ] **Step 3: Holistic branch review**

Dispatch a final spec-compliance + code-quality review over `git diff main...HEAD` against spec §1 (IPC-client hardening) + §2.3 (web routes/template). Confirm: routes are POST; binary `Response` headers correct; error mapping (404 / 413 / 502); the recv loop is genuinely linear + guarded; no XSS regression in the new template buttons (the `sha` is daemon-validated hex, but confirm Jinja autoescaping still applies to `filename`/`sha` in attributes). Apply nits inline.

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin <branch>
gh pr create --fill
gh pr checks <N> --watch
```

---

## Self-review notes (spec coverage)

- §1 transport / IPC-client hardening (linear accumulation + ~96 MiB max-response guard) → Task 1.
- §2.3 `POST /cases/{id}/export` (binary `Response`, `application/zip`, `Content-Disposition`, 404/413/502 handling) → Task 2.
- §2.3 `POST /cases/{id}/evidence/{sha}` (blob, returned `media_type`, 404) → Task 3.
- §2.3 template: replace "coming soon" with Export + per-row Download POST buttons → Task 4.
- §3 routes-are-POST rationale (custody not polluted by prefetch) → satisfied by Tasks 2–4 being POST.
- **Out of scope** (deferred per spec §4): hash-chained `audit_log`, retention/GC, >64 MiB streaming, `exported_at` field, incidents.
- Note: this completes the Case ZIP export feature (slice 3 of the Cases sub-project). After merge, the Case detail panel's "coming soon" placeholder is gone and export/download are live end-to-end.
