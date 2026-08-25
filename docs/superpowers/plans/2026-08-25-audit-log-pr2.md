# Audit Log PR2 (web panel) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `/audit` web panel — paged audit trail + on-demand chain verification — per
`docs/superpowers/specs/2026-08-25-audit-log-design.md` §7 (PR2 of 2; PR1 = #148).

**Architecture:** Pure-IPC-client web route calling `list_audit_log` /
`verify_audit_log`. Verify is a POST-redirect control (house convention: POSTs for
actions so prefetch can't trigger them); the verification result renders via a query
flag after redirect. Jinja autoescape is the XSS defense.

**Tech Stack:** FastAPI + Jinja2, existing `inspectorctl.web.ipc.call`.

**Gates (before every commit):**
`.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` ·
`.venv/bin/python -m pytest -m "integration" -q` ·
`.venv/bin/ruff check inspectord inspectorctl tests` ·
`.venv/bin/ruff format --check inspectord inspectorctl tests` · `.venv/bin/mypy inspectord`

**Verified facts:**
- IPC responses: `list_audit_log` → `{schema_version, ok, rows: [{seq, ts, actor,
  action, target, details}]}` newest-first, limit clamp 1..500 (default 100).
  `verify_audit_log` → `{schema_version, ok, verification: {ok, rows, first_bad_seq,
  reason, anchor_checked, last_good, first_bad}}`.
- Route pattern to mirror: `inspectorctl/web/routes/entity.py` (shell, no feed split)
  and the POST pattern in `inspectorctl/web/routes/cases.py` / `alerts.py`
  (POST → `RedirectResponse(status_code=303)`).
- Router registration in `inspectorctl/web/app.py`; nav links live in `base.html`
  (check how other panels appear there and mirror).
- Web tests: `tests/web/` w/ the `ipc_factory` fixture (real IpcServer + stub Methods);
  see `tests/web/test_entity.py` for the current style.

---

### Task 1: Route + template + nav

**Files:**
- Create: `inspectorctl/web/routes/audit.py`, `inspectorctl/web/templates/audit.html`
- Modify: `inspectorctl/web/app.py` (register router), `inspectorctl/web/templates/base.html` (nav link, mirroring neighbors)
- Test: `tests/web/test_audit.py`

- [ ] **Step 1: Failing tests** (adapt to the `ipc_factory` fixture style in
`tests/web/test_entity.py`):

```python
def test_audit_page_lists_rows(...):
    # stub list_audit_log -> ok with 2 rows (seq 2 newest first)
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert "alert_acked" in resp.text and "user:local" in resp.text

def test_audit_page_daemon_down_banner(...):
    resp = client.get("/audit")   # dead socket
    assert resp.status_code == 200 and "daemon unreachable" in resp.text

def test_verify_post_redirects_and_renders_ok(...):
    # stub verify_audit_log -> verification ok=True, rows=5, anchor_checked=True
    resp = client.post("/audit/verify", follow_redirects=True)
    assert resp.status_code == 200
    assert "chain consistent" in resp.text.lower()

def test_verify_post_renders_break_guidance(...):
    # stub verification ok=False, first_bad_seq=3, reason="row_hash_mismatch",
    # last_good={"seq":2,...}, first_bad={"seq":3,...}
    resp = client.post("/audit/verify", follow_redirects=True)
    assert "untrusted" in resp.text          # spec §7 break guidance
    assert "3" in resp.text and "row_hash_mismatch" in resp.text

def test_audit_page_escapes_hostile_values(...):
    # stub a row with target='<script>alert(1)</script>'
    assert "<script>alert(1)" not in resp.text
    assert "&lt;script&gt;" in resp.text
```

- [ ] **Step 2: Verify red** (404s).

- [ ] **Step 3: Implement `routes/audit.py`:**

```python
"""GET /audit + POST /audit/verify — audit trail panel (spec §7, PR2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    verified: str | None = Query(default=None),
) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    rows: list[dict[str, Any]] = []
    verification: dict[str, Any] | None = None
    error: str | None = None
    try:
        result = call(socket_path, "list_audit_log", {"limit": limit})
        rows = result.get("rows", [])
        if verified is not None:
            vres = call(socket_path, "verify_audit_log", {})
            verification = vres.get("verification")
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "request": request,
            "title": "inspectord — Audit log",
            "current_path": "/audit",
            "rows": rows,
            "verification": verification,
            "error": error,
        },
    )


@router.post("/audit/verify")
def audit_verify(request: Request) -> RedirectResponse:
    return RedirectResponse(url="/audit?verified=1", status_code=303)
```

(POST-redirect keeps the verify user-initiated and un-prefetchable; the GET performs
the actual verify only when the `verified` flag is present — read-only IPC, so running
it on the redirected GET is safe and keeps state out of the web tier.)

- [ ] **Step 4: `audit.html`** — mirror an existing panel shell (`entity.html`
conventions; autoescape, no `|safe`):

```html
{% extends "base.html" %}
{% block content %}
<h1>Audit log</h1>
{% if verification %}
  {% if verification.ok %}
  <div class="ok">✓ Chain consistent — {{ verification.rows }} rows
    {% if verification.anchor_checked %}(anchor checked){% endif %}</div>
  {% else %}
  <div class="error">✗ Chain BROKEN at seq {{ verification.first_bad_seq }}
    ({{ verification.reason }}). Rows from seq {{ verification.first_bad_seq }} onward
    are untrusted; cross-check the event journal and backups.
    {% if verification.last_good %}Last good row: seq {{ verification.last_good.seq }}
    at {{ verification.last_good.ts }} ({{ verification.last_good.action }}).{% endif %}
  </div>
  {% endif %}
{% endif %}
<form method="post" action="/audit/verify"><button type="submit">Verify chain</button></form>
{% if rows %}
<table>
  <thead><tr><th>Seq</th><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
  <tbody>
    {% for r in rows %}
    <tr>
      <td class="mono">{{ r.seq }}</td>
      <td class="mono muted">{{ r.ts }}</td>
      <td class="mono">{{ r.actor }}</td>
      <td>{{ r.action }}</td>
      <td class="mono">{{ r.target or '' }}</td>
      <td class="mono muted">{{ r.details if r.details else '' }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<div class="empty">No audit rows yet.</div>
{% endif %}
{% endblock %}
```

Register the router in `app.py`; add the nav link in `base.html` beside the other
panels (mirror the exact markup).

- [ ] **Step 5: Tests + full gates.** PASS.
- [ ] **Step 6: Commit** — `feat(web): /audit panel with chain verification`

---

### Task 2: Ship PR2

- [ ] Full gates.
- [ ] `git push -u origin audit-log-pr2`; `gh pr create` — title
`feat(web): audit log panel (PR2)`; body links spec + #148; standard footer.
- [ ] Monitor poll loop for CI (not `--watch`), `gh pr merge --squash --delete-branch`,
sync main.
