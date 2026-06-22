# Cases web panel (PR9) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. TDD throughout: write tests first, watch fail, implement, watch pass, run gates, commit.

**Goal:** Ship the Cases web panel — a `/cases` list + `/cases/{id}` detail (add-note, close), plus "Open case" and "Attach to case" actions on the alert detail page — completing sub-project 3 v1.

**Architecture:** Mirrors the existing web routes (FastAPI + Jinja2, `call(socket_path, method, params)` IPC, 303-redirect POSTs). Cases is NOT an htmx auto-refresh feed (user-driven), so plain GET pages + redirect-after-POST. Backend IPC (PR8, merged) provides `open_case`/`attach_alert`/`add_note`/`close_case`/`list_cases`/`get_case`.

**Tech Stack:** FastAPI (incl. `Form(...)` for the note/case_id form fields), Jinja2 (autoescape on), htmx not used here, pytest + `TestClient`.

**Spec:** `docs/superpowers/specs/2026-06-21-cases-panel-design.md` §6 (web panel — has the exact routes/behaviours), §1.1 (v1 is not tamper-evident), §8 (tests incl. the `<script>`-escaping test). This PR = spec §7 "PR9".

**Gates (run from repo root, all must pass before done):**
- `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- `.venv/bin/ruff check inspectorctl tests` · `.venv/bin/ruff format --check inspectorctl tests`
- `.venv/bin/mypy inspectord`

**Branch:** `feat/cases-panel` (already checked out; spec + this plan ride along).

**Key codebase facts:**
- IPC from web: `from inspectorctl.web.ipc import WebIpcError, call`; `call(socket_path, method, params)` returns the result dict (so `call(...)["case_id"]` works). On failure raises `WebIpcError`.
- Pattern for a read page: see `inspectorctl/web/routes/services.py` (`GET /services` shell) and the alerts list. Pattern for a POST → redirect: `_mutate` in `inspectorctl/web/routes/alerts.py` (302/303 + `HTTPException(502)` on `WebIpcError`).
- Web tests: `tests/web/conftest.py` `ipc_factory([Method(...)])` spins a real `IpcServer` with mock methods + a `TestClient`. Register every IPC method the page calls. See `tests/web/test_services.py` / `test_alerts.py`.
- `get_case` returns `{"case": {case_id,title,status,opened_at,closed_at,alerts:[{alert_id,rule_id,severity,status,rendered_short,ts}],timeline:[{ts,seq,kind,text}]}|None}`. `list_cases` → `{"cases":[{case_id,title,status,opened_at,closed_at,alert_count}]}`.

---

## File structure
- Create: `inspectorctl/web/routes/cases.py`, `inspectorctl/web/templates/cases.html`, `inspectorctl/web/templates/case_detail.html`
- Modify: `inspectorctl/web/app.py` (register router), `inspectorctl/web/templates/base.html` (nav link), `inspectorctl/web/routes/alerts.py` (two new POST routes + pass open-cases to the detail template), `inspectorctl/web/templates/alert_detail.html` (Case actions block)
- Test: `tests/web/test_cases.py`; additions to `tests/web/test_alerts.py`

---

## Task 1: Cases panel — list + detail + note/close POSTs

**Files:** Create `inspectorctl/web/routes/cases.py`, `cases.html`, `case_detail.html`; Modify `app.py`, `base.html`; Test `tests/web/test_cases.py`.

- [ ] **Step 1: Write failing tests** `tests/web/test_cases.py` (mirror `tests/web/test_services.py` style; use `ipc_factory` + `from inspectord.ipc_server import Method`).

Helper mock methods:
```python
def _list_cases(cases):
    return Method(name="list_cases", handler=lambda params: {"schema_version": "1.0.0", "cases": cases}, mutates=False)

def _get_case(case):
    return Method(name="get_case", handler=lambda params: {"schema_version": "1.0.0", "case": case}, mutates=False)
```
A sample case for detail:
```python
CASE = {
    "case_id": "c1", "title": "sshd brute force", "status": "open",
    "opened_at": "2026-06-20T00:00:00", "closed_at": None,
    "alerts": [{"alert_id": "a1", "rule_id": "auth.ssh", "severity": "high",
                "status": "new", "rendered_short": "brute force", "ts": "2026-06-20T00:00:00"}],
    "timeline": [{"ts": "2026-06-20T00:00:00", "seq": 0, "kind": "opened", "text": None},
                 {"ts": "2026-06-20T00:00:00", "seq": 1, "kind": "alert_attached", "text": "a1"}],
}
```
Tests:
- `GET /cases` with `_list_cases([{case_id,title,status,opened_at,alert_count}])` → 200, the title appears, a link to `/cases/c1` appears.
- `GET /cases` with `_list_cases([])` → 200, "No cases yet".
- `GET /cases` daemon-unreachable: `create_app(socket_path=tmp_path/"no.sock")` → 200, "daemon unreachable".
- `GET /cases/c1` with `_get_case(CASE)` → 200; title, the linked alert (`a1` + `/alerts/a1`), and timeline kinds (`opened`, `alert_attached`) appear; the add-note form (`/cases/c1/notes`) and Close button (`/cases/c1/close`) present.
- `GET /cases/missing` with `_get_case(None)` → 404.
- **escaping:** `_get_case` with a timeline note `{"kind":"note","text":"<script>alert(1)</script>", ...}` → the raw `<script>alert(1)</script>` is NOT in the response, the escaped `&lt;script&gt;` IS.
- add-note POST: `client.post("/cases/c1/notes", data={"text":"hi"}, follow_redirects=False)` → 303, `Location` is `/cases/c1`; the mocked `add_note` recorded `params` with `case_id=="c1"` and `text=="hi"`.
- close POST: `client.post("/cases/c1/close", follow_redirects=False)` → 303 to `/cases/c1`; mocked `close_case` recorded `case_id=="c1"`.

(For the POST tests, register recording mocks, e.g. `add_note` whose handler appends `params` to a list and returns `{"schema_version":"1.0.0","ok":True}`.)

- [ ] **Step 2: Run — expect failure** (404s).
- [ ] **Step 3: Implement `inspectorctl/web/routes/cases.py`:**

```python
"""GET /cases, GET /cases/{id}, POST notes/close."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()


@router.get("/cases", response_class=HTMLResponse)
def cases_list(request: Request) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    cases: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(request.app.state.socket_path, "list_cases", {})
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        cases = result.get("cases", [])
    return templates.TemplateResponse(
        request,
        "cases.html",
        {"request": request, "title": "inspectord — Cases", "current_path": "/cases",
         "cases": cases, "error": error},
    )


@router.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(request: Request, case_id: str) -> _TemplateResponse:
    templates: Jinja2Templates = request.app.state.templates
    try:
        result = call(request.app.state.socket_path, "get_case", {"case_id": case_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    case = result.get("case")
    if case is None:
        raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
    return templates.TemplateResponse(
        request,
        "case_detail.html",
        {"request": request, "title": f"inspectord — Case {case_id[:8]}",
         "current_path": "/cases", "case": case},
    )


def _case_mutate(socket_path: Any, method: str, params: dict[str, Any], case_id: str) -> RedirectResponse:
    try:
        call(socket_path, method, params)
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


@router.post("/cases/{case_id}/notes")
def case_add_note(request: Request, case_id: str, text: str = Form(...)) -> RedirectResponse:
    return _case_mutate(request.app.state.socket_path, "add_note",
                        {"case_id": case_id, "text": text}, case_id)


@router.post("/cases/{case_id}/close")
def case_close(request: Request, case_id: str) -> RedirectResponse:
    return _case_mutate(request.app.state.socket_path, "close_case",
                        {"case_id": case_id}, case_id)
```

- [ ] **Step 4: Templates.**

`inspectorctl/web/templates/cases.html`:
```html
{% extends "base.html" %}
{% from "_macros.html" import status_badge %}
{% block content %}
<h1>Cases</h1>
{% if error %}
<div class="error">⚠ {{ error }}</div>
{% elif cases %}
<table>
  <thead><tr><th>Title</th><th>Status</th><th>Alerts</th><th>Opened</th></tr></thead>
  <tbody>
    {% for c in cases %}
    <tr>
      <td><a href="/cases/{{ c.case_id }}">{{ c.title }}</a></td>
      <td>{{ status_badge(c.status) }}</td>
      <td class="mono">{{ c.alert_count }}</td>
      <td class="mono muted">{{ c.opened_at }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<div class="empty">No cases yet. Open one from an alert.</div>
{% endif %}
{% endblock %}
```

`inspectorctl/web/templates/case_detail.html`:
```html
{% extends "base.html" %}
{% from "_macros.html" import severity_badge, status_badge %}
{% block content %}
<h1>{{ case.title }}</h1>
<p>{{ status_badge(case.status) }} <span class="mono muted">opened {{ case.opened_at }}</span></p>

<h2>Alerts</h2>
{% if case.alerts %}
<table>
  <thead><tr><th>Alert</th><th>Rule</th><th>Severity</th><th>Summary</th></tr></thead>
  <tbody>
    {% for a in case.alerts %}
    <tr>
      <td class="mono"><a href="/alerts/{{ a.alert_id }}">{{ a.alert_id[:8] }}…</a></td>
      <td class="mono">{{ a.rule_id or '—' }}</td>
      <td>{{ severity_badge(a.severity) if a.severity else '—' }}</td>
      <td>{{ a.rendered_short or '(alert no longer available)' }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<div class="empty">No alerts linked.</div>
{% endif %}

<h2>Timeline</h2>
<table>
  <thead><tr><th>Time</th><th>Event</th><th>Detail</th></tr></thead>
  <tbody>
    {% for t in case.timeline %}
    <tr><td class="mono muted">{{ t.ts }}</td><td>{{ t.kind }}</td><td>{{ t.text or '' }}</td></tr>
    {% endfor %}
  </tbody>
</table>

{% if case.status == "open" %}
<div class="actions">
  <form method="post" action="/cases/{{ case.case_id }}/notes">
    <input type="text" name="text" placeholder="Add a note" required>
    <button type="submit">Add note</button>
  </form>
  <form method="post" action="/cases/{{ case.case_id }}/close">
    <button type="submit">Close case</button>
  </form>
</div>
{% endif %}
{% endblock %}
```

(`a.alert_id[:8]` is safe — alert_id is always present even for pruned-alert placeholder rows.)

- [ ] **Step 5: Wire.** In `inspectorctl/web/app.py` add `cases` to the `from inspectorctl.web.routes import ...` line and `app.include_router(cases.router)`. In `base.html`, add `{{ nav_link("/cases", "Cases", current_path) }}` after the Persistence link.
- [ ] **Step 6: Run tests — expect pass.** Then run the full gate set.
- [ ] **Step 7: Commit.** `feat(web): Cases panel — list + detail + note/close`.

---

## Task 2: Alert-detail "Open case" + "Attach to case" actions

**Files:** Modify `inspectorctl/web/routes/alerts.py`, `inspectorctl/web/templates/alert_detail.html`; Test additions to `tests/web/test_alerts.py`.

- [ ] **Step 1: Write failing tests** in `tests/web/test_alerts.py` (the file already mocks `get_alert`; the alert-detail page will now ALSO call `list_cases`, so register a `list_cases` mock too). The alert dict shape `get_alert` returns must match what `alert_detail.html` already reads (copy an existing alert mock in that file).
  - "Open case" POST: register `open_case` returning `{"schema_version":"1.0.0","case_id":"c9"}`; `client.post("/alerts/a1/open-case", follow_redirects=False)` → 303, `Location == "/cases/c9"`; mocked `open_case` recorded `params["alert_id"]=="a1"`.
  - "Attach to case" POST: register a recording `attach_alert`; `client.post("/alerts/a1/attach-case", data={"case_id":"c1"}, follow_redirects=False)` → 303, `Location == "/alerts/a1"`; recorded `case_id=="c1"`, `alert_id=="a1"`.
  - alert detail renders the case actions: `GET /alerts/a1` (with `get_alert` + a `list_cases` returning one open case) → the "Open case" form (`/alerts/a1/open-case`) and an "Attach to case" form (`/alerts/a1/attach-case`) with the open case as an option appear.

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement** in `inspectorctl/web/routes/alerts.py`:
  - Add `Form` to the fastapi import. Add two routes:

```python
@router.post("/alerts/{alert_id}/open-case")
def alert_open_case(request: Request, alert_id: str) -> RedirectResponse:
    socket_path = request.app.state.socket_path
    try:
        result = call(socket_path, "open_case", {"alert_id": alert_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    case_id = result["case_id"]
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


@router.post("/alerts/{alert_id}/attach-case")
def alert_attach_case(request: Request, alert_id: str, case_id: str = Form(...)) -> RedirectResponse:
    try:
        call(request.app.state.socket_path, "attach_alert", {"case_id": case_id, "alert_id": alert_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url=f"/alerts/{alert_id}", status_code=303)
```
  - In `alert_detail`, fetch open cases for the attach picker (best-effort; an error here must not break the page):

```python
    open_cases: list[dict[str, Any]] = []
    try:
        cresult = call(socket_path, "list_cases", {})
    except WebIpcError:
        open_cases = []
    else:
        open_cases = [c for c in cresult.get("cases", []) if c.get("status") == "open"]
```
    and pass `"open_cases": open_cases` in the template context.

- [ ] **Step 4: Template** — in `alert_detail.html`, add a Case-actions block (always shown, regardless of alert status — you can open a case from any alert), after the existing `actions` block / before `</div>`:

```html
  <h2>Case</h2>
  <div class="actions">
    <form method="post" action="/alerts/{{ alert.alert_id }}/open-case">
      <button type="submit">Open case</button>
    </form>
    {% if open_cases %}
    <form method="post" action="/alerts/{{ alert.alert_id }}/attach-case">
      <select name="case_id" required>
        {% for c in open_cases %}
        <option value="{{ c.case_id }}">{{ c.title }}</option>
        {% endfor %}
      </select>
      <button type="submit">Attach to case</button>
    </form>
    {% endif %}
  </div>
```

- [ ] **Step 5: Run tests — expect pass.** Run the full gate set (the existing alert-detail test now needs a `list_cases` mock — update any existing `GET /alerts/{id}` test in `test_alerts.py` that would otherwise fail because the page now calls `list_cases`; since `list_cases` failure is caught and degrades to no picker, a missing mock would surface as a daemon error only if the IPC server lacks the method — so add the `list_cases` mock to those tests).
- [ ] **Step 6: Commit.** `feat(web): Open case + Attach to case actions on alert detail`.

---

## Self-review checklist (before handoff)
- [ ] Spec §6 coverage: `/cases` list + empty + unreachable; `/cases/{id}` detail (alerts + timeline + add-note + close) + 404; note/close POSTs → 303; alert-detail Open case (→ `/cases/{new}`) + Attach to case (picker of open cases) → both POST + redirect; nav link; escaping test. ✓
- [ ] No `| safe` in the new templates; the `<script>`-in-note escaping test present. ✓
- [ ] `Form(...)` used for the note `text` and attach `case_id` fields. ✓
- [ ] Existing alert-detail tests updated for the new `list_cases` call. ✓
- [ ] No backend (`inspectord/`) changes (PR8 shipped the IPC). Out of scope: evidence_collector, export.
