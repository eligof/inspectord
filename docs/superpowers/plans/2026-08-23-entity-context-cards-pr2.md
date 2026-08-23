# Entity Context Cards PR2 (web) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Web surface for entity context cards — `/entity/{kind}?key=...` page + entity
links from existing panels, per
`docs/superpowers/specs/2026-08-23-entity-context-cards-design.md` §5 (PR2 of 2; PR1
shipped the daemon side in #146).

**Architecture:** The web app stays a pure IPC client. One new route module calls the
`get_entity_card` IPC method and renders `entity.html`. Panel feed templates get plain
`<a>` links to entity pages via a shared Jinja macro. Small daemon addition rides along:
three read handlers return the current `boot_id` so templates can build process keys.

**Tech Stack:** FastAPI + Jinja2 (autoescape on), line-JSON IPC, pytest + httpx.

**Gates (before every commit):**
`.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` ·
`.venv/bin/python -m pytest -m "integration" -q` ·
`.venv/bin/ruff check inspectord inspectorctl tests` ·
`.venv/bin/ruff format --check inspectord inspectorctl tests` · `.venv/bin/mypy inspectord`

**Verified facts:**
- `get_entity_card` IPC (PR1): params `{kind, key, window_h?}` → `{schema_version, ok,
  card}` or `{schema_version, ok: False, error: "invalid_kind"|"invalid_key"}`. Card =
  `{kind, key, found, header, events, alerts, related, warnings}`; related items =
  `{kind, key, label, relation}`; alerts items include `alert_id`, `rendered_short`;
  events items = `{event_id, ts, module, action, severity, payload}`.
- Valid kinds: process, executable, user, ip, file, port, service, device. Process key
  `<pid>@<boot_id>`; port key `<addr>:<port>/<proto>`.
- Web route pattern: `inspectorctl/web/routes/processes.py` (templates from
  `request.app.state.templates`, socket from `request.app.state.socket_path`,
  `from inspectorctl.web.ipc import WebIpcError, call`, error-banner-in-page style).
- `handle_list_processes` (`inspectord/state/ipc_handlers.py:~113`) returns rows WITHOUT
  boot_id; `handle_list_connections` rows have pid, no boot; `handle_list_devices`
  SELECTs `dev_key` (check whether the row dict includes it; add if not).
- `inspectord.state.reconcile.current_boot_id()` raises OSError-family on failure.
- Feed templates and their cells: `processes_feed.html` (pid/comm/ppid...),
  `network_feed.html` (pid, saddr:sport, daddr:dport), `services_feed.html` (unit),
  `devices_feed.html` (vendor/product/serial/devnode — NO dev_key cell),
  `file_integrity_feed.html` (path). Shared macros live in `_macros.html`.

---

### Task 1: Daemon — current boot_id in list responses

**Files:**
- Modify: `inspectord/state/ipc_handlers.py` (`handle_list_processes`,
  `handle_list_connections`), `inspectord/alerts/ipc_handlers.py` (`handle_get_alert`)
- Test: `tests/state/test_ipc_handlers.py`, plus the get_alert test file (find with
  `grep -rln handle_get_alert tests/`)

- [ ] **Step 1: Failing tests** — for each of the three handlers, assert the response
carries a top-level `"boot_id"` that is a non-empty string (the handlers run on a real
Linux box in tests, so `current_boot_id()` succeeds; don't mock it):

```python
def test_list_processes_includes_boot_id(tmp_path):
    db_path = _fresh(tmp_path)
    out = handle_list_processes(params={}, db_path=db_path)
    assert isinstance(out["boot_id"], str) and out["boot_id"]
```

(same shape for `handle_list_connections`; for `handle_get_alert` use its existing
fixture that seeds an alert, and assert on a successful response.)

- [ ] **Step 2: Run to verify failure** (KeyError: 'boot_id').

- [ ] **Step 3: Implement** — one tiny shared helper in
`inspectord/state/ipc_handlers.py`:

```python
def _current_boot_id_or_none() -> str | None:
    try:
        return current_boot_id()
    except OSError:
        return None
```

(import `current_boot_id` from `inspectord.state.reconcile`; the alerts handler imports
the helper from `inspectord.state.ipc_handlers`). Add
`"boot_id": _current_boot_id_or_none()` to the three response dicts.

- [ ] **Step 4: Gates.** All green.
- [ ] **Step 5: Commit** — `feat(state): expose current boot_id in list/get IPC responses`

---

### Task 2: Entity page — route + template

**Files:**
- Create: `inspectorctl/web/routes/entity.py`, `inspectorctl/web/templates/entity.html`
- Modify: wherever routers are registered (grep `include_router` under
  `inspectorctl/web/` and mirror the existing list)
- Test: new web test file mirroring the existing web test style (find them with
  `grep -rln "create_app" tests/ | head`)

- [ ] **Step 1: Failing tests** (adapt to the house web-test fixture, which fakes IPC —
read how existing web tests stub `call`/the socket before writing these):

```python
def test_entity_page_renders_card(...):
    # stub IPC get_entity_card -> ok card with one related entity + one alert
    resp = client.get("/entity/process", params={"key": "42@boot-1"})
    assert resp.status_code == 200
    assert "42@boot-1" in resp.text
    assert "/entity/ip?key=9.9.9.9" in resp.text          # related link
    assert "/alerts/a1" in resp.text                       # alert link

def test_entity_page_unknown_kind_404(...):
    resp = client.get("/entity/nonsense", params={"key": "x"})
    assert resp.status_code == 404

def test_entity_page_invalid_key_shows_error(...):
    # stub IPC -> {"ok": False, "error": "invalid_key"}
    resp = client.get("/entity/process", params={"key": "bad"})
    assert resp.status_code == 200 and "invalid_key" in resp.text

def test_entity_page_daemon_down_banner(...):
    # stub call to raise WebIpcError
    resp = client.get("/entity/service", params={"key": "sshd.service"})
    assert resp.status_code == 200 and "daemon unreachable" in resp.text

def test_entity_page_escapes_hostile_values(...):
    # stub card with header comm = '<script>alert(1)</script>'
    assert "<script>alert(1)" not in resp.text
    assert "&lt;script&gt;" in resp.text
```

- [ ] **Step 2: Verify failure** (404 on all — route absent).

- [ ] **Step 3: Implement route** `inspectorctl/web/routes/entity.py`:

```python
"""GET /entity/{kind} — entity context card page (spec §5, PR2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from inspectorctl.web.ipc import WebIpcError, call

router = APIRouter()

_KINDS = frozenset(
    {"process", "executable", "user", "ip", "file", "port", "service", "device"}
)


@router.get("/entity/{kind}", response_class=HTMLResponse)
def entity_page(
    request: Request,
    kind: str,
    key: str = Query(min_length=1, max_length=512),
    window_h: int = Query(default=24, ge=1, le=168),
) -> _TemplateResponse:
    if kind not in _KINDS:
        raise HTTPException(status_code=404, detail="unknown entity kind")
    templates: Jinja2Templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    card: dict[str, Any] | None = None
    error: str | None = None
    try:
        result = call(
            socket_path, "get_entity_card",
            {"kind": kind, "key": key, "window_h": window_h},
        )
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        if result.get("ok"):
            card = result.get("card")
        else:
            error = str(result.get("error", "unknown error"))
    return templates.TemplateResponse(
        request,
        "entity.html",
        {
            "request": request,
            "title": f"inspectord — {kind}:{key}",
            "current_path": "/entity",
            "kind": kind,
            "key": key,
            "window_h": window_h,
            "card": card,
            "error": error,
        },
    )
```

Register the router exactly like the neighbors (grep `include_router`).

- [ ] **Step 4: Implement `entity.html`** — mirror an existing page template's shell
(read `services.html` and `base.html` first for the real extends/block names; this page
has NO feed split). Sections, all autoescaped (no `|safe` anywhere):

```html
{% extends "base.html" %}
{% block content %}
<h1><span class="muted">{{ kind }}:</span> <span class="mono">{{ key }}</span></h1>
{% if error %}<div class="error">⚠ {{ error }}</div>{% endif %}
{% if card %}
  {% if card.warnings %}
  <div class="error">⚠ degraded sections: {{ card.warnings | join(", ") }}</div>
  {% endif %}
  {% if not card.found %}
  <div class="empty">No current state for this entity — showing history only.</div>
  {% endif %}

  <h2>Identity</h2>
  <table><tbody>
    {% for k, v in card.header.items() %}
    <tr><th>{{ k }}</th><td class="mono">{{ v if v is not none else '' }}</td></tr>
    {% endfor %}
  </tbody></table>

  <h2>Related entities</h2>
  {% if card.related %}
  <table><thead><tr><th>Relation</th><th>Kind</th><th>Entity</th></tr></thead><tbody>
    {% for r in card.related %}
    <tr>
      <td>{{ r.relation }}</td><td>{{ r.kind }}</td>
      <td><a class="mono" href="/entity/{{ r.kind }}?key={{ r.key | urlencode }}">{{ r.label }}</a></td>
    </tr>
    {% endfor %}
  </tbody></table>
  {% else %}<div class="empty">None.</div>{% endif %}

  <h2>Alerts</h2>
  {% if card.alerts %}
  <table><thead><tr><th>When</th><th>Rule</th><th>Severity</th><th>Status</th><th>Summary</th></tr></thead><tbody>
    {% for a in card.alerts %}
    <tr>
      <td class="mono muted">{{ a.ts or '' }}</td>
      <td class="mono"><a href="/alerts/{{ a.alert_id | urlencode }}">{{ a.rule_id }}</a></td>
      <td>{{ a.severity }}</td><td>{{ a.status }}</td><td>{{ a.rendered_short }}</td>
    </tr>
    {% endfor %}
  </tbody></table>
  {% else %}<div class="empty">No alerts reference this entity.</div>{% endif %}

  <h2>Events (last {{ window_h }}h)</h2>
  {% if card.events %}
  <table><thead><tr><th>When</th><th>Module</th><th>Action</th><th>Severity</th></tr></thead><tbody>
    {% for e in card.events %}
    <tr>
      <td class="mono muted">{{ e.ts or '' }}</td>
      <td class="mono">{{ e.module }}</td>
      <td>{{ e.action }}</td><td>{{ e.severity }}</td>
    </tr>
    {% endfor %}
  </tbody></table>
  {% else %}<div class="empty">No events in the window.</div>{% endif %}
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Run tests, then gates.** All green.
- [ ] **Step 6: Commit** — `feat(web): entity context card page`

---

### Task 3: Panel links

**Files:**
- Modify: `inspectorctl/web/templates/_macros.html` + the feed templates below; routes
  only where a template needs data it doesn't get (boot_id)
- Test: extend the existing per-panel web tests (find them via
  `grep -rln "processes_feed\|/processes" tests/`)

- [ ] **Step 1: Macro** — add to `_macros.html` (mirror its existing macro style):

```html
{% macro entity_link(kind, key, label) -%}
<a class="mono" href="/entity/{{ kind }}?key={{ key | urlencode }}">{{ label }}</a>
{%- endmacro %}
```

- [ ] **Step 2: Failing tests** — one per panel: the feed response contains an
`/entity/...` link for a seeded row (stubbed IPC). Example assertion:
`'/entity/service?key=sshd.service' in resp.text`.

- [ ] **Step 3: Wire links** (import the macro the way other feed templates import from
`_macros.html`):
- `processes_feed.html`: pid cell → `entity_link("process", p.pid ~ "@" ~ boot_id, p.pid)`
  only when `boot_id` is truthy (from the `list_processes` response's new top-level
  `boot_id`; plain text fallback otherwise). Modify `routes/processes.py` to pass
  `boot_id` through the template context.
- `network_feed.html`: daddr cell → `entity_link("ip", c.daddr, c.daddr ~ ":" ~ c.dport)`;
  pid cell → process link with `boot_id` from the `list_connections` response (route
  passes it through), plain text fallback.
- `services_feed.html`: unit cell → `entity_link("service", s.unit, s.unit)`.
- `devices_feed.html`: devnode cell (vendor cell if devnode empty is fine too) →
  `entity_link("device", d.dev_key, d.devnode or d.dev_key)` — requires `dev_key` in the
  `list_devices` row dicts; verify it is there and add it to the handler + its test if not.
- `file_integrity_feed.html`: path cell → `entity_link("file", f.path, f.path)`.
- Listeners (spec §5): grep `list_listeners` under `inspectorctl/web/` — if the network
  panel renders a listeners table, link each row's port cell via
  `entity_link("port", addr ~ ":" ~ port ~ "/" ~ proto, ...)`. If no listener table is
  rendered anywhere, note that in the commit message and skip (nothing to link).
- `alert_detail.html` (spec §5): read the template + its route first. Where the alert's
  payload fields are rendered, add entity links for the fields present:
  `process.pid` → process card using the `boot_id` now returned by `get_alert` (Task 1;
  plain text if boot_id missing), `destination.ip` → ip card, `file.path` → file card,
  `service.name` → service card. If the template renders payload as one opaque JSON
  blob rather than fields, add a small "Entities" link row above it instead of rewriting
  the blob rendering.

- [ ] **Step 4: Run tests + gates.** Green.
- [ ] **Step 5: Commit** — `feat(web): entity links from panel feeds`

---

### Task 4: Ship PR2

- [ ] Full gates (unit + integration + ruff + format + mypy).
- [ ] `git push -u origin entity-context-cards-pr2`
- [ ] `gh pr create` — title `feat(web): entity context cards — page + panel links (PR2)`;
  body: links spec, notes PR1 #146, standard footer.
- [ ] `gh pr checks <N> --watch` → `gh pr merge <N> --squash --delete-branch` →
  `git checkout main && git pull --ff-only`.
