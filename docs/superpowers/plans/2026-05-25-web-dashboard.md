# Web Dashboard (Phase 1 final slice) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the four Phase 1 dashboard panels — **Alerts** (inbox-zero triage), **Live Events** (auto-refreshing tail), **Health** (worker status), **Dependencies** (read-only status table). After this lands, `inspectorctl-web` starts a local FastAPI server bound to `127.0.0.1:8765`, the user opens the URL in any browser, and clicks `Ack`/`Resolve`/`Suppress` to drain the alerts inbox. Phase 1 of the spec is then COMPLETE.

**Architecture:** A user-mode FastAPI app (`inspectorctl/web/`) that is a thin **client** of the daemon's IPC. Each HTTP request makes one or two `IpcClient.call(method)` round-trips and renders server-side Jinja2 HTML. Live updates use HTMX `hx-trigger="every Ns"` partial swaps (no SSE in v1; HTMX is one `<script>` tag). Static assets shipped in the wheel. The app holds no persistent state — it's a pure projection of the daemon.

**Tech Stack:** Python 3.12 · FastAPI · Uvicorn · Jinja2 · HTMX (vendored as one file) · existing `inspectorctl.ipc_client.IpcClient` + daemon IPC.

**Scope discipline:** 4 panels only (of 28 in the spec). The other 24 stay in spec, deferred. CSRF, sessions, TLS deferred (always 127.0.0.1, no untrusted-browser context). No SSE (HTMX polling covers v1).

---

## Repository state at the start

`/home/eli/Development/inspectord` on `main` after PR #53. **257 tests passing.** CI green. Existing pieces this plan builds on:

- `inspectorctl/ipc_client.py` — `IpcClient(socket_path=...).call(method, params)` and `IpcError`.
- `inspectorctl/cli/{app, alerts, deps, events, status, self_test, version}.py` — patterns to follow.
- `inspectord/__main__.py` exposes the IPC methods we'll consume.
- `pyproject.toml` already has `[project.scripts]` entries; we'll add `inspectorctl-web`.
- `[tool.hatch.build.targets.wheel.force-include]` already used for migrations_data/manifest_files/templates/starter_pack. We'll add the web templates+static dirs.

## File structure produced by this plan

```
inspectorctl/web/
├── __init__.py
├── __main__.py                          # entry point: uvicorn host=127.0.0.1
├── app.py                               # FastAPI app factory
├── ipc.py                               # _client() helper + small adapter funcs
├── routes/
│   ├── __init__.py
│   ├── health.py
│   ├── deps.py
│   ├── events.py
│   └── alerts.py
├── templates/
│   ├── base.html
│   ├── _macros.html
│   ├── health.html
│   ├── deps.html
│   ├── events.html
│   ├── events_feed.html                 # HTMX-swapped partial
│   ├── alerts.html
│   └── alert_detail.html
└── static/
    ├── htmx.min.js                      # vendored HTMX
    └── styles.css

tests/
└── web/
    ├── __init__.py
    ├── conftest.py
    ├── test_health.py
    ├── test_deps.py
    ├── test_events.py
    ├── test_alerts.py
    └── test_app_bootstrap.py
```

New runtime deps in `pyproject.toml`: `fastapi>=0.115,<1`, `uvicorn[standard]>=0.30,<1`. Jinja2 is already a runtime dep from the dep_manager plan. Dev dep: `httpx>=0.27,<1` (FastAPI's TestClient needs it).

`inspectorctl-web` script entry added to `[project.scripts]`.

Total new: 11 source modules + 8 Jinja2 templates + 2 static assets + 7 test modules. **Approximately 7 PRs.**

## Workflow

Same as the prior plans. Each task lands on its own feature branch `task-web-NN-<slug>` and goes through a PR with CI gating. Squash-merge after CI green. TDD: for each route, write a failing TestClient test, then implement.

---

## Task 1: Scaffolding (pyproject + package skeleton)

**Files:**
- Modify: `pyproject.toml`
- Create: `inspectorctl/web/__init__.py`
- Create: `inspectorctl/web/static/.gitkeep`
- Create: `inspectorctl/web/templates/.gitkeep`
- Create: `inspectorctl/web/routes/__init__.py`
- Create: `tests/web/__init__.py`

**Branch:** `task-web-01-scaffold`

- [ ] **Step 1: Update pyproject**

In `/home/eli/Development/inspectord/pyproject.toml`:

1. Append to `[project] dependencies`:

```toml
    "fastapi>=0.115,<1",
    "uvicorn[standard]>=0.30,<1",
```

2. Append to dev extras:

```toml
    "httpx>=0.27,<1",
```

3. Add to `[project.scripts]`:

```toml
inspectorctl-web = "inspectorctl.web.__main__:main"
```

4. Append two entries to `[tool.hatch.build.targets.wheel.force-include]` (preserve existing ones):

```toml
"inspectorctl/web/templates" = "inspectorctl/web/templates"
"inspectorctl/web/static" = "inspectorctl/web/static"
```

- [ ] **Step 2: Reinstall**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pip install -e '.[dev]'
```

Verify versions install cleanly via `python -c "import fastapi, uvicorn, httpx"`.

- [ ] **Step 3: Create package skeleton**

```bash
mkdir -p /home/eli/Development/inspectord/inspectorctl/web/routes
mkdir -p /home/eli/Development/inspectord/inspectorctl/web/templates
mkdir -p /home/eli/Development/inspectord/inspectorctl/web/static
mkdir -p /home/eli/Development/inspectord/tests/web
touch /home/eli/Development/inspectord/inspectorctl/web/routes/__init__.py
touch /home/eli/Development/inspectord/inspectorctl/web/templates/.gitkeep
touch /home/eli/Development/inspectord/inspectorctl/web/static/.gitkeep
touch /home/eli/Development/inspectord/tests/web/__init__.py
```

Write `/home/eli/Development/inspectord/inspectorctl/web/__init__.py`:

```python
"""Local web dashboard (spec §16.4).

User-mode FastAPI app that proxies daemon IPC into a single-pane-of-glass UI.
Bound to 127.0.0.1 only; no auth, no CSRF, no TLS in v1 — those land with the
hardening pass once the dashboard ships externally.
"""
```

- [ ] **Step 4: Sanity check**

```bash
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: still 257 tests passing.

- [ ] **Step 5: Branch + commit + push + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-web-01-scaffold
git add pyproject.toml inspectorctl/web/ tests/web/
git commit -m "chore(web): add FastAPI/uvicorn deps + package scaffolding"
git push -u origin task-web-01-scaffold
gh pr create --base main --head task-web-01-scaffold \
  --title "chore(web): scaffold + FastAPI deps" \
  --body "Adds fastapi + uvicorn + httpx (test) deps, the inspectorctl/web/ package skeleton, the inspectorctl-web script entry, and the wheel force-include for templates/static. No routes yet — that's the next PRs."
```

Wait for CI green; do NOT merge.

---

## Task 2: FastAPI app factory + base template + static assets

**Files:**
- Create: `inspectorctl/web/app.py`
- Create: `inspectorctl/web/ipc.py`
- Create: `inspectorctl/web/templates/base.html`
- Create: `inspectorctl/web/templates/_macros.html`
- Create: `inspectorctl/web/static/styles.css`
- Create: `inspectorctl/web/static/htmx.min.js` (vendored)
- Create: `inspectorctl/web/routes/{health,deps,events,alerts}.py` (stubs)
- Create: `tests/web/conftest.py`
- Create: `tests/web/test_app_bootstrap.py`

**Branch:** `task-web-02-app-factory`

- [ ] **Step 1: Vendor HTMX**

Download the official HTMX library to ship in the wheel:

```bash
cd /home/eli/Development/inspectord
curl -sSL https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js \
    -o inspectorctl/web/static/htmx.min.js
test -s inspectorctl/web/static/htmx.min.js && wc -c inspectorctl/web/static/htmx.min.js
```

Expected: a file ~40 KB containing the HTMX 2.0.4 minified library.

If the network is unavailable, fetch from any local cache or use a more recent HTMX version — any 2.x release works. Confirm the file is non-empty and contains the substring `htmx`.

- [ ] **Step 2: Write styles.css**

Write `/home/eli/Development/inspectord/inspectorctl/web/static/styles.css`:

```css
:root {
  --bg: #0e1116;
  --panel: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --muted: #8b949e;
  --link: #58a6ff;
  --critical: #ff6b6b;
  --high: #ffa657;
  --medium: #79c0ff;
  --low: #a371f7;
  --info: #8b949e;
  --ok: #2ea043;
  --bad: #f85149;
}
* { box-sizing: border-box; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  margin: 0;
  font-size: 14px;
  line-height: 1.5;
}
nav {
  background: var(--panel);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
  display: flex;
  gap: 18px;
  align-items: center;
}
nav a {
  color: var(--text);
  text-decoration: none;
  padding: 6px 10px;
  border-radius: 6px;
}
nav a:hover { background: rgba(255,255,255,0.04); }
nav a.active { background: var(--border); color: #fff; }
main { max-width: 1280px; margin: 24px auto; padding: 0 24px; }
h1 { font-size: 20px; margin: 0 0 16px 0; }
h2 { font-size: 16px; margin: 24px 0 8px 0; color: var(--muted); }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
th { color: var(--muted); font-weight: 500; font-size: 12px; text-transform: uppercase; }
td.mono { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
.sev-critical { background: rgba(255,107,107,0.15); color: var(--critical); }
.sev-high { background: rgba(255,166,87,0.15); color: var(--high); }
.sev-medium { background: rgba(121,192,255,0.15); color: var(--medium); }
.sev-low { background: rgba(163,113,247,0.15); color: var(--low); }
.sev-info { background: rgba(139,148,158,0.15); color: var(--info); }
.status-new { background: rgba(255,166,87,0.15); color: var(--high); }
.status-acknowledged { background: rgba(121,192,255,0.15); color: var(--medium); }
.status-resolved { background: rgba(46,160,67,0.15); color: var(--ok); }
.status-suppressed { background: rgba(139,148,158,0.15); color: var(--muted); }
.muted { color: var(--muted); }
.bad { color: var(--bad); }
.ok { color: var(--ok); }
button, input[type=submit] {
  background: var(--panel); color: var(--text);
  border: 1px solid var(--border); padding: 6px 12px;
  border-radius: 6px; font-size: 13px; cursor: pointer;
}
button:hover { border-color: var(--link); color: #fff; }
input[type=text] {
  background: var(--panel); border: 1px solid var(--border);
  padding: 6px 10px; border-radius: 6px; color: var(--text);
  font-size: 13px; font-family: inherit;
}
.empty { padding: 32px; text-align: center; color: var(--muted); border: 1px dashed var(--border); border-radius: 8px; }
.filter-bar { display: flex; gap: 12px; margin-bottom: 16px; align-items: center; }
.detail { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }
.detail pre { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; font-size: 12px; }
.actions { display: flex; gap: 8px; margin-top: 16px; }
.actions form { display: inline; }
.error { background: rgba(248,81,73,0.1); border: 1px solid var(--bad); color: var(--bad); padding: 12px; border-radius: 6px; margin: 16px 0; }
```

- [ ] **Step 3: IPC adapter**

Write `inspectorctl/web/ipc.py`:

```python
"""Thin adapter so routes never touch IpcClient directly.

Centralising the calls makes future swaps (e.g. async IPC) a one-place change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inspectorctl.ipc_client import IpcClient, IpcError


class WebIpcError(RuntimeError):
    """Raised when the daemon isn't reachable or returns an RPC error."""


def call(socket_path: Path, method: str, params: dict[str, Any] | None = None) -> Any:
    try:
        return IpcClient(socket_path=Path(socket_path)).call(method, params)
    except IpcError as exc:
        raise WebIpcError(str(exc)) from exc
```

- [ ] **Step 4: Macros template**

Write `inspectorctl/web/templates/_macros.html`:

```html
{% macro severity_badge(value) -%}
<span class="badge sev-{{ value }}">{{ value }}</span>
{%- endmacro %}

{% macro status_badge(value) -%}
<span class="badge status-{{ value }}">{{ value }}</span>
{%- endmacro %}

{% macro nav_link(href, label, current) -%}
<a href="{{ href }}" class="{{ 'active' if current == href else '' }}">{{ label }}</a>
{%- endmacro %}
```

- [ ] **Step 5: Base layout**

Write `inspectorctl/web/templates/base.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ title or "inspectord" }}</title>
  <link rel="stylesheet" href="/static/styles.css">
  <script src="/static/htmx.min.js" defer></script>
</head>
<body>
  {%- from "_macros.html" import nav_link %}
  <nav>
    <strong>inspectord</strong>
    {{ nav_link("/alerts", "Alerts", current_path) }}
    {{ nav_link("/events", "Live events", current_path) }}
    {{ nav_link("/health", "Health", current_path) }}
    {{ nav_link("/deps", "Dependencies", current_path) }}
  </nav>
  <main>
    {%- if error %}
    <div class="error">⚠ {{ error }}</div>
    {%- endif %}
    {% block content %}{% endblock %}
  </main>
</body>
</html>
```

- [ ] **Step 6: Stub the four route modules**

Write `inspectorctl/web/routes/__init__.py`:

```python
"""Route modules for the web dashboard."""
```

For each of `health.py`, `deps.py`, `events.py`, `alerts.py`, write:

```python
"""Filled in by a later task."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
```

(Same content in all four files, with the docstring updated to indicate the panel.)

- [ ] **Step 7: App factory**

Write `inspectorctl/web/app.py`:

```python
"""FastAPI app factory."""

from __future__ import annotations

from importlib.resources import as_file, files
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


def create_app(*, socket_path: Path) -> FastAPI:
    """Create a FastAPI app that proxies the daemon's IPC at ``socket_path``."""
    app = FastAPI(title="inspectord")
    app.state.socket_path = Path(socket_path)

    pkg_static = files("inspectorctl.web.static")
    pkg_templates = files("inspectorctl.web.templates")
    with as_file(pkg_static) as static_dir, as_file(pkg_templates) as tmpl_dir:
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
        templates = Jinja2Templates(directory=str(tmpl_dir))
    app.state.templates = templates

    @app.get("/")
    async def root() -> RedirectResponse:
        return RedirectResponse(url="/alerts", status_code=307)

    from inspectorctl.web.routes import alerts, deps, events, health

    app.include_router(health.router)
    app.include_router(deps.router)
    app.include_router(events.router)
    app.include_router(alerts.router)

    return app
```

- [ ] **Step 8: Conftest + bootstrap test**

Write `tests/web/conftest.py`:

```python
"""Shared fixtures for web dashboard tests."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from inspectord.ipc_server import IpcServer, Method
from inspectorctl.web.app import create_app


@pytest.fixture
def ipc_factory(tmp_path: Path) -> Iterator[Callable[[list[Method]], TestClient]]:
    """Spawn an IpcServer with the given methods; return a TestClient pointed at it."""

    server: IpcServer | None = None

    def make(methods: list[Method]) -> TestClient:
        nonlocal server
        sock_path = tmp_path / "ipc.sock"
        server = IpcServer(socket_path=sock_path, methods=methods, allowed_uids=[])
        server.start()
        app = create_app(socket_path=sock_path)
        return TestClient(app)

    yield make

    if server is not None:
        server.stop()
```

Write `tests/web/test_app_bootstrap.py`:

```python
"""Smoke test: the FastAPI app boots and serves /static/."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app


def test_create_app_returns_fastapi(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "nonexistent.sock")
    assert app is not None
    assert hasattr(app, "router")


def test_static_files_are_served(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "nonexistent.sock")
    client = TestClient(app)
    response = client.get("/static/htmx.min.js")
    assert response.status_code == 200
    assert len(response.content) > 100


def test_root_redirects_to_alerts(tmp_path: Path) -> None:
    app = create_app(socket_path=tmp_path / "nonexistent.sock")
    client = TestClient(app, follow_redirects=False)
    response = client.get("/")
    assert response.status_code in (302, 307)
    assert response.headers["location"].endswith("/alerts")
```

- [ ] **Step 9: Run + lint**

```bash
pytest tests/web/test_app_bootstrap.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 3 new bootstrap tests pass; total 260.

- [ ] **Step 10: Branch + commit + push + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-web-02-app-factory
git add inspectorctl/web/ tests/web/conftest.py tests/web/test_app_bootstrap.py
git commit -m "feat(web): FastAPI app factory + IPC adapter + base template"
git push -u origin task-web-02-app-factory
gh pr create --base main --head task-web-02-app-factory \
  --title "feat(web): app factory + base template" \
  --body "create_app(socket_path) builds a FastAPI app with /static and Jinja2 templates wired from the wheel. Mounts the four route modules (stubbed in this PR; filled in later PRs). / redirects to /alerts. Vendors HTMX and ships styles.css."
```

Wait for CI green; do NOT merge.

---

## Task 3: Health page

**Files:**
- Modify: `inspectorctl/web/routes/health.py`
- Create: `inspectorctl/web/templates/health.html`
- Create: `tests/web/test_health.py`

**Branch:** `task-web-03-health`

- [ ] **Step 1: Failing test**

Write `tests/web/test_health.py`:

```python
"""Tests for the /health page."""

from __future__ import annotations

from inspectord.ipc_server import Method


def _ok_health() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "supervisor": "running",
            "workers": [
                {"name": "healthcheck", "status": "up"},
                {"name": "log_tailer", "status": "up"},
            ],
        }

    return Method(name="get_health", handler=handler, mutates=False)


def test_health_page_renders_workers(ipc_factory) -> None:
    client = ipc_factory([_ok_health()])
    response = client.get("/health")
    assert response.status_code == 200
    assert "supervisor" in response.text
    assert "healthcheck" in response.text
    assert "log_tailer" in response.text


def test_health_page_when_daemon_unreachable(tmp_path) -> None:
    """If IPC fails, render an error block instead of 500."""
    from fastapi.testclient import TestClient

    from inspectorctl.web.app import create_app

    app = create_app(socket_path=tmp_path / "absent.sock")
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert "daemon" in response.text.lower() or "error" in response.text.lower()
```

- [ ] **Step 2: Confirm failure**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest tests/web/test_health.py -v
```

Expected: AttributeError / 404 (the stub router has no GET /health route).

- [ ] **Step 3: Template**

Write `inspectorctl/web/templates/health.html`:

```html
{% extends "base.html" %}

{% block content %}
<h1>Health</h1>

<div class="detail">
  <h2>Supervisor</h2>
  <p>Status: <span class="badge {{ 'sev-info' if supervisor == 'running' else 'sev-critical' }}">{{ supervisor }}</span></p>

  <h2>Workers</h2>
  {% if workers %}
  <table>
    <thead>
      <tr><th>Name</th><th>Status</th></tr>
    </thead>
    <tbody>
      {% for w in workers %}
      <tr>
        <td class="mono">{{ w.name }}</td>
        <td>
          {% if w.status == "up" %}
            <span class="badge sev-info">up</span>
          {% else %}
            <span class="badge sev-critical">{{ w.status }}</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No workers reported.</div>
  {% endif %}
</div>
{% endblock %}
```

- [ ] **Step 4: Implement route**

Write `inspectorctl/web/routes/health.py`:

```python
"""GET /health — worker status panel."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from inspectorctl.web.ipc import WebIpcError, call


router = APIRouter()


@router.get("/health", response_class=HTMLResponse)
def health(request: Request) -> HTMLResponse:
    templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    context: dict[str, Any] = {
        "request": request,
        "title": "inspectord — Health",
        "current_path": "/health",
        "supervisor": "?",
        "workers": [],
        "error": None,
    }
    try:
        report = call(socket_path, "get_health")
    except WebIpcError as exc:
        context["error"] = f"daemon unreachable: {exc}"
    else:
        context["supervisor"] = report.get("supervisor", "?")
        context["workers"] = report.get("workers", [])
    return templates.TemplateResponse(request, "health.html", context)
```

- [ ] **Step 5: Confirm pass + lint**

```bash
pytest tests/web/test_health.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 2 new tests pass; total 262.

- [ ] **Step 6: Branch + commit + push + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-web-03-health
git add inspectorctl/web/routes/health.py inspectorctl/web/templates/health.html \
        tests/web/test_health.py
git commit -m "feat(web): /health page"
git push -u origin task-web-03-health
gh pr create --base main --head task-web-03-health \
  --title "feat(web): /health page" \
  --body "Renders supervisor status + per-worker table from get_health IPC. Gracefully handles daemon-unreachable by rendering an error banner instead of 500-ing."
```

Wait for CI green; do NOT merge.

---

## Task 4: Dependencies page

**Files:**
- Modify: `inspectorctl/web/routes/deps.py`
- Create: `inspectorctl/web/templates/deps.html`
- Create: `tests/web/test_deps.py`

**Branch:** `task-web-04-deps`

- [ ] **Step 1: Failing test**

Write `tests/web/test_deps.py`:

```python
"""Tests for the /deps page."""

from __future__ import annotations

from inspectord.ipc_server import Method


def _deps_listing() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "dependencies": [
                {
                    "name": "auditd",
                    "description": "Linux audit daemon",
                    "required_when_profiles": ["minimal", "standard"],
                    "packages_for_arch": ["audit"],
                    "installed": True,
                    "installed_version": "3.1.5-1",
                    "dropin_present": True,
                    "last_verify_ts": "2026-05-25T00:01:02+00:00",
                    "last_verify_pass": True,
                    "last_verify_detail": "auditd.service active",
                },
                {
                    "name": "yara",
                    "description": "YARA matcher",
                    "required_when_profiles": ["minimal", "standard"],
                    "packages_for_arch": ["yara"],
                    "installed": False,
                    "installed_version": None,
                    "dropin_present": False,
                    "last_verify_ts": None,
                    "last_verify_pass": None,
                    "last_verify_detail": None,
                },
            ],
        }

    return Method(name="list_dependencies", handler=handler, mutates=False)


def test_deps_page_renders_table(ipc_factory) -> None:
    client = ipc_factory([_deps_listing()])
    response = client.get("/deps")
    assert response.status_code == 200
    assert "auditd" in response.text
    assert "yara" in response.text
    assert "3.1.5-1" in response.text


def test_deps_page_when_daemon_unreachable(tmp_path) -> None:
    from fastapi.testclient import TestClient

    from inspectorctl.web.app import create_app

    app = create_app(socket_path=tmp_path / "absent.sock")
    client = TestClient(app)
    response = client.get("/deps")
    assert response.status_code == 200
    assert "error" in response.text.lower() or "unreachable" in response.text.lower()
```

- [ ] **Step 2: Confirm failure**

```bash
pytest tests/web/test_deps.py -v
```

Expected: 404 (no route yet).

- [ ] **Step 3: Template**

Write `inspectorctl/web/templates/deps.html`:

```html
{% extends "base.html" %}
{% from "_macros.html" import severity_badge %}

{% block content %}
<h1>Dependencies</h1>

{% if dependencies %}
<table>
  <thead>
    <tr>
      <th>Name</th>
      <th>Required by</th>
      <th>Installed</th>
      <th>Version</th>
      <th>Drop-in</th>
      <th>Last verify</th>
    </tr>
  </thead>
  <tbody>
    {% for d in dependencies %}
    <tr>
      <td class="mono">{{ d.name }}</td>
      <td class="muted">{{ d.required_when_profiles | join(', ') }}</td>
      <td>
        {% if d.installed is sameas true %}
          <span class="badge sev-info">yes</span>
        {% elif d.installed is sameas false %}
          <span class="badge sev-critical">no</span>
        {% else %}
          <span class="muted">—</span>
        {% endif %}
      </td>
      <td class="mono">{{ d.installed_version or "" }}</td>
      <td>
        {% if d.dropin_present %}
          <span class="badge sev-info">yes</span>
        {% else %}
          <span class="muted">—</span>
        {% endif %}
      </td>
      <td>
        {% if d.last_verify_pass is sameas true %}
          <span class="badge sev-info">pass</span>
        {% elif d.last_verify_pass is sameas false %}
          <span class="badge sev-critical">fail</span>
        {% else %}
          <span class="muted">—</span>
        {% endif %}
        {% if d.last_verify_detail %}
          <div class="muted" style="font-size: 12px;">{{ d.last_verify_detail }}</div>
        {% endif %}
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<div class="empty">No dependencies declared.</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 4: Route**

Write `inspectorctl/web/routes/deps.py`:

```python
"""GET /deps — dependency status panel."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from inspectorctl.web.ipc import WebIpcError, call


router = APIRouter()


@router.get("/deps", response_class=HTMLResponse)
def deps(request: Request) -> HTMLResponse:
    templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    context: dict[str, Any] = {
        "request": request,
        "title": "inspectord — Dependencies",
        "current_path": "/deps",
        "dependencies": [],
        "error": None,
    }
    try:
        result = call(socket_path, "list_dependencies")
    except WebIpcError as exc:
        context["error"] = f"daemon unreachable: {exc}"
    else:
        context["dependencies"] = result.get("dependencies", [])
    return templates.TemplateResponse(request, "deps.html", context)
```

- [ ] **Step 5: Confirm pass + lint**

```bash
pytest tests/web/test_deps.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 2 new tests pass; total 264.

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-web-04-deps
git add inspectorctl/web/routes/deps.py inspectorctl/web/templates/deps.html \
        tests/web/test_deps.py
git commit -m "feat(web): /deps page"
git push -u origin task-web-04-deps
gh pr create --base main --head task-web-04-deps \
  --title "feat(web): /deps page" \
  --body "Read-only dependency table. Renders name / required-by-profile / installed / version / drop-in / last-verify columns from list_dependencies IPC. Install actions stay in the CLI for v1."
```

Wait for CI green; do NOT merge.

---

## Task 5: Live events page (HTMX polling)

**Files:**
- Modify: `inspectorctl/web/routes/events.py`
- Create: `inspectorctl/web/templates/events.html`
- Create: `inspectorctl/web/templates/events_feed.html`
- Create: `tests/web/test_events.py`

**Branch:** `task-web-05-events`

The Live Events page renders an outer shell (`events.html`) that HTMX-polls the `/events/feed` partial every 2 seconds. The partial template renders just the table rows.

- [ ] **Step 1: Failing tests**

Write `tests/web/test_events.py`:

```python
"""Tests for the /events page."""

from __future__ import annotations

from inspectord.ipc_server import Method


def _list_events() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "events": [
                {
                    "event_id": "01900000-0000-7000-8000-000000000001",
                    "ts": "2026-05-25T14:23:10+00:00",
                    "module": "log_tailer",
                    "action": "package_installed",
                    "severity": "info",
                    "message": "installed audit",
                },
                {
                    "event_id": "01900000-0000-7000-8000-000000000002",
                    "ts": "2026-05-25T14:23:11+00:00",
                    "module": "fim_watcher",
                    "action": "file_created",
                    "severity": "low",
                    "message": "/etc/x",
                },
            ],
        }

    return Method(name="list_events", handler=handler, mutates=False)


def test_events_shell_renders(ipc_factory) -> None:
    client = ipc_factory([_list_events()])
    response = client.get("/events")
    assert response.status_code == 200
    # The shell includes the HTMX trigger and the target div.
    assert "hx-get" in response.text
    assert "/events/feed" in response.text
    assert "events-feed" in response.text


def test_events_feed_partial_returns_rows(ipc_factory) -> None:
    client = ipc_factory([_list_events()])
    response = client.get("/events/feed")
    assert response.status_code == 200
    assert "package_installed" in response.text
    assert "file_created" in response.text
    # Partial should NOT include the full base.html navigation chrome.
    assert "<nav>" not in response.text


def test_events_feed_supports_module_filter(ipc_factory) -> None:
    calls: list[dict] = []

    def handler(params: dict) -> dict:
        calls.append(params)
        return {"schema_version": "1.0.0", "events": []}

    client = ipc_factory([Method(name="list_events", handler=handler, mutates=False)])
    response = client.get("/events/feed?module=log_tailer")
    assert response.status_code == 200
    assert any(c.get("module") == "log_tailer" for c in calls)
```

- [ ] **Step 2: Confirm failure**

```bash
pytest tests/web/test_events.py -v
```

Expected: 404.

- [ ] **Step 3: Templates**

Write `inspectorctl/web/templates/events.html`:

```html
{% extends "base.html" %}

{% block content %}
<h1>Live events</h1>

<form class="filter-bar" method="get" action="/events">
  <label class="muted">Module:</label>
  <input type="text" name="module" value="{{ module or '' }}" placeholder="any">
  <button type="submit">Filter</button>
</form>

<div id="events-feed"
     hx-get="/events/feed{% if module %}?module={{ module }}{% endif %}"
     hx-target="#events-feed"
     hx-trigger="load, every 2s">
  <div class="empty">Loading…</div>
</div>
{% endblock %}
```

Write `inspectorctl/web/templates/events_feed.html`:

```html
{% if events %}
<table>
  <thead>
    <tr>
      <th>Time</th>
      <th>Severity</th>
      <th>Module</th>
      <th>Action</th>
      <th>Message</th>
    </tr>
  </thead>
  <tbody>
    {% for e in events %}
    <tr>
      <td class="mono muted">{{ e.ts or '' }}</td>
      <td><span class="badge sev-{{ e.severity }}">{{ e.severity }}</span></td>
      <td class="mono">{{ e.module }}</td>
      <td class="mono">{{ e.action }}</td>
      <td>{{ e.message or '' }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<div class="empty">No events yet.</div>
{% endif %}
```

- [ ] **Step 4: Route**

Write `inspectorctl/web/routes/events.py`:

```python
"""GET /events + /events/feed — live events panel with HTMX polling."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from inspectorctl.web.ipc import WebIpcError, call


router = APIRouter()


@router.get("/events", response_class=HTMLResponse)
def events_shell(
    request: Request,
    module: str | None = Query(default=None),
) -> HTMLResponse:
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "events.html",
        {
            "request": request,
            "title": "inspectord — Events",
            "current_path": "/events",
            "module": module,
        },
    )


@router.get("/events/feed", response_class=HTMLResponse)
def events_feed(
    request: Request,
    module: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
) -> HTMLResponse:
    templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    params: dict[str, Any] = {"limit": limit}
    if module:
        params["module"] = module
    events: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(socket_path, "list_events", params)
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        events = list(reversed(result.get("events", [])))
    return templates.TemplateResponse(
        request,
        "events_feed.html",
        {"request": request, "events": events, "error": error},
    )
```

Note: `list_events` returns events in ascending `event_id` order; the feed reverses to show newest first.

- [ ] **Step 5: Confirm pass + lint**

```bash
pytest tests/web/test_events.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 3 new tests pass; total 267.

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-web-05-events
git add inspectorctl/web/routes/events.py \
        inspectorctl/web/templates/events.html \
        inspectorctl/web/templates/events_feed.html \
        tests/web/test_events.py
git commit -m "feat(web): /events page with HTMX-polled feed"
git push -u origin task-web-05-events
gh pr create --base main --head task-web-05-events \
  --title "feat(web): live events panel" \
  --body "Shell page contains an HTMX hx-trigger=\"every 2s\" that swaps in the /events/feed partial. Partial renders newest-first table rows from list_events. Module filter persists across polls."
```

Wait for CI green; do NOT merge.

---

## Task 6: Alerts list + detail + ack/resolve/suppress

**Files:**
- Modify: `inspectorctl/web/routes/alerts.py`
- Create: `inspectorctl/web/templates/alerts.html`
- Create: `inspectorctl/web/templates/alert_detail.html`
- Create: `tests/web/test_alerts.py`

**Branch:** `task-web-06-alerts`

- [ ] **Step 1: Failing tests**

Write `tests/web/test_alerts.py`:

```python
"""Tests for the /alerts panel."""

from __future__ import annotations

from inspectord.ipc_server import Method


def _alerts_listing() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "alerts": [
                {
                    "alert_id": "01900000-0000-7000-8000-000000000001",
                    "rule_id": "lolbin.bash_dev_tcp",
                    "ts": "2026-05-25T14:23:10+00:00",
                    "severity": "critical",
                    "status": "new",
                    "category": "intrusion_detection",
                    "dedup_count": 3,
                    "rendered_short": "Reverse shell pid 9999",
                }
            ],
        }

    return Method(name="list_alerts", handler=handler, mutates=False)


def _get_alert() -> Method:
    def handler(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "alert": {
                "alert_id": "01900000-0000-7000-8000-000000000001",
                "rule": {
                    "id": "lolbin.bash_dev_tcp",
                    "name": "Reverse-shell pattern",
                    "severity": "critical",
                    "why": "bash -i >& /dev/tcp/ is a classic reverse-shell idiom",
                    "false_positives": ["pentest/CTF tools"],
                },
                "ts": "2026-05-25T14:23:10+00:00",
                "severity": "critical",
                "status": "new",
                "category": "intrusion_detection",
                "rendered": {"short": "Reverse shell pid 9999", "detail": "long detail"},
                "entities": [{"kind": "process", "key": "pid:9999"}],
                "dedup_count": 3,
                "first_seen_at": "2026-05-25T14:00:00+00:00",
                "last_seen_at": "2026-05-25T14:23:10+00:00",
                "labels": ["lolbin", "reverse-shell"],
            },
        }

    return Method(name="get_alert", handler=handler, mutates=False)


def _ack_alert() -> Method:
    calls: list[dict] = []

    def handler(params: dict) -> dict:
        calls.append(params)
        return {"schema_version": "1.0.0", "ok": True, "status": "acknowledged"}

    method = Method(name="ack_alert", handler=handler, mutates=True)
    method._calls = calls  # type: ignore[attr-defined]
    return method


def _resolve_alert() -> Method:
    def handler(_params: dict) -> dict:
        return {"schema_version": "1.0.0", "ok": True, "status": "resolved"}

    return Method(name="resolve_alert", handler=handler, mutates=True)


def _suppress_alert() -> Method:
    def handler(_params: dict) -> dict:
        return {"schema_version": "1.0.0", "ok": True, "status": "suppressed"}

    return Method(name="suppress_alert", handler=handler, mutates=True)


def test_alerts_list_renders(ipc_factory) -> None:
    client = ipc_factory([_alerts_listing()])
    response = client.get("/alerts")
    assert response.status_code == 200
    assert "lolbin.bash_dev_tcp" in response.text
    assert "Reverse shell pid 9999" in response.text


def test_alerts_list_filter_by_status(ipc_factory) -> None:
    calls: list[dict] = []

    def handler(params: dict) -> dict:
        calls.append(params)
        return {"schema_version": "1.0.0", "alerts": []}

    client = ipc_factory([Method(name="list_alerts", handler=handler, mutates=False)])
    client.get("/alerts?status=new")
    assert any(c.get("status") == "new" for c in calls)


def test_alert_detail_renders(ipc_factory) -> None:
    client = ipc_factory([_get_alert()])
    response = client.get("/alerts/01900000-0000-7000-8000-000000000001")
    assert response.status_code == 200
    assert "Reverse-shell pattern" in response.text
    assert "long detail" in response.text
    assert "pentest/CTF tools" in response.text


def test_alert_detail_404_when_missing(tmp_path) -> None:
    from fastapi.testclient import TestClient

    from inspectord.ipc_server import IpcServer, Method
    from inspectorctl.web.app import create_app

    def handler(_params: dict) -> dict:
        return {"schema_version": "1.0.0", "alert": None}

    sock = tmp_path / "ipc.sock"
    server = IpcServer(
        socket_path=sock,
        methods=[Method(name="get_alert", handler=handler, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        client = TestClient(create_app(socket_path=sock))
        response = client.get("/alerts/absent")
        assert response.status_code == 404
    finally:
        server.stop()


def test_ack_alert_post_redirects_to_list(ipc_factory) -> None:
    ack_method = _ack_alert()
    client = ipc_factory([_get_alert(), ack_method])
    response = client.post(
        "/alerts/01900000-0000-7000-8000-000000000001/ack",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith("/alerts")
    assert any(
        c.get("alert_id") == "01900000-0000-7000-8000-000000000001"
        for c in ack_method._calls  # type: ignore[attr-defined]
    )


def test_resolve_alert_post(ipc_factory) -> None:
    client = ipc_factory([_get_alert(), _resolve_alert()])
    response = client.post(
        "/alerts/01900000-0000-7000-8000-000000000001/resolve",
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_suppress_alert_post(ipc_factory) -> None:
    client = ipc_factory([_get_alert(), _suppress_alert()])
    response = client.post(
        "/alerts/01900000-0000-7000-8000-000000000001/suppress",
        follow_redirects=False,
    )
    assert response.status_code == 303
```

- [ ] **Step 2: Confirm failure**

```bash
pytest tests/web/test_alerts.py -v
```

Expected: 404s.

- [ ] **Step 3: List template**

Write `inspectorctl/web/templates/alerts.html`:

```html
{% extends "base.html" %}
{% from "_macros.html" import severity_badge, status_badge %}

{% block content %}
<h1>Alerts</h1>

<form class="filter-bar" method="get" action="/alerts">
  <label class="muted">Status:</label>
  <select name="status">
    <option value="" {{ 'selected' if not status else '' }}>any</option>
    <option value="new" {{ 'selected' if status == 'new' else '' }}>new</option>
    <option value="acknowledged" {{ 'selected' if status == 'acknowledged' else '' }}>acknowledged</option>
    <option value="resolved" {{ 'selected' if status == 'resolved' else '' }}>resolved</option>
    <option value="suppressed" {{ 'selected' if status == 'suppressed' else '' }}>suppressed</option>
  </select>
  <label class="muted">Severity:</label>
  <select name="severity">
    <option value="" {{ 'selected' if not severity else '' }}>any</option>
    <option value="critical" {{ 'selected' if severity == 'critical' else '' }}>critical</option>
    <option value="high" {{ 'selected' if severity == 'high' else '' }}>high</option>
    <option value="medium" {{ 'selected' if severity == 'medium' else '' }}>medium</option>
    <option value="low" {{ 'selected' if severity == 'low' else '' }}>low</option>
    <option value="info" {{ 'selected' if severity == 'info' else '' }}>info</option>
  </select>
  <button type="submit">Filter</button>
</form>

{% if alerts %}
<table>
  <thead>
    <tr>
      <th>Time</th>
      <th>Severity</th>
      <th>Status</th>
      <th>Rule</th>
      <th>Dedup</th>
      <th>Summary</th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    {% for a in alerts %}
    <tr>
      <td class="mono muted">{{ a.ts or '' }}</td>
      <td>{{ severity_badge(a.severity) }}</td>
      <td>{{ status_badge(a.status) }}</td>
      <td class="mono">{{ a.rule_id }}</td>
      <td>{{ a.dedup_count or 1 }}</td>
      <td>{{ a.rendered_short or '' }}</td>
      <td><a href="/alerts/{{ a.alert_id }}">open →</a></td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<div class="empty">Inbox zero. No alerts match the filter.</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 4: Detail template**

Write `inspectorctl/web/templates/alert_detail.html`:

```html
{% extends "base.html" %}
{% from "_macros.html" import severity_badge, status_badge %}

{% block content %}
<h1>Alert {{ alert.alert_id[:8] }}…</h1>

<div class="detail">
  <p>
    {{ severity_badge(alert.severity) }}
    {{ status_badge(alert.status) }}
    <span class="mono">{{ alert.rule.id }}</span>
  </p>

  <h2>Summary</h2>
  <p>{{ alert.rendered.short }}</p>

  <h2>Detail</h2>
  <pre>{{ alert.rendered.detail }}</pre>

  <h2>Why this rule</h2>
  <p>{{ alert.rule.why or '—' }}</p>

  {% if alert.rule.false_positives %}
  <h2>Known false positives</h2>
  <ul class="muted">
    {% for fp in alert.rule.false_positives %}
    <li>{{ fp }}</li>
    {% endfor %}
  </ul>
  {% endif %}

  <h2>Entities</h2>
  <table>
    <thead><tr><th>Kind</th><th>Key</th></tr></thead>
    <tbody>
      {% for e in alert.entities %}
      <tr><td class="mono">{{ e.kind }}</td><td class="mono">{{ e.key }}</td></tr>
      {% endfor %}
    </tbody>
  </table>

  <h2>Times</h2>
  <p class="muted">First seen: {{ alert.first_seen_at }}<br>Last seen: {{ alert.last_seen_at }}<br>Dedup count: {{ alert.dedup_count }}</p>

  {% if alert.status == "new" or alert.status == "acknowledged" %}
  <div class="actions">
    {% if alert.status == "new" %}
    <form method="post" action="/alerts/{{ alert.alert_id }}/ack">
      <button type="submit">Acknowledge</button>
    </form>
    {% endif %}
    <form method="post" action="/alerts/{{ alert.alert_id }}/resolve">
      <button type="submit">Resolve</button>
    </form>
    <form method="post" action="/alerts/{{ alert.alert_id }}/suppress">
      <button type="submit">Suppress</button>
    </form>
  </div>
  {% endif %}
</div>
{% endblock %}
```

- [ ] **Step 5: Route**

Write `inspectorctl/web/routes/alerts.py`:

```python
"""GET /alerts, GET /alerts/{id}, POST mutations."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from inspectorctl.web.ipc import WebIpcError, call


router = APIRouter()


@router.get("/alerts", response_class=HTMLResponse)
def alerts_list(
    request: Request,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> HTMLResponse:
    templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    params: dict[str, Any] = {"limit": limit}
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity
    alerts: list[dict[str, Any]] = []
    error: str | None = None
    try:
        result = call(socket_path, "list_alerts", params)
    except WebIpcError as exc:
        error = f"daemon unreachable: {exc}"
    else:
        alerts = result.get("alerts", [])
    return templates.TemplateResponse(
        request,
        "alerts.html",
        {
            "request": request,
            "title": "inspectord — Alerts",
            "current_path": "/alerts",
            "status": status,
            "severity": severity,
            "alerts": alerts,
            "error": error,
        },
    )


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: str) -> HTMLResponse:
    templates = request.app.state.templates
    socket_path = request.app.state.socket_path
    try:
        result = call(socket_path, "get_alert", {"alert_id": alert_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    alert = result.get("alert")
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert not found: {alert_id}")
    return templates.TemplateResponse(
        request,
        "alert_detail.html",
        {
            "request": request,
            "title": f"inspectord — Alert {alert_id[:8]}",
            "current_path": "/alerts",
            "alert": alert,
        },
    )


def _mutate(socket_path: Any, method: str, alert_id: str) -> RedirectResponse:
    try:
        call(socket_path, method, {"alert_id": alert_id})
    except WebIpcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url="/alerts", status_code=303)


@router.post("/alerts/{alert_id}/ack")
def alert_ack(request: Request, alert_id: str) -> RedirectResponse:
    return _mutate(request.app.state.socket_path, "ack_alert", alert_id)


@router.post("/alerts/{alert_id}/resolve")
def alert_resolve(request: Request, alert_id: str) -> RedirectResponse:
    return _mutate(request.app.state.socket_path, "resolve_alert", alert_id)


@router.post("/alerts/{alert_id}/suppress")
def alert_suppress(request: Request, alert_id: str) -> RedirectResponse:
    return _mutate(request.app.state.socket_path, "suppress_alert", alert_id)
```

- [ ] **Step 6: Confirm pass + lint**

```bash
pytest tests/web/test_alerts.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 7 new tests pass; total 274.

- [ ] **Step 7: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-web-06-alerts
git add inspectorctl/web/routes/alerts.py \
        inspectorctl/web/templates/alerts.html \
        inspectorctl/web/templates/alert_detail.html \
        tests/web/test_alerts.py
git commit -m "feat(web): /alerts list + detail + ack/resolve/suppress"
git push -u origin task-web-06-alerts
gh pr create --base main --head task-web-06-alerts \
  --title "feat(web): alerts panel + mutations" \
  --body "List view (filter by status/severity), detail view (rule context + why + false positives + entities + times), and POST mutations (ack/resolve/suppress) that redirect back to the list. 404 when alert is missing; 502 on IPC failure."
```

Wait for CI green; do NOT merge.

---

## Task 7: Entry point + systemd unit + acceptance docs + spec bump

**Files:**
- Create: `inspectorctl/web/__main__.py`
- Create: `packaging/systemd/inspectorctl-web.service.template`
- Modify: `docs/superpowers/specs/2026-05-24-local-inspection-design.md`

**Branch:** `task-web-07-entry-systemd-spec`

- [ ] **Step 1: Entry point**

Write `inspectorctl/web/__main__.py`:

```python
"""inspectorctl-web entry point — runs uvicorn on 127.0.0.1.

Usage:
  inspectorctl-web                          # dev mode: socket under ./var/
  inspectorctl-web --socket /run/inspectord/inspectord.sock --port 8765
"""

from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from inspectorctl.web.app import create_app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="inspectorctl-web")
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path.cwd() / "var" / "inspectord.sock",
        help="Path to the inspectord IPC socket",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address; defaults to 127.0.0.1 (no external interface)",
    )
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)

    app = create_app(socket_path=args.socket)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: systemd user-unit template**

Write `packaging/systemd/inspectorctl-web.service.template`:

```ini
# inspectorctl-web.service — installed to ~/.config/systemd/user/
# Templated: @PYTHON@ substituted at install time.

[Unit]
Description=Local Inspection web dashboard
After=graphical-session.target

[Service]
Type=simple
ExecStart=@PYTHON@ -m inspectorctl.web --socket /run/inspectord/inspectord.sock --port 8765
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=graphical-session.target
```

- [ ] **Step 3: Spec bump**

In `/home/eli/Development/inspectord/docs/superpowers/specs/2026-05-24-local-inspection-design.md`:

1. Change the `Spec version` header from `0.2.3` to `0.2.4`.
2. Append this row to the changelog table:

```
| 0.2.4 | 2026-05-25 | Phase 1 dashboard slice landed: web/Alerts (inbox-zero triage with ack/resolve/suppress), web/Live Events (HTMX-polled feed), web/Health, web/Dependencies. FastAPI app bound to 127.0.0.1:8765, served by inspectorctl-web (also as a user-mode systemd unit template). 24 of 28 spec panels still pending; CSRF/sessions/TLS deferred to a future hardening pass. **Phase 1 of the design is now complete: collector → enrichment → rule engine → allowlist → notifier → CLI → web dashboard all working end-to-end.** |
```

- [ ] **Step 4: Run the daemon + web manually as a smoke check**

This is a one-time human sanity check (no automated test); document it in the PR body so the reviewer can repeat it.

```bash
# In one shell:
cd /home/eli/Development/inspectord
source .venv/bin/activate
rm -rf var/
inspectord --dev &
sleep 2

# In another shell:
cd /home/eli/Development/inspectord
source .venv/bin/activate
inspectorctl-web --socket var/inspectord.sock --port 8765 &
sleep 1

# Open http://127.0.0.1:8765 in any browser.
# Expected: redirects to /alerts; the nav bar shows Alerts/Events/Health/Dependencies.
# Health and Deps render. Events page polls every 2s.

# Cleanup:
kill %1 %2
rm -rf var/
```

The smoke check is for the human reviewer; CI doesn't run it (it requires a browser).

- [ ] **Step 5: Confirm tests pass + lint**

```bash
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: no new tests; total stays at 274. (The entry-point function is exercised manually; uvicorn integration tests aren't worth the complexity for v1.)

- [ ] **Step 6: Branch + commit + push + PR (also commit this plan doc)**

```bash
git checkout main && git pull origin main
git checkout -b task-web-07-entry-systemd-spec
git add inspectorctl/web/__main__.py \
        packaging/systemd/inspectorctl-web.service.template \
        docs/superpowers/specs/2026-05-24-local-inspection-design.md \
        docs/superpowers/plans/2026-05-25-web-dashboard.md
git commit -m "feat(web): entry point + systemd unit + spec bump to v0.2.4"
git push -u origin task-web-07-entry-systemd-spec
gh pr create --base main --head task-web-07-entry-systemd-spec \
  --title "feat(web): entry point + systemd unit + spec v0.2.4" \
  --body $'Adds inspectorctl-web entry point that runs uvicorn on 127.0.0.1:8765. Adds the systemd user unit template the tray will eventually invoke. Bumps spec to v0.2.4 — Phase 1 is COMPLETE.\n\nManual smoke check (not in CI):\n```\ninspectord --dev &\ninspectorctl-web --socket var/inspectord.sock &\nopen http://127.0.0.1:8765\n```'
```

Wait for CI green; do NOT merge.

---

## Acceptance criteria (this plan complete)

After all 7 PRs merge:

```bash
$ pytest tests/                     → ~274 passed
$ ruff / mypy                       → clean
$ inspectord --dev &                # in shell 1
$ inspectorctl-web --socket var/inspectord.sock &   # in shell 2
$ xdg-open http://127.0.0.1:8765    # or whatever browser invocation
```

The browser shows:
- **/alerts** (default): table of current alerts with filter controls and inline `open →` links to detail.
- **/alerts/<id>**: full detail with rule.why, false_positives, entities, times, and `Acknowledge` / `Resolve` / `Suppress` POST forms.
- **/events**: HTMX-polled tail; new events appear within 2 s of being persisted to DuckDB.
- **/health**: supervisor + per-worker status.
- **/deps**: read-only dependency table.

## What this plan deliberately defers

- 24 of the 28 dashboard panels (Posture, Incidents, Pending Actions, Hunt, Cases, Processes, Network, Firewall, Services, Users & Access, Devices, Persistence, File Integrity, AV/Scanners, Quarantine, Packages, Threat Intel, Allowlist, Rules, Notifications, Reports, Audit, Settings) — they all reuse this app shell.
- CSRF tokens, session cookies, TLS, polkit-mediated mutations — all deferred to a hardening plan once the UI is exposed beyond `127.0.0.1`.
- Server-Sent Events for live-events feed — HTMX polling is enough for v1.
- Entity context cards (spec §14) — comes with the Processes / Network / Files panels.
- Triage statistics, posture score, system-state cards — same.

## Next plans after this one

Phase 1 is complete. Phase 2 starts with: `process_collector` (eBPF-based real process monitoring) — the rule engine is in place but currently fires only against synthetic events; the process_collector hooks `sched_process_exec` and produces real process_start events so `lolbin.bash_dev_tcp` fires on actual reverse-shell attempts. After that, the rest of Phase 2 from spec §31 (`outbound_connection_tracker`, `kmod_watcher`, `services_monitor`, `udev_monitor`, `firewall_inspector`, `listening_socket_snapshotter`, `anomaly_detector`, `evidence_collector`, entity context cards, the remaining dashboard panels).
