# Hunt data-horizon banner (PR1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `run_hunt_query` reports the oldest surviving event timestamp (`data_horizon`), and the hunt panel + CLI render an effective-coverage warning only when the requested window reaches past the surviving data.

**Architecture:** Daemon adds one field to the existing `run_hunt_query` response (spec `2026-09-07-hunt-followups-design.md` §2). The warning conditional lives ONCE in `inspectorctl/cli/hunt.py` (`horizon_note()`); the web route reuses it (precedent: the web already imports `to_iso` from the CLI to avoid parser drift). Template stays dumb — it prints a pre-computed string or nothing.

**Tech Stack:** Python 3.14, FastAPI/Jinja2 (web), typer/rich (CLI), DuckDB, pytest.

**Branch:** work on `hunt-followups` (spec already committed there).

**Gates before push (all must pass):**
```sh
.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q
.venv/bin/python -m pytest -m "integration" -q
.venv/bin/ruff check inspectord inspectorctl tests
.venv/bin/ruff format --check inspectord inspectorctl tests
.venv/bin/mypy inspectord
```

---

### Task 1: daemon — `data_horizon` in the run response

**Files:**
- Modify: `inspectord/hunt/ipc_handlers.py`
- Test: `tests/hunt/test_ipc_handlers.py`

- [ ] **Step 1: Write the failing tests**

Read `tests/hunt/test_ipc_handlers.py` first and mirror its existing fixtures/helpers for building a DB with events (it already inserts events and calls `handle_run_hunt_query`). Add:

```python
def test_run_reports_data_horizon(...existing db/event fixtures...):
    # insert two events with distinct ts, e.g. 2026-09-01T00:00:00 and 2026-09-05T00:00:00
    result = handle_run_hunt_query(params={"expression": "..."}, db_path=db_path)
    assert result["ok"] is True
    assert result["data_horizon"] == "2026-09-01T00:00:00"  # MIN(ts), ISO, as stored (naive UTC)

def test_run_reports_null_horizon_on_empty_store(...):
    # no events inserted
    result = handle_run_hunt_query(params={"expression": "..."}, db_path=db_path)
    assert result["ok"] is True
    assert result["data_horizon"] is None
```

Match the exact expression/fixture style already in the file — don't invent new scaffolding.

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/python -m pytest tests/hunt/test_ipc_handlers.py -q -k horizon`
Expected: FAIL with `KeyError: 'data_horizon'` (or assert on missing key).

- [ ] **Step 3: Implement**

In `inspectord/hunt/ipc_handlers.py`:

```python
def _data_horizon(db: Database) -> datetime | None:
    """MIN(ts) over the store — the oldest surviving event, None when empty.

    Advisory (spec §2): a log-derived event carries its log line's timestamp,
    so one backdated line can overstate coverage. It is also a second
    statement, not one transaction with the query SELECT — a retention prune
    committing between the two skews the value by at most one prune cycle.
    """
    row = db.query("SELECT MIN(ts) FROM events_enriched").fetchone()
    return row[0] if row is not None else None
```

In `handle_run_hunt_query`, inside the `with Database(db_path) as db:` block after `run_hunt_query`:

```python
            result = run_hunt_query(db, compiled)
            horizon = _data_horizon(db)
```

Thread it through `_result_dict` (add keyword-only param `data_horizon: datetime | None`) and emit `"data_horizon": _iso(data_horizon)` in the returned dict.

- [ ] **Step 4: Run tests, verify pass**

Run: `.venv/bin/python -m pytest tests/hunt/test_ipc_handlers.py -q`
Expected: all PASS (including pre-existing tests — `_result_dict` callers must all pass the new param).

- [ ] **Step 5: Commit**

```bash
git add inspectord/hunt/ipc_handlers.py tests/hunt/test_ipc_handlers.py
git commit -m "feat(hunt): report data_horizon (oldest surviving event) in run_hunt_query"
```

---

### Task 2: shared conditional + CLI stderr line

**Files:**
- Modify: `inspectorctl/cli/hunt.py`
- Test: `tests/test_cli_hunt.py`

- [ ] **Step 1: Write the failing tests**

Read `tests/test_cli_hunt.py` first; mirror how it invokes `render_result` / captures output (it uses rich console capture or capsys). Add:

```python
def test_horizon_note_none_when_horizon_before_since():
    assert horizon_note({"data_horizon": "2026-08-01T00:00:00", "since": "2026-09-01T00:00:00+00:00"}) is None

def test_horizon_note_warns_when_window_reaches_past_data():
    note = horizon_note({"data_horizon": "2026-09-03T00:00:00", "since": "2026-09-01T00:00:00+00:00"})
    assert note is not None
    assert "2026-09-03" in note and "only cover" in note

def test_horizon_note_empty_store():
    assert horizon_note({"data_horizon": None, "since": "2026-09-01T00:00:00+00:00"}) == "no events in the store"

def test_render_result_prints_horizon_note_to_stderr(capsys):
    # minimal ok-result dict with data_horizon > since and one event row,
    # mirroring the file's existing render_result fixtures
    render_result({...})
    captured = capsys.readouterr()
    assert "only cover" in captured.err
    assert "only cover" not in captured.out
```

Note the naive-vs-aware mix in the fixtures: `data_horizon` comes back naive (DuckDB strips tz), `since` is aware. `horizon_note` must not raise `TypeError` on that mix — that IS one of the tests.

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/python -m pytest tests/test_cli_hunt.py -q -k horizon`
Expected: FAIL with `ImportError: cannot import name 'horizon_note'`.

- [ ] **Step 3: Implement**

In `inspectorctl/cli/hunt.py`:

```python
from rich.console import Console

_err_console = Console(stderr=True)


def _as_utc(value: datetime) -> datetime:
    """Naive timestamps are UTC by contract (DuckDB strips tz on read)."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def horizon_note(result: dict[str, Any]) -> str | None:
    """The effective-coverage warning for one run response, or None.

    Only warns when the requested window reaches past the surviving data
    (spec §2: the common case — horizon far older than the window — must not
    over-claim coverage, so it renders nothing). Shared by the CLI and the
    web route so there is exactly one implementation of the conditional.
    """
    if "data_horizon" not in result:
        return None  # older daemon; claim nothing
    horizon = result.get("data_horizon")
    if horizon is None:
        return "no events in the store"
    since = result.get("since")
    if since is None:
        return None
    try:
        horizon_ts = _as_utc(datetime.fromisoformat(str(horizon)))
        since_ts = _as_utc(datetime.fromisoformat(str(since)))
    except ValueError:
        return None
    if horizon_ts > since_ts:
        return (
            "your window reaches past the surviving data; "
            f"results only cover since {horizon_ts.isoformat()}"
        )
    return None
```

In `render_result`, right after the `window` line is printed:

```python
    note = horizon_note(result)
    if note is not None:
        _err_console.print(f"[yellow]{escape(note)}[/yellow]")
```

- [ ] **Step 4: Run tests, verify pass**

Run: `.venv/bin/python -m pytest tests/test_cli_hunt.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectorctl/cli/hunt.py tests/test_cli_hunt.py
git commit -m "feat(hunt): effective-coverage warning in CLI output (horizon_note)"
```

---

### Task 3: web — banner on /hunt

**Files:**
- Modify: `inspectorctl/web/routes/hunt.py`, `inspectorctl/web/templates/hunt.html`
- Test: `tests/web/test_hunt.py`

- [ ] **Step 1: Write the failing tests**

Read `tests/web/test_hunt.py` first; it fakes the IPC layer — reuse its fake-response helpers. Add cases:

```python
def test_hunt_renders_horizon_banner_when_window_reaches_past_data(client_with_fake_ipc):
    # fake run_hunt_query response: data_horizon "2026-09-03T00:00:00",
    # since "2026-09-01T00:00:00+00:00", one event
    html = ...get("/hunt?q=...").text
    assert "only cover since" in html

def test_hunt_no_banner_when_horizon_older_than_window(client_with_fake_ipc):
    # data_horizon far older than since
    assert "only cover since" not in html

def test_hunt_banner_empty_store(client_with_fake_ipc):
    # data_horizon None
    assert "no events in the store" in html
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/python -m pytest tests/web/test_hunt.py -q -k horizon`
Expected: FAIL (banner text absent).

- [ ] **Step 3: Implement**

`inspectorctl/web/routes/hunt.py` — import the shared helper beside the existing `to_iso` import:

```python
from inspectorctl.cli.hunt import horizon_note, to_iso
```

In the template context dict add:

```python
            "horizon_note": horizon_note(result) if result else None,
```

`inspectorctl/web/templates/hunt.html` — directly under the `window … → … · limit …` line:

```html
  {%- if horizon_note %}
  <p class="mono warn">{{ horizon_note }}</p>
  {%- endif %}
```

(Jinja autoescape handles the text; check `base.html`/existing templates for the warning CSS class actually in use — reuse the existing one, e.g. the class the TRUNCATED block uses, rather than inventing `warn` if one exists.)

- [ ] **Step 4: Run tests, verify pass**

Run: `.venv/bin/python -m pytest tests/web/test_hunt.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectorctl/web/routes/hunt.py inspectorctl/web/templates/hunt.html tests/web/test_hunt.py
git commit -m "feat(web): data-horizon banner on /hunt"
```

---

### Task 4: gates, push, PR

- [ ] **Step 1: Run all gates** (commands in the header). All green, including the
  integration marker run — CI runs it in a separate step and the unit-marker
  command alone has missed integration breakage before.
- [ ] **Step 2: Push and open the PR**

```bash
git push -u origin hunt-followups
gh pr create --title "feat(hunt): data-horizon banner (PR1)" --body "..."
```

Body: what + why (spec §2 of `2026-09-07-hunt-followups-design.md`), note the spec is
autonomously drafted + concilium-reviewed. Watch CI with the Monitor tool
(NOT background `gh pr checks --watch` — it gets killed at ~10 min), then
`gh pr merge --squash --delete-branch`, sync main.
