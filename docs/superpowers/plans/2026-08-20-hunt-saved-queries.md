# Hunt — saved queries, IPC and CLI (PR2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** give the PR1 compiler its first real caller. A `hunt_query` table, IPC handlers for
list / get / run / save / delete, and the `inspectorctl events search` / `hunt save` /
`hunt run` verbs named in parent §24 — with output an investigator can trust: bounded,
newest-first, and loud about truncation and emptiness.

**Spec:** `docs/superpowers/specs/2026-08-20-hunt-design.md` — §7 (bounds), §8 (saved queries),
§9 (this is PR2). Parent `2026-05-24-local-inspection-design.md` §24 (CLI surface).

**Tech Stack:** Python 3.12 stdlib, existing `duckdb` handle, `typer` + `rich` (already
dependencies), pytest. **No new third-party dependencies.**

**Explicitly NOT in this PR:** the `/hunt` web panel (PR3), aggregation, joins, any change to
the compiler's semantics. `tests/hunt/test_differential.py` is the fidelity contract and must
pass untouched.

---

## Decisions taken up front

### Name collisions: refuse, unless the caller says `replace`

A saved query name is a key an investigator types at 2am. Silent overwrite is the failure mode
that costs an investigation — you type `hunt save suspicious-curl "<new thing>"`, and the query
you wrote three weeks ago is gone with no message. So:

- `save_hunt_query` **refuses** a name that already exists and returns the *existing*
  expression in the error, so the caller can see what they nearly clobbered.
- `replace: true` (CLI `--replace`) overwrites, and the response says `replaced: true` and
  carries `previous_expression`.
- The CLI prints three visibly different things: `saved`, `replaced … (was: <old>)`, and the
  refusal naming `--replace`. No path prints the same line as another.

### `mutates` per handler

The repo has precedent both ways, and the reason is in `2026-06-23-case-export-design.md` §2.2:
the case export/download handlers are `mutates=False` *despite writing a custody row*, because
the flag is a future polkit gate on the **user's intent**, not an audit of every INSERT — and
prompting for authorization on a download would be wrong.

Applying the same rule:

| method | mutates | why |
| --- | --- | --- |
| `list_hunt_queries` | `False` | pure read |
| `get_hunt_query` | `False` | pure read |
| `run_hunt_query` | `False` | Hunt is read-only by construction (§10). Running an investigation query is the single most common thing this feature does; a permission prompt per query would be intolerable, and there is nothing to authorize — the only statement executed is the compiled SELECT. |
| `save_hunt_query` | `True` | writes durable, named user state that another caller can later run. Intent-bearing, and it can *destroy* a prior query under `replace`. |
| `delete_hunt_query` | `True` | destroys durable user state |

### Bounds at the edge (§7)

- `MAX_EXPRESSION_CHARS = 4096`, `MAX_NAME_CHARS = 64`, `MAX_DESCRIPTION_CHARS = 512`. Over the
  cap is a **rejection with a clear message**, never a truncation — a silently shortened query
  is a silently different query.
- `DEFAULT_WINDOW = 7 days`. When the caller supplies no `since`, the handler defaults it, so
  the common case never scans all history. The window used is **always reported back and always
  printed**, because a default window that the user cannot see is itself a silent truncation.
- `limit` defaults/caps come from PR1 (`DEFAULT_LIMIT = 500`, `MAX_LIMIT = 5000`).

### Name pattern

`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` — starts alphanumeric, then alphanumerics, dot, underscore
or hyphen; 1–64 characters. This is deliberately narrow because the name is echoed into a
terminal today and into HTML in PR3: the pattern excludes whitespace, quotes, `<`, `&`, control
characters, ANSI escape introducers and every non-ASCII codepoint (so no RTL override, no
homoglyph). Rejection names the offending input.

### The two deferred PR1 items

1. **`run_hunt_query` wraps DuckDB errors.** A `duckdb.Error` message can quote the failing SQL
   with a `LINE n:` marker, and `IpcServer._dispatch` sends `repr(exc)` straight to the client.
   So `run_hunt_query` catches `duckdb.Error` and raises `HuntExecutionError` whose message
   contains **the user's own expression and nothing else** — no SQL, no column names, no file
   path. The DuckDB detail is logged daemon-side at warning level, where it belongs.
2. **Expression length cap**, above, applied in `hunt/ipc_handlers.py` before compiling.

---

## File structure

| File | Responsibility |
| --- | --- |
| `inspectord/storage/migrations_data/0009_hunt_query.sql` | **New.** The `hunt_query` table. |
| `inspectord/hunt/errors.py` | Adds `HuntExecutionError`, `HuntNameError`, `HuntQueryExists`, `HuntQueryNotFound`. |
| `inspectord/hunt/execute.py` | Wraps `duckdb.Error` in `HuntExecutionError`. |
| `inspectord/hunt/store.py` | **New.** `HuntQuery` record, `validate_name`, `save`, `get`, `list_queries`, `delete`. Compiles on save (§8). |
| `inspectord/hunt/ipc_handlers.py` | **New.** The five handlers, the request bounds, the default window, and the `HuntError` → `{ok: False, error, error_kind}` translation. |
| `inspectord/__main__.py` | Registers the five methods with the `mutates` values above. |
| `inspectorctl/cli/hunt.py` | **New.** `save` / `run` / `list` / `delete`, plus the shared result renderer. |
| `inspectorctl/cli/events.py` | `events search "<query>"` — optional positional query; with one it hunts, without one it keeps today's recent-event listing. |
| `inspectorctl/cli/app.py` | `app.add_typer(hunt.app, name="hunt")`. |

### Tests

| File | What it pins |
| --- | --- |
| `tests/test_hunt_query_migration.py` | table, columns, PK, idempotence |
| `tests/hunt/test_store.py` | name validation, save compiles, collision refusal + replace, get/list/delete, timestamps |
| `tests/hunt/test_execute.py` (extended) | a **real** DuckDB error is wrapped, and the message leaks no SQL/path |
| `tests/hunt/test_ipc_handlers.py` | the five handlers, bounds rejection, default window, error shapes |
| `tests/test_cli_hunt.py` | save/replace/refuse output, run rendering, truncated banner, empty banner, compile-error passthrough |
| `tests/test_cli_events.py` (extended) | `events search "<query>"` hits `run_hunt_query`; no query keeps `list_events` |

No fixed-sleep assertions anywhere: the CLI tests drive a real `IpcServer` over a tmp socket and
assert on the command's own result, which is synchronous.

---

## Tasks

- [x] **Task 1 — migration.** `0009_hunt_query.sql` + `tests/test_hunt_query_migration.py`.
- [x] **Task 2 — the deferred PR1 items.** `HuntExecutionError` + the `duckdb.Error` wrap in
      `execute.py`, with a leak test that provokes a real DuckDB failure.
- [x] **Task 3 — the store.** `hunt/store.py`: name validation, compile-on-save, collision
      policy, CRUD. `tests/hunt/test_store.py`.
- [x] **Task 4 — IPC handlers.** `hunt/ipc_handlers.py` + registration in `__main__.py` +
      `tests/hunt/test_ipc_handlers.py`.
- [x] **Task 5 — CLI.** `inspectorctl/cli/hunt.py`, `events search`, wiring, and the CLI tests.

## Verification

Both suites, since CI runs integration separately from the documented gate:

```
.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q
.venv/bin/python -m pytest -m "integration and not ebpf_load" -q
.venv/bin/ruff check inspectord inspectorctl tests
.venv/bin/ruff format --check inspectord inspectorctl tests
.venv/bin/mypy inspectord
```
