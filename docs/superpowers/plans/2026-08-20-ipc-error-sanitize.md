# IPC error sanitization — stop `repr(exc)` reaching the client

| Field | Value |
| --- | --- |
| Date | 2026-08-20 |
| Branch | `ipc-error-sanitize` |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` (§ IPC surface) |
| Related | `docs/superpowers/plans/2026-08-20-hunt-compiler.md` (`HuntExecutionError` — the same problem solved for one slice) |

## 1. Problem

`IpcServer._dispatch` ends with:

```python
except Exception as exc:
    log.exception("handler raised")
    conn.sendall(_err(req_id, -32000, repr(exc)))
```

Every handler's raw exception `repr` is sent to the client. Verified leaks (real, not assumed):

| Exception | `repr(exc)` |
| --- | --- |
| `duckdb.CatalogException` | `Catalog Error: Table with name events_enriched does not exist! … LINE 2: FROM events_enriched` — the generated SQL and the schema |
| `duckdb.IOException` | `IO Error: Cannot open file "/…/inspectord.duckdb": …` — a filesystem path |
| any future handler bug | whatever the exception happens to hold |

(Checked and worth recording: a plain `OSError`/`FileNotFoundError` `repr` is
`FileNotFoundError(2, 'No such file or directory')` — CPython omits `filename` from
`OSError.__repr__`, so *that* shape does not leak the path today. `str(exc)` does, and
DuckDB's own IO error embeds the path in its message, so the class of bug is real.)

Threat model, stated honestly: the socket is `0600` (opt-in `0660` with a configured group), so
the client is the user or a member of that group — this is defence in depth, not a remote hole.
It matters because **`inspectorctl`'s web UI is a pure IPC client and renders these strings**
(`error = f"daemon unreachable: {exc}"` in every route), so an error string lands on a browser
page, and Hunt PR3 will put query errors on a page.

Hunt already solved this for itself (`HuntExecutionError` carries the user's own query, never
DuckDB's message) — which proves the pattern but leaves every other handler exposed.

## 2. Mechanism: a marker base class, default-sanitize

`inspectord/ipc_errors.py` (a leaf module, no imports from the daemon):

```python
class ClientFacingError(Exception):
    """An exception whose message was written for the IPC client."""
```

`_dispatch` grows one branch *before* the blanket one:

```python
except ClientFacingError as exc:      # opt-in: message written for a human client
    log.info("ipc: %s rejected the request: %s", name, exc)
    conn.sendall(_err(req_id, -32000, str(exc)))
except Exception:                     # everything else: sanitized
    ref = new_error_ref()
    log.exception("ipc: %s failed (error_ref=%s)", name, ref)
    conn.sendall(_err(req_id, -32000, f"internal error (error_ref={ref})…"))
```

**Why a marker class rather than an allowlist of types or an explicit `code`:**

* It fails safe by construction. The *only* way to reach the client is to inherit from
  `ClientFacingError`, which is a deliberate act at the point where the message is written —
  the same place a developer decides the wording. Any exception a future handler raises,
  imports, or lets escape from a library is sanitized with no registry to remember to update.
* An allowlist lives far from the `raise` and drifts: adding an error type in
  `inspectord/hunt/errors.py` and forgetting the table in `ipc_server.py` silently degrades
  Hunt, and the failure is *silent* (a working message becomes "internal error") so nothing
  catches it in review.
* An explicit `code` on the error is the same opt-in as the marker, but weaker: an untyped
  `code` attribute can appear accidentally on an unrelated exception (`e.code` exists on
  `SystemExit`, `urllib.error.HTTPError`, …), and duck-typing an attribute makes the leak
  path implicit. Marker inheritance is grep-able: `grep -rn ClientFacingError inspectord`
  enumerates every class allowed to speak to a client.

**Correlation id.** `new_error_ref()` returns `secrets.token_hex(8)` — 64 uniformly random
bits. The first attempt was `uuid7().hex[:16]`, to match the project's usual id, and the
uniqueness test rejected it: a uuid7 prefix is a millisecond timestamp with only 12 random bits
behind it, so two failures in the same millisecond collide — exactly when correlation matters.
The log record carries its own timestamp, so the ref does not need to, and a random ref also
tells the client nothing. It appears in *both* the client message and the daemon log line
that carries the full traceback (`log.exception` → `JsonFormatter` emits `exc_info`), so a user
can paste the id and the operator finds the traceback. Nothing is lost for debugging.

**Wire format is unchanged**: still `{"error": {"code": -32000, "message": …}}`. Only the
message content changes. Both branches keep `-32000` deliberately — a distinct code would be a
wire change and existing clients only display the message.

## 3. Which exceptions are user-facing

Determined by reading every registered handler in `inspectord/__main__.py:_ipc_methods` and
tracing what each can raise:

| Type | Verdict | Why |
| --- | --- | --- |
| `HuntError` + 9 subclasses (`inspectord/hunt/errors.py`) | **user-facing** | Its own docstring: "shown to IPC clients verbatim … must never quote generated SQL, schema internals or filesystem paths". `HuntSyntaxError`/`HuntPathError` name what is wrong with *the user's query*; flattening them makes Hunt unusable. |
| `InvalidTransitionError` (`inspectord/alerts/lifecycle.py`) | **user-facing** | `cannot transition 'resolved' → 'acknowledged'`. It escapes `_transition` uncaught **today**, so it is a currently-useful client-facing message that must not regress. Contains only alert-status enum values. |
| missing required param in `inspectord/cases/ipc_handlers.py` (`params["case_id"]` → `KeyError`) | **user-facing, but reworked** | Today the client usefully sees `KeyError('case_id')`. Sanitizing that would be a real regression, so those eight `params[...]` reads become a `_required` helper raising `IpcParamError("case_id is required")`. Echoes only a param name the client itself chose. |
| `ValueError("plan_id required")` (`dependencies/ipc_handlers.py`) | **user-facing, retyped** | Written for the caller; becomes `IpcParamError`. A bare `ValueError` must not be user-facing as a *class* — `int("abc")` raises one too. |
| `ValueError(f"unsupported baseline kind: {kind!r}")` (`state/baseline.py`) | **user-facing, retyped** | `kind` is the client's own param; becomes `IpcParamError`. |
| `duckdb.Error` and subclasses | sanitized | Carries SQL and paths. |
| `OSError`, `KeyError` from storage rows, `json.JSONDecodeError`, everything else | sanitized | Daemon internals. |
| `int(params.get("limit", 200))` raising `ValueError` (13 call sites) | sanitized — **accepted, documented** | The message only echoes the caller's own value, so it is not a disclosure; the client loses a little clarity on a request only a buggy client sends (CLI and web always send ints). Converting 13 call sites is out of scope for a security fix. |

`IpcParamError(ClientFacingError)` is the one shared subclass, so "a required parameter is
missing" reads the same from every subsystem.

Note verified while reading: hunt handlers catch `HuntError` internally and return
`{ok: False, error, error_kind}`, so today no `HuntError` reaches `_dispatch`. The passthrough
branch is what makes that *safe to stop doing* (Hunt PR3) and is tested directly.

## 4. Tasks

1. **`inspectord/ipc_errors.py`** — `ClientFacingError`, `IpcParamError`, `new_error_ref()`.
   Tests: ref shape/uniqueness.
2. **`_dispatch`** — passthrough + sanitize branches. Tests (real failures, no mocks):
   * a handler running a real query against a missing table on a real DuckDB file: response
     must not contain `events_enriched`, `Catalog Error`, `SELECT`, or `LINE`;
   * a handler doing a real `duckdb.connect` on a bad path: response must not contain the path;
   * both: response matches `internal error (error_ref=<16 hex>)`, the *same* ref appears in
     a daemon log record, and that record carries a traceback;
   * a handler raising a real `HuntSyntaxError` from `compile_hunt_query("")`: the full message
     reaches the client verbatim.
3. **Retype the user-facing raises** — `HuntError(ClientFacingError, ValueError)` (keeps
   `ValueError` so existing `except ValueError` / `pytest.raises(ValueError)` still hold),
   `InvalidTransitionError(ClientFacingError, RuntimeError)`, cases `_required`, dependencies
   and baseline `IpcParamError`. Tests: end-to-end over a real socket for the alert-transition
   and missing-`case_id` messages.

## 5. Constraints

* Wire format unchanged beyond message content; no new third-party dependencies.
* Both suites green before each commit (unit **and** integration — the documented gate excludes
  integration, CI runs it separately), plus ruff check/format and mypy.
* No fixed-sleep assertions: the log record is written *before* `sendall`, so reading the
  response is itself the synchronisation point — no sleeping, no polling needed.
