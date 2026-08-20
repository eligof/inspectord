# hunt panel — `/hunt` (PR3)

| Field | Value |
| --- | --- |
| Date | 2026-08-20 |
| Branch | `hunt-panel` |
| Design doc | `docs/superpowers/specs/2026-08-20-hunt-design.md` — §7 (bounds), §8 (saved queries), §9 (PR3), §10 (out of scope) |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` §2.2 ("Hunt — saved + ad-hoc queries") |
| Builds on | #134 (compiler, PR1), #135 (saved queries + CLI, PR2), #136 (IPC error sanitisation) |
| Pattern | the Antivirus panel (#132): `routes/scanners.py`, `templates/scanners*.html`, `tests/web/test_scanners.py` |

## 1. Problem

The compiler and the saved-query store ship, and `inspectorctl hunt` can run both, but the only
way to hunt is the terminal. §9 names the last slice: "`/hunt`: a query box, a results table, the
saved-query list."

Everything on that page is attacker-influenceable — event payloads carry process names, file
paths and scanner findings, and the scanner adapters' docstrings record that *a filename can
forge report text* — so the escaping discipline and the XSS test of the Antivirus panel apply
verbatim.

## 2. What gets built

1. `inspectorctl/web/routes/hunt.py` — one route, `GET /hunt`.
2. `inspectorctl/web/templates/hunt.html` — form, saved-query list, results table.
3. A nav link in `base.html`, the router wired in `app.py`.
4. `tests/web/test_hunt.py`.

Nothing daemon-side changes. The compiler, the store and the IPC handlers are untouched: if
this slice finds a bug in them it gets reported, not patched here — `tests/hunt/test_differential.py`
is the compiler's contract.

## 3. The web is a pure IPC client

Same constraint as case export (`2026-06-23-case-export-design.md` §1): the panel has no
filesystem, no database, and imports no `inspectord.hunt` execution code. It calls
`inspectorctl.web.ipc.call(socket_path, ...)` and renders what comes back.

Three methods, all `mutates=False`:

| call | why |
| --- | --- |
| `run_hunt_query` | the query box, and "run" on a saved query |
| `list_hunt_queries` | the saved-query list |

`get_hunt_query` is not needed: the list already carries every field the page shows.

## 4. Decision — save/delete are NOT on the page

The panel is **read-only**. It runs queries and lists saved ones; it never calls
`save_hunt_query` or `delete_hunt_query`.

- §9 scopes PR3 to "a query box, a results table, the saved-query list" — running, not authoring.
- Those two methods are the only Hunt methods registered `mutates=True`, and `__main__.py` says
  why in as many words: they "write durable, named state that another caller later runs, and a
  save with `replace` destroys the previous query". The case-export design (§2.2) shows the other
  half of that rule — user-initiated *reads* are deliberately `mutates=False` "so a future polkit
  gate does not prompt on every download". `mutates=True` is precisely the set a future
  authorization gate will prompt for, and a browser page has no path to service such a prompt.
- The dashboard has no CSRF token. A cross-site form post to a localhost dashboard that can
  `save --replace` (destroying the previous expression) or `delete` a saved hunt is a worse
  trade than making the user type `inspectorctl hunt save`, which is one command and is where an
  authorization prompt can actually be answered.
- The page therefore stays entirely on `GET`, which is what makes every result URL bookmarkable
  and re-runnable (§6).

The page says so, and names the CLI command that saves, so the missing button is a documented
choice rather than a hole.

## 5. Bounds are visible or the panel is lying (§7)

PR2's CLI prints the window and limit on **every** run and distinguishes truncated / empty /
complete in words (`inspectorctl/cli/hunt.py`). The panel does the same, from the same response
fields — no second truncation signal is invented:

| response field | rendered as |
| --- | --- |
| `since`, `until` | "window <since> → <until or now>" above the results |
| `limit` | "limit N" — the *resolved* limit, so the daemon's silent cap at `MAX_LIMIT` shows |
| `truncated` | a loud "TRUNCATED — showing N of possibly more; these are the newest matches, so older ones are missing", plus how to fix it |
| `count == 0` | "no matches — 0 events in this window", plus "widen the window" |
| otherwise | "N matches — complete for this window" |

The three states are mutually exclusive and each is a sentence, not a blank.

## 6. Shape of the page

One endpoint, `GET /hunt`, with query parameters `q`, `name`, `since`, `limit`. No results are
run when neither `q` nor `name` is present — the page opens idle rather than firing a default
query at the database.

The form is a plain `<form method="get" action="/hunt">`, enhanced with
`hx-get="/hunt" hx-select="#hunt-results" hx-target="#hunt-results" hx-push-url="true"` so htmx
(already loaded by `base.html`) swaps just the results while pushing a URL that is a real page.
That is deliberately *not* the shell + `_feed.html` polling pattern of the other panels:

- a hunt is an explicit action, not a live feed — polling would re-run a heavy query every 10s;
- pushing `/hunt?q=…` means a result is bookmarkable, reloadable and pasteable into a case note,
  which is what an investigation actually wants;
- with JS off the same form still works, because the fallback is a normal GET.

Saved queries are `<a href="/hunt?name=…">` links for the same reason.

`since` accepts `24h` / `7d` shorthand or ISO-8601, converted by **`inspectorctl.cli.hunt.to_iso`
— the existing one**. A second shorthand parser on this page would drift from the CLI's, which is
the same failure mode §3 of the design forbids for the query grammar itself.

## 7. What a result row shows

Time · severity badge · kind · module · action · message · details.

"Details" is a bounded, whitelisted set of payload paths rendered as `label value` chips — the
fields an investigation pivots on:

`process.name`, `process.pid`, `process.executable`, `process.command_line`, `user.name`,
`user.id`, `file.path`, `file.hash.sha256`, `source.ip`, `source.port`, `destination.ip`,
`destination.port`, `network.transport`, `service.name`, `service.state`, `persistence.kind`,
`persistence.name`, `persistence.source_path`, `device.name`, `device.vendor`, `device.serial`,
`threat.indicator.type`, `threat.indicator.value`, `rule.name`, `rule.id`.

Absent paths are omitted, so a row is as short as the event is. Each value is stringified and
clipped to 300 characters with an explicit `…` so one hostile 4 MB `command_line` cannot push the
rest of the table off the screen — and the clip is visible, because a silent clip is the same lie
as a silent truncation.

Left out on purpose: `raw` (the unparsed source line — the largest and least structured field,
and reproducing it is what "a wall of raw JSON" means), `host` (single-host product), `labels`,
`baseline`, `evidence`, `package`, `category`/`type`. `event_id` is shown once per row, as a
muted mono line under the timestamp, because it is the handle for pivoting to a case.

## 8. Errors: two kinds, never flattened

| arrives as | rendered as |
| --- | --- |
| `{ok: False, error, error_kind}` — a `HuntError`, written for the person who typed the query and passed through IPC intact since #136 | a warning **next to the query box**: "query rejected (`<kind>`)" and the daemon's own message, verbatim. The form keeps the text so it can be edited. |
| `WebIpcError` whose message contains `error_ref=` — the daemon's internal-error envelope | "the daemon failed to answer — this is not a problem with your query", plus the `error_ref` to paste. Never in the query-box slot. |
| `WebIpcError` otherwise (socket missing) | "daemon unreachable", the existing wording of every other panel. |

## 9. Escaping

Jinja2 autoescaping only. No `|safe`, no `Markup`, nothing rendered as markup — the template
carries the same comment block as `scanners_feed.html`. Attacker-influenceable on this page:
every payload value, `module`/`action`/`severity`/`kind`, the message, the echoed expression, the
daemon's error message (it quotes the user's query back), and every saved query's name,
expression and description.

`store.NAME_PATTERN` already excludes `<`, `&`, quotes and non-ASCII from *new* names, but the
page must not depend on that: the test drives a payload through the name field too, because a row
already in the table predates any pattern and a defence that only works upstream is not a
defence.

## 10. Tests (`tests/web/test_hunt.py`)

Fake `run_hunt_query` / `list_hunt_queries` `Method`s over the real `IpcServer`, via the existing
`ipc_factory` fixture. No sleeps anywhere.

1. idle page: form renders, no query is run.
2. ad-hoc query runs and renders rows newest-first, as returned.
3. the window and the resolved limit are on the page, always.
4. truncated says TRUNCATED and how to fix it.
5. empty says "no matches", not a blank.
6. complete says "complete for this window".
7. saved queries list with run links; empty list names the CLI save command.
8. `?name=` runs the saved query and says which saved query ran.
9. a `HuntError` renders as a readable message with its kind, next to the box.
10. an internal error renders the `error_ref` and does not blame the query.
11. daemon unreachable.
12. `24h` shorthand reaches the daemon as an ISO timestamp.
13. a long value is clipped and says so.
14. the page says save/delete live in the CLI.
15. **XSS**: one payload driven through *every* attacker-influenceable field — module, action,
    severity, kind, message, several payload values, the echoed expression, the error message, and
    a saved query's name, expression and description — asserting the raw form never appears and
    the escaped form appears at least N times, so a silently dropped field cannot pass.

## 11. Out of scope

No aggregation, no charts, no query autocomplete, no "save this query" button (§4), no export.
Nothing daemon-side changes.
