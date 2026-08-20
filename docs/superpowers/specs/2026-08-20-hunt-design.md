# Hunt — design

| Field | Value |
| --- | --- |
| Date | 2026-08-20 |
| Status | Drafted autonomously. The core decision — reuse the YAML rule grammar rather than invent a second query language — was made by the user. |
| Parent spec | `docs/superpowers/specs/2026-05-24-local-inspection-design.md` |
| Parent refs | §2.2 (Hunt panel), §24 (`inspectorctl events search`, `hunt save`, `hunt run`), §31 (Phase 3), §32 (no playbooks shipped) |
| Phase | 3 |

## 1. Purpose

Hunt is investigation: ask a question of the stored event history, save the question, run it
again later. Parent §2.2 asks for "saved + ad-hoc queries (KQL-ish syntax compiled to SQL
against DuckDB)" and §24 names `inspectorctl events search "<query>"`, `hunt save <name>`,
`hunt run <name>`.

The parent spec never defined the grammar. **The decision is to reuse the YAML rule engine's
expression grammar** rather than design a second one, so a hunt query and a detection rule are
written the same way — and so a query that finds something can become a rule by copy-paste.

## 2. The grammar already exists

`inspectord/rules/yaml_loader.py` implements it for in-memory evaluation:

- **Leaf operators**: `==`, `!=`, `IN`, `NOT IN`, `STARTSWITH`, `ENDSWITH`, `CONTAINS`,
  `MATCHES`
- **Boolean**: `AND`, `OR`, `NOT`
- **Paths**: dotted, walking nested dicts — `process.name`, `threat.indicator.source`,
  `event.module`
- **Literals**: quoted strings, bare numbers, `[a, b]` lists

Keywords are uppercase-only and case-sensitive; a lowercase `and` is not an operator. That is
existing behavior, and Hunt inherits it rather than diverging from it.

## 3. The load-bearing constraint: one parser, two backends

"Reuse the grammar" must not become "write a second parser that agrees with the first". Two
parsers drift, and the drift shows up as *a hunt query that finds different events than the
identical rule* — a trust-destroying bug in an investigation tool.

So the parsing layer — tokenizer, leaf splitter, literal parser — is **extracted into a shared
module** and used unchanged by both:

- the existing **evaluator** (`Event` in memory → bool), and
- the new **compiler** (expression → parameterized SQL).

The extraction must be behavior-preserving: the rule engine's existing tests are the regression
suite for that step and must pass untouched.

## 4. Storage shape, and what compiles to what

`events_enriched` (migration 0001):

```sql
event_id VARCHAR PRIMARY KEY, ts TIMESTAMP, kind VARCHAR, module VARCHAR,
action VARCHAR, severity VARCHAR, payload_json VARCHAR
```

with indexes on `ts` and `module`.

Five fields are **real columns**; everything else lives in a JSON blob. The compiler exploits
that:

| path | compiles to |
| --- | --- |
| `event.module`, `event.action`, `event.severity`, `event.kind` | the column directly — indexed, no JSON parsing |
| `event.ts` | the `ts` column, with timestamp literals |
| anything else (`process.name`, `threat.indicator.source`, …) | `json_extract_string(payload_json, '$.process.name')` |

Verified working against the installed DuckDB 1.5.3.

## 5. Semantic fidelity is the crux

**The same query must select the same events through SQL as the evaluator selects in memory.**
That is not automatic, because SQL's NULL is not Python's "missing key". Measured on this
machine:

| | result |
| --- | --- |
| evaluator: `process.name != "curl"` on an event with **no** `process` | **True** — it matches |
| SQL: `p != 'curl'` where `p IS NULL` | **0 rows** — silently dropped |
| SQL: `p IS DISTINCT FROM 'curl'` | **1 row** — matches the evaluator |

A naive compiler would therefore *hide exactly the events a hunter is looking for*, with no
error anywhere. So:

- `!=` compiles to `IS DISTINCT FROM`, and `NOT IN` to a NULL-safe equivalent.
- Every other operator gets the same treatment: decide, per operator, what the evaluator does
  with a missing field, and make the SQL agree.
- `STARTSWITH` / `ENDSWITH` / `CONTAINS` must not let a literal's `%` or `_` act as a LIKE
  wildcard — use DuckDB's `starts_with` / `ends_with` / `contains` functions, or escape the
  pattern. The evaluator does plain Python string operations, so the SQL must too.

### 5.1 The test that makes this credible

A **differential test**: build a corpus of events covering present / missing / null / empty
fields, nested paths, numeric and string values, and unicode; persist them; then for a list of
expressions run *both* backends and assert the selected `event_id` sets are **identical**.

That is the only test that can prove the two backends agree, and it is why this slice is worth
doing carefully. Any operator added later must be added to that corpus.

## 6. Injection

The compiler turns user text into SQL, so it is an injection surface and is treated as one.

- **Literals are always bound parameters**, never interpolated.
- **Paths are interpolated** (they become part of a JSON path string), so every segment is
  validated against a strict identifier pattern first, and anything else is rejected with an
  error naming the offending segment.
- Rejection is a normal outcome, not an exception to swallow: an unparseable query must produce
  a readable message, never a partial or silently-empty result.

## 7. Bounds

An investigation query must not be able to hang the daemon or exhaust memory:

- Every query gets a **`LIMIT`**, defaulted and capped.
- Every query gets a **time bound** (defaulted to a recent window) so the common case never
  scans all history.
- Results are ordered newest-first, so a truncated result is the useful half.
- A truncated result **says so**. A silently-cut result set in an investigation tool is actively
  misleading.

## 8. Saved queries

A `hunt_query` table (name, expression, optional description, created/updated timestamps), plus
read/write IPC handlers, plus the `hunt save` / `hunt run` / `events search` CLI verbs named in
§24. Saving does not validate a query against events — but it **does** compile it, so a query
that cannot compile is rejected at save time rather than at 2am.

## 9. Slices

- **PR1 — the compiler.** Extract the shared parser, build expression → parameterized SQL, and
  the differential test. No UI, no storage. This is the part that has to be right.
- **PR2 — saved queries.** Migration, IPC handlers, CLI verbs.
- **PR3 — the panel.** `/hunt`: a query box, a results table, the saved-query list. Scanner and
  process text reaches this page, and a filename can forge report text (see the scanner
  adapters' docstrings), so the same escaping discipline as the Antivirus panel applies, with
  the same kind of test.

## 10. Out of scope

Shipped hunting content (§32: none — the community can contribute later); joins across tables;
aggregation (`count by`, `summarize`); a second grammar of any kind; anything that mutates data.
Hunt is read-only by construction.
