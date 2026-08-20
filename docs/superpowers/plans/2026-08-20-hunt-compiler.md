# Hunt — the compiler (PR1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn a hunt expression — written in the *existing* YAML-rule grammar — into a
parameterized SQL query against `events_enriched`, such that the SQL selects exactly the events
the in-memory rule evaluator selects. No storage, no IPC, no CLI, no panel.

**Spec:** `docs/superpowers/specs/2026-08-20-hunt-design.md` — §3 (one parser, two backends),
§4 (what compiles to what), §5 (semantic fidelity + the differential test), §6 (injection),
§7 (bounds), §9 (this is PR1).

**Tech Stack:** Python 3.12+ stdlib (`re`, `dataclasses`, `datetime`), existing `duckdb` handle
(`inspectord/storage/db.py`), pytest. **No new third-party dependencies.**

**Explicitly NOT in this PR:** the `hunt_query` table and migration, IPC handlers, the
`inspectorctl events search` / `hunt save` / `hunt run` verbs, the `/hunt` panel, aggregation,
joins, any new grammar.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `inspectord/expr.py` | **New, shared.** The whole parsing layer: tokenizer, boolean grouping, leaf splitting, literal/list parsing, path splitting. Produces a `ParsedExpression` (OR-of-AND groups of `Leaf` / `InvalidLeaf` nodes). Never raises. |
| `inspectord/rules/yaml_loader.py` | Loses its private parser; keeps only *evaluation*. New public `evaluate_expression(expr, event) -> bool`. |
| `inspectord/hunt/__init__.py` | Package docstring + public re-exports. |
| `inspectord/hunt/errors.py` | `HuntError` + `HuntSyntaxError` / `HuntPathError` / `HuntUnsupportedError` / `HuntBoundsError`. |
| `inspectord/hunt/compiler.py` | `CompiledQuery`, `compile_hunt_query()`, operand mapping (column / JSON / always-missing), per-operator SQL. |
| `inspectord/hunt/execute.py` | `HuntRow`, `HuntResult`, `run_hunt_query(db, compiled)` — runs the compiled SQL and reports truncation. |
| `inspectord/storage/events.py` | `insert_event(db, event, payload_json)` — the one INSERT into `events_enriched`, extracted from the supervisor so tests can use *the real* persist path. |
| `inspectord/supervisor.py` | `_persist` calls `insert_event`. No behavior change. |
| `tests/test_expr.py` | Parser unit tests: tokenizing, grouping quirks, leaf splitting, literals, lists, path segments. |
| `tests/hunt/test_compiler.py` | Compilation unit tests: column vs JSON mapping, parameter binding, path rejection, bounds, errors. |
| `tests/hunt/test_execute.py` | Truncation reporting, ordering, limit capping against a real temp DuckDB. |
| `tests/hunt/test_differential.py` | **The deliverable.** Corpus + expression matrix, both backends, identical `event_id` sets. |

---

## The load-bearing decision: where the parser boundary goes

`yaml_loader` today interleaves parsing with evaluation — `_eval_leaf` splits the leaf *and*
resolves the path *and* compares. The boundary is drawn so that **everything that reads the query
text** moves to `inspectord/expr.py` and **everything that touches an `Event`** stays in
`yaml_loader`:

```
expr.py:        text ──► ParsedExpression(groups=((Node, ...), ...))
yaml_loader.py: ParsedExpression + Event ──► bool
hunt/compiler:  ParsedExpression          ──► (sql, params)
```

`ParsedExpression` is *already folded* into OR-of-AND groups, so operator precedence — including
the evaluator's quirks — is decided in one place and neither backend can drift on it. A new
operator is added by extending `expr.LEAF_OPS` (one place) and then by both backends failing
loudly until they handle it: the evaluator returns `False` for an operator it does not know, and
the compiler *raises*.

`parse_expression` is **total**: it never raises. An unparseable leaf becomes an `InvalidLeaf`
node, which is exactly how the evaluator behaves today (`_eval_leaf` returns `False` when its
regex does not match). Each backend then decides: the evaluator keeps returning `False`
(behavior-preserving), the compiler raises `HuntSyntaxError` (§6: never a silently-empty result).

**Regression suite:** `tests/rules/` must pass **untouched**.

---

## Semantic fidelity, operator by operator

Measured against the evaluator on this machine (`_resolve_path` returns `None` for a missing key,
a JSON `null`, a non-dict parent, *and* for any single-segment path such as `message`).

| evaluator does | missing / JSON `null` | empty string `""` | non-string value | SQL |
| --- | --- | --- | --- | --- |
| `==` | `None == lit` → **False** | `"" == ""` → True | typed: `42 == 42` True, `42 == "42"` False, `True == 1` True | `(<typed eq>) IS TRUE` |
| `!=` | **True** — the field is absent, so it differs | as above negated | as above negated | `(<typed eq>) IS NOT TRUE` |
| `IN` | `None in [...]` → **False** | member-wise `==` | member-wise typed `==` | `(<eq> OR <eq> …) IS TRUE` |
| `NOT IN` | **True** | | | `(<eq> OR …) IS NOT TRUE` |
| `STARTSWITH` | guarded by `isinstance(lhs, str)` → **False** | `"".startswith("x")` False | non-str lhs → **False** | `(<is str> AND starts_with(v, ?)) IS TRUE` |
| `ENDSWITH` | **False** | | **False** | `ends_with` |
| `CONTAINS` | **False** | `"" in "abc"` True | **False** | `contains` |
| `MATCHES` | **False** | | **False** | `regexp_matches` (partial match, like `re.search`) |

Consequences that the implementation must encode:

1. **NULL is not "missing"** — every leaf predicate is wrapped in `IS TRUE` / `IS NOT TRUE` so
   SQL three-valued logic collapses to Python two-valued logic. That is the general form of the
   `!=` → `IS DISTINCT FROM` rule in §5, and it fixes `NOT IN` for free.
2. **JSON `null` and a missing key are the same thing.** `json_type()` returns `'NULL'` for the
   former and SQL `NULL` for the latter; both must read as "missing".
3. **Comparison is typed.** `json_extract_string` flattens `42` and `"42"` to the same `'42'`, so
   every equality is guarded by `json_type()`: a string literal only matches `'VARCHAR'`, an int
   literal only matches `'BIGINT' / 'UBIGINT' / 'DOUBLE'` (via `TRY_CAST(... AS DOUBLE)`), a bool
   literal only matches `'BOOLEAN'`. Python's `True == 1` quirk is mirrored explicitly.
4. **String operators are not LIKE.** `starts_with` / `ends_with` / `contains` take plain strings,
   so `%` and `_` in a literal are literal. Tested with a literal containing both.
5. **Real columns are never NULL and always strings.** `event.module|action|severity|kind` compile
   to the column; a non-string literal against them compiles to a constant `FALSE` (the evaluator
   can never match either, since the value is always a `str`).
6. **Single-segment paths always resolve to `None`** in the evaluator (`message`, `event`), so
   they compile to the "always missing" operand — `!=` / `NOT IN` match everything, the rest
   match nothing.

### Deliberate rejections (compiler raises where the evaluator silently answers)

| expression | evaluator | compiler | why |
| --- | --- | --- | --- |
| unparseable leaf (`garbage`, `NOT`) | `False` | `HuntSyntaxError` | §6 — a typo must not read as "no results" |
| `event.ts <op> …` | compares a `datetime` to a `str` → `==` always False, `!=` always True | `HuntUnsupportedError` | faithful compilation would be a silent-empty trap; time filtering is the `since` / `until` bound |
| `path STARTSWITH 5` | raises `TypeError` | `HuntUnsupportedError` | both refuse; the compiler's message is readable |
| `a..b`, `a.` | resolves to `None` | `HuntPathError` naming the segment | §6 — paths are interpolated |
| `MATCHES` with a lookaround/backreference | Python `re` accepts | `HuntUnsupportedError` | DuckDB is RE2; rejecting beats disagreeing |

---

## Bounds (§7)

- `LIMIT` defaults to `DEFAULT_LIMIT = 500`, capped at `MAX_LIMIT = 5000`; `limit <= 0` raises.
- The emitted SQL binds `limit + 1` so the caller can *see* truncation; `CompiledQuery.limit` is
  the real limit and `run_hunt_query` trims the probe row and sets `HuntResult.truncated`.
- Ordered `ts DESC, event_id DESC` — newest-first, with a deterministic tiebreak.
- `since` (inclusive) / `until` (inclusive) are optional bound parameters on the indexed `ts`
  column. PR2 supplies the default recent window at the CLI/IPC edge.

---

## Tasks

- [ ] **Task 1 — extract the parser.** Create `inspectord/expr.py`; rewrite `yaml_loader` to use
      it; `tests/test_expr.py`. `tests/rules/` passes untouched.
- [ ] **Task 2 — the compiler.** `inspectord/hunt/`; `insert_event` extraction;
      `tests/hunt/test_compiler.py`, `tests/hunt/test_execute.py`.
- [ ] **Task 3 — the differential test.** Corpus + expression matrix + useful failure output.

## Testing strategy

- Parser tests assert *structure*, not behavior of either backend.
- Compiler tests assert the SQL shape and, critically, that **no literal appears in the SQL text**.
- The differential test is the contract: corpus events covering present / missing / JSON-null /
  empty-string / nested / numeric / boolean / unicode / partially-present paths, persisted through
  `insert_event` (the same call the supervisor makes), then every expression run through both
  backends with the selected `event_id` sets compared. Failure output names the expression and
  prints `only-in-SQL` / `only-in-evaluator` id sets.
