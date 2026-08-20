"""Hunt expression → parameterized SQL over `events_enriched` (hunt design §4, §5, §6, §7).

The expression grammar is the rule engine's, parsed by the *shared* parser in
`inspectord.expr`. This module only decides what each parsed node means in SQL.

Two properties are load-bearing.

**Injection (§6).** Literals are always bound parameters — no literal ever
reaches the SQL text. Paths *are* interpolated, because they become part of a
JSON path string, so every segment is validated against a strict identifier
pattern first and anything else is rejected by name.

**Semantic fidelity (§5).** The same expression must select the same events
here as `inspectord.rules.yaml_loader` selects in memory. That does not happen
by writing the obvious SQL, because SQL and Python disagree twice:

*NULL is not "missing".* The evaluator resolves a missing key, a JSON `null`, a
non-dict parent and any single-segment path all to `None`, and then compares
with Python semantics — so `process.name != "curl"` is **true** for an event
with no process block. In SQL the same comparison is `NULL`, and a `NULL` WHERE
clause drops the row. Every leaf predicate is therefore wrapped in `IS TRUE` /
`IS NOT TRUE`, collapsing three-valued logic to two-valued exactly where the
evaluator does. (That is the general form of the `!=` → `IS DISTINCT FROM` rule
in §5, and it fixes `NOT IN` at the same time.)

*Integers compare exactly.* Python integers are arbitrary-precision and
compare exactly; IEEE-754 doubles are only exact to 2**53, so a `DOUBLE`
comparison fuses distinct integers — `9007199254740992` and
`9007199254740993` are one value to a double. A pid, inode or nanosecond
timestamp is easily that large, and the failure is silent: the hunt returns an
event holding a *different* number than the one asked for. `_append_numeric`
therefore never routes an integer through a double unless it is provably
lossless; see its docstring.

*Comparison is typed.* `json_extract_string` flattens the JSON number `42` and
the JSON string `"42"` to the same `'42'`, while the evaluator says
`42 == "42"` is false. So every equality is guarded by `json_type()`: a string
literal can only match `VARCHAR`, an integer literal only a JSON number (and,
mirroring Python's `True == 1`, a boolean), a boolean literal only `BOOLEAN`
(and a numeric 0/1). Likewise `STARTSWITH` / `ENDSWITH` / `CONTAINS` /
`MATCHES` are guarded on `VARCHAR`, because the evaluator applies them only
when the resolved value `isinstance(lhs, str)`.

String operators use DuckDB's `starts_with` / `ends_with` / `contains`, not
`LIKE`, so a literal `%` or `_` is a literal `%` or `_`.

Known residual gap: `MATCHES` runs under DuckDB's RE2, whose shorthand classes
(`\\w`, `\\d`, `\\s`, `\\b`) are ASCII-only while Python's are Unicode-aware,
and whose `$` does not match before a trailing newline. Constructs RE2 cannot
parse at all are rejected at compile time rather than blowing up mid-query.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from inspectord.expr import (
    LEAF_OPS,
    InvalidLeaf,
    Leaf,
    LiteralValue,
    Node,
    ParsedExpression,
    parse_expression,
    parse_list,
    parse_literal,
    path_segments,
)
from inspectord.hunt.errors import (
    HuntBoundsError,
    HuntPathError,
    HuntSyntaxError,
    HuntUnsupportedError,
)

__all__ = [
    "COLUMN_PATHS",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "CompiledQuery",
    "compile_hunt_query",
]

#: `event.<name>` paths that live in a real, indexed column rather than in the
#: JSON payload. `event.ts` is deliberately absent — see `_operand_for`.
COLUMN_PATHS: dict[str, str] = {
    "kind": "kind",
    "module": "module",
    "action": "action",
    "severity": "severity",
}

DEFAULT_LIMIT = 500
MAX_LIMIT = 5000

_SEGMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_JSON_NUMBER_TYPES = "('BIGINT', 'UBIGINT', 'DOUBLE')"

#: A JSON *integer* token, as `json_extract_string` hands it back: canonical
#: decimal, optional minus, no point and no exponent. A token that does not
#: match this is a float, and is compared as one.
_JSON_INTEGER_TOKEN = "'^-?[0-9]+$'"

_STRING_FUNCS = {
    "STARTSWITH": "starts_with",
    "ENDSWITH": "ends_with",
    "CONTAINS": "contains",
}

# Perl constructs RE2 does not implement. DuckDB raises on them anyway; catching
# them here turns a mid-investigation query error into a compile-time message.
_RE2_UNSUPPORTED: tuple[tuple[str, str], ...] = (
    ("(?=", "lookahead"),
    ("(?!", "negative lookahead"),
    ("(?<=", "lookbehind"),
    ("(?<!", "negative lookbehind"),
    ("(?>", "atomic group"),
    ("(?P=", "named backreference"),
    ("(?(", "conditional"),
    ("\\Z", "\\Z (RE2 has no \\Z; use $)"),
)
_BACKREFERENCE_RE = re.compile(r"(?<!\\)\\[1-9]")

_SELECT = "SELECT event_id, ts, kind, module, action, severity, payload_json"


class _OperandKind(Enum):
    COLUMN = "column"
    JSON = "json"
    MISSING = "missing"


@dataclass(frozen=True)
class _Operand:
    """How one field path reads out of a row.

    `text` is a VARCHAR-valued SQL expression and `type_sql` a `json_type()`
    call; both are empty for `MISSING`, which is a path that can never resolve
    (the evaluator returns `None` for any single-segment path, so `message` and
    `event` are constants, not fields).
    """

    kind: _OperandKind
    text: str = ""
    type_sql: str = ""


_MISSING_OPERAND = _Operand(kind=_OperandKind.MISSING)


@dataclass(frozen=True)
class CompiledQuery:
    """A ready-to-execute hunt query.

    `sql` binds `limit + 1` rows on purpose: the extra row is how a caller tells
    a truncated result from a complete one (§7). `limit` is the real limit.
    """

    expression: str
    sql: str
    params: tuple[Any, ...]
    limit: int
    since: datetime | None = None
    until: datetime | None = None


class _Binder:
    """Collects bound parameters in the order their placeholders are emitted."""

    def __init__(self) -> None:
        self.params: list[Any] = []

    def bind(self, value: Any) -> str:
        self.params.append(value)
        return "?"


def compile_hunt_query(
    expression: str,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int | None = None,
) -> CompiledQuery:
    """Compile `expression` into a parameterized query, or raise `HuntError`.

    `since` / `until` are inclusive bounds on the indexed `ts` column. They are
    optional here; the caller (CLI, IPC) is responsible for defaulting them to
    a recent window.
    """
    resolved_limit = _resolve_limit(limit)
    if since is not None and until is not None and since > until:
        raise HuntBoundsError(f"since ({since.isoformat()}) is after until ({until.isoformat()})")
    parsed = parse_expression(expression)
    if not parsed.groups:
        raise HuntSyntaxError(
            "empty query: write a predicate, for example 'process.name == \"curl\"'"
        )
    binder = _Binder()
    clauses = [f"({_compile_parsed(parsed, binder)})"]
    if since is not None:
        clauses.append(f"ts >= {binder.bind(since)}")
    if until is not None:
        clauses.append(f"ts <= {binder.bind(until)}")
    sql = (
        f"{_SELECT}\n"
        "FROM events_enriched\n"
        f"WHERE {' AND '.join(clauses)}\n"
        "ORDER BY ts DESC, event_id DESC\n"
        f"LIMIT {binder.bind(resolved_limit + 1)}"
    )
    return CompiledQuery(
        expression=expression,
        sql=sql,
        params=tuple(binder.params),
        limit=resolved_limit,
        since=since,
        until=until,
    )


def _resolve_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    if limit <= 0:
        raise HuntBoundsError(f"limit must be positive, got {limit}")
    return min(limit, MAX_LIMIT)


def _compile_parsed(parsed: ParsedExpression, binder: _Binder) -> str:
    groups: list[str] = []
    for group in parsed.groups:
        if not group:
            # An empty AND group is vacuously true — same as the evaluator's fold.
            groups.append("TRUE")
            continue
        groups.append(" AND ".join(_compile_node(node, binder) for node in group))
    return " OR ".join(f"({group})" for group in groups)


def _compile_node(node: Node, binder: _Binder) -> str:
    if isinstance(node, InvalidLeaf):
        raise HuntSyntaxError(
            f"cannot parse {node.text!r}: expected '<path> <operator> <value>' with an "
            f"operator from {', '.join(LEAF_OPS)}"
        )
    sql = _compile_leaf(node, binder)
    # Leaf SQL is always two-valued (it ends in IS TRUE / IS NOT TRUE), so a
    # plain NOT cannot reintroduce NULL here.
    return f"NOT ({sql})" if node.negated else sql


def _compile_leaf(leaf: Leaf, binder: _Binder) -> str:
    operand = _operand_for(leaf.path)
    if leaf.op in ("==", "!="):
        predicate = _equals(operand, parse_literal(leaf.rhs), binder)
        return _truth(predicate, positive=leaf.op == "==")
    if leaf.op in ("IN", "NOT IN"):
        return _truth(_in_list(operand, leaf.rhs, binder), positive=leaf.op == "IN")
    if leaf.op in _STRING_FUNCS:
        return _truth(_string_call(operand, leaf, binder), positive=True)
    if leaf.op == "MATCHES":
        return _truth(_matches(operand, leaf, binder), positive=True)
    # Unreachable while `expr.LEAF_OPS` and this function agree; if a new
    # operator is added to the grammar it lands here loudly rather than
    # silently selecting nothing.
    raise HuntUnsupportedError(f"operator {leaf.op!r} has no SQL compilation")


def _truth(predicate: str, *, positive: bool) -> str:
    """Collapse SQL's three-valued result to Python's two-valued one.

    `IS NOT TRUE` is what makes `!=` and `NOT IN` match rows where the field is
    absent, which is what the in-memory evaluator does.
    """
    return f"(({predicate}) IS {'TRUE' if positive else 'NOT TRUE'})"


# --------------------------------------------------------------------------
# operands
# --------------------------------------------------------------------------


def _operand_for(path: str) -> _Operand:
    segments = path_segments(path)
    for segment in segments:
        if not _SEGMENT_RE.match(segment):
            raise HuntPathError(
                f"invalid path segment {segment!r} in {path!r}: "
                "segments must match [A-Za-z_][A-Za-z0-9_]*"
            )
    if len(segments) == 1:
        # The evaluator resolves any single-segment path to None (it looks for a
        # dict-valued block and finds a scalar, or nothing at all).
        return _MISSING_OPERAND
    if segments[0] == "event":
        rest = segments[1:]
        if rest[0] == "ts":
            raise HuntUnsupportedError(
                "event.ts cannot appear in a hunt expression: the evaluator compares it as a "
                "datetime and never matches a text literal. Use the since/until time bound."
            )
        if len(rest) == 1 and rest[0] in COLUMN_PATHS:
            return _Operand(kind=_OperandKind.COLUMN, text=COLUMN_PATHS[rest[0]])
        return _json_operand(rest)
    return _json_operand(segments)


def _json_operand(segments: list[str]) -> _Operand:
    # Safe to interpolate: every segment matched _SEGMENT_RE above.
    json_path = "$." + ".".join(segments)
    return _Operand(
        kind=_OperandKind.JSON,
        text=f"json_extract_string(payload_json, '{json_path}')",
        type_sql=f"json_type(payload_json, '{json_path}')",
    )


def _is_string(operand: _Operand) -> str:
    if operand.kind is _OperandKind.COLUMN:
        return "TRUE"  # the five real columns are NOT NULL VARCHAR
    if operand.kind is _OperandKind.JSON:
        return f"{operand.type_sql} = 'VARCHAR'"
    return "FALSE"


def _is_number(operand: _Operand) -> str:
    if operand.kind is _OperandKind.JSON:
        return f"{operand.type_sql} IN {_JSON_NUMBER_TYPES}"
    return "FALSE"


def _is_boolean(operand: _Operand) -> str:
    if operand.kind is _OperandKind.JSON:
        return f"{operand.type_sql} = 'BOOLEAN'"
    return "FALSE"


def _guarded(guard: str, body: str) -> str:
    return body if guard == "TRUE" else f"({guard} AND {body})"


def _disjoin(parts: list[str]) -> str:
    if not parts:
        return "FALSE"
    return parts[0] if len(parts) == 1 else f"({' OR '.join(parts)})"


# --------------------------------------------------------------------------
# operators
# --------------------------------------------------------------------------


def _equals(operand: _Operand, literal: LiteralValue, binder: _Binder) -> str:
    """Python `lhs == literal`, typed, as SQL.

    Returns a possibly-NULL predicate; the caller wraps it in `_truth`. Nothing
    is bound for a branch that cannot match, so the parameter list stays in step
    with the placeholders actually emitted.
    """
    if operand.kind is _OperandKind.MISSING:
        # No literal in this grammar is None, so `None == literal` is never true.
        return "FALSE"
    parts: list[str] = []
    if isinstance(literal, bool):
        _append_typed(parts, _is_boolean(operand), operand, binder, "true" if literal else "false")
        _append_numeric(parts, operand, binder, 1 if literal else 0)
    elif isinstance(literal, int):
        _append_numeric(parts, operand, binder, literal)
        if literal in (0, 1):
            # Python's `True == 1` / `False == 0`, mirrored.
            _append_typed(
                parts, _is_boolean(operand), operand, binder, "true" if literal == 1 else "false"
            )
    else:
        _append_typed(parts, _is_string(operand), operand, binder, literal)
    return _disjoin(parts)


def _append_typed(
    parts: list[str], guard: str, operand: _Operand, binder: _Binder, value: str
) -> None:
    if guard == "FALSE":
        return
    parts.append(_guarded(guard, f"{operand.text} = {binder.bind(value)}"))


def _append_numeric(parts: list[str], operand: _Operand, binder: _Binder, value: int) -> None:
    """Python `lhs == <integer literal>` against a JSON number, exactly.

    Two disjoint cases, because `json_extract_string` returns the number's own
    token text and that text says which one it is:

    *An integer token* came from a Python `int`, and the evaluator compares it
    to `value` as an exact integer. Its JSON form is canonical decimal, so
    comparing the token text to `str(value)` **is** that exact comparison — at
    any width, with no cast to round it off. Casting to `DOUBLE` here is what
    made `pid == 9007199254740993` select the event whose pid is
    `9007199254740992`.

    *A float token* came from a Python `float`, and `float == int` in Python is
    exact too: a double can only equal `value` when `value` survives the trip
    through a double unchanged. So that branch is emitted only when it does,
    and when it is emitted the double comparison is exact by construction.
    """
    guard = _is_number(operand)
    if guard == "FALSE":
        return
    branches = [f"{operand.text} = {binder.bind(str(value))}"]
    as_double = _lossless_double(value)
    if as_double is not None:
        branches.append(
            f"(NOT regexp_matches({operand.text}, {_JSON_INTEGER_TOKEN}) "
            f"AND TRY_CAST({operand.text} AS DOUBLE) = {binder.bind(as_double)})"
        )
    parts.append(_guarded(guard, _disjoin(branches)))


def _lossless_double(value: int) -> float | None:
    """`float(value)` when nothing is lost, else `None` (no double equals it)."""
    try:
        as_double = float(value)
    except OverflowError:
        return None
    return as_double if int(as_double) == value else None


def _in_list(operand: _Operand, rhs: str, binder: _Binder) -> str:
    members = parse_list(rhs)
    parts = [
        predicate
        for predicate in (_equals(operand, member, binder) for member in members)
        if predicate != "FALSE"
    ]
    # An empty or malformed list matches nothing — `lhs in []` is false — which
    # still leaves `NOT IN []` matching everything, as the evaluator does.
    return _disjoin(parts)


def _string_call(operand: _Operand, leaf: Leaf, binder: _Binder) -> str:
    literal = _string_literal(leaf)
    guard = _is_string(operand)
    if guard == "FALSE":
        return "FALSE"
    func = _STRING_FUNCS[leaf.op]
    # starts_with/ends_with/contains take plain strings, so '%' and '_' in the
    # literal are literal — unlike LIKE.
    return _guarded(guard, f"{func}({operand.text}, {binder.bind(literal)})")


def _matches(operand: _Operand, leaf: Leaf, binder: _Binder) -> str:
    pattern = _string_literal(leaf)
    _validate_regex(pattern)
    guard = _is_string(operand)
    if guard == "FALSE":
        return "FALSE"
    # regexp_matches is a partial match, like Python's re.search.
    return _guarded(guard, f"regexp_matches({operand.text}, {binder.bind(pattern)})")


def _string_literal(leaf: Leaf) -> str:
    literal = parse_literal(leaf.rhs)
    if not isinstance(literal, str):
        raise HuntUnsupportedError(
            f"{leaf.op} needs a string on the right-hand side, got {leaf.rhs!r} "
            f'({type(literal).__name__}); quote it as "{leaf.rhs}"'
        )
    return literal


def _validate_regex(pattern: str) -> None:
    try:
        re.compile(pattern)
    except re.error as exc:
        raise HuntSyntaxError(f"invalid regular expression {pattern!r}: {exc}") from exc
    for construct, name in _RE2_UNSUPPORTED:
        if construct in pattern:
            raise HuntUnsupportedError(
                f"regular expression {pattern!r} uses {name}, which DuckDB's RE2 engine "
                "does not support"
            )
    if _BACKREFERENCE_RE.search(pattern):
        raise HuntUnsupportedError(
            f"regular expression {pattern!r} uses a backreference, which DuckDB's RE2 "
            "engine does not support"
        )
