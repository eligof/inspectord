"""Unit tests for the hunt compiler.

What the events *select* is the differential test's job (test_differential.py);
this file covers the shape of the SQL, the parameter binding, and every path
that must be rejected rather than silently answered.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from inspectord.hunt import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    HuntBoundsError,
    HuntPathError,
    HuntSyntaxError,
    HuntUnsupportedError,
    compile_hunt_query,
)

# --------------------------------------------------------------------------
# injection surface
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        'process.name == "\'; DROP TABLE events_enriched; --"',
        'process.name STARTSWITH "\'; DELETE FROM events_enriched --"',
        'process.name IN ["zzz1\'", "zzz2\\""]',
        'file.path MATCHES "zzz-injected\'"',
        'process.name != "100%_of_it"',
    ],
)
def test_literals_are_never_interpolated(expression: str) -> None:
    compiled = compile_hunt_query(expression)
    # Every literal must be reachable only through the bound parameter list:
    # none of them may appear anywhere in the SQL text.
    literals = [p for p in compiled.params if isinstance(p, str)]
    assert literals, "expected at least one bound literal"
    for literal in literals:
        assert literal not in compiled.sql, literal
    assert compiled.sql.count("?") == len(compiled.params)


def test_bound_parameters_are_in_placeholder_order() -> None:
    compiled = compile_hunt_query(
        'process.name == "a" AND file.path CONTAINS "b" OR user.name != "c"',
        since=datetime(2026, 8, 1, tzinfo=UTC),
        until=datetime(2026, 8, 20, tzinfo=UTC),
        limit=10,
    )
    assert compiled.params == (
        "a",
        "b",
        "c",
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 8, 20, tzinfo=UTC),
        11,
    )


@pytest.mark.parametrize(
    ("path", "offender"),
    [
        ("a..b", ""),
        ("a.", ""),
        ("process.9name", "9name"),
    ],
)
def test_invalid_path_segments_are_rejected_by_name(path: str, offender: str) -> None:
    with pytest.raises(HuntPathError) as exc:
        compile_hunt_query(f'{path} == "x"')
    assert repr(offender) in str(exc.value)


# --------------------------------------------------------------------------
# column vs JSON mapping (§4)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["module", "action", "severity", "kind"])
def test_real_columns_compile_without_json_parsing(field: str) -> None:
    compiled = compile_hunt_query(f'event.{field} == "x"')
    assert f"({field} = ?)" in compiled.sql
    assert "json_extract_string" not in compiled.sql


def test_other_event_fields_go_through_json() -> None:
    compiled = compile_hunt_query('event.outcome == "failure"')
    assert "json_extract_string(payload_json, '$.outcome')" in compiled.sql


def test_nested_paths_become_json_paths() -> None:
    compiled = compile_hunt_query('threat.indicator.source == "yara"')
    assert "json_extract_string(payload_json, '$.threat.indicator.source')" in compiled.sql


def test_column_lookalike_with_extra_segment_is_json() -> None:
    """`event.module.x` is not the module column — the evaluator walks into it."""
    compiled = compile_hunt_query('event.module.x == "y"')
    assert "'$.module.x'" in compiled.sql


def test_non_string_literal_against_a_column_cannot_match() -> None:
    """A column is always a str, and Python never equates a str to an int."""
    compiled = compile_hunt_query("event.module == 42")
    assert "FALSE" in compiled.sql
    assert compiled.params == (DEFAULT_LIMIT + 1,)


@pytest.mark.parametrize("expression", ['event.ts == "2026-08-20"', 'event.ts STARTSWITH "2026"'])
def test_event_ts_is_rejected(expression: str) -> None:
    with pytest.raises(HuntUnsupportedError) as exc:
        compile_hunt_query(expression)
    assert "since/until" in str(exc.value)


# --------------------------------------------------------------------------
# operators
# --------------------------------------------------------------------------


def test_not_equal_is_null_safe() -> None:
    """The whole point of §5: `!=` must still match a row with no such field."""
    compiled = compile_hunt_query('process.name != "curl"')
    assert "IS NOT TRUE" in compiled.sql


def test_not_in_is_null_safe() -> None:
    compiled = compile_hunt_query('process.name NOT IN ["a", "b"]')
    assert "IS NOT TRUE" in compiled.sql
    assert compiled.params == ("a", "b", DEFAULT_LIMIT + 1)


def test_empty_in_list_matches_nothing() -> None:
    assert "(FALSE) IS TRUE" in compile_hunt_query("process.name IN []").sql


@pytest.mark.parametrize(
    ("op", "func"),
    [("STARTSWITH", "starts_with"), ("ENDSWITH", "ends_with"), ("CONTAINS", "contains")],
)
def test_string_operators_use_functions_not_like(op: str, func: str) -> None:
    compiled = compile_hunt_query(f'file.path {op} "50%_off"')
    assert f"{func}(" in compiled.sql
    assert "LIKE" not in compiled.sql.upper()
    assert compiled.params[0] == "50%_off"


def test_string_operators_are_guarded_on_string_typed_values() -> None:
    """The evaluator only applies them when `isinstance(lhs, str)`."""
    assert "= 'VARCHAR'" in compile_hunt_query('process.pid CONTAINS "4"').sql


def test_equality_is_typed() -> None:
    """`42` and `"42"` extract to the same text, so the type guard separates them."""
    string_side = compile_hunt_query('process.pid == "42"')
    number_side = compile_hunt_query("process.pid == 42")
    assert "= 'VARCHAR'" in string_side.sql
    assert "IN ('BIGINT', 'UBIGINT', 'DOUBLE')" in number_side.sql
    assert string_side.params[0] == "42"
    assert number_side.params[0] == "42"


def test_boolean_literal_also_accepts_one_and_zero() -> None:
    """Mirrors Python's `True == 1`, which the evaluator inherits."""
    compiled = compile_hunt_query("process.flag == true")
    assert "= 'BOOLEAN'" in compiled.sql
    assert compiled.params[:2] == ("true", "1")


# --------------------------------------------------------------------------
# integers compare exactly, not through a double (§5)
# --------------------------------------------------------------------------


def test_an_integer_wider_than_a_double_never_reaches_a_double() -> None:
    """2**53 + 1 has no double of its own — comparing as one would find 2**53."""
    compiled = compile_hunt_query("process.pid == 9007199254740993")
    assert compiled.params == ("9007199254740993", DEFAULT_LIMIT + 1)
    assert "TRY_CAST" not in compiled.sql


@pytest.mark.parametrize(
    "literal",
    ["-9007199254740993", "1" + "0" * 30, "-" + "1" + "0" * 30],
)
def test_negative_and_oversized_integers_bind_their_own_decimal_text(literal: str) -> None:
    compiled = compile_hunt_query(f"process.pid == {literal}")
    assert compiled.params[0] == literal
    assert "TRY_CAST" not in compiled.sql


def test_an_integer_a_double_holds_exactly_still_matches_a_float_field() -> None:
    """`ratio == 5` must keep matching a stored `5.0`, as Python's `5.0 == 5` does."""
    compiled = compile_hunt_query("process.ratio == 5")
    assert compiled.params[:2] == ("5", 5.0)
    # ...but only for float-shaped tokens; an integer token is compared as text.
    assert "regexp_matches" in compiled.sql


def test_each_in_list_member_is_compared_exactly() -> None:
    compiled = compile_hunt_query("process.pid IN [9007199254740992, 9007199254740993]")
    assert compiled.params[:3] == (
        "9007199254740992",
        9007199254740992.0,  # 2**53 is exactly representable, so the float branch stays
        "9007199254740993",
    )


@pytest.mark.parametrize("op", ["STARTSWITH", "ENDSWITH", "CONTAINS", "MATCHES"])
def test_string_operator_with_a_non_string_literal_is_rejected(op: str) -> None:
    """The evaluator raises TypeError here; the compiler says why instead."""
    with pytest.raises(HuntUnsupportedError):
        compile_hunt_query(f"process.name {op} 5")


def test_matches_uses_a_partial_match() -> None:
    assert "regexp_matches(" in compile_hunt_query('process.name MATCHES "url"').sql


def test_matches_accepts_an_inline_flag_group() -> None:
    """The shipped av.yara rule uses this form; it must keep compiling."""
    compiled = compile_hunt_query('threat.indicator.severity MATCHES "^(?i:high|critical)$"')
    assert compiled.params[0] == "^(?i:high|critical)$"


def test_matches_rejects_an_invalid_regex() -> None:
    with pytest.raises(HuntSyntaxError):
        compile_hunt_query('process.name MATCHES "(unclosed"')


@pytest.mark.parametrize("pattern", ["(?=x)", "(?!x)", "(?<=x)y", "(a)\\1"])
def test_matches_rejects_patterns_re2_cannot_run(pattern: str) -> None:
    with pytest.raises(HuntUnsupportedError):
        compile_hunt_query(f'process.name MATCHES "{pattern}"')


# --------------------------------------------------------------------------
# rejection instead of a silently-empty answer (§6)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("expression", ["", "   ", "garbage", "NOT", "process.name LIKE 'x'"])
def test_unparseable_queries_raise(expression: str) -> None:
    with pytest.raises(HuntSyntaxError):
        compile_hunt_query(expression)


def test_error_message_lists_the_operators() -> None:
    with pytest.raises(HuntSyntaxError) as exc:
        compile_hunt_query("process.name LIKE 'x'")
    assert "STARTSWITH" in str(exc.value)


# --------------------------------------------------------------------------
# bounds (§7)
# --------------------------------------------------------------------------


def test_default_limit_is_applied_and_probes_one_extra_row() -> None:
    compiled = compile_hunt_query('event.module == "m"')
    assert compiled.limit == DEFAULT_LIMIT
    assert compiled.params[-1] == DEFAULT_LIMIT + 1


def test_limit_is_capped() -> None:
    compiled = compile_hunt_query('event.module == "m"', limit=10**6)
    assert compiled.limit == MAX_LIMIT
    assert compiled.params[-1] == MAX_LIMIT + 1


@pytest.mark.parametrize("limit", [0, -1])
def test_non_positive_limit_is_rejected(limit: int) -> None:
    with pytest.raises(HuntBoundsError):
        compile_hunt_query('event.module == "m"', limit=limit)


def test_inverted_time_window_is_rejected() -> None:
    with pytest.raises(HuntBoundsError):
        compile_hunt_query(
            'event.module == "m"',
            since=datetime(2026, 8, 20, tzinfo=UTC),
            until=datetime(2026, 8, 1, tzinfo=UTC),
        )


def test_results_are_ordered_newest_first() -> None:
    assert "ORDER BY ts DESC, event_id DESC" in compile_hunt_query('event.module == "m"').sql


def test_time_bounds_are_optional_and_bound_as_parameters() -> None:
    unbounded = compile_hunt_query('event.module == "m"')
    assert "ts >=" not in unbounded.sql
    bounded = compile_hunt_query('event.module == "m"', since=datetime(2026, 8, 1, tzinfo=UTC))
    assert "ts >= ?" in bounded.sql


def test_the_query_is_read_only() -> None:
    sql = compile_hunt_query('process.name == "curl"').sql.upper()
    assert sql.startswith("SELECT")
    assert ";" not in sql
    for statement in ("INSERT", "UPDATE", "DELETE", "DROP", "ATTACH", "COPY"):
        assert statement not in sql
