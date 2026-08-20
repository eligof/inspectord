"""Tests for the shared expression parser (`inspectord/expr.py`).

These assert the *structure* the parser produces. Both the rule evaluator and
the hunt compiler consume that structure, so anything asserted here is a
promise made to both backends at once.
"""

from __future__ import annotations

import pytest

from inspectord.expr import (
    InvalidLeaf,
    Leaf,
    parse_expression,
    parse_list,
    parse_literal,
    path_segments,
)


def _leaves(expr: str) -> list[tuple[str, str, str, bool]]:
    parsed = parse_expression(expr)
    out: list[tuple[str, str, str, bool]] = []
    for group in parsed.groups:
        for node in group:
            assert isinstance(node, Leaf), node
            out.append((node.path, node.op, node.rhs, node.negated))
    return out


# --------------------------------------------------------------------------
# leaf splitting
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ('process.name == "curl"', ("process.name", "==", '"curl"', False)),
        ('process.name != "curl"', ("process.name", "!=", '"curl"', False)),
        ('process.name IN ["a", "b"]', ("process.name", "IN", '["a", "b"]', False)),
        ('process.name NOT IN ["a"]', ("process.name", "NOT IN", '["a"]', False)),
        ('file.path STARTSWITH "/etc"', ("file.path", "STARTSWITH", '"/etc"', False)),
        ('file.path ENDSWITH ".sh"', ("file.path", "ENDSWITH", '".sh"', False)),
        ('file.path CONTAINS "tmp"', ("file.path", "CONTAINS", '"tmp"', False)),
        ('file.path MATCHES "^/etc/.*"', ("file.path", "MATCHES", '"^/etc/.*"', False)),
    ],
)
def test_leaf_splitting(expr: str, expected: tuple[str, str, str, bool]) -> None:
    assert _leaves(expr) == [expected]


def test_not_in_is_one_operator_not_a_unary_not() -> None:
    """`NOT IN` must survive the boolean tokenizer as a leaf operator."""
    assert _leaves('process.name NOT IN ["modprobe"]') == [
        ("process.name", "NOT IN", '["modprobe"]', False)
    ]


def test_unary_not_negates_the_following_leaf() -> None:
    assert _leaves('NOT process.name == "curl"') == [("process.name", "==", '"curl"', True)]


def test_multi_space_operator_is_normalized() -> None:
    assert _leaves('process.name NOT   IN ["a"]') == [("process.name", "NOT IN", '["a"]', False)]


# --------------------------------------------------------------------------
# boolean grouping — OR of AND groups
# --------------------------------------------------------------------------


def _shape(expr: str) -> list[list[str]]:
    return [
        [n.path if isinstance(n, Leaf) else f"!{n.text}" for n in group]
        for group in parse_expression(expr).groups
    ]


@pytest.mark.parametrize(
    ("expr", "shape"),
    [
        ('a.x == "1"', [["a.x"]]),
        ('a.x == "1" AND b.y == "2"', [["a.x", "b.y"]]),
        ('a.x == "1" OR b.y == "2"', [["a.x"], ["b.y"]]),
        # AND binds tighter than OR, and the fold is flat (no parentheses).
        ('a.x == "1" AND b.y == "2" OR c.z == "3"', [["a.x", "b.y"], ["c.z"]]),
        ('a.x == "1" OR b.y == "2" AND c.z == "3"', [["a.x"], ["b.y", "c.z"]]),
    ],
)
def test_boolean_grouping(expr: str, shape: list[list[str]]) -> None:
    assert _shape(expr) == shape


def test_empty_expression_has_no_groups() -> None:
    assert parse_expression("").groups == ()
    assert parse_expression("   ").groups == ()


def test_trailing_or_group_is_dropped() -> None:
    """`A OR` must stay equal to `A`, not become `A OR <empty>` (which is true)."""
    assert _shape('a.x == "1" OR') == [["a.x"]]


def test_leading_or_keeps_the_empty_group() -> None:
    """An empty AND group is vacuously true; only a *trailing* one is dropped."""
    groups = parse_expression('OR a.x == "1"').groups
    assert len(groups) == 2
    assert groups[0] == ()


def test_bare_or_yields_one_empty_group() -> None:
    assert parse_expression("OR").groups == ((),)


# --------------------------------------------------------------------------
# invalid leaves — the parser never raises
# --------------------------------------------------------------------------


@pytest.mark.parametrize("expr", ["garbage", "NOT", "== 5", "process.name ==", "a.b LIKE 'x'"])
def test_unparseable_leaves_become_invalid_nodes(expr: str) -> None:
    parsed = parse_expression(expr)
    nodes = [n for group in parsed.groups for n in group]
    assert nodes
    assert all(isinstance(n, InvalidLeaf) for n in nodes), nodes


def test_dangling_not_produces_a_negated_invalid_leaf() -> None:
    (node,) = parse_expression("NOT").groups[0]
    assert isinstance(node, InvalidLeaf)
    assert node.negated is True
    assert node.text == ""


def test_not_followed_by_a_keyword_consumes_it() -> None:
    """`NOT` swallows the next token whatever it is — preserved evaluator quirk."""
    nodes = [n for group in parse_expression('NOT AND a.x == "1"').groups for n in group]
    assert isinstance(nodes[0], InvalidLeaf)
    assert nodes[0].text == "AND"
    assert isinstance(nodes[1], Leaf)


# --------------------------------------------------------------------------
# literals and lists
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('"curl"', "curl"),
        ("'curl'", "curl"),
        ('""', ""),
        ("42", 42),
        ("-3", -3),
        ("true", True),
        ("false", False),
        ("bare", "bare"),
        ("5.5", "5.5"),  # floats are not parsed: they fall through to a string
        ('  "spaced"  ', "spaced"),
    ],
)
def test_parse_literal(raw: str, expected: object) -> None:
    result = parse_literal(raw)
    assert result == expected
    assert type(result) is type(expected)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('["a", "b"]', ["a", "b"]),
        ("[]", []),
        ("[ ]", []),
        ("[1, 2]", [1, 2]),
        ('["a"]', ["a"]),
        ("not-a-list", []),
        ('"a"', []),
    ],
)
def test_parse_list(raw: str, expected: list[object]) -> None:
    assert parse_list(raw) == expected


# --------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "segments"),
    [
        ("process.name", ["process", "name"]),
        ("message", ["message"]),
        ("threat.indicator.source", ["threat", "indicator", "source"]),
        ("a..b", ["a", "", "b"]),
        ("a.", ["a", ""]),
    ],
)
def test_path_segments(path: str, segments: list[str]) -> None:
    assert path_segments(path) == segments
