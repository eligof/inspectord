"""The rule/hunt expression grammar — parsing only, no evaluation.

This is the *single* parser behind both backends (hunt design §3):

    text ──► ParsedExpression ──┬──► inspectord.rules.yaml_loader  (Event → bool)
                                └──► inspectord.hunt.compiler      (→ SQL)

Keeping it in one place is not tidiness: two parsers drift, and the drift shows
up as a hunt query selecting different events than the byte-identical detection
rule. A new operator is added *here*, once, and both backends then have to grow
a case for it — the evaluator by not matching it, the compiler by raising.

The grammar (unchanged from the YAML rule engine, keywords uppercase-only):

    leaf     := PATH OP RHS
    OP       := == | != | IN | NOT IN | STARTSWITH | ENDSWITH | CONTAINS | MATCHES
    boolean  := AND | OR | NOT     (NOT is unary and binds to the next token only)
    literal  := "quoted" | 'quoted' | true | false | <int> | bare-word
    list     := [ literal, ... ]

There are no parentheses. AND binds tighter than OR, and the whole expression
folds flat into an OR of AND groups — which is precisely what `ParsedExpression`
holds, so neither backend gets to re-decide precedence.

`parse_expression` is **total**: it never raises. A leaf it cannot split becomes
an `InvalidLeaf`, mirroring the evaluator's long-standing "unparseable leaf is
false" behavior; the compiler turns the same node into a hard error instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "LEAF_OPS",
    "InvalidLeaf",
    "Leaf",
    "Node",
    "ParsedExpression",
    "parse_expression",
    "parse_list",
    "parse_literal",
    "path_segments",
]

#: Every leaf operator the grammar knows, in one place.
LEAF_OPS: tuple[str, ...] = (
    "==",
    "!=",
    "IN",
    "NOT IN",
    "STARTSWITH",
    "ENDSWITH",
    "CONTAINS",
    "MATCHES",
)

_LEAF_OP = re.compile(
    r"""
    ^\s*
    (?P<path>[a-zA-Z_][a-zA-Z0-9_.]*)
    \s+
    (?P<op>==|!=|IN|NOT\s+IN|STARTSWITH|ENDSWITH|CONTAINS|MATCHES)
    \s+
    (?P<rhs>.+?)
    \s*$
    """,
    re.VERBOSE,
)
# A NOT that opens a `path NOT IN [...]` leaf belongs to that leaf's operator,
# not to the boolean grammar; splitting there would leave a bare `IN [...]`
# fragment that the leaf regex cannot parse.
_BOOL_TOKEN_RE = re.compile(r"\bAND\b|\bOR\b|\bNOT\b(?!\s+IN\b)")


@dataclass(frozen=True)
class Leaf:
    """A parsed `path OP rhs` predicate, optionally negated by a unary `NOT`."""

    path: str
    op: str
    rhs: str
    negated: bool = False


@dataclass(frozen=True)
class InvalidLeaf:
    """Text in a leaf position that the grammar does not accept.

    Carried rather than raised so the parser stays total and each backend can
    choose: the evaluator treats it as false (unchanged behavior), the compiler
    refuses to compile it.
    """

    text: str
    negated: bool = False


Node = Leaf | InvalidLeaf


@dataclass(frozen=True)
class ParsedExpression:
    """An expression as an OR of AND groups.

    An *empty* AND group is vacuously true, and no groups at all is false —
    both inherited from the evaluator's fold, and both reachable from odd input
    (`OR a.b == "1"`, and the empty string, respectively).
    """

    groups: tuple[tuple[Node, ...], ...]

    def nodes(self) -> tuple[Node, ...]:
        return tuple(node for group in self.groups for node in group)


def tokenize(expr: str) -> list[str]:
    """Split on the boolean keywords, keeping them as their own tokens."""
    parts: list[str] = []
    last = 0
    for m in _BOOL_TOKEN_RE.finditer(expr):
        if m.start() > last:
            parts.append(expr[last : m.start()].strip())
        parts.append(m.group(0))
        last = m.end()
    if last < len(expr):
        parts.append(expr[last:].strip())
    return [p for p in parts if p]


def parse_leaf(text: str, *, negated: bool = False) -> Node:
    m = _LEAF_OP.match(text)
    if m is None:
        return InvalidLeaf(text=text.strip(), negated=negated)
    return Leaf(
        path=m.group("path"),
        op=re.sub(r"\s+", " ", m.group("op")),
        rhs=m.group("rhs").strip(),
        negated=negated,
    )


def parse_expression(expr: str) -> ParsedExpression:
    """Parse `expr` into OR-of-AND groups. Never raises.

    `NOT` consumes exactly the next token, whatever it is — including `AND` /
    `OR` / nothing at all. That is the evaluator's behavior and it is preserved
    verbatim so the extraction cannot change what an existing rule matches.
    """
    tokens = tokenize(expr)
    groups: list[list[Node]] = [[]]
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "NOT":
            following = tokens[i + 1] if i + 1 < len(tokens) else ""
            groups[-1].append(parse_leaf(following, negated=True))
            i += 2
        elif token == "AND":
            i += 1
        elif token == "OR":
            groups.append([])
            i += 1
        else:
            groups[-1].append(parse_leaf(token))
            i += 1
    # A trailing OR contributes nothing (`A OR` means `A`), while a *leading* or
    # interior empty group is vacuously true (`OR A` means `true OR A`).
    if groups and not groups[-1]:
        groups.pop()
    return ParsedExpression(groups=tuple(tuple(g) for g in groups))


def parse_literal(raw: str) -> Any:
    """Parse one RHS literal: quoted string, `true`/`false`, int, or bare word.

    Note there is no float and no null literal: `5.5` is the *string* "5.5",
    and nothing on the right-hand side can ever equal a missing field.
    """
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw == "true":
        return True
    if raw == "false":
        return False
    try:
        return int(raw)
    except ValueError:
        return raw


def parse_list(raw: str) -> list[Any]:
    """Parse a `[a, b]` RHS list. Anything else is an empty list."""
    raw = raw.strip()
    if not (raw.startswith("[") and raw.endswith("]")):
        return []
    inner = raw[1:-1].strip()
    if not inner:
        return []
    return [parse_literal(p.strip()) for p in inner.split(",")]


def path_segments(path: str) -> list[str]:
    """Split a dotted path. Segments are *not* validated here — callers that
    interpolate them into SQL must validate (see `hunt.compiler`)."""
    return path.split(".")
