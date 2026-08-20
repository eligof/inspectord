"""The differential test: SQL and the in-memory evaluator must agree exactly.

Hunt reuses the rule engine's grammar so a query and a detection rule are
written identically (hunt design §3). That promise is only worth something if
the two backends *select the same events* — otherwise a hunt query silently
finds different events than the byte-identical rule, which is the worst kind of
bug an investigation tool can have.

So: a corpus of events covering present / missing / JSON-null / empty-string /
numeric / boolean / unicode / nested / partially-present fields is persisted
through the same `insert_event` the daemon uses, and every expression below is
run through *both* backends with the selected `event_id` sets compared.

Any operator added to the grammar later must be added to `EXPRESSIONS`.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from inspectord.expr import LEAF_OPS
from inspectord.hunt import (
    MAX_LIMIT,
    HuntPathError,
    HuntSyntaxError,
    HuntUnsupportedError,
    compile_hunt_query,
    run_hunt_query,
)
from inspectord.parsers.base import build_event
from inspectord.rules.yaml_loader import evaluate_expression
from inspectord.schemas.event import Event
from inspectord.storage.db import Database
from inspectord.storage.events import insert_event
from inspectord.storage.migrations import run_migrations

BASE = datetime(2026, 8, 20, 9, 0, tzinfo=UTC)


# --------------------------------------------------------------------------
# the corpus
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Corpus:
    events: tuple[Event, ...]

    def label(self, event_id: str) -> str:
        for event in self.events:
            if event.event_id == event_id:
                return event.module
        return event_id  # pragma: no cover - only reachable if ids leak

    def labels(self, event_ids: set[str]) -> list[str]:
        return sorted(self.label(event_id) for event_id in event_ids)


def _build_corpus() -> Corpus:
    """One event per interesting shape. `module` doubles as a readable label."""
    specs: list[dict[str, object]] = [
        # A fully-populated event: string, int, float, bool, empty string and an
        # explicit JSON null all inside one block, plus a nested path.
        {
            "module": "full",
            "process": {
                "pid": 42,
                "name": "curl",
                "flag": True,
                "ratio": 5.0,
                "empty": "",
                "nul": None,
                "args": ["-x", "http://x"],
            },
            "file": {"path": "/tmp/100%_off_it.sh"},
            "threat": {"indicator": {"source": "yara", "severity": "HIGH"}},
            "message": "hello world",
        },
        # No process block at all — the case §5 is written about.
        {"module": "no_process", "file": {"path": "/etc/passwd"}, "severity": "high"},
        # Block present, key missing.
        {"module": "pid_only", "process": {"pid": 7}},
        # Key present, value is JSON null. Must behave exactly like "missing".
        {"module": "name_null", "process": {"pid": 8, "name": None}},
        # Empty string is a *present* value, not a missing one.
        {"module": "name_empty", "process": {"pid": 9, "name": ""}},
        # Unicode, including in a literal the queries below use.
        {"module": "unicode", "process": {"pid": 10, "name": "Ünïcödé-café"}},
        # A number-shaped string vs. a real number: `== 42` must tell them apart.
        {"module": "name_numeric_string", "process": {"pid": "42", "name": "42"}},
        {"module": "pid_number", "process": {"pid": 42, "name": "wget"}},
        # Booleans, including the false side and the 0/1 cross-comparison.
        {"module": "flag_false", "process": {"pid": 0, "name": "bash", "flag": False}},
        {"module": "flag_true_zero_pid", "process": {"pid": 1, "name": "sh", "flag": True}},
        # LIKE wildcards that must stay literal.
        {
            "module": "wildcards",
            "process": {"pid": 11, "name": "a%b_c"},
            "file": {"path": "/var/log/a%b_c.log"},
        },
        # The nested path exists here too, with different values.
        {
            "module": "nested_other",
            "threat": {"indicator": {"source": "aide", "severity": "low"}},
            "process": {"pid": 12, "name": "aide"},
        },
        # A different kind/severity so the column paths have something to split on.
        {
            "module": "alert_row",
            "kind": "alert",
            "severity": "critical",
            "action": "rule_matched",
            "process": {"pid": 13, "name": "curly"},
        },
        # A negative number, and a trailing newline (which is where Python's `$`
        # and RE2's `$` part ways — see test_known_regex_divergences).
        {"module": "negative", "process": {"pid": 16, "name": "neg", "exit_code": -1}},
        {"module": "trailing_newline", "process": {"pid": 14, "name": "hello\n"}},
        # Integers past 2**53, where the doubles stop being able to tell
        # consecutive integers apart: `int_2p53` and `int_2p53_plus_1` share a
        # double, and `int_negative_big` is the same collision below zero.
        {"module": "int_2p53", "process": {"pid": 9007199254740992, "name": "two53"}},
        {"module": "int_2p53_plus_1", "process": {"pid": 9007199254740993, "name": "two53b"}},
        {"module": "int_negative_big", "process": {"pid": -9007199254740993, "name": "negbig"}},
        # An integer no double can hold, next to the float it would be confused
        # with: `1e30` is 1000000000000000019884624838656, not 10**30.
        {"module": "int_huge", "process": {"pid": 10**30, "name": "huge"}},
        {"module": "float_huge", "process": {"pid": 20, "name": "fhuge", "ratio": 1e30}},
        # A float that is exactly 2**53: `== 2**53` matches it, `== 2**53 + 1`
        # must not, even though both integers round to this same double.
        {
            "module": "float_2p53",
            "process": {"pid": 21, "name": "f53", "ratio": 9007199254740992.0},
        },
        # Deliberately sparse: no process, no file, no threat, no message.
        {"module": "bare"},
    ]
    events: list[Event] = []
    for index, spec in enumerate(specs):
        events.append(
            build_event(
                module=str(spec["module"]),
                action=str(spec.get("action", "tick")),
                category=["c"],
                type_=["t"],
                severity=str(spec.get("severity", "info")),
                kind=str(spec.get("kind", "event")),
                process=spec.get("process"),  # type: ignore[arg-type]
                file=spec.get("file"),  # type: ignore[arg-type]
                threat=spec.get("threat"),  # type: ignore[arg-type]
                message=spec.get("message"),  # type: ignore[arg-type]
                ts=BASE + timedelta(minutes=index),
            )
        )
    return Corpus(events=tuple(events))


@pytest.fixture(scope="module")
def corpus() -> Corpus:
    return _build_corpus()


@pytest.fixture(scope="module")
def db(tmp_path_factory: pytest.TempPathFactory, corpus: Corpus) -> Iterator[Database]:
    path: Path = tmp_path_factory.mktemp("hunt-differential") / "events.duckdb"
    with Database(path) as handle:
        run_migrations(handle)
        for event in corpus.events:
            # The real persist path, so the rows under test are the rows the
            # daemon would have written.
            insert_event(handle, event, event.model_dump_json())
        yield handle


# --------------------------------------------------------------------------
# the expressions — every operator, every boolean combination
# --------------------------------------------------------------------------

_LEAVES = [
    # == on a real column, on JSON, on a nested path, on a missing path
    'event.module == "full"',
    'event.action == "tick"',
    'event.severity == "critical"',
    'event.kind == "alert"',
    'process.name == "curl"',
    'threat.indicator.source == "yara"',
    'process.nothere == "x"',
    'nothere.at.all == "x"',
    # == against the tricky values
    'process.name == ""',
    'process.nul == "x"',
    'process.name == "Ünïcödé-café"',
    'process.name == "a%b_c"',
    "process.pid == 42",
    'process.pid == "42"',
    "process.pid == 0",
    "process.ratio == 5",
    "process.flag == true",
    "process.flag == false",
    "process.flag == 1",
    "process.flag == 0",
    "event.module == 42",
    # != — the operator that makes or breaks NULL handling
    'process.name != "curl"',
    'process.nul != "curl"',
    'process.nothere != "curl"',
    'process.name != ""',
    "process.pid != 42",
    'event.module != "full"',
    'threat.indicator.source != "yara"',
    # IN / NOT IN
    'process.name IN ["curl", "wget"]',
    'process.name NOT IN ["curl", "wget"]',
    'process.nothere IN ["curl"]',
    'process.nothere NOT IN ["curl"]',
    "process.pid IN [42, 7]",
    "process.pid NOT IN [42, 7]",
    "process.name IN []",
    "process.name NOT IN []",
    'event.severity IN ["high", "critical"]',
    'event.severity NOT IN ["info"]',
    'process.name IN ["a%b_c", "Ünïcödé-café"]',
    # STARTSWITH / ENDSWITH / CONTAINS — plain string ops, not LIKE
    'process.name STARTSWITH "cur"',
    'process.name ENDSWITH "rl"',
    'process.name CONTAINS "ur"',
    'process.name STARTSWITH "a%"',
    'process.name ENDSWITH "_c"',
    'process.name CONTAINS "%b_"',
    'file.path CONTAINS "100%_"',
    'file.path STARTSWITH "/var"',
    'process.name CONTAINS ""',
    'process.name STARTSWITH "Ün"',
    'process.pid CONTAINS "4"',
    'process.flag CONTAINS "ru"',
    'process.nothere CONTAINS "x"',
    'threat.indicator.severity CONTAINS "IG"',
    'message CONTAINS "hello"',
    'event CONTAINS "x"',
    # MATCHES — partial match, like re.search
    'process.name MATCHES "^c.rl$"',
    'process.name MATCHES "url"',
    'process.name MATCHES "^(?i:CURL|WGET)$"',
    'threat.indicator.severity MATCHES "^(?i:high|critical)$"',
    'process.name MATCHES "a%b"',
    'process.nothere MATCHES "."',
    'process.pid MATCHES "42"',
    # single-segment paths always resolve to None in the evaluator
    'message != "x"',
    'event != "x"',
    # non-scalar JSON values: an array and an object are neither string nor
    # number, so nothing but != / NOT IN may match them
    'process.args == "-x"',
    'process.args != "-x"',
    'process.args CONTAINS "x"',
    'process.args IN ["-x"]',
    'event.process == "x"',
    'event.process != "x"',
    # walking into a scalar yields nothing, in both backends
    'process.name.deep == "x"',
    'process.name.deep != "x"',
    # literal forms: bare word, single quotes, negative int, float-shaped text
    "process.name == curl",
    "process.name == 'curl'",
    "process.exit_code == -1",
    "process.exit_code != -1",
    "process.ratio == 5.0",
    # unicode through the string operators and the regex engine
    'process.name CONTAINS "café"',
    'process.name ENDSWITH "café"',
    'process.name MATCHES "café"',
    # the empty string is a value: it is found, and it is not "missing"
    'process.empty == ""',
    'process.empty != ""',
    'process.empty CONTAINS ""',
    'process.empty STARTSWITH ""',
    'process.nul == ""',
    'process.nul CONTAINS ""',
    "process.flag != true",
    "process.pid == 1",
    # Integers wider than a double's 53-bit mantissa. Python compares them
    # exactly, so the SQL must too: 9007199254740992 and 9007199254740993 are
    # different events even though float() maps them onto the same double.
    "process.pid == 9007199254740992",
    "process.pid == 9007199254740993",
    "process.pid != 9007199254740993",
    "process.pid == -9007199254740993",
    "process.pid == -9007199254740992",
    "process.pid IN [9007199254740992, 7]",
    "process.pid NOT IN [9007199254740993]",
    # Beyond every double: only the integer stored as an integer may match.
    "process.pid == 1000000000000000000000000000000",
    "process.ratio == 1000000000000000000000000000000",
    # ...and the exact integer value of 1e30, which the *float* does equal.
    "process.ratio == 1000000000000000019884624838656",
    # A float-valued field at the same boundary.
    "process.ratio == 9007199254740992",
    "process.ratio == 9007199254740993",
    "process.pid == 9007199254740992.0",
]

_COMBINATIONS = [
    # AND
    'event.module == "full" AND process.name == "curl"',
    'process.name == "curl" AND process.pid == 42',
    'event.severity == "info" AND process.name != "curl"',
    # OR
    'process.name == "curl" OR process.name == "wget"',
    'process.nothere == "x" OR event.module == "bare"',
    # NOT (unary)
    'NOT process.name == "curl"',
    'NOT process.name IN ["curl", "wget"]',
    'NOT process.nothere != "curl"',
    'NOT process.name STARTSWITH "cur"',
    'NOT event.severity == "info"',
    # AND binds tighter than OR
    'process.name == "curl" AND process.pid == 42 OR event.module == "bare"',
    'event.module == "bare" OR process.name == "curl" AND process.pid == 42',
    'event.module == "bare" OR process.name == "curl" AND process.pid == 7',
    # NOT inside chains
    'NOT process.name == "curl" AND event.severity == "info"',
    'event.severity == "info" AND NOT process.name == "curl"',
    'event.severity == "info" OR NOT process.name == "curl"',
    'NOT process.name == "curl" AND NOT process.name == "wget"',
    'NOT process.name == "curl" OR NOT process.pid == 42',
    # three-term chains and mixed operators
    'event.kind == "event" AND process.name != "curl" AND process.pid NOT IN [7]',
    'process.name STARTSWITH "a" OR process.name ENDSWITH "l" OR process.name == ""',
    'process.name CONTAINS "c" AND NOT process.name MATCHES "^cur"',
    'threat.indicator.source == "yara" OR threat.indicator.source == "aide"',
    'NOT threat.indicator.source IN ["yara", "aide"]',
    # a leaf whose path exists on some events and not others, both ways round
    'threat.indicator.severity != "HIGH" AND event.kind == "event"',
    'threat.indicator.severity NOT IN ["HIGH"] OR event.module == "full"',
]

EXPRESSIONS = _LEAVES + _COMBINATIONS


# --------------------------------------------------------------------------
# the comparison
# --------------------------------------------------------------------------


def _evaluator_ids(corpus: Corpus, expression: str) -> set[str]:
    return {event.event_id for event in corpus.events if evaluate_expression(expression, event)}


def _sql_ids(db: Database, expression: str) -> set[str]:
    compiled = compile_hunt_query(expression, limit=MAX_LIMIT)
    result = run_hunt_query(db, compiled)
    assert not result.truncated, "corpus outgrew the limit; the comparison would be meaningless"
    return set(result.event_ids)


def _report(corpus: Corpus, expression: str, evaluator: set[str], sql: set[str]) -> str:
    return "\n".join(
        [
            "",
            f"expression:      {expression}",
            f"evaluator chose: {corpus.labels(evaluator)}",
            f"SQL chose:       {corpus.labels(sql)}",
            f"only in SQL:     {corpus.labels(sql - evaluator)}",
            f"only in memory:  {corpus.labels(evaluator - sql)}",
            "",
            "compiled SQL:",
            compile_hunt_query(expression, limit=MAX_LIMIT).sql,
            f"params: {compile_hunt_query(expression, limit=MAX_LIMIT).params}",
        ]
    )


@pytest.mark.parametrize("expression", EXPRESSIONS, ids=EXPRESSIONS)
def test_backends_select_the_same_events(db: Database, corpus: Corpus, expression: str) -> None:
    evaluator = _evaluator_ids(corpus, expression)
    sql = _sql_ids(db, expression)
    assert sql == evaluator, _report(corpus, expression, evaluator, sql)


def test_the_corpus_covers_every_operator() -> None:
    """A new operator must not be able to slip in untested."""
    text = " ".join(EXPRESSIONS)
    for op in LEAF_OPS:
        assert f" {op} " in text, f"no differential case exercises {op}"


@pytest.mark.parametrize(
    ("expression", "only_in_evaluator"),
    [
        # Python's `$` also matches just before a trailing newline; RE2's does
        # not. `trailing_newline` carries process.name == "hello\n".
        ('process.name MATCHES "hello$"', ["trailing_newline"]),
        # RE2's shorthand classes are ASCII-only; Python's are Unicode-aware, so
        # `\w` matches the "Ü" of `unicode` in memory but not in SQL.
        ('process.name MATCHES "^\\w"', ["unicode"]),
    ],
)
def test_known_regex_divergences(
    db: Database,
    corpus: Corpus,
    expression: str,
    only_in_evaluator: list[str],
) -> None:
    """The one place the backends do NOT agree, pinned so it cannot drift silently.

    MATCHES runs under Python's `re` in memory and DuckDB's RE2 in SQL. Patterns
    RE2 cannot parse are rejected at compile time, but these two differences are
    *silent*: both engines accept the pattern and disagree about the answer.
    They are documented in `hunt.compiler`'s module docstring and asserted here
    so that a future fix (or regression) shows up as a failing test.
    """
    evaluator = _evaluator_ids(corpus, expression)
    sql = _sql_ids(db, expression)
    assert corpus.labels(evaluator - sql) == sorted(only_in_evaluator)
    assert corpus.labels(sql - evaluator) == []


@pytest.mark.parametrize(
    ("expression", "error"),
    [
        # A typo. The evaluator quietly answers "no events"; for a hunt query
        # that reads as "you are clean", which is the wrong answer to give.
        ("garbage", HuntSyntaxError),
        ("process.name LIKE 'curl'", HuntSyntaxError),
        ("NOT", HuntSyntaxError),
        # Comparing the ts column: the evaluator compares a datetime to a text
        # literal, so `==` can never match and `!=` always does.
        ('event.ts == "2026-08-20"', HuntUnsupportedError),
        # The evaluator raises TypeError here (str.startswith(int)).
        ("process.name STARTSWITH 5", HuntUnsupportedError),
        # A path segment that cannot be interpolated into a JSON path.
        ('process..name == "curl"', HuntPathError),
    ],
)
def test_the_compiler_rejects_what_the_evaluator_answers_silently(
    corpus: Corpus, expression: str, error: type[Exception]
) -> None:
    """The intended divergences, listed.

    In each case the compiler refuses rather than returning a result, because a
    query that quietly means something other than what was typed is worse than
    an error during an investigation (hunt design §6).
    """
    with pytest.raises(error):
        compile_hunt_query(expression)


def test_the_corpus_is_actually_discriminating(db: Database, corpus: Corpus) -> None:
    """Guard against the vacuous pass where every expression selects nothing.

    Two identically-empty sets are equal, so a corpus that matches nothing would
    make this whole file green and worthless.
    """
    selections = {expression: _sql_ids(db, expression) for expression in EXPRESSIONS}
    non_empty = [e for e, ids in selections.items() if ids]
    partial = [e for e, ids in selections.items() if 0 < len(ids) < len(corpus.events)]
    assert len(non_empty) > len(EXPRESSIONS) // 2
    assert len(partial) > len(EXPRESSIONS) // 2
