"""Tests for the YARA scanner adapter.

Pure functions over fixture strings plus a `tmp_path` rules directory: no
scanning subprocess, no root. The live counterpart is
``tests/workers/test_scanner_runner_live_scanners.py``.

Every fixture below is **verbatim stdout captured from yara 4.5.7 on this
machine**. Design §4.1's ``yara -r -w <rules-dir> <target>`` does not work at
all: a rules *directory* is rejected (``error: input in flex scanner failed``)
and a second target is read as another rules file. The real grammar is
``yara [OPTIONS] RULES_FILE... FILE|DIR|PID`` -- many rules files, exactly one
target, last.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.workers.scanner_runner.scanners.base import ScanOutcome
from inspectord.workers.scanner_runner.scanners.yara import YaraAdapter

# --- captured stdout ------------------------------------------------------

# `yara rules/demo.yar tgt/hit.txt`
PLAIN_MATCH = "Demo_Rule /scan/tgt/hit.txt\n"

# `yara -m -r <two rule files> <dir>` -- note `score =42`: yara prints integer
# meta as `name =value` and string meta as `name="value"`, and a meta string can
# contain commas and escaped quotes.
META_MATCHES = (
    'Demo_Rule [severity="high",description="demo, with spaces and \\"quotes\\"",score =42]'
    " /scan/tgt/hit.txt\n"
    'Demo_Rule [severity="high",description="demo, with spaces and \\"quotes\\"",score =42]'
    " /scan/tgt/both.txt\n"
    "Second_Rule [] /scan/tgt/both.txt\n"
)

# `yara -s -m ...` -- the indented line is a string match, NOT a finding.
STRING_MATCHES = 'Demo_Rule [severity="high"] /scan/tgt/hit.txt\n0x6:$a: SUSPICIOUS_MARKER\n'

# A matched path really can contain spaces and a `]` (captured, not invented),
# which is why the meta block is split with a quote-aware scanner.
AWKWARD_PATH = 'Demo_Rule [severity="high"] /scan/tgt3/we ird/a]b c.txt\n'

# An unreadable file inside a scanned directory: stderr only, and yara still
# exits 0. Scanning /home unprivileged always hits some.
UNREADABLE_STDERR = "error scanning /scan/tgt2/unreadable.txt: could not open file\n"

# A rules file that does not compile, and a missing target: both exit 1.
COMPILE_ERROR_STDERR = "/scan/bad.yar(1): error: syntax error, unexpected identifier\n"
MISSING_TARGET_STDERR = "error scanning /nonexistent/xyz: could not open file\n"


def _adapter() -> YaraAdapter:
    return YaraAdapter()


def _rules_dir(tmp_path: Path, *names: str) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    for name in names:
        path = rules / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("rule R { condition: false }\n")
    return rules


def _config(tmp_path: Path, rules: Path, **overrides: object) -> dict[str, object]:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    config: dict[str, object] = {"rules_dir": str(rules), "target": str(target)}
    config.update(overrides)
    return config


# --------------------------------------------------------------------------
# argv -- the rules-directory problem
# --------------------------------------------------------------------------


def test_argv_expands_the_rules_directory_into_sorted_rule_files(tmp_path: Path) -> None:
    rules = _rules_dir(tmp_path, "b.yar", "a.yara", "sub/c.yar")
    argv = _adapter().argv(_config(tmp_path, rules))
    rule_args = [part for part in argv if part.endswith((".yar", ".yara"))]
    assert rule_args == [
        str(rules / "a.yara"),
        str(rules / "b.yar"),
        str(rules / "sub" / "c.yar"),
    ]


def test_argv_never_passes_the_rules_directory_itself(tmp_path: Path) -> None:
    """Design §4.1's argv: yara rejects a directory as RULES_FILE outright."""
    rules = _rules_dir(tmp_path, "a.yar")
    argv = _adapter().argv(_config(tmp_path, rules))
    assert str(rules) not in argv


def test_argv_ignores_non_rule_files(tmp_path: Path) -> None:
    rules = _rules_dir(tmp_path, "a.yar")
    (rules / "README.md").write_text("not a rule\n")
    (rules / "index.json").write_text("{}\n")
    argv = _adapter().argv(_config(tmp_path, rules))
    assert not any(part.endswith((".md", ".json")) for part in argv)


def test_argv_puts_exactly_one_target_last(tmp_path: Path) -> None:
    rules = _rules_dir(tmp_path, "a.yar", "b.yar")
    config = _config(tmp_path, rules)
    argv = _adapter().argv(config)
    assert argv[-1] == config["target"]
    assert argv.count(str(config["target"])) == 1


def test_argv_carries_the_recursive_meta_and_no_warnings_flags(tmp_path: Path) -> None:
    rules = _rules_dir(tmp_path, "a.yar")
    argv = _adapter().argv(_config(tmp_path, rules))
    assert argv[0] == "yara"
    # -m is where threat.indicator.severity comes from (§4.2).
    for flag in ("-r", "-m", "-w"):
        assert flag in argv, flag


def test_argv_is_a_list_never_a_shell_string(tmp_path: Path) -> None:
    rules = _rules_dir(tmp_path, "a.yar")
    argv = _adapter().argv(_config(tmp_path, rules, target="/home/a b; rm -rf /"))
    assert isinstance(argv, list)
    assert argv[-1] == "/home/a b; rm -rf /"


def test_argv_on_an_unlistable_rules_dir_yields_no_rule_files(tmp_path: Path) -> None:
    """preflight catches this first; argv is defensive anyway and never raises."""
    argv = _adapter().argv({"rules_dir": str(tmp_path / "nope"), "target": str(tmp_path)})
    assert not any(part.endswith((".yar", ".yara")) for part in argv)


# --------------------------------------------------------------------------
# preflight -- "no rules shipped yet" is an ordinary state, not a failure
# --------------------------------------------------------------------------


def test_preflight_reports_a_missing_rules_directory(tmp_path: Path) -> None:
    config = {"rules_dir": str(tmp_path / "absent"), "target": str(tmp_path)}
    assert _adapter().preflight(config) == "rules_missing"


def test_preflight_reports_an_empty_rules_directory(tmp_path: Path) -> None:
    rules = _rules_dir(tmp_path)
    (rules / "README.md").write_text("rules go here\n")
    assert _adapter().preflight(_config(tmp_path, rules)) == "rules_empty"


def test_preflight_reports_a_missing_target(tmp_path: Path) -> None:
    rules = _rules_dir(tmp_path, "a.yar")
    config = _config(tmp_path, rules, target=str(tmp_path / "gone"))
    assert _adapter().preflight(config) == "target_missing"


def test_preflight_passes_when_rules_and_target_exist(tmp_path: Path) -> None:
    rules = _rules_dir(tmp_path, "a.yar")
    assert _adapter().preflight(_config(tmp_path, rules)) is None


def test_preflight_reports_a_rules_path_that_is_a_file(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule R { condition: false }\n")
    config = {"rules_dir": str(rules), "target": str(tmp_path)}
    assert _adapter().preflight(config) == "rules_missing"


# --------------------------------------------------------------------------
# interpret_outcome
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stdout", "code", "expected"),
    [
        (META_MATCHES, 0, ScanOutcome.findings),
        (PLAIN_MATCH, 0, ScanOutcome.findings),
        # Matches beat the code, so a run that died late never hides a hit.
        (PLAIN_MATCH, 1, ScanOutcome.findings),
        (PLAIN_MATCH, -9, ScanOutcome.findings),
        # No matches: yara exits 0 whether or not anything matched.
        ("", 0, ScanOutcome.clean),
        ("\n\n", 0, ScanOutcome.clean),
        # A compile error or a missing target: exit 1, nothing on stdout.
        ("", 1, ScanOutcome.failure),
        ("", 255, ScanOutcome.failure),
    ],
)
def test_interpret_outcome_table(stdout: str, code: int, expected: ScanOutcome) -> None:
    assert _adapter().interpret_outcome(code, stdout, "") is expected


def test_unreadable_files_do_not_fail_the_run() -> None:
    """Measured: yara reports them on stderr and still exits 0."""
    assert _adapter().interpret_outcome(0, "", UNREADABLE_STDERR) is ScanOutcome.clean


def test_a_compile_error_is_a_failure_not_a_clean_scan() -> None:
    """The bug this prevents: broken rules reported as "nothing found"."""
    assert _adapter().interpret_outcome(1, "", COMPILE_ERROR_STDERR) is ScanOutcome.failure
    assert _adapter().interpret_outcome(1, "", MISSING_TARGET_STDERR) is ScanOutcome.failure


# --------------------------------------------------------------------------
# parse
# --------------------------------------------------------------------------


def test_parse_plain_match_line() -> None:
    finding = _adapter().parse(PLAIN_MATCH, "")[0]
    assert finding.indicator_type == "yara_rule"
    assert finding.indicator_value == "Demo_Rule"
    assert finding.path == "/scan/tgt/hit.txt"
    assert finding.category == "file"
    assert finding.severity is None
    assert finding.raw_line == PLAIN_MATCH.rstrip("\n")


def test_parse_reads_the_scanners_own_severity_from_meta() -> None:
    findings = _adapter().parse(META_MATCHES, "")
    assert [f.severity for f in findings] == ["high", "high", None]


def test_parse_handles_meta_with_commas_and_escaped_quotes() -> None:
    findings = _adapter().parse(META_MATCHES, "")
    assert [f.path for f in findings] == [
        "/scan/tgt/hit.txt",
        "/scan/tgt/both.txt",
        "/scan/tgt/both.txt",
    ]
    assert [f.indicator_value for f in findings] == ["Demo_Rule", "Demo_Rule", "Second_Rule"]


def test_parse_handles_empty_meta_brackets() -> None:
    finding = _adapter().parse("Second_Rule [] /scan/tgt/both.txt\n", "")[0]
    assert finding.indicator_value == "Second_Rule"
    assert finding.path == "/scan/tgt/both.txt"
    assert finding.severity is None


def test_parse_skips_indented_string_match_lines() -> None:
    findings = _adapter().parse(STRING_MATCHES, "")
    assert len(findings) == 1
    assert findings[0].path == "/scan/tgt/hit.txt"


def test_parse_handles_a_path_with_spaces_and_a_bracket() -> None:
    finding = _adapter().parse(AWKWARD_PATH, "")[0]
    assert finding.path == "/scan/tgt3/we ird/a]b c.txt"


def test_parse_ignores_stderr() -> None:
    assert _adapter().parse("", UNREADABLE_STDERR + COMPILE_ERROR_STDERR) == []


def test_parse_ignores_error_lines_on_stdout() -> None:
    assert _adapter().parse(COMPILE_ERROR_STDERR + MISSING_TARGET_STDERR, "") == []


def test_parse_message_names_the_rule_and_the_file() -> None:
    finding = _adapter().parse(PLAIN_MATCH, "")[0]
    assert finding.message is not None
    assert "Demo_Rule" in finding.message
    assert "/scan/tgt/hit.txt" in finding.message


# --------------------------------------------------------------------------
# a line break in a scanned path -- the forged match-line exposure
#
# Requiring the path to start with `/` does NOT make this parser immune: the
# injected fragment supplies the rule name first and the slash after it, and
# the slashes of the fake path are just nested directories under a directory
# whose NAME carries the break. Measured live against yara 4.5.7 (see the
# adapter's module docstring and the live tests): eight of the nine characters
# `str.splitlines` breaks on reach us raw and forged a match line; only newline
# and CR are escaped by yara itself, and that escaping is not relied on. These
# tests PIN what is closed and what remains.
# --------------------------------------------------------------------------

# The residual shape: a path yara printed with a RAW newline in it. yara 4.5.7
# escapes newlines, so this needs a yara that does not -- assumed reachable
# rather than argued away.
FORGED_MATCH = "Real_Rule /tmp/legit\nEvil_Rule /etc/shadow\n"


def test_a_newline_in_a_filename_forges_an_extra_match() -> None:
    """The split cannot be undone once yara has printed the name.

    By the time `parse` runs the forged line is byte-for-byte a real match
    line, so it becomes a second finding naming an attacker-chosen rule on an
    attacker-chosen path -- both `threat.indicator.value` and `file.path`.
    Pinned, not fixed: guessing which match lines look "unexpected" would risk
    dropping real YARA hits.
    """
    findings = _adapter().parse(FORGED_MATCH, "")
    assert len(findings) == 2
    assert findings[1].indicator_value == "Evil_Rule"
    assert findings[1].path == "/etc/shadow"


def test_the_real_match_survives_the_forged_line() -> None:
    """The bound that matters: an injection can ADD a match, never hide one.

    Lines are parsed independently and appended, so the genuine line is already
    a finding -- rule name and meta severity intact -- when the forged line is
    read. Only the tail of its `path` is lost with the newline, which is the
    one way a real detection can be made to name a shorter, innocent-looking
    path.
    """
    findings = _adapter().parse(FORGED_MATCH, "")
    assert findings[0].indicator_value == "Real_Rule"
    assert findings[0].path == "/tmp/legit"
    assert findings[0].category == "file"

    with_meta = _adapter().parse('Real_Rule [severity="high"] /tmp/legit\nEvil_Rule /x\n', "")
    assert with_meta[0].severity == "high"


def test_a_forged_match_line_cannot_change_the_outcome() -> None:
    """The other bound: attacker text needs a genuine match to ride in on.

    `-w` silences compile warnings and per-file open errors go to stderr, which
    is never parsed, so stdout carries match lines only -- a run with nothing
    genuine to report has nothing to inject into and keeps its classification.
    """
    adapter = _adapter()
    assert adapter.interpret_outcome(0, "", "") is ScanOutcome.clean
    assert adapter.interpret_outcome(1, "", COMPILE_ERROR_STDERR) is ScanOutcome.failure
    # The forged line rides inside a genuine match, which was already `findings`.
    assert adapter.interpret_outcome(0, FORGED_MATCH, "") is ScanOutcome.findings


@pytest.mark.parametrize(
    "break_char", ["\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
)
def test_only_a_raw_newline_forges_a_match_line(break_char: str) -> None:
    """`str.splitlines` breaks on eight characters beyond `\\n`, and a path may
    contain every one of them -- yara 4.5.7 was measured printing VT, FF,
    `\\x1c`-`\\x1e`, `\\x85` and U+2028/9 raw, so these eight forged real
    findings before the fix. Splitting on `\\n` alone closes all of them and
    narrows the forgery to the one character no line-based parser can defend
    against."""
    findings = _adapter().parse(f"Real_Rule /tmp/x{break_char}Evil_Rule /etc/shadow\n", "")
    assert len(findings) == 1
    assert findings[0].indicator_value == "Real_Rule"


def test_control_characters_never_reach_a_finding() -> None:
    """Sanitized so nothing downstream -- a terminal, a log tailer -- can
    re-interpret them. NUL and an ESC sequence are the ones actually measured."""
    text = 'Demo_Rule [severity="hi\x00gh"] /scan/tgt/\x1b[31ma\x00b\x07.txt\n'
    findings = _adapter().parse(text, "")
    assert len(findings) == 1
    assert findings[0].severity == "high"
    for field in (
        findings[0].indicator_value,
        findings[0].raw_line,
        findings[0].message or "",
        findings[0].path or "",
    ):
        assert not any(ch < " " or "\x7f" <= ch <= "\x9f" for ch in field), repr(field)


# --------------------------------------------------------------------------
# malformed input -- `inspectord/parsers/base.py`: parsers NEVER raise
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n\n\n",
        "   \n\t\n",
        "\x00\x01\x02\xff\xfe",
        "Demo_Rule\n",  # no path
        "Demo_Rule \n",
        "Demo_Rule [\n",  # truncated meta
        'Demo_Rule [severity="unterminated /scan/x\n',
        "Demo_Rule [] \n",
        "Demo_Rule relative/path.txt\n",  # not absolute
        "[] /scan/x\n",  # no rule name
        "]]][[[\n",
        "Demo_Rule [] " + "/x" * 100_000 + "\n",
        "D" * 200_000 + " /scan/x\n",
        "Demo_Rule [severity=] /scan/x\n",
        "Demo_Rule [=high] /scan/x\n",
        "Demo_Rule [severity=\x00] /scan/x\n",
        "0x6:$a: SUSPICIOUS_MARKER\n",  # a string-match line with no owner
    ],
)
def test_parse_never_raises_on_garbage(text: str) -> None:
    assert isinstance(_adapter().parse(text, "\x00garbage"), list)


def test_parse_returns_the_findings_parsed_so_far_around_garbage() -> None:
    text = PLAIN_MATCH + "\x00\xff not a line\nDemo_Rule [] /scan/tgt/second.txt\n"
    findings = _adapter().parse(text, "")
    assert [f.path for f in findings] == ["/scan/tgt/hit.txt", "/scan/tgt/second.txt"]


def test_parse_rejects_a_relative_path_rather_than_guessing() -> None:
    """The adapter always passes an absolute target, so a relative path means
    the line is not a match line."""
    assert _adapter().parse("Demo_Rule tgt/hit.txt\n", "") == []


def test_parse_caps_the_size_of_a_single_finding() -> None:
    findings = _adapter().parse("D" * 200_000 + " /scan/x\n", "")
    for finding in findings:
        assert len(finding.indicator_value) <= 256
        assert len(finding.raw_line) <= 4096
        assert len(finding.message or "") <= 4096


def test_severity_from_meta_is_capped_and_stringified() -> None:
    findings = _adapter().parse('R [severity="' + "h" * 500 + '"] /scan/x\n', "")
    assert findings and findings[0].severity is not None
    assert len(findings[0].severity) <= 64


@pytest.mark.parametrize("code", [0, 1, -9])
def test_interpret_outcome_never_raises_on_garbage(code: int) -> None:
    assert _adapter().interpret_outcome(code, "\x00\xff]]][[[\n", "\x00") in set(ScanOutcome)


def test_preflight_never_raises_on_a_junk_config() -> None:
    for config in ({}, {"rules_dir": ""}, {"rules_dir": "\x00"}, {"target": None}):
        assert _adapter().preflight(config) is None or isinstance(_adapter().preflight(config), str)
