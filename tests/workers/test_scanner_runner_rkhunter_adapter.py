"""Tests for the rkhunter scanner adapter.

Pure functions over fixture strings: no subprocess, no root, no installed
rkhunter. The live counterpart is
``tests/workers/test_scanner_runner_live_scanners.py``.

Every fixture below is **verbatim stdout captured from rkhunter 1.4.6 on this
machine** (via ``sudo .venv/bin/python -m pytest``; ``/usr/bin/rkhunter`` is
``0700 root:root``), run as
``rkhunter --check --sk --nocolors --rwo --nomow --logfile <tmp> …``.

The centerpiece is ``interpret_outcome``: rkhunter exits **1** both when it
finds warnings and when it refuses to run at all, so a classifier that looked at
the code alone would report a misconfigured scanner as a rootkit detection --
the exact inverse of the bug design decision 10 exists to prevent.
"""

from __future__ import annotations

from typing import Any

import pytest

from inspectord.workers.scanner_runner.scanners.base import ScanOutcome
from inspectord.workers.scanner_runner.scanners.rkhunter import RkhunterAdapter

# --- captured stdout ------------------------------------------------------

# `--enable properties`, exit 1. FIVE warnings, not nine lines: the second and
# third blocks carry indented continuation lines that are part of the warning.
#
# Three of the captured lines are longer than this repo's 100-column limit, so
# they are written as adjacent string literals. The bytes are unchanged.
PROPERTIES_WARNINGS = (
    "Warning: Checking for prerequisites               [ Warning ]\n"
    "         The file of stored file properties (rkhunter.dat) does not exist,"
    " and should be created. To do this type in 'rkhunter --propupd'.\n"
    "Warning: WARNING! It is the users responsibility to ensure that when the"
    " '--propupd' option\n"
    "         is used, all the files on their system are known to be genuine,"
    " and installed from a\n"
    "         reliable source. The rkhunter '--check' option will compare the"
    " current file properties\n"
    "         against previously stored values, and report if any values differ."
    " However, rkhunter\n"
    "         cannot determine what has caused the change, that is for the user to do.\n"
    "Warning: The command '/usr/bin/egrep' has been replaced by a script:"
    " /usr/bin/egrep: POSIX shell script, ASCII text executable\n"
    "Warning: The command '/usr/bin/fgrep' has been replaced by a script:"
    " /usr/bin/fgrep: POSIX shell script, ASCII text executable\n"
    "Warning: The command '/usr/bin/ldd' has been replaced by a script:"
    " /usr/bin/ldd: Bourne-Again shell script, ASCII text executable\n"
)

# `--enable passwd_changes`, exit 1. One warning, no continuation.
ONE_WARNING = (
    "Warning: Unable to check for passwd file differences: no copy of the passwd file exists.\n"
)

# `--enable hidden_ports` / `promisc` / `immutable`: exit 0, nothing on stdout.
CLEAN = ""

# `--disable all`, exit 1 -- an INVALID argument, not a detection.
DISABLE_ALL_ERROR = "'all' cannot be used in the disabled test list.\n"

# `--enable bogus_test`, exit 1.
UNKNOWN_TEST_ERROR = "Unknown enabled test name given: bogus_test\n"

# `--configfile /nonexistent/rk.conf`, exit 1.
BAD_CONFIG_ERROR = "Unable to find configuration file: /nonexistent/rk.conf\n"

# `--nolog` together with `--rwo`, exit 1. This is why the adapter never passes
# `--nolog`: rkhunter reports warnings *from* its log file.
NOLOG_ERROR = "The logfile has been disabled - unable to report warnings.\n"

# rkhunter's own shell internals write this to stderr on every single run.
STDERR_NOISE = (
    "grep: warning: stray \\ before -\n"
    "grep: warning: stray \\ before +\n"
    "egrep: warning: egrep is obsolescent; using grep -E\n"
)


def _adapter() -> RkhunterAdapter:
    return RkhunterAdapter()


# --------------------------------------------------------------------------
# argv
# --------------------------------------------------------------------------


def test_argv_always_carries_the_mandatory_flags() -> None:
    argv = _adapter().argv({})
    assert argv[0] == "rkhunter"
    for flag in (
        "--check",
        "--skip-keypress",
        "--nocolors",
        "--report-warnings-only",
        "--no-mail-on-warning",
    ):
        assert flag in argv, flag


def test_argv_never_updates_anything_and_never_disables_the_log() -> None:
    """Decision 8 (no network, ever) and the measured `--nolog` + `--rwo` clash."""
    argv = _adapter().argv({"enable": ["properties"], "logfile": "/tmp/rk.log"})
    for forbidden in ("--update", "--propupd", "--versioncheck", "--nolog"):
        assert forbidden not in argv, forbidden


def test_argv_joins_enabled_tests_with_commas() -> None:
    argv = _adapter().argv({"enable": ["properties", "rootkits"]})
    assert argv[argv.index("--enable") + 1] == "properties,rootkits"


def test_argv_accepts_a_plain_string_for_enable_and_disable() -> None:
    argv = _adapter().argv({"enable": "properties", "disable": "suspscan"})
    assert argv[argv.index("--enable") + 1] == "properties"
    assert argv[argv.index("--disable") + 1] == "suspscan"


def test_argv_omits_unconfigured_options() -> None:
    argv = _adapter().argv({})
    for absent in ("--enable", "--disable", "--configfile", "--logfile"):
        assert absent not in argv, absent


def test_argv_passes_configfile_and_logfile_when_configured() -> None:
    argv = _adapter().argv({"configfile": "/etc/rkhunter.conf", "logfile": "/var/log/rk.log"})
    assert argv[argv.index("--configfile") + 1] == "/etc/rkhunter.conf"
    assert argv[argv.index("--logfile") + 1] == "/var/log/rk.log"


def test_argv_is_a_list_never_a_shell_string() -> None:
    argv = _adapter().argv({"logfile": "/tmp/a b; rm -rf /"})
    assert isinstance(argv, list)
    # The dangerous value survives as ONE argument -- nothing re-parses it.
    assert "/tmp/a b; rm -rf /" in argv


def test_argv_ignores_empty_option_values() -> None:
    argv = _adapter().argv({"enable": [], "disable": "", "logfile": None})
    assert "--enable" not in argv
    assert "--disable" not in argv
    assert "--logfile" not in argv


def test_preflight_is_none_rkhunter_ships_its_own_data() -> None:
    assert _adapter().preflight({}) is None


# --------------------------------------------------------------------------
# interpret_outcome -- design decision 10, the whole point of this adapter
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stdout", "code", "expected"),
    [
        # Real detections. rkhunter exits 1 when it warns.
        (PROPERTIES_WARNINGS, 1, ScanOutcome.findings),
        (ONE_WARNING, 1, ScanOutcome.findings),
        # ... and warnings win over the code, so a partly-broken run can never
        # HIDE a detection.
        (PROPERTIES_WARNINGS, 0, ScanOutcome.findings),
        (PROPERTIES_WARNINGS, 2, ScanOutcome.findings),
        (PROPERTIES_WARNINGS, -9, ScanOutcome.findings),
        # Refusals: also exit 1, but with no warning anywhere.
        (DISABLE_ALL_ERROR, 1, ScanOutcome.failure),
        (UNKNOWN_TEST_ERROR, 1, ScanOutcome.failure),
        (BAD_CONFIG_ERROR, 1, ScanOutcome.failure),
        (NOLOG_ERROR, 1, ScanOutcome.failure),
        # A clean check prints nothing at all and exits 0.
        (CLEAN, 0, ScanOutcome.clean),
        ("\n\n", 0, ScanOutcome.clean),
        # Nothing found and a non-zero code is never "clean".
        (CLEAN, 1, ScanOutcome.failure),
        (CLEAN, 255, ScanOutcome.failure),
        (CLEAN, -15, ScanOutcome.failure),
    ],
)
def test_interpret_outcome_table(stdout: str, code: int, expected: ScanOutcome) -> None:
    assert _adapter().interpret_outcome(code, stdout, STDERR_NOISE) is expected


def test_warning_exit_1_is_findings_not_failure() -> None:
    """Bug #1: reporting a real rootkit warning as a broken scan."""
    assert _adapter().interpret_outcome(1, PROPERTIES_WARNINGS, "") is ScanOutcome.findings


def test_misconfiguration_exit_1_is_failure_not_findings() -> None:
    """Bug #2, the inverse and the worse one: a scanner that REFUSED to run
    reported as a detection. Same exit code as the test above."""
    assert _adapter().interpret_outcome(1, DISABLE_ALL_ERROR, "") is ScanOutcome.failure


def test_stderr_noise_alone_never_makes_a_run_look_like_findings() -> None:
    assert _adapter().interpret_outcome(0, "", STDERR_NOISE) is ScanOutcome.clean


# --------------------------------------------------------------------------
# parse
# --------------------------------------------------------------------------


def test_parse_counts_warning_blocks_not_lines() -> None:
    """The continuation-line trap: 5 warnings spread over 10 lines."""
    findings = _adapter().parse(PROPERTIES_WARNINGS, "")
    assert len(findings) == 5


def test_parse_folds_continuations_into_the_owning_warning() -> None:
    first = _adapter().parse(PROPERTIES_WARNINGS, "")[0]
    assert first.indicator_value == "Checking for prerequisites"
    assert "rkhunter.dat" in (first.message or "")
    assert "--propupd" in (first.message or "")


def test_parse_extracts_the_check_name_from_the_warning_marker() -> None:
    findings = _adapter().parse("Warning: Checking the local host   [ Warning ]\n", "")
    assert [f.indicator_value for f in findings] == ["Checking the local host"]


def test_parse_extracts_a_quoted_path_as_the_file() -> None:
    findings = _adapter().parse(PROPERTIES_WARNINGS, "")
    replaced = [f for f in findings if f.path is not None]
    assert [f.path for f in replaced] == ["/usr/bin/egrep", "/usr/bin/fgrep", "/usr/bin/ldd"]
    assert {f.category for f in replaced} == {"file"}


def test_parse_uses_category_process_when_no_file_is_named() -> None:
    findings = _adapter().parse(PROPERTIES_WARNINGS, "")
    assert findings[0].path is None
    assert findings[0].category == "process"


def test_parse_finding_shape() -> None:
    finding = _adapter().parse(ONE_WARNING, "")[0]
    assert finding.indicator_type == "rkhunter_test"
    assert finding.raw_line == ONE_WARNING.rstrip("\n")
    # Decision 7: rkhunter grades nothing, so the adapter invents no severity.
    assert finding.severity is None
    assert finding.message is not None and "passwd file" in finding.message


def test_parse_clean_output_yields_nothing() -> None:
    assert _adapter().parse(CLEAN, STDERR_NOISE) == []


@pytest.mark.parametrize(
    "text", [DISABLE_ALL_ERROR, UNKNOWN_TEST_ERROR, BAD_CONFIG_ERROR, NOLOG_ERROR]
)
def test_parse_never_turns_an_error_message_into_a_finding(text: str) -> None:
    """This is what makes `interpret_outcome` call those runs failures."""
    assert _adapter().parse(text, "") == []


def test_parse_ignores_stderr_entirely() -> None:
    """stderr is rkhunter's own shell noise; findings come from stdout only."""
    assert _adapter().parse("", "Warning: this is on stderr\n") == []


def test_parse_ignores_a_warning_that_does_not_start_the_line() -> None:
    """Only a column-0 `Warning:` opens a block -- an indented one is a
    continuation, and an embedded one is just text."""
    text = "Warning: real one\n         Warning: still a continuation\n"
    findings = _adapter().parse(text, "")
    assert len(findings) == 1
    assert "still a continuation" in (findings[0].message or "")


def test_parse_closes_a_block_on_an_unindented_line() -> None:
    text = "Warning: first\n         detail\nSomething else entirely\n         orphan detail\n"
    findings = _adapter().parse(text, "")
    assert len(findings) == 1
    assert "orphan detail" not in (findings[0].message or "")


# --------------------------------------------------------------------------
# malformed input -- `inspectord/parsers/base.py`: parsers NEVER raise
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n\n\n",
        "   \t  \n",
        "\x00\x01\x02\xff\xfe",
        "Warning:",  # truncated mid-header
        "Warning: \n",  # empty warning text
        "Warning",  # not a warning at all
        "         orphan continuation with no header\n",
        "Warning: block\n         truncated mid-cont",  # no trailing newline
        "Warning: \x00\xff [ Warning ]\n         \x00\n",
        "Warning: " + "A" * 200_000 + "\n",  # a single enormous line
        "Warning: '" + "/x" * 50_000 + "'\n",  # an enormous quoted path
        "[ Warning ]\n",
        "Warning: [ Warning ]\n",  # empty check name
        "Warning: '' has been replaced\n",  # empty quoted path
        "Warning: '/tmp/\x00evil' replaced\n",
    ],
)
def test_parse_never_raises_on_garbage(text: str) -> None:
    findings = _adapter().parse(text, "\x00garbage")
    assert isinstance(findings, list)


def test_parse_returns_the_findings_parsed_so_far_around_garbage() -> None:
    text = "Warning: first one\n\x00\xff not a line at all\nWarning: second one\n"
    findings = _adapter().parse(text, "")
    assert [f.indicator_value for f in findings] == ["first one", "second one"]


def test_parse_caps_the_size_of_a_single_finding() -> None:
    """Scanner output is untrusted and a warning embeds attacker-influenceable
    paths; one pathological line must not become a multi-megabyte event."""
    findings = _adapter().parse("Warning: " + "A" * 200_000 + "\n", "")
    assert len(findings) == 1
    assert len(findings[0].indicator_value) <= 256
    assert len(findings[0].message or "") <= 4096
    assert len(findings[0].raw_line) <= 4096


@pytest.mark.parametrize("code", [0, 1, 2, 255, -9])
def test_interpret_outcome_never_raises_on_garbage(code: int) -> None:
    outcome: Any = _adapter().interpret_outcome(code, "\x00\xff\n\n", "\x00")
    assert outcome in set(ScanOutcome)
