"""Tests for the AIDE scanner adapter.

Pure functions over fixture strings: no subprocess, no root, no installed AIDE.

The `interpret_exit` table test is the centerpiece (design decision 10): AIDE's
exit status is a BITMASK whose low bits mean new/removed/changed entries --
i.e. findings, a successful scan -- and only the high error codes mean failure.
Treating any non-zero code as a failure would report every real detection as a
broken scan.
"""

from __future__ import annotations

import pytest

from inspectord.workers.scanner_runner.scanners.aide import AideAdapter
from inspectord.workers.scanner_runner.scanners.base import ScanOutcome

# A capture-shaped AIDE 0.18 `--check` report with one added, one removed and
# two changed entries, including the trailing "Detailed information" block that
# must NOT be double-counted.
REPORT = """\
Start timestamp: 2026-08-19 03:00:01 +0300 (AIDE 0.18.6)
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:\t42817
  Added entries:\t\t1
  Removed entries:\t\t1
  Changed entries:\t\t2

---------------------------------------------------
Added entries:
---------------------------------------------------

f++++++++++++++++: /usr/bin/definitely-new

---------------------------------------------------
Removed entries:
---------------------------------------------------

f----------------: /usr/bin/gone-away

---------------------------------------------------
Changed entries:
---------------------------------------------------

f   ...    .C... : /etc/passwd
f =.... mc..  . : /usr/lib/libfoo.so

---------------------------------------------------
Detailed information about changes:
---------------------------------------------------

File: /etc/passwd
  SHA256   : 0011deadbeef | ffee00c0ffee

The attributes of the (uncompressed) database(s):
  /var/lib/inspectord/aide/aide.db.gz
  SHA256   : abcdef0123456789
"""

CLEAN_REPORT = """\
Start timestamp: 2026-08-19 03:00:01 +0300 (AIDE 0.18.6)
AIDE found NO differences between database and filesystem. Looks okay!!

Summary:
  Total number of entries:\t42817
  Added entries:\t\t0
  Removed entries:\t\t0
  Changed entries:\t\t0
"""


# --------------------------------------------------------------------------
# argv
# --------------------------------------------------------------------------


def test_argv_uses_the_inspectord_owned_config_and_check() -> None:
    argv = AideAdapter().argv({})
    assert argv == ["aide", "--config", "/var/lib/inspectord/aide/aide.conf", "--check"]


def test_argv_config_path_is_overridable() -> None:
    argv = AideAdapter().argv({"config_path": "/etc/aide.conf"})
    assert argv == ["aide", "--config", "/etc/aide.conf", "--check"]


def test_argv_is_a_list_never_a_shell_string() -> None:
    argv = AideAdapter().argv({"config_path": "/tmp/x; rm -rf /"})
    assert isinstance(argv, list)
    # The injection attempt is one inert argv element, not a second command.
    assert argv[2] == "/tmp/x; rm -rf /"


# --------------------------------------------------------------------------
# interpret_outcome -- design decision 10
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (0, ScanOutcome.clean),  # no differences
        (1, ScanOutcome.findings),  # new entries
        (2, ScanOutcome.findings),  # removed entries
        (3, ScanOutcome.findings),  # new | removed
        (4, ScanOutcome.findings),  # changed entries
        (5, ScanOutcome.findings),  # new | changed
        (6, ScanOutcome.findings),  # removed | changed
        (7, ScanOutcome.findings),  # new | removed | changed
        (14, ScanOutcome.failure),  # write error
        (15, ScanOutcome.failure),  # invalid argument
        (16, ScanOutcome.failure),  # unimplemented function
        (17, ScanOutcome.failure),  # invalid config line
        (18, ScanOutcome.failure),  # IO error
        (19, ScanOutcome.failure),  # version mismatch
        (20, ScanOutcome.failure),  # exec error
        (21, ScanOutcome.failure),  # file lock error
        (22, ScanOutcome.failure),  # memory allocation error
        (23, ScanOutcome.failure),  # thread error
        (24, ScanOutcome.failure),  # database error (documented by AIDE 0.19)
        (25, ScanOutcome.failure),  # killed by SIGINT/SIGTERM/SIGHUP (AIDE 0.19)
        (8, ScanOutcome.failure),  # undocumented -> failure, never clean
        (13, ScanOutcome.failure),
        (26, ScanOutcome.failure),
        (255, ScanOutcome.failure),
        (-9, ScanOutcome.failure),  # killed by SIGKILL
    ],
)
def test_interpret_outcome_table(code: int, expected: ScanOutcome) -> None:
    assert AideAdapter().interpret_outcome(code, "", "") is expected


def test_nonzero_exit_is_findings_not_failure() -> None:
    """The bug this test exists to prevent: a real detection reported as a broken scan."""
    for code in (1, 2, 3, 4, 5, 6, 7):
        assert AideAdapter().interpret_outcome(code, "", "") is ScanOutcome.findings, code


def test_interpret_outcome_ignores_the_output() -> None:
    """AIDE's exit status is self-describing; unlike rkhunter it needs no output.

    Pinned so nobody "helpfully" makes AIDE's verdict depend on a report body
    that an attacker-controlled file path can appear in.
    """
    adapter = AideAdapter()
    assert adapter.interpret_outcome(0, REPORT, "boom") is ScanOutcome.clean
    assert adapter.interpret_outcome(4, "", "") is ScanOutcome.findings
    assert adapter.interpret_outcome(18, REPORT, "") is ScanOutcome.failure


def test_preflight_is_none_because_aide_needs_no_setup() -> None:
    """AIDE's config path is a plain argv value; there is nothing to expand or count."""
    assert AideAdapter().preflight({}) is None
    assert AideAdapter().preflight({"config_path": "/nope/aide.conf"}) is None


# --------------------------------------------------------------------------
# parse
# --------------------------------------------------------------------------


def test_parse_extracts_added_removed_and_changed_entries() -> None:
    findings = AideAdapter().parse(REPORT, "")
    assert [(f.indicator_value, f.path) for f in findings] == [
        ("added", "/usr/bin/definitely-new"),
        ("removed", "/usr/bin/gone-away"),
        ("changed", "/etc/passwd"),
        ("changed", "/usr/lib/libfoo.so"),
    ]


def test_parse_does_not_double_count_the_detailed_section() -> None:
    findings = AideAdapter().parse(REPORT, "")
    assert [f.path for f in findings].count("/etc/passwd") == 1


def test_parse_ignores_the_summary_counters() -> None:
    """`  Total number of entries:\t42817` looks like `attrs: value` but has no path."""
    findings = AideAdapter().parse(REPORT, "")
    assert all(f.path is not None and f.path.startswith("/") for f in findings)


def test_parse_finding_shape() -> None:
    finding = AideAdapter().parse(REPORT, "")[0]
    assert finding.indicator_type == "aide_change"
    assert finding.indicator_value == "added"
    assert finding.category == "file"
    assert finding.severity is None  # AIDE has no severity of its own
    assert finding.raw_line == "f++++++++++++++++: /usr/bin/definitely-new"
    assert finding.message is not None and "/usr/bin/definitely-new" in finding.message


def test_parse_clean_report_yields_nothing() -> None:
    assert AideAdapter().parse(CLEAN_REPORT, "") == []


def test_parse_legacy_inline_form() -> None:
    """AIDE 0.15-era output used `added: /path` with no section headers."""
    text = "added: /etc/new\nremoved: /etc/old\nchanged: /etc/mod\n"
    findings = AideAdapter().parse(text, "")
    assert [(f.indicator_value, f.path) for f in findings] == [
        ("added", "/etc/new"),
        ("removed", "/etc/old"),
        ("changed", "/etc/mod"),
    ]


# --------------------------------------------------------------------------
# malformed input -- never raise, return the findings parsed so far
# --------------------------------------------------------------------------


def test_parse_malformed_returns_findings_so_far() -> None:
    text = (
        "Added entries:\n"
        "f++++++++++++++++: /etc/first\n"
        "\x00\xff garbage that is not a line at all\n"
        ":::::::\n"
        "f++++++++++++++++: /etc/second\n"
    )
    findings = AideAdapter().parse(text, "")
    assert [f.path for f in findings] == ["/etc/first", "/etc/second"]


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n\n\n",
        "\x00\x01\x02",
        "Summary:\n  Total number of entries:\t12345\n",
        "not a report at all",
        ":" * 5000,
        "Added entries:\n" + "no path here\n" * 100,
    ],
)
def test_parse_never_raises_on_garbage(text: str) -> None:
    assert AideAdapter().parse(text, text) == []


def test_parse_treats_paths_as_untrusted_data() -> None:
    """Scanner output embeds attacker-controllable paths; they are data, never code."""
    text = "Added entries:\nf++++++++++++++++: /tmp/$(id)`whoami`;rm -rf /\n"
    findings = AideAdapter().parse(text, "")
    assert [f.path for f in findings] == ["/tmp/$(id)`whoami`;rm -rf /"]
