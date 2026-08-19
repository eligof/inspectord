"""Tests for the AIDE scanner adapter.

Pure functions over fixture strings: no subprocess, no root, no installed AIDE.

The `interpret_outcome` table test is the centerpiece (design decision 10): AIDE's
exit status is a BITMASK whose low bits mean new/removed/changed entries --
i.e. findings, a successful scan -- and only the high error codes mean failure.
Treating any non-zero code as a failure would report every real detection as a
broken scan.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.workers.scanner_runner.scanners import aide as aide_module
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


# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------


def _conf(tmp_path: Path, body: str) -> str:
    conf = tmp_path / "aide.conf"
    conf.write_text(body, encoding="utf-8")
    return str(conf)


def test_preflight_reports_config_missing_rather_than_a_nightly_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A host that has not installed the config yet.

    Measured against AIDE 0.19.3, `--config /nonexistent --check` exits 18,
    which `interpret_outcome` correctly calls a failure -- so without this the
    enabled-by-default scanner would report "exit 18" every night forever.

    The no-config_path case is exercised against a REDIRECTED default rather
    than the real `/var/lib/inspectord/aide/aide.conf`: the repo now ships
    `packaging/aide.conf.example` and `setup.sh` installs it to exactly that
    path, so asserting on the live filesystem would pass or fail depending on
    whether the developer had run setup.
    """
    monkeypatch.setattr(aide_module, "DEFAULT_CONFIG_PATH", str(tmp_path / "absent.conf"))
    assert AideAdapter().preflight({}) == "config_missing"
    assert AideAdapter().preflight({"config_path": "/nope/aide.conf"}) == "config_missing"


def test_preflight_reports_database_missing_when_the_config_names_an_absent_db(
    tmp_path: Path,
) -> None:
    """`aide --init` is the user's decision, so an uninitialized database skips.

    Measured: AIDE 0.19.3 exits 18 here too, with an "open (read-only) failed"
    diagnostic -- indistinguishable, from the exit code alone, from a disk fault.
    """
    conf = _conf(tmp_path, f"database_in=file:{tmp_path}/aide.db\nreport_url=stdout\n")
    assert AideAdapter().preflight({"config_path": conf}) == "database_missing"


def test_preflight_passes_once_the_database_exists(tmp_path: Path) -> None:
    (tmp_path / "aide.db").write_text("", encoding="utf-8")
    conf = _conf(tmp_path, f"database_in=file:{tmp_path}/aide.db\n")
    assert AideAdapter().preflight({"config_path": conf}) is None


def test_preflight_accepts_the_pre_0_19_database_spelling(tmp_path: Path) -> None:
    conf = _conf(tmp_path, f"database=file:{tmp_path}/aide.db\n")
    assert AideAdapter().preflight({"config_path": conf}) == "database_missing"


def test_preflight_tolerates_spaces_around_the_equals(tmp_path: Path) -> None:
    # AIDE 0.19.3 accepts `database_in = file:...`; measured.
    conf = _conf(tmp_path, f"database_in = file:{tmp_path}/aide.db\n")
    assert AideAdapter().preflight({"config_path": conf}) == "database_missing"


def test_preflight_uses_the_first_database_line_like_aide_does(tmp_path: Path) -> None:
    """`man aide.conf`: "If there are multiple database lines then the first is used"."""
    (tmp_path / "second.db").write_text("", encoding="utf-8")
    conf = _conf(
        tmp_path,
        f"database_in=file:{tmp_path}/first.db\ndatabase_in=file:{tmp_path}/second.db\n",
    )
    assert AideAdapter().preflight({"config_path": conf}) == "database_missing"


def test_preflight_ignores_a_commented_out_database_line(tmp_path: Path) -> None:
    conf = _conf(tmp_path, f"# database_in=file:{tmp_path}/aide.db\nreport_url=stdout\n")
    assert AideAdapter().preflight({"config_path": conf}) is None


@pytest.mark.parametrize(
    "url",
    [
        "stdin",  # legal per `man aide.conf`
        "https://example.com/aide.db",  # also legal; not a local file
        "file:@@{DBDIR}/aide.db",  # a config variable this parser does not expand
        "file:relative/aide.db",  # not absolute -- we cannot resolve it
    ],
)
def test_preflight_lets_aide_speak_when_the_database_is_undecidable(
    tmp_path: Path, url: str
) -> None:
    """Undecidable is NOT "not configured" -- skipping on a guess would silence a
    scanner that could have run, which is the failure mode this whole worker exists
    to avoid."""
    conf = _conf(tmp_path, f"database_in={url}\n")
    assert AideAdapter().preflight({"config_path": conf}) is None


def test_preflight_lets_aide_speak_when_the_config_declares_no_database(
    tmp_path: Path,
) -> None:
    # e.g. a config that pulls the setting in through `@@include`.
    conf = _conf(tmp_path, "@@include /etc/aide.conf.d\nreport_url=stdout\n")
    assert AideAdapter().preflight({"config_path": conf}) is None


def test_preflight_never_raises_on_a_hostile_config(tmp_path: Path) -> None:
    """Adapters promise not to raise; a directory, a NUL and undecodable bytes."""
    adapter = AideAdapter()
    (tmp_path / "dir.conf").mkdir()
    assert adapter.preflight({"config_path": str(tmp_path / "dir.conf")}) == "config_missing"
    assert adapter.preflight({"config_path": "/nope\x00/aide.conf"}) == "config_missing"

    binary = tmp_path / "binary.conf"
    binary.write_bytes(b"database_in=file:/\xff\xfe/aide.db\n")
    assert adapter.preflight({"config_path": str(binary)}) == "database_missing"


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
# a line break in a reported filename -- the forged report-line exposure
#
# `/` and NUL are the only bytes a Linux filename may not contain, and every
# line of an `aide --check` report ends in a path AIDE is reporting on, so the
# tail after a break is fully attacker-chosen. This parser is SECTION-DRIVEN,
# so a forged line is not limited to inventing an entry: it can open a spurious
# section, mislabel genuine entries, and -- uniquely among the three adapters --
# SUPPRESS a genuine one by closing the section. Measured live against AIDE
# 0.19.3 (see the adapter's module docstring and the live tests): it escapes
# control characters 00-31 and 127 as octal, but passes U+0085, U+2028 and
# U+2029 through raw, and `str.splitlines` breaks on all three. These tests PIN
# what is closed and what remains.
# --------------------------------------------------------------------------

# One honest report of a planted tree, as the parser would see it from an AIDE
# that printed a RAW newline in a path. AIDE 0.19.3 escapes newlines, so this
# needs an older/other AIDE -- assumed reachable rather than argued away.
FORGED_REPORT = (
    "Added entries:\n"
    "f++++++++++++++++: /data/a_genuine\n"
    "d++++++++++++++++: /data/m1\nf++++++++++++++++: /etc/shadow\n"
    "d++++++++++++++++: /data/m2\nRemoved entries:\n"
    "d++++++++++++++++: /data/m3\nSome heading:\n"
    "f++++++++++++++++: /data/zzz_genuine\n"
)


def test_a_newline_in_a_filename_forges_an_extra_entry() -> None:
    """The split cannot be undone once AIDE has printed the name.

    By the time `parse` runs the forged line is byte-for-byte a real entry
    line, so it becomes a finding on an attacker-chosen `file.path`. Pinned,
    not fixed: guessing which report lines look "unexpected" would risk
    dropping real AIDE changes.
    """
    findings = AideAdapter().parse(FORGED_REPORT, "")
    assert ("added", "/etc/shadow") in [(f.indicator_value, f.path) for f in findings]


def test_a_forged_line_can_open_a_spurious_section() -> None:
    """Wider than the rkhunter/YARA case: the forged tail can be a HEADER.

    `Removed entries:` riding in a filename opens a `removed` section, so the
    next genuine entry -- a real, newly added file -- is reported with the
    attacker's change kind instead of its own.
    """
    findings = AideAdapter().parse(FORGED_REPORT, "")
    assert ("removed", "/data/m3") in [(f.indicator_value, f.path) for f in findings]


def test_a_forged_heading_suppresses_a_genuine_entry() -> None:
    """The bound rkhunter and YARA do NOT share: an AIDE forgery can HIDE.

    A forged bare heading matches `_HEADING_RE` and closes the open section, so
    every genuine entry sorted after it -- AIDE sorts a section by path -- is
    skipped. Here a genuinely new file vanishes from the findings entirely.
    Pinned so nobody reads the section machinery and assumes only addition is
    possible.
    """
    findings = AideAdapter().parse(FORGED_REPORT, "")
    assert "/data/zzz_genuine" not in [f.path for f in findings]


def test_a_forged_line_needs_no_open_section_at_all() -> None:
    """The legacy inline form matches before the section check, so a forged
    `changed: /path` works anywhere in the report -- including the trailing
    "Detailed information" block, where no section is open."""
    findings = AideAdapter().parse("Summary:\nFile: /data/m4\nchanged: /etc/passwd\n", "")
    assert [(f.indicator_value, f.path) for f in findings] == [("changed", "/etc/passwd")]


def test_the_genuine_entry_survives_the_forged_line() -> None:
    """The bound that matters most: entries before the forgery are untouched.

    The genuine `added` entry read before the injected line is already a
    finding, with its own change kind and its whole path, when the forged line
    is parsed.
    """
    findings = AideAdapter().parse(FORGED_REPORT, "")
    assert findings[0].indicator_value == "added"
    assert findings[0].path == "/data/a_genuine"
    assert findings[0].category == "file"


def test_a_forged_report_line_cannot_change_the_outcome() -> None:
    """The bound AIDE holds more firmly than either sibling.

    `interpret_outcome` reads the exit bitmask and nothing else, so no amount
    of forged report text can move a `clean` or a `failure` to `findings`.
    Sanitizing the text the PARSER reads must never leak into the verdict.
    """
    adapter = AideAdapter()
    assert adapter.interpret_outcome(0, FORGED_REPORT, "") is ScanOutcome.clean
    assert adapter.interpret_outcome(18, FORGED_REPORT, "") is ScanOutcome.failure
    # The forged line rides inside a real report, which was already `findings`.
    assert adapter.interpret_outcome(5, FORGED_REPORT, "") is ScanOutcome.findings


@pytest.mark.parametrize(
    "break_char", ["\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
)
def test_only_a_raw_newline_forges_a_report_line(break_char: str) -> None:
    """`str.splitlines` breaks on eight characters beyond `\\n`, and a filename
    may contain every one of them -- AIDE 0.19.3 was measured printing `\\x85`
    and U+2028/9 raw, so those three forged real findings before the fix.
    Splitting on `\\n` alone closes all eight and narrows the forgery to the one
    character no line-based parser can defend against."""
    text = f"Added entries:\nf++++++++++++++++: /data/x{break_char}f+++: /etc/shadow\n"
    findings = AideAdapter().parse(text, "")
    assert len(findings) == 1
    assert findings[0].indicator_value == "added"
    assert findings[0].path != "/etc/shadow"


@pytest.mark.parametrize(
    "break_char", ["\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
)
def test_only_a_raw_newline_forges_a_section_header(break_char: str) -> None:
    """The section-driven half of the same surface: a forged tail that is a
    HEADER would relabel every following entry, and a forged bare heading would
    close the section and drop them. Neither reaches the parser any more."""
    text = (
        f"Added entries:\nf++++++++++++++++: /data/x{break_char}Removed entries:\n"
        f"f++++++++++++++++: /data/y{break_char}Some heading:\n"
        "f++++++++++++++++: /data/still_here\n"
    )
    findings = AideAdapter().parse(text, "")
    assert [f.indicator_value for f in findings] == ["added", "added", "added"]
    assert "/data/still_here" in [f.path for f in findings]


def test_control_characters_never_reach_a_finding() -> None:
    """Sanitized so nothing downstream -- a terminal, a log tailer -- can
    re-interpret them. NUL and an ESC sequence are the ones actually measured."""
    text = "Added entries:\nf++++++++++++++++: /data/\x1b[31ma\x00b\x07.txt\n"
    findings = AideAdapter().parse(text, "")
    assert len(findings) == 1
    for field in (
        findings[0].indicator_value,
        findings[0].raw_line,
        findings[0].message or "",
        findings[0].path or "",
    ):
        assert not any(ch < " " or "\x7f" <= ch <= "\x9f" for ch in field), repr(field)


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
