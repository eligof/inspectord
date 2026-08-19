"""Tests for packaging/aide.conf.example.

This is the AIDE config parent spec §30.6 promises ("we own its database under
/var/lib/inspectord/aide/"), and the one the `aide` scanner adapter reaches for
by default. Shipping it wrong fails in two ways that unit tests alone would miss:

* a config error, because AIDE 0.19 predefines almost no groups -- naming an
  undefined group like `NORMAL` is fatal, not a warning; and
* a report the adapter cannot read, because its parser is written against the
  plain, grouped report on stdout.

So the checks here run in two tiers. The pure-Python ones (groups, URLs, report
options) run everywhere including CI. The ones marked `requires_aide` drive the
**real binary** against the **exact shipped bytes** -- `--before` sets config
parameters ahead of the config file, and "if there are multiple X lines the
first is used", so redirecting `database_in`, `database_out` and `root_prefix`
confines a genuine `--init` + `--check` cycle to `tmp_path`. Nothing here reads
or writes `/var/lib/aide`, `/var/lib/inspectord`, or any other system path.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from inspectord.workers.scanner_runner.scanners import aide as aide_adapter
from inspectord.workers.scanner_runner.scanners.base import ScanOutcome

_REPO_ROOT = Path(__file__).parent.parent
_AIDE_CONFIG = _REPO_ROOT / "packaging" / "aide.conf.example"

requires_aide = pytest.mark.skipif(shutil.which("aide") is None, reason="needs the aide binary")

#: Groups AIDE 0.19.3 defines itself, from `aide --version` ("Default compound
#: groups") plus the empty group E. Everything else must be defined in the file.
_BUILTIN_GROUPS = {"R", "L", ">", "H", "X", "E"}

_GROUP_DEF_RE = re.compile(r"^(?P<name>[A-Za-z0-9]+)[ \t]*=[ \t]*(?P<expr>\S.*)$")
_OPTION_RE = re.compile(r"^(?P<key>[a-z_]+)=(?P<value>.*)$")


def _lines() -> list[str]:
    return [
        line.strip()
        for line in _AIDE_CONFIG.read_text(encoding="utf-8").split("\n")
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _options() -> dict[str, str]:
    """`parameter=value` lines, first occurrence winning as AIDE does."""
    found: dict[str, str] = {}
    for line in _lines():
        match = _OPTION_RE.match(line)
        if match is not None and "=" in line and not _GROUP_DEF_RE.match(line):
            found.setdefault(match.group("key"), match.group("value"))
    return found


def test_aide_config_example_exists() -> None:
    assert _AIDE_CONFIG.exists(), f"Missing: {_AIDE_CONFIG}"


def test_report_url_is_stdout() -> None:
    """The adapter parses stdout; a file:/syslog: URL would starve it silently."""
    assert _options()["report_url"] == "stdout"


def test_report_options_precede_report_url() -> None:
    """`man aide.conf`: report options "have to be set before report_url"."""
    keys = [m.group("key") for line in _lines() if (m := _OPTION_RE.match(line))]
    url_at = keys.index("report_url")
    for option in ("report_level", "report_format", "report_grouped"):
        assert keys.index(option) < url_at, f"{option} must come before report_url"


def test_report_shape_matches_what_the_parser_expects() -> None:
    """The parser is section-driven and reads the plain format."""
    options = _options()
    assert options["report_format"] == "plain"
    assert options["report_grouped"] == "yes"
    # Anything below `list_entries` prints counts without paths.
    assert options["report_level"] in ("list_entries", "changed_attributes")


def test_database_is_ours_not_the_distro_s() -> None:
    """§30.6: we own the database. The Arch `aide` package owns /var/lib/aide
    and drives it from its own aidecheck.timer -- colliding with that would
    rewrite a baseline the user did not ask us to touch."""
    options = _options()
    assert options["database_in"] == "file:/var/lib/inspectord/aide/aide.db"
    assert options["database_out"] == "file:/var/lib/inspectord/aide/aide.db.new"
    assert "/var/lib/aide" not in _AIDE_CONFIG.read_text(encoding="utf-8").replace(
        "/var/lib/aide/", "@@"
    ).replace("@@", "/var/lib/inspectord")


def test_database_in_is_literal_so_preflight_can_read_it() -> None:
    """No `@@{...}` macro in database_in, or the skip reason goes blind.

    `AideAdapter.preflight` deliberately refuses to expand AIDE's config
    variables and returns None ("undecidable") when it sees `@@`. A macro here
    would therefore turn the honest `database_missing` skip back into the exit-18
    nightly failure the adapter exists to avoid.
    """
    assert aide_adapter._database_in(str(_AIDE_CONFIG)) == "/var/lib/inspectord/aide/aide.db"


def test_config_path_matches_the_adapter_default() -> None:
    """setup.sh installs this where the adapter looks for it, with no config."""
    assert aide_adapter.DEFAULT_CONFIG_PATH == "/var/lib/inspectord/aide/aide.conf"


def test_every_group_used_is_defined() -> None:
    """AIDE 0.19 predefines only R, L, >, H, X and E.

    `NORMAL` and friends are distro conventions, not built-ins, and a rule that
    names an undefined group is a fatal config error -- so a config referencing
    one is not "mostly fine", it does not run at all.
    """

    def _group_refs(expression: str) -> list[str]:
        """The group names in an attribute expression: attributes are lowercase."""
        return [
            token
            for raw in re.split(r"[+\-]", expression)
            if (token := raw.strip()) and not token.islower()
        ]

    defined: set[str] = set()
    for line in _lines():
        match = _GROUP_DEF_RE.match(line)
        if match is None or _OPTION_RE.match(line):
            continue
        for token in _group_refs(match.group("expr")):
            assert token in defined | _BUILTIN_GROUPS, (
                f"group definition {match.group('name')} uses undefined {token!r}"
            )
        defined.add(match.group("name"))

    for line in _lines():
        if not line.startswith("/"):
            continue  # option, group definition, or a `!`/`-` exclusion
        for token in _group_refs(line.split()[-1]):
            assert token in defined | _BUILTIN_GROUPS, (
                f"rule {line!r} uses undefined group {token!r}"
            )


def test_the_usual_integrity_targets_are_covered() -> None:
    rules = {line.split()[0] for line in _lines() if line.startswith("/")}
    assert {"/usr/bin", "/usr/sbin", "/etc", "/boot"} <= rules


@requires_aide
def test_aide_config_example_parses_against_the_real_binary() -> None:
    """`--config-check` reads the config and stops. No database, no scan, no
    filesystem traversal -- so this runs the SHIPPED BYTES with zero side effects."""
    proc = subprocess.run(
        ["aide", "--config", str(_AIDE_CONFIG), "--config-check"],
        capture_output=True,
        text=True,
        timeout=120.0,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@requires_aide
def test_an_undefined_group_really_is_fatal(tmp_path: Path) -> None:
    """The control for the test above: prove `--config-check` would have caught it.

    Without this, a green config-check might only mean AIDE ignores what it does
    not understand. It does not: measured against 0.19.3, swapping one group for
    `NORMAL` fails with "group 'NORMAL' is not defined".
    """
    broken = tmp_path / "broken.conf"
    broken.write_text(
        _AIDE_CONFIG.read_text(encoding="utf-8").replace("InspectordStatic\n", "NORMAL\n"),
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["aide", "--config", str(broken), "--config-check"],
        capture_output=True,
        text=True,
        timeout=120.0,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    assert proc.returncode != 0
    assert "NORMAL" in proc.stdout + proc.stderr


@requires_aide
def test_the_shipped_config_detects_a_real_change(tmp_path: Path) -> None:
    """A full init -> tamper -> check cycle, confined to tmp_path.

    `--before` is applied ahead of the config file and AIDE keeps the FIRST value
    it sees for each of these, so the shipped rules, groups and report options
    are the ones actually exercised; only the database and the scan root move.
    `root_prefix` makes `/usr/bin` and `/etc` resolve under the scratch tree, so
    no system path is read, hashed or recorded.
    """
    root = tmp_path / "root"
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "usr" / "sbin").mkdir(parents=True)
    (root / "etc").mkdir()
    (root / "boot").mkdir()
    db = tmp_path / "db"
    db.mkdir()

    binary = root / "usr" / "bin" / "tool"
    binary.write_text("#!/bin/sh\necho hello\n", encoding="utf-8")
    (root / "etc" / "thing.conf").write_text("key = value\n", encoding="utf-8")

    before = "\n".join(
        [
            f"database_in=file:{db}/aide.db",
            f"database_out=file:{db}/aide.db.new",
            f"root_prefix={root}",
        ]
    )

    def _aide(command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["aide", "--config", str(_AIDE_CONFIG), "--before", before, command],
            capture_output=True,
            text=True,
            timeout=300.0,
            stdin=subprocess.DEVNULL,
            check=False,
        )

    init = _aide("--init")
    assert init.returncode == 0, init.stdout + init.stderr
    (db / "aide.db.new").rename(db / "aide.db")

    # Nothing changed yet: a clean check must be exit 0, i.e. ScanOutcome.clean.
    clean = _aide("--check")
    adapter = aide_adapter.AideAdapter()
    assert adapter.interpret_outcome(clean.returncode, clean.stdout, clean.stderr) is (
        ScanOutcome.clean
    ), clean.stdout

    binary.write_text("#!/bin/sh\necho hello\nrm -rf /\n", encoding="utf-8")
    (root / "etc" / "added.conf").write_text("new\n", encoding="utf-8")

    checked = _aide("--check")
    # A difference is a FINDING, never a failure -- the bug decision 10 exists for.
    assert adapter.interpret_outcome(checked.returncode, checked.stdout, checked.stderr) is (
        ScanOutcome.findings
    ), f"exit {checked.returncode}\n{checked.stdout}\n{checked.stderr}"

    findings = adapter.parse(checked.stdout, checked.stderr)
    by_path = {f.path: f.indicator_value for f in findings}
    assert by_path.get("/usr/bin/tool") == "changed", checked.stdout
    assert by_path.get("/etc/added.conf") == "added", checked.stdout

    # The directory-quieting groups do their job: adding a file to /etc must not
    # also report /etc itself as changed.
    assert "/etc" not in by_path, checked.stdout


# --------------------------------------------------------------------------
# How the file reaches /var/lib/inspectord/aide/
# --------------------------------------------------------------------------

_SETUP_SH = _REPO_ROOT / "packaging" / "scripts" / "setup.sh.in"


def test_setup_script_installs_this_config_where_the_adapter_looks() -> None:
    """Same shape as config.example.toml -> /etc/inspectord/config.toml.

    `@AIDE_CONFIG_EXAMPLE@` is a placeholder the packaging step substitutes,
    exactly like the `@PYTHON@` / `@CONFIG_EXAMPLE@` already in this script.
    """
    body = _SETUP_SH.read_text(encoding="utf-8")
    assert "@AIDE_CONFIG_EXAMPLE@" in body
    assert aide_adapter.DEFAULT_CONFIG_PATH in body


def test_setup_script_never_builds_a_baseline() -> None:
    """The one thing setup must not do on the user's behalf.

    `aide --init` certifies the disk exactly as it is at that moment, including
    anything that was already there. Same class of act as `rkhunter --propupd`
    and `freshclam`, all three forbidden by scanner-runner design decision 8 /
    the user's own judgement. Setup copies a config and stops.
    """
    body = _SETUP_SH.read_text(encoding="utf-8")
    commands = [
        line.strip()
        for line in body.split("\n")
        if line.strip()
        and not line.lstrip().startswith("#")
        and not line.strip().startswith("echo")
    ]
    joined = "\n".join(commands)
    for forbidden in ("--init", "--propupd", "--update", "freshclam"):
        assert forbidden not in joined, f"setup.sh must not run {forbidden}"
