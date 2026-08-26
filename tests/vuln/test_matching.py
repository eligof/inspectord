"""Tests for installed-set parsing, vercmp wrapping, and advisory matching (§4)."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any

import pytest

from inspectord.vuln.advisories import Advisory
from inspectord.vuln.matching import (
    VercmpUnavailableError,
    match_advisories,
    parse_installed,
    vercmp,
)

# -- installed-set parsing ---------------------------------------------------


def test_parse_installed_reads_pacman_q_lines() -> None:
    installed, bad = parse_installed("bash 5.2.026-1\nopenssl 3.3.1-1\n")
    assert installed == {"bash": "5.2.026-1", "openssl": "3.3.1-1"}
    assert bad == 0


def test_parse_installed_counts_unparseable_lines() -> None:
    installed, bad = parse_installed("bash 5.2.026-1\nnoversionhere\n\nx y z\n")
    assert installed == {"bash": "5.2.026-1"}
    assert bad == 2  # blank lines are not unparseable, they are absence


# -- the vercmp wrapper ------------------------------------------------------


class _FakeRun:
    """A subprocess.run stand-in returning canned vercmp results."""

    def __init__(self, results: dict[tuple[str, str], int]) -> None:
        self.results = results
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        result = self.results[(argv[1], argv[2])]
        return subprocess.CompletedProcess(argv, 0, stdout=f"{result}\n", stderr="")


def test_vercmp_runs_the_binary_and_parses_the_result() -> None:
    run = _FakeRun({("1.0-1", "1.1-1"): -1})
    cache: dict[tuple[str, str], int] = {}
    assert vercmp("1.0-1", "1.1-1", cache=cache, run=run) == -1
    assert run.calls == [["vercmp", "1.0-1", "1.1-1"]]


def test_vercmp_caches_by_pair() -> None:
    run = _FakeRun({("1.0-1", "1.1-1"): -1, ("2.0-1", "1.1-1"): 1})
    cache: dict[tuple[str, str], int] = {}
    for _ in range(3):
        vercmp("1.0-1", "1.1-1", cache=cache, run=run)
    vercmp("2.0-1", "1.1-1", cache=cache, run=run)
    assert len(run.calls) == 2
    assert cache == {("1.0-1", "1.1-1"): -1, ("2.0-1", "1.1-1"): 1}


def test_vercmp_missing_binary_raises() -> None:
    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("vercmp")

    with pytest.raises(VercmpUnavailableError):
        vercmp("1", "2", cache={}, run=run)


def test_vercmp_garbage_output_raises() -> None:
    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, stdout="not-a-number\n", stderr="")

    with pytest.raises(VercmpUnavailableError):
        vercmp("1", "2", cache={}, run=run)


requires_vercmp = pytest.mark.skipif(
    shutil.which("vercmp") is None, reason="needs the vercmp binary (pacman)"
)


@requires_vercmp
def test_vercmp_live_epoch_and_missing_pkgrel() -> None:
    cache: dict[tuple[str, str], int] = {}
    # Epoch dominates: 1:1.0-1 is NEWER than 2.0-1 despite the smaller version.
    assert vercmp("1:1.0-1", "2.0-1", cache=cache) > 0
    assert vercmp("2.0-1", "1:1.0-1", cache=cache) < 0
    # alpm skips the pkgrel comparison when one side has none: a feed entry
    # missing its pkgrel therefore masks rel-only fixes (design §8).
    assert vercmp("1.2.3-2", "1.2.3", cache=cache) == 0
    assert vercmp("1.2.3-1", "1.2.3-2", cache=cache) < 0


# -- matching ----------------------------------------------------------------


def _advisory(**overrides: Any) -> Advisory:
    fields: dict[str, Any] = {
        "avg_id": "AVG-1",
        "packages": ("openssl",),
        "status": "Fixed",
        "severity": "Critical",
        "fixed": "3.3.2-1",
        "affected": "3.3.1-1",
        "issues": ("CVE-2026-1234",),
    }
    fields.update(overrides)
    return Advisory(**fields)


def _fake_vercmp(a: str, b: str) -> int:
    # Orders plain "x.y.z-r" strings well enough for these tests.
    def key(v: str) -> list[int]:
        return [int(p) for p in v.replace("-", ".").split(".")]

    return (key(a) > key(b)) - (key(a) < key(b))


_INSTALLED = {"openssl": "3.3.1-1", "bash": "5.2.026-1"}


def test_not_affected_never_matches() -> None:
    result = match_advisories([_advisory(status="Not affected")], _INSTALLED, vercmp=_fake_vercmp)
    assert result.matches == []
    assert result.skipped_avg_ids == []


def test_fixed_matches_when_installed_older() -> None:
    result = match_advisories([_advisory()], _INSTALLED, vercmp=_fake_vercmp)
    assert len(result.matches) == 1
    m = result.matches[0]
    assert (m.avg_id, m.cve_id, m.package) == ("AVG-1", "CVE-2026-1234", "openssl")
    assert m.installed_version == "3.3.1-1"
    assert m.fixed_version == "3.3.2-1"
    assert m.severity == "Critical"
    assert m.status == "Fixed"
    assert m.fix_in_testing is False
    assert m.advisory_url == "https://security.archlinux.org/AVG-1"


def test_fixed_does_not_match_when_installed_up_to_date() -> None:
    result = match_advisories([_advisory(fixed="3.3.1-1")], _INSTALLED, vercmp=_fake_vercmp)
    assert result.matches == []


def test_vulnerable_with_null_fixed_matches() -> None:
    result = match_advisories(
        [_advisory(status="Vulnerable", fixed=None)], _INSTALLED, vercmp=_fake_vercmp
    )
    assert len(result.matches) == 1


def test_fixed_status_with_null_fixed_does_not_match() -> None:
    result = match_advisories(
        [_advisory(status="Fixed", fixed=None)], _INSTALLED, vercmp=_fake_vercmp
    )
    assert result.matches == []


def test_testing_match_carries_fix_in_testing() -> None:
    result = match_advisories([_advisory(status="Testing")], _INSTALLED, vercmp=_fake_vercmp)
    assert len(result.matches) == 1
    assert result.matches[0].fix_in_testing is True


def test_testing_with_null_fixed_does_not_match() -> None:
    result = match_advisories(
        [_advisory(status="Testing", fixed=None)], _INSTALLED, vercmp=_fake_vercmp
    )
    assert result.matches == []


def test_unknown_with_null_fixed_matches() -> None:
    result = match_advisories(
        [_advisory(status="Unknown", fixed=None)], _INSTALLED, vercmp=_fake_vercmp
    )
    assert len(result.matches) == 1
    assert result.matches[0].status == "Unknown"
    assert result.matches[0].fix_in_testing is False


def test_unrecognized_status_skips_the_avg() -> None:
    # No guessing, no resolution side-effects: the AVG is treated as skipped so
    # the sweep cannot resolve rows it may legitimately own (design §4).
    result = match_advisories(
        [_advisory(status="Regression?"), _advisory(avg_id="AVG-2")],
        _INSTALLED,
        vercmp=_fake_vercmp,
    )
    assert result.skipped_avg_ids == ["AVG-1"]
    assert result.warnings == 1
    assert [m.avg_id for m in result.matches] == ["AVG-2"]


def test_uninstalled_packages_never_reach_vercmp() -> None:
    calls: list[tuple[str, str]] = []

    def counting_vercmp(a: str, b: str) -> int:
        calls.append((a, b))
        return -1

    match_advisories(
        [_advisory(packages=("nothere", "alsonot"))], _INSTALLED, vercmp=counting_vercmp
    )
    assert calls == []


def test_one_match_per_avg_cve_package() -> None:
    adv = _advisory(
        packages=("openssl", "bash", "notinstalled"),
        issues=("CVE-1", "CVE-2"),
        status="Vulnerable",
        fixed=None,
    )
    result = match_advisories([adv], _INSTALLED, vercmp=_fake_vercmp)
    keys = {(m.package, m.cve_id) for m in result.matches}
    assert keys == {
        ("openssl", "CVE-1"),
        ("openssl", "CVE-2"),
        ("bash", "CVE-1"),
        ("bash", "CVE-2"),
    }
