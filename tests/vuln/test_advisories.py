"""Tests for the Arch advisory-file parser (vuln-scanner design §3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from inspectord.vuln.advisories import (
    MAX_ADVISORIES,
    MAX_FILE_BYTES,
    MAX_ITEMS_PER_AVG,
    MAX_STRING_LEN,
    AdvisoryLoadError,
    load_advisories,
    parse_advisories,
)


def _avg(avg_id: str = "AVG-1", **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": avg_id,
        "packages": ["openssl"],
        "status": "Fixed",
        "severity": "Critical",
        "affected": "3.3.1-1",
        "fixed": "3.3.2-1",
        "issues": ["CVE-2026-1234"],
    }
    entry.update(overrides)
    return entry


def _dump(entries: list[dict[str, Any]]) -> bytes:
    return json.dumps(entries).encode()


# -- happy path --------------------------------------------------------------


def test_parses_valid_advisories() -> None:
    parsed = parse_advisories(
        _dump([_avg("AVG-1"), _avg("AVG-2", packages=["bash", "zsh"], issues=["CVE-1", "CVE-2"])])
    )
    assert parsed.warnings == 0
    assert parsed.skipped_avg_ids == ()
    assert len(parsed.advisories) == 2
    first, second = parsed.advisories
    assert first.avg_id == "AVG-1"
    assert first.packages == ("openssl",)
    assert first.status == "Fixed"
    assert first.severity == "Critical"
    assert first.fixed == "3.3.2-1"
    assert first.issues == ("CVE-2026-1234",)
    assert second.packages == ("bash", "zsh")
    assert second.issues == ("CVE-1", "CVE-2")


def test_null_fixed_and_affected_are_allowed() -> None:
    parsed = parse_advisories(_dump([_avg(fixed=None, affected=None, status="Vulnerable")]))
    assert parsed.advisories[0].fixed is None
    assert parsed.advisories[0].affected is None


# -- whole-file failures -----------------------------------------------------


def test_invalid_json_is_parse_failed() -> None:
    with pytest.raises(AdvisoryLoadError) as exc:
        parse_advisories(b"{not json")
    assert exc.value.reason == "parse_failed"


def test_non_array_is_parse_failed() -> None:
    with pytest.raises(AdvisoryLoadError) as exc:
        parse_advisories(b'{"name": "AVG-1"}')
    assert exc.value.reason == "parse_failed"


def test_empty_array_is_advisories_empty() -> None:
    # An empty Arch advisory DB is never legitimate; treating it as data would
    # mass-resolve every open vulnerability row (design §3).
    with pytest.raises(AdvisoryLoadError) as exc:
        parse_advisories(b"[]")
    assert exc.value.reason == "advisories_empty"


def test_too_many_advisories_is_parse_failed() -> None:
    entries = [{"name": f"AVG-{i}"} for i in range(MAX_ADVISORIES + 1)]
    with pytest.raises(AdvisoryLoadError) as exc:
        parse_advisories(_dump(entries))
    assert exc.value.reason == "parse_failed"


# -- per-AVG skips -----------------------------------------------------------


def test_malformed_avg_is_skipped_and_recorded_others_kept() -> None:
    parsed = parse_advisories(_dump([_avg("AVG-1"), _avg("AVG-2", packages="openssl")]))
    assert [a.avg_id for a in parsed.advisories] == ["AVG-1"]
    assert parsed.skipped_avg_ids == ("AVG-2",)
    assert parsed.warnings == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"packages": []},
        {"packages": ["ok", 7]},
        {"issues": []},
        {"issues": "CVE-1"},
        {"status": None},
        {"severity": 3},
        {"fixed": 42},
        {"affected": ["1.0"]},
    ],
)
def test_field_violations_skip_the_avg(overrides: dict[str, Any]) -> None:
    parsed = parse_advisories(_dump([_avg("AVG-9", **overrides), _avg("AVG-1")]))
    assert parsed.skipped_avg_ids == ("AVG-9",)
    assert [a.avg_id for a in parsed.advisories] == ["AVG-1"]


def test_per_avg_item_caps_skip_the_avg() -> None:
    over = [f"pkg{i}" for i in range(MAX_ITEMS_PER_AVG + 1)]
    parsed = parse_advisories(
        _dump([_avg("AVG-1", packages=over), _avg("AVG-2", issues=over), _avg("AVG-3")])
    )
    assert parsed.skipped_avg_ids == ("AVG-1", "AVG-2")
    assert [a.avg_id for a in parsed.advisories] == ["AVG-3"]
    assert parsed.warnings == 2


def test_invalid_avg_id_is_a_warning_but_not_recorded() -> None:
    # An id that never validated can never have produced a row, so there is
    # nothing for the sweep to protect — it is counted, not recorded.
    parsed = parse_advisories(
        _dump([_avg("AVG-x"), _avg("totally-wrong"), {"name": 5}, _avg("AVG-2")])
    )
    assert parsed.skipped_avg_ids == ()
    assert parsed.warnings == 3
    assert [a.avg_id for a in parsed.advisories] == ["AVG-2"]


def test_non_dict_entry_is_a_warning() -> None:
    data = json.dumps([["not", "a", "dict"], _avg("AVG-1")]).encode()
    parsed = parse_advisories(data)
    assert parsed.warnings == 1
    assert [a.avg_id for a in parsed.advisories] == ["AVG-1"]


# -- string hygiene ----------------------------------------------------------


def test_control_characters_are_stripped() -> None:
    parsed = parse_advisories(_dump([_avg(severity="Cri\x00tical\x1b", status="Fix\x7fed")]))
    assert parsed.advisories[0].severity == "Critical"
    assert parsed.advisories[0].status == "Fixed"


def test_strings_are_length_capped() -> None:
    parsed = parse_advisories(_dump([_avg(fixed="9" * (MAX_STRING_LEN * 2))]))
    fixed = parsed.advisories[0].fixed
    assert fixed is not None
    assert len(fixed) == MAX_STRING_LEN


def test_avg_id_with_control_chars_does_not_validate() -> None:
    parsed = parse_advisories(_dump([_avg("AVG-\x001")]))
    # After the strip the id is "AVG-1"; the pre-strip form must not sneak by.
    assert [a.avg_id for a in parsed.advisories] == ["AVG-1"]


# -- file loading ------------------------------------------------------------


def test_load_missing_file_is_advisories_missing(tmp_path: Path) -> None:
    with pytest.raises(AdvisoryLoadError) as exc:
        load_advisories(tmp_path / "advisories.json")
    assert exc.value.reason == "advisories_missing"


def test_load_oversize_file_is_rejected_before_read(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_bytes(_dump([_avg()]))
    with pytest.raises(AdvisoryLoadError) as exc:
        load_advisories(path, max_bytes=8)
    assert exc.value.reason == "file_too_large"


def test_load_read_is_bounded_even_if_stat_lied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A file that grows between stat and read (mid-`mv` flap) must still hit
    # the byte ceiling: the read itself is bounded, not just the stat.
    path = tmp_path / "advisories.json"
    path.write_bytes(_dump([_avg()]))
    real_stat = Path.stat

    class _FakeStat:
        st_size = 8

    monkeypatch.setattr(Path, "stat", lambda self, **kw: _FakeStat())
    try:
        with pytest.raises(AdvisoryLoadError) as exc:
            load_advisories(path, max_bytes=8)
    finally:
        monkeypatch.setattr(Path, "stat", real_stat)
    assert exc.value.reason == "file_too_large"


def test_load_valid_file_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_bytes(_dump([_avg("AVG-77")]))
    parsed = load_advisories(path)
    assert [a.avg_id for a in parsed.advisories] == ["AVG-77"]


def test_default_cap_is_64_mb() -> None:
    assert MAX_FILE_BYTES == 64 * 1024 * 1024
