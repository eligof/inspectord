"""Tests for the allowlist file loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.allowlist.file_loader import (
    AllowlistFileError,
    load_allowlist_file,
    load_allowlist_from_path,
)


def test_loads_valid_yaml(tmp_path: Path) -> None:
    f = tmp_path / "allowlist.yaml"
    f.write_text(
        """
entries:
  - id: "01900000-0000-7000-8000-000000000000"
    schema_version: "1.0.0"
    scope:
      rule_id: lolbin.bash_dev_tcp
    reason: "Pentest tools I run on this box."
    created_by: eli@local
    created_at: "2026-05-24T14:23:10+00:00"
    auto_origin: false
    stats:
      suppressed_count: 0
      last_suppressed_at: null
""".lstrip()
    )
    entries = load_allowlist_from_path(f)
    assert len(entries) == 1
    assert entries[0].scope.rule_id == "lolbin.bash_dev_tcp"


def test_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert load_allowlist_from_path(tmp_path / "absent.yaml") == []


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text(": : :")
    with pytest.raises(AllowlistFileError):
        load_allowlist_from_path(f)


def test_load_allowlist_file_uses_default_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "inspectord.allowlist.file_loader._DEFAULT_PATH",
        tmp_path / "allowlist.yaml",
    )
    (tmp_path / "allowlist.yaml").write_text("entries: []\n")
    assert load_allowlist_file() == []
