"""RetentionConfig defaults, validators, and wiring (retention spec §3)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from inspectord.config import DaemonConfig, RetentionConfig, dev_config, load


def test_retention_config_defaults() -> None:
    cfg = RetentionConfig()
    assert cfg.enabled is True
    assert cfg.events_days == 30
    assert cfg.events_max_rows_per_run == 100_000
    assert cfg.journal_days == 30
    assert cfg.journal_quota_mb == 500
    assert cfg.journal_quota_floor_days == 7
    assert cfg.alerts_days == 365
    assert cfg.evidence_days == 365


@pytest.mark.parametrize(
    "field,value",
    [
        ("events_days", 0),
        ("journal_days", 0),
        ("journal_quota_floor_days", 0),
        ("alerts_days", 0),
        ("evidence_days", 0),
        ("journal_quota_mb", 5),
        ("events_max_rows_per_run", 100),
    ],
)
def test_retention_config_rejects_out_of_range(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        RetentionConfig.model_validate({field: value})


def test_retention_config_rejects_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        RetentionConfig.model_validate({"no_such_knob": 1})


def test_daemon_config_defaults_retention_section(tmp_path: Path) -> None:
    # A config with no [retention] section still validates and is enabled.
    cfg = DaemonConfig.model_validate(
        {
            "version": "1.0.0",
            "storage": {
                "db_path": str(tmp_path / "d.duckdb"),
                "journal_dir": str(tmp_path / "j"),
            },
            "ipc": {"socket_path": str(tmp_path / "s.sock")},
        }
    )
    assert cfg.retention.enabled is True
    assert cfg.retention.events_days == 30


def test_toml_round_trip_sets_retention_fields(tmp_path: Path) -> None:
    toml_path = tmp_path / "inspectord.toml"
    toml_path.write_text(
        f"""
version = "1.0.0"

[storage]
db_path = "{tmp_path / "d.duckdb"}"
journal_dir = "{tmp_path / "j"}"

[ipc]
socket_path = "{tmp_path / "s.sock"}"

[retention]
enabled = false
events_days = 14
journal_quota_mb = 100
"""
    )
    cfg = load(toml_path)
    assert cfg.retention.enabled is False
    assert cfg.retention.events_days == 14
    assert cfg.retention.journal_quota_mb == 100
    # Unset keys keep their defaults.
    assert cfg.retention.alerts_days == 365


def test_dev_config_has_retention(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    assert cfg.retention.enabled is True
