"""AnomalyConfig defaults and wiring."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import AnomalyConfig, DaemonConfig, dev_config


def test_anomaly_config_defaults() -> None:
    cfg = AnomalyConfig()
    assert cfg.enabled is True
    assert cfg.tick_s == 60.0
    assert cfg.z_threshold == 3.0
    assert cfg.min_samples == 50
    assert cfg.checkpoint_interval_s == 300.0
    assert cfg.max_entities_per_metric == 512


def test_daemon_config_defaults_anomaly_section(tmp_path: Path) -> None:
    # A config with no [anomaly] section still validates and is enabled.
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
    assert cfg.anomaly.enabled is True


def test_dev_config_has_anomaly(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    assert cfg.anomaly.enabled is True
