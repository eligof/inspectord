"""dev_config must include a firewall_inspector worker entry."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_contains_firewall_inspector(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "firewall_inspector" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "firewall_inspector")
    assert worker.module == "inspectord.workers.firewall_inspector", worker.module
