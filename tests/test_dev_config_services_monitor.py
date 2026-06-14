"""dev_config must include a services_monitor worker entry."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_contains_services_monitor(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "services_monitor" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "services_monitor")
    assert worker.module == "inspectord.workers.services_monitor", worker.module
