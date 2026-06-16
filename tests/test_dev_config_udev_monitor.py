"""dev_config must include a udev_monitor worker entry."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_contains_udev_monitor(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "udev_monitor" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "udev_monitor")
    assert worker.module == "inspectord.workers.udev_monitor", worker.module
