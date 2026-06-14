"""dev_config must include a kmod_watcher worker entry."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_contains_kmod_watcher(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "kmod_watcher" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "kmod_watcher")
    assert worker.module == "inspectord.workers.kmod_watcher", worker.module
