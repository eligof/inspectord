"""dev_config must include a process_collector worker entry."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_contains_process_collector(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "process_collector" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "process_collector")
    assert worker.module == "inspectord.workers.process_collector", worker.module
