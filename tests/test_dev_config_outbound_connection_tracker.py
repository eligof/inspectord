"""dev_config must include an outbound_connection_tracker worker entry."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_contains_outbound_connection_tracker(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "outbound_connection_tracker" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "outbound_connection_tracker")
    assert worker.module == "inspectord.workers.outbound_connection_tracker", worker.module
