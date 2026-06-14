"""dev_config must include a listening_socket_snapshotter worker entry."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_contains_listening_socket_snapshotter(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "listening_socket_snapshotter" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "listening_socket_snapshotter")
    assert worker.module == "inspectord.workers.listening_socket_snapshotter", worker.module
