"""Daemon config.

Phase 0 keeps the config minimal — paths and which workers to spawn. It will
expand in later phases (profiles, retention, notifier sinks, etc.).
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class WorkerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    module: str
    config: dict[str, Any] = Field(default_factory=dict)


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    db_path: Path
    journal_dir: Path


class IpcConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    socket_path: Path
    allowed_uids: list[int] = Field(default_factory=list)


class DaemonConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    storage: StorageConfig
    ipc: IpcConfig
    workers: list[WorkerSpec] = Field(default_factory=list)


def load(path: Path) -> DaemonConfig:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return DaemonConfig.model_validate(data)


def dev_config(*, base: Path) -> DaemonConfig:
    """Return a config suitable for running inspectord out of a working copy.

    Paths live under <base>/var/ so we don't need root to test the daemon.
    """
    base = Path(base)
    return DaemonConfig.model_validate(
        {
            "version": "1.0.0",
            "storage": {
                "db_path": str(base / "var" / "inspectord.duckdb"),
                "journal_dir": str(base / "var" / "journal"),
            },
            "ipc": {
                "socket_path": str(base / "var" / "inspectord.sock"),
                "allowed_uids": [],
            },
            "workers": [
                {
                    "name": "healthcheck",
                    "module": "inspectord.workers.healthcheck",
                    "config": {"interval_s": 1.0},
                },
                {
                    "name": "dependency_manager",
                    "module": "inspectord.workers.dependency_manager",
                    "config": {"interval_s": 30.0},
                },
            ],
        }
    )
