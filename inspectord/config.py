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
    evidence_dir: Path = Path("/var/lib/inspectord/evidence")


class IpcConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    socket_path: Path
    allowed_uids: list[int] = Field(default_factory=list)
    socket_group: str | None = None


class DaemonConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    storage: StorageConfig
    ipc: IpcConfig
    workers: list[WorkerSpec] = Field(default_factory=list)
    notifier_desktop_enabled: bool = False


def load(path: Path) -> DaemonConfig:
    path = Path(path)
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
                "evidence_dir": str(base / "var" / "evidence"),
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
                {
                    "name": "log_tailer",
                    "module": "inspectord.workers.log_tailer",
                    "config": {
                        "pacman_log_path": "/var/log/pacman.log",
                        "auth_log_path": "/var/log/auth.log",
                    },
                },
                {
                    "name": "fim_watcher",
                    "module": "inspectord.workers.fim_watcher",
                    "config": {},
                },
                {
                    "name": "process_collector",
                    "module": "inspectord.workers.process_collector",
                    "config": {},
                },
                {
                    "name": "process_collector_exit",
                    "module": "inspectord.workers.process_collector_exit",
                    "config": {},
                },
                {
                    "name": "process_collector_ptrace",
                    "module": "inspectord.workers.process_collector_ptrace",
                    "config": {},
                },
                {
                    "name": "process_collector_module_load",
                    "module": "inspectord.workers.process_collector_module_load",
                    "config": {},
                },
                {
                    "name": "process_collector_raw_socket",
                    "module": "inspectord.workers.process_collector_raw_socket",
                    "config": {},
                },
                {
                    "name": "outbound_connection_tracker",
                    "module": "inspectord.workers.outbound_connection_tracker",
                    "config": {},
                },
                {
                    "name": "outbound_connection_tracker6",
                    "module": "inspectord.workers.outbound_connection_tracker6",
                    "config": {},
                },
                {
                    "name": "kmod_watcher",
                    "module": "inspectord.workers.kmod_watcher",
                    "config": {},
                },
                {
                    "name": "listening_socket_snapshotter",
                    "module": "inspectord.workers.listening_socket_snapshotter",
                    "config": {},
                },
                {
                    "name": "firewall_inspector",
                    "module": "inspectord.workers.firewall_inspector",
                    "config": {},
                },
                {
                    "name": "services_monitor",
                    "module": "inspectord.workers.services_monitor",
                    "config": {},
                },
                {
                    "name": "udev_monitor",
                    "module": "inspectord.workers.udev_monitor",
                    "config": {},
                },
                {
                    "name": "persistence_snapshotter",
                    "module": "inspectord.workers.persistence_snapshotter",
                    "config": {},
                },
                {
                    "name": "scanner_runner",
                    "module": "inspectord.workers.scanner_runner",
                    "config": {
                        # The worker's own tick -- cheap; it only checks what is due.
                        "interval_s": 60.0,
                        "startup_delay_s": 300.0,
                        "max_findings_per_run": 500,
                        # Bounds the MEMORY of a run, as the finding cap bounds
                        # its events: a first AIDE check can print a huge diff.
                        "max_output_bytes": 8 * 1024 * 1024,
                        # Every scanner ships DISABLED: a scan takes minutes, so
                        # this is opt-in per host, never on by default.
                        "scanners": {
                            "aide": {
                                "enabled": False,
                                "interval_s": 86400.0,
                                "timeout_s": 3600.0,
                            },
                            "rkhunter": {
                                "enabled": False,
                                "interval_s": 86400.0,
                                "timeout_s": 1800.0,
                            },
                            "yara": {
                                "enabled": False,
                                "interval_s": 86400.0,
                                "timeout_s": 1800.0,
                                # We ship the rulesets (§30.6). With none
                                # installed the scanner skips with a reason
                                # instead of failing.
                                "rules_dir": "/var/lib/inspectord/yara",
                                # ONE path: yara takes exactly one target, so
                                # point this at a common ancestor rather than
                                # expecting a list.
                                "target": "/home",
                            },
                        },
                    },
                },
            ],
        }
    )
