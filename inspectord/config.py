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


class AnomalyConfig(BaseModel):
    """Anomaly detector settings (spec 2026-08-20-anomaly-detector-design.md §8)."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    tick_s: float = 60.0
    z_threshold: float = 3.0
    min_samples: int = 50
    checkpoint_interval_s: float = 300.0
    max_entities_per_metric: int = 512
    # beaconing (PR3)
    beacon_min_events: int = 12
    beacon_min_interval_s: float = 5.0
    beacon_max_interval_s: float = 3600.0
    beacon_max_cv: float = 0.1
    # entity/resource baselines (PR4)
    resource_tick_s: float = 30.0
    sustained_factor: float = 5.0
    sustained_ticks: int = 6


class RetentionConfig(BaseModel):
    """Retention & rotation settings (spec 2026-08-26-retention-design.md §3)."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    events_days: int = Field(default=30, ge=1)
    events_max_rows_per_run: int = Field(default=100_000, ge=1000)
    journal_days: int = Field(default=30, ge=1)
    # MiB — quota backstop on the journal dir (quota_bytes = journal_quota_mb * 2**20).
    journal_quota_mb: int = Field(default=500, ge=10)
    journal_quota_floor_days: int = Field(default=7, ge=1)
    alerts_days: int = Field(default=365, ge=1)
    evidence_days: int = Field(default=365, ge=1)


class DaemonConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    storage: StorageConfig
    ipc: IpcConfig
    workers: list[WorkerSpec] = Field(default_factory=list)
    notifier_desktop_enabled: bool = False
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)


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
                    "name": "vuln_scanner",
                    "module": "inspectord.workers.vuln_scanner",
                    # No `enabled` key anywhere: WorkerSpec has none, and
                    # inclusion in this list IS enablement (vuln design §9).
                    "config": {
                        # User-maintained local copy of the Arch advisory JSON
                        # (their own cron refreshes it; zero egress from us).
                        "advisory_path": "/var/lib/inspectord/advisories.json",
                        # Full rescan cadence; file/pacman-db changes trigger
                        # earlier rescans, so daily is a backstop, not a lag.
                        "interval_s": 86400.0,
                        # The worker's own tick -- cheap; stat + trigger checks.
                        "poll_s": 60.0,
                        # Panel styles the advisory-age line as a warning past
                        # this (a silently dead refresh cron gets a face, §6).
                        "advisory_stale_after_s": 14 * 86400.0,
                    },
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
                        # Every scanner ships ENABLED -- a scanner nobody turns
                        # on detects nothing -- and each one that is not set up
                        # yet SKIPS with a reason rather than failing. Neither
                        # the daemon nor this config ever creates a baseline:
                        # `aide --init`, `rkhunter --propupd` and installing
                        # YARA rulesets are all the user's decision (design
                        # decision 8), so "enabled" means "run it once it is
                        # ready", never "set it up for me".
                        #
                        # What that costs on a stock host, measured 2026-08-19:
                        #   aide     -> scan_skipped "config_missing" daily; no
                        #               config ships yet. Nothing runs, nothing
                        #               fails.
                        #   yara     -> scan_skipped "rules_missing" daily;
                        #               /var/lib/inspectord/yara does not exist.
                        #   rkhunter -> actually RUNS, and a healthy Arch box
                        #               yields five warnings per scan (the
                        #               egrep/fgrep/ldd wrapper warnings, the
                        #               missing rkhunter.dat baseline and the
                        #               --propupd notice). Those become five
                        #               SEPARATE `medium` alerts per night under
                        #               av.rkhunter_warning_or_worse -- measured
                        #               end to end, not inferred. They do not
                        #               collapse: the dedup key is per finding
                        #               (file path, or the event id when the
                        #               warning names no path, which can never
                        #               dedup at all) and its window is 600s
                        #               against an 86400s interval. That rule's
                        #               `why` and false_positives spell it out;
                        #               `rkhunter --propupd`, run by the user on
                        #               a machine they believe is clean, retires
                        #               two of the five.
                        "scanners": {
                            "aide": {
                                "enabled": True,
                                "interval_s": 86400.0,
                                "timeout_s": 3600.0,
                            },
                            "rkhunter": {
                                "enabled": True,
                                "interval_s": 86400.0,
                                "timeout_s": 1800.0,
                            },
                            "yara": {
                                "enabled": True,
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
