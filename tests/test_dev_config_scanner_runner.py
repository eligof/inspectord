"""dev_config must include a scanner_runner entry -- and it must ship disabled.

This is the first worker in the project whose job takes MINUTES. It must not
start scanning on every developer run, so the dev config registers it with
every scanner disabled: the worker ticks cheaply and the operator opts in.
"""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_contains_scanner_runner(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "scanner_runner" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "scanner_runner")
    assert worker.module == "inspectord.workers.scanner_runner", worker.module


def test_dev_config_scanner_runner_ships_disabled(tmp_path: Path) -> None:
    worker = next(w for w in dev_config(base=tmp_path).workers if w.name == "scanner_runner")
    scanners = worker.config["scanners"]

    assert scanners, "the scanner_runner config must declare its scanners"
    for name, scanner in scanners.items():
        assert scanner["enabled"] is False, f"{name} must ship disabled -- scans take minutes"


def test_dev_config_scanner_runner_defers_and_spaces_out_scans(tmp_path: Path) -> None:
    worker = next(w for w in dev_config(base=tmp_path).workers if w.name == "scanner_runner")

    # Belt and braces behind `enabled: false`: even opted in, nothing runs on
    # the boot path and nothing runs more than daily.
    assert worker.config["startup_delay_s"] >= 300.0
    for scanner in worker.config["scanners"].values():
        assert scanner["interval_s"] >= 86400.0


def test_dev_config_scanner_runner_bounds_captured_output(tmp_path: Path) -> None:
    """The finding cap bounds emitted events; this bounds resident memory."""
    worker = next(w for w in dev_config(base=tmp_path).workers if w.name == "scanner_runner")

    ceiling = worker.config["max_output_bytes"]
    assert 0 < ceiling <= 32 * 1024 * 1024, ceiling
