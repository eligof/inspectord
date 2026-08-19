"""dev_config must include a scanner_runner entry -- with every scanner ENABLED.

This is the first worker in the project whose job takes MINUTES, and it used to
ship with every scanner off. A scanner nobody turns on detects nothing, so the
default flipped: all three are enabled, and the two that are not set up on a
fresh host (AIDE has no config, YARA has no rulesets) SKIP with an explicit
reason rather than failing. Nothing here creates a baseline -- `aide --init`,
`rkhunter --propupd` and installing rulesets stay the operator's decisions.

What keeps that from being reckless is the schedule, which these tests pin:
nothing runs on the boot path and nothing runs more than daily.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from inspectord.config import dev_config
from inspectord.workers.scanner_runner.scanners import aide as aide_adapter
from inspectord.workers.scanner_runner.scanners import default_adapters


def _scanners(tmp_path: Path) -> dict[str, Any]:
    """The shipped per-scanner config, exactly as dev_config hands it to the worker."""
    worker = next(w for w in dev_config(base=tmp_path).workers if w.name == "scanner_runner")
    scanners: dict[str, Any] = worker.config["scanners"]
    return scanners


def test_dev_config_contains_scanner_runner(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "scanner_runner" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "scanner_runner")
    assert worker.module == "inspectord.workers.scanner_runner", worker.module


def test_dev_config_scanner_runner_ships_every_scanner_enabled(tmp_path: Path) -> None:
    """A scanner nobody turns on detects nothing.

    The safety here is not the `enabled` flag -- it is that an unconfigured
    scanner skips with a reason (`config_missing`, `rules_missing`) instead of
    scanning or failing, and that the schedule below keeps every run off the
    boot path and down to once a day.
    """
    worker = next(w for w in dev_config(base=tmp_path).workers if w.name == "scanner_runner")
    scanners = worker.config["scanners"]

    assert scanners, "the scanner_runner config must declare its scanners"
    for name, scanner in scanners.items():
        assert scanner["enabled"] is True, f"{name} must ship enabled"


def test_dev_config_scanners_that_are_not_set_up_skip_rather_than_fail(tmp_path: Path) -> None:
    """The precondition for enabling by default, checked against the real adapters.

    Both defaults point under /var/lib/inspectord, which nothing in this repo
    creates, so on an un-set-up host `preflight` must turn each into an explicit
    `scan_skipped` reason. If either returned None there, the enabled-by-default
    scanner would report a `failure` every night on a host that is merely new.

    Conditioned on the paths actually being absent so the test states a fact
    about the *code*, not about the machine it runs on: an operator who really
    has set AIDE up must not see a red test for it.
    """
    scanners = _scanners(tmp_path)
    adapters = {a.name: a for a in default_adapters()}

    if not Path(aide_adapter.DEFAULT_CONFIG_PATH).is_file():
        assert adapters["aide"].preflight(scanners["aide"]) == "config_missing"
    if not Path(scanners["yara"]["rules_dir"]).is_dir():
        assert adapters["yara"].preflight(scanners["yara"]) == "rules_missing"


def test_dev_config_scanner_runner_defers_and_spaces_out_scans(tmp_path: Path) -> None:
    worker = next(w for w in dev_config(base=tmp_path).workers if w.name == "scanner_runner")

    # This is what makes enabled-by-default defensible: nothing runs on the
    # boot path and nothing runs more than daily.
    assert worker.config["startup_delay_s"] >= 300.0
    for scanner in worker.config["scanners"].values():
        assert scanner["interval_s"] >= 86400.0


def test_dev_config_scanner_runner_bounds_captured_output(tmp_path: Path) -> None:
    """The finding cap bounds emitted events; this bounds resident memory."""
    worker = next(w for w in dev_config(base=tmp_path).workers if w.name == "scanner_runner")

    ceiling = worker.config["max_output_bytes"]
    assert 0 < ceiling <= 32 * 1024 * 1024, ceiling


def test_dev_config_declares_every_known_scanner(tmp_path: Path) -> None:
    """A scanner the build knows about but the config never mentions is invisible.

    It would sit at the adapter defaults (daily, one-hour timeout) with nobody
    able to see that from the shipped config, so the two lists are kept equal.
    """
    worker = next(w for w in dev_config(base=tmp_path).workers if w.name == "scanner_runner")
    assert set(worker.config["scanners"]) == {a.name for a in default_adapters()}


def test_dev_config_yara_says_where_its_rules_and_target_are(tmp_path: Path) -> None:
    """YARA is the one scanner whose config is not just a schedule: without a
    rules directory it can only skip, so the shipped config documents both."""
    worker = next(w for w in dev_config(base=tmp_path).workers if w.name == "scanner_runner")
    yara = worker.config["scanners"]["yara"]
    assert yara["rules_dir"] == "/var/lib/inspectord/yara"
    assert yara["target"] == "/home"
    # §4.4 says `targets` (a list); yara takes exactly one target, so the
    # adapter takes `target`. Pinned so the plural never sneaks back in.
    assert "targets" not in yara
