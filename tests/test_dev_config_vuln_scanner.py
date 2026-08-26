"""dev_config must include a vuln_scanner entry (vuln-scanner design §3, §9)."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def _worker(tmp_path: Path):
    return next(w for w in dev_config(base=tmp_path).workers if w.name == "vuln_scanner")


def test_dev_config_contains_vuln_scanner(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    assert worker.module == "inspectord.workers.vuln_scanner", worker.module


def test_dev_config_vuln_scanner_has_no_enabled_key(tmp_path: Path) -> None:
    # WorkerSpec has no top-level `enabled`; inclusion is enablement (§9).
    worker = _worker(tmp_path)
    assert "enabled" not in worker.config


def test_dev_config_vuln_scanner_config_keys(tmp_path: Path) -> None:
    cfg = _worker(tmp_path).config
    assert cfg["advisory_path"] == "/var/lib/inspectord/advisories.json"
    assert cfg["interval_s"] >= 86400.0
    assert 0 < cfg["poll_s"] <= 300.0
    assert cfg["advisory_stale_after_s"] == 14 * 86400.0
