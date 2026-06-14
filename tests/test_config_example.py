"""Tests for packaging/config.example.json.

Asserts that the example config is valid and documents the IPC hardening.
Guards against worker list drift relative to dev_config().
"""

from __future__ import annotations

from pathlib import Path

from inspectord.config import DaemonConfig, dev_config, load

# Resolve the example config relative to this test file's location in the repo.
_REPO_ROOT = Path(__file__).parent.parent
_EXAMPLE_CONFIG = _REPO_ROOT / "packaging" / "config.example.json"


def test_example_config_exists() -> None:
    assert _EXAMPLE_CONFIG.exists(), f"Missing: {_EXAMPLE_CONFIG}"


def test_example_config_is_valid_daemon_config() -> None:
    cfg = load(_EXAMPLE_CONFIG)
    assert isinstance(cfg, DaemonConfig)


def test_example_config_ipc_socket_group() -> None:
    cfg = load(_EXAMPLE_CONFIG)
    assert cfg.ipc.socket_group == "inspectord"


def test_example_config_ipc_socket_path() -> None:
    cfg = load(_EXAMPLE_CONFIG)
    assert cfg.ipc.socket_path == Path("/run/inspectord/inspectord.sock")


def test_example_config_worker_names_match_dev_config(tmp_path: Path) -> None:
    """Worker names in the example must exactly match those from dev_config()."""
    example_cfg = load(_EXAMPLE_CONFIG)
    reference_cfg = dev_config(base=tmp_path)

    example_names = {w.name for w in example_cfg.workers}
    reference_names = {w.name for w in reference_cfg.workers}

    assert example_names == reference_names, (
        f"Worker name mismatch.\n"
        f"  In example but not dev_config: {example_names - reference_names}\n"
        f"  In dev_config but not example: {reference_names - example_names}"
    )
