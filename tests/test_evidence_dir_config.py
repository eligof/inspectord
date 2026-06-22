"""Test that dev_config wires the evidence_dir storage path."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_evidence_dir(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    assert cfg.storage.evidence_dir == tmp_path / "var" / "evidence"
