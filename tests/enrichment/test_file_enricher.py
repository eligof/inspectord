"""Tests for the file enricher."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from inspectord.enrichment.file import enrich_file
from inspectord.parsers.base import build_event


def _ev_for(path: Path) -> object:
    return build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": str(path)},
    )


def test_enrich_attaches_sha256(tmp_path: Path) -> None:
    target = tmp_path / "x"
    target.write_text("hello")
    expected = hashlib.sha256(b"hello").hexdigest()
    out = enrich_file(_ev_for(target))
    assert out.file is not None
    assert out.file["hash"]["sha256"] == expected
    assert out.file["size"] == 5


def test_enrich_marks_setuid(tmp_path: Path) -> None:
    target = tmp_path / "x"
    target.write_text("ok")
    os.chmod(target, stat.S_IRUSR | stat.S_IXUSR | stat.S_ISUID)
    out = enrich_file(_ev_for(target))
    assert out.file is not None
    assert out.file.get("setuid") is True


def test_enrich_skips_when_path_missing() -> None:
    ev = build_event(
        module="fim_watcher",
        action="x",
        category=["file"],
        type_=["change"],
        severity="info",
    )
    out = enrich_file(ev)
    assert out.file is None


def test_enrich_skips_when_file_does_not_exist(tmp_path: Path) -> None:
    out = enrich_file(_ev_for(tmp_path / "missing"))
    assert out.file == {"path": str(tmp_path / "missing")}
