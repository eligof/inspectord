"""Tests for the append-only hash-chained journal."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from inspectord.journal import Journal, JournalError, verify_chain


def test_journal_appends_lines(tmp_path: Path) -> None:
    j = Journal(tmp_path)
    j.append({"event_id": "1", "msg": "hi"})
    j.append({"event_id": "2", "msg": "ho"})
    j.flush()
    j.close()

    files = sorted(tmp_path.glob("*.jsonl.gz"))
    assert len(files) == 1
    with gzip.open(files[0], "rt") as f:
        lines = [json.loads(line) for line in f]
    assert len(lines) == 2
    assert lines[0]["event_id"] == "1"
    assert lines[1]["event_id"] == "2"


def test_journal_includes_prev_hash(tmp_path: Path) -> None:
    j = Journal(tmp_path)
    j.append({"event_id": "1"})
    j.append({"event_id": "2"})
    j.close()
    files = sorted(tmp_path.glob("*.jsonl.gz"))
    with gzip.open(files[0], "rt") as f:
        lines = [json.loads(line) for line in f]
    assert lines[0]["prev_hash"] == "0" * 64
    assert lines[1]["prev_hash"] != "0" * 64
    assert len(lines[1]["prev_hash"]) == 64  # sha256 hex


def test_verify_chain_accepts_valid(tmp_path: Path) -> None:
    j = Journal(tmp_path)
    for i in range(5):
        j.append({"event_id": str(i)})
    j.close()
    files = sorted(tmp_path.glob("*.jsonl.gz"))
    assert verify_chain(files[0]) is True


def test_verify_chain_detects_tamper(tmp_path: Path) -> None:
    j = Journal(tmp_path)
    j.append({"event_id": "1"})
    j.append({"event_id": "2"})
    j.close()
    files = sorted(tmp_path.glob("*.jsonl.gz"))

    with gzip.open(files[0], "rt") as f:
        records = [json.loads(line) for line in f]
    records[1]["event_id"] = "tampered"
    with gzip.open(files[0], "wt") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    assert verify_chain(files[0]) is False


def test_append_after_close_raises(tmp_path: Path) -> None:
    j = Journal(tmp_path)
    j.close()
    with pytest.raises(JournalError):
        j.append({"event_id": "1"})
