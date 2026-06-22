"""Tests for the bounded all-states /proc/net snapshot (spec §3.4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from inspectord.evidence import netsnapshot
from inspectord.evidence.netsnapshot import network_snapshot

_HEADER = "  sl  local_address rem_address   st ...\n"


def _write(d: Path, proto: str, rows: list[str]) -> None:
    (d / proto).write_text(_HEADER + "".join(f"  0: {r}\n" for r in rows))


def test_decodes_listen_and_established(tmp_path: Path) -> None:
    # 0100007F:0016 = 127.0.0.1:22 ; remote 00000000:0000 ; st 0A=listen / 01=established
    _write(
        tmp_path,
        "tcp",
        ["0100007F:0016 00000000:0000 0A", "0100007F:0016 0101A8C0:1F90 01"],
    )
    snap = network_snapshot(proc_net_dir=tmp_path)
    states = {s["state"] for s in snap["sockets"]}
    assert "listen" in states and "established" in states
    assert any(s["local"] == ["127.0.0.1", 22] for s in snap["sockets"])
    assert "captured_at" in snap and snap["truncated"] is False


def test_missing_proto_file_is_skipped(tmp_path: Path) -> None:
    snap = network_snapshot(proc_net_dir=tmp_path)  # empty dir
    assert snap["sockets"] == [] and snap["truncated"] is False


def test_malformed_rows_do_not_raise(tmp_path: Path) -> None:
    _write(tmp_path, "tcp", ["garbage", "0100007F:0016 00000000:0000 0A"])
    snap = network_snapshot(proc_net_dir=tmp_path)
    assert len(snap["sockets"]) == 1
    assert snap["sockets"][0]["state"] == "listen"


def test_bounded_sets_truncated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netsnapshot, "_MAX_ROWS", 2)
    _write(
        tmp_path,
        "tcp",
        ["0100007F:0016 00000000:0000 0A"] * 5,
    )
    snap = network_snapshot(proc_net_dir=tmp_path)
    assert snap["truncated"] is True
    assert len(snap["sockets"]) == 2
