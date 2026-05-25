"""Reads real ring-buffer records produced by the tracepoint.

Runs only as root and only when invoked explicitly:

  sudo pytest -m ebpf_load tests/test_native_records.py
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest
from inspectord._native import ProcessExecStream


@pytest.mark.ebpf_load
@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF")
def test_poll_captures_subprocess_exec_with_cmdline() -> None:
    with ProcessExecStream() as stream:
        stream.poll(100)  # warm-up drain
        subprocess.run(["/usr/bin/true", "--marker-arg-xyz"], check=True)
        records: list[dict[str, object]] = []
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            records.extend(stream.poll(100))
            if any(r["comm"] == "true" and "marker-arg-xyz" in str(r["cmdline"]) for r in records):
                break
        assert any(
            r["comm"] == "true" and "marker-arg-xyz" in str(r["cmdline"]) for r in records
        ), f"did not observe true --marker-arg-xyz; records={records!r}"
