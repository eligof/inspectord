"""Smoke test: ProcessExecStream loads the eBPF program when run as root."""

from __future__ import annotations

import os

import pytest

from inspectord._native import ProcessExecStream


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_process_exec_stream_loads_and_closes() -> None:
    stream = ProcessExecStream()
    try:
        assert stream is not None
    finally:
        stream.close()
