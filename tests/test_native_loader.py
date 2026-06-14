"""Smoke test: the eBPF streams load their programs when run as root."""

from __future__ import annotations

import os

import pytest
from inspectord._native import ProcessConnectStream6, ProcessExecStream


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_process_exec_stream_loads_and_closes() -> None:
    stream = ProcessExecStream()
    try:
        assert stream is not None
    finally:
        stream.close()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_process_connect6_stream_loads_and_closes() -> None:
    """The outbound_connection6 program passes the verifier and attaches."""
    stream = ProcessConnectStream6()
    try:
        assert stream is not None
    finally:
        stream.close()
