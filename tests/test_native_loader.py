"""Smoke test: the eBPF streams load their programs when run as root."""

from __future__ import annotations

import ctypes
import os
import time

import pytest
from inspectord._native import (
    ProcessConnectStream6,
    ProcessExecStream,
    ProcessPtraceStream,
)


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


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_process_ptrace_stream_loads_and_closes() -> None:
    """The ptrace_syscall program passes the verifier and attaches."""
    stream = ProcessPtraceStream()
    try:
        assert stream is not None
    finally:
        stream.close()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_ptrace_stream_captures_attach_but_not_out_of_set() -> None:
    """A real cross-process PTRACE_ATTACH is captured; a subsequent out-of-set
    request (PTRACE_PEEKTEXT) on the same child is dropped by the in-BPF filter.

    Note: the child must NOT call PTRACE_TRACEME — that would make this process
    its tracer implicitly, and the later PTRACE_ATTACH would then fail EPERM
    (already traced). The child just sleeps; the parent drives all ptrace calls.
    """
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    ptrace_peektext = 1  # out of the emitted set
    ptrace_cont = 7  # out of the emitted set (used to resume before cleanup)
    ptrace_attach = 16  # in the emitted set
    ptrace_detach = 17

    stream = ProcessPtraceStream()
    child = os.fork()
    if child == 0:  # child: just live long enough to be attached to
        time.sleep(5)
        os._exit(0)
    try:
        time.sleep(0.2)
        stream.poll(200)  # drain anything unrelated produced so far

        # Cross-process, in-set -> must be captured.
        rc = libc.ptrace(ptrace_attach, child, 0, 0)
        assert rc == 0, f"PTRACE_ATTACH failed: errno {ctypes.get_errno()}"
        os.waitpid(child, 0)  # wait for the attach-stop

        # Cross-process but OUT of set -> must be dropped. The syscall enters
        # (and thus fires the tracepoint) regardless of success, so a null addr
        # is fine — we only need sys_enter_ptrace to run with request=1.
        libc.ptrace(ptrace_peektext, child, 0, 0)

        records: list[dict] = []
        for _ in range(10):
            records.extend(stream.poll(200))
            if any(r["request_name"] == "PTRACE_ATTACH" for r in records):
                break

        attach_records = [r for r in records if r["request_name"] == "PTRACE_ATTACH"]
        assert attach_records, f"no PTRACE_ATTACH record captured; got {records}"
        assert attach_records[0]["target_pid"] == child
        # The out-of-set PEEKTEXT (request 1) must never appear.
        assert all(r["request"] != ptrace_peektext for r in records), records
    finally:
        # Resume + detach + reap; ignore errors if the child is already gone.
        try:
            libc.ptrace(ptrace_cont, child, 0, 0)
            libc.ptrace(ptrace_detach, child, 0, 0)
            os.kill(child, 9)
            os.waitpid(child, 0)
        except (ProcessLookupError, ChildProcessError):
            pass
        stream.close()
