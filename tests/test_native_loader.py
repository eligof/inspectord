"""Smoke test: the eBPF streams load their programs when run as root."""

from __future__ import annotations

import ctypes
import os
import time

import pytest
from inspectord._native import (
    ProcessConnectStream6,
    ProcessExecStream,
    ProcessModuleLoadStream,
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


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_process_module_load_stream_loads_and_closes() -> None:
    """Both module-load programs pass the verifier and attach."""
    stream = ProcessModuleLoadStream()
    try:
        assert stream is not None
    finally:
        stream.close()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_module_load_stream_captures_both_syscall_variants() -> None:
    """A failing finit_module and a failing init_module are both recorded.

    sys_enter fires before the kernel validates the fd or the image, so
    deliberately invalid arguments still produce records — no module is ever
    loaded by this test.
    """
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    sys_init_module = 175
    sys_finit_module = 313

    # Run the syscalls off CPU 0 on purpose. aya attaches a tracepoint with a
    # single perf event on CPU 0, and these two tracepoints only invoke the
    # kernel's perf handler on CPUs that have an event registered — so without
    # the loader's per-CPU events this test would only pass when the scheduler
    # happened to put us on CPU 0.
    original_affinity = os.sched_getaffinity(0)
    off_cpu0 = sorted(original_affinity)[-1]

    stream = ProcessModuleLoadStream()
    try:
        os.sched_setaffinity(0, {off_cpu0})
        time.sleep(0.2)
        stream.poll(200)  # drain anything unrelated

        # Invalid fd -> EBADF, but the tracepoint has already fired.
        libc.syscall(sys_finit_module, -1, b"", 0)
        # NULL image -> ENOEXEC, likewise after the tracepoint fired.
        libc.syscall(sys_init_module, None, 0, b"")

        records: list[dict] = []
        for _ in range(10):
            records.extend(stream.poll(200))
            names = {r["variant_name"] for r in records if r["pid"] == os.getpid()}
            if {"finit_module", "init_module"} <= names:
                break

        mine = [r for r in records if r["pid"] == os.getpid()]
        finits = [r for r in mine if r["variant_name"] == "finit_module"]
        inits = [r for r in mine if r["variant_name"] == "init_module"]
        assert finits, f"no finit_module record captured; got {records}"
        assert inits, f"no init_module record captured; got {records}"
        assert finits[0]["fd"] == -1
        assert inits[0]["fd"] == -1  # init_module has no fd
        assert finits[0]["uid"] == 0
    finally:
        os.sched_setaffinity(0, original_affinity)
        stream.close()
