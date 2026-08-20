"""Smoke test: the eBPF streams load their programs when run as root."""

from __future__ import annotations

import ctypes
import os
import socket
import subprocess
import time
import uuid

import pytest
from inspectord._native import (
    ProcessConnectStream6,
    ProcessExecStream,
    ProcessModuleLoadStream,
    ProcessPtraceStream,
    ProcessRawSocketStream,
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
        # Exactly one record per syscall. The loader registers a prog-less perf
        # event on every online CPU to un-gate the faultable tracepoint handler
        # (see enable_tracepoint_on_all_cpus); if those events ever ended up
        # carrying the BPF program too, each call would fan out into one record
        # per CPU. This is the assertion that would catch that.
        assert len(finits) == 1, f"expected exactly one finit_module record, got {finits}"
        assert len(inits) == 1, f"expected exactly one init_module record, got {inits}"
        assert finits[0]["fd"] == -1
        assert inits[0]["fd"] == -1  # init_module has no fd
        assert finits[0]["uid"] == 0
    finally:
        os.sched_setaffinity(0, original_affinity)
        stream.close()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_process_raw_socket_stream_loads_and_closes() -> None:
    """The socket_syscall program passes the verifier and attaches."""
    stream = ProcessRawSocketStream()
    try:
        assert stream is not None
    finally:
        stream.close()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_raw_socket_stream_captures_af_packet_but_filters_the_rest() -> None:
    """AF_PACKET is captured; a plain TCP socket and an AF_NETLINK SOCK_RAW
    socket are dropped by the in-BPF family scope.

    The AF_NETLINK case is the whole point of the family scope: netlink sockets
    are conventionally SOCK_RAW, need no CAP_NET_RAW, and are opened constantly
    by ordinary desktop software (iproute2, sd-netlink, NetworkManager), so a
    type-only filter would flood the stream.

    The two sockets that must be filtered out are created first and the
    AF_PACKET one last, so that once its record arrives the other two syscalls
    have provably already run — making their absence an assertion, not a race.

    No CPU pinning here (unlike test_module_load_stream_captures_both_syscall_variants):
    sys_enter_socket takes three scalar ints and copies nothing from userspace,
    so it is not one of the faultable tracepoints whose kernel handler is gated
    on a per-CPU perf event.
    """
    af_netlink = 16  # socket.AF_NETLINK, spelled out to keep the filter explicit
    netlink_route = 0

    stream = ProcessRawSocketStream()
    tcp_sock = None
    netlink_sock = None
    packet_sock = None
    try:
        time.sleep(0.2)
        stream.poll(200)  # drain anything unrelated

        # Must NOT be captured: an ordinary TCP socket is not raw.
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        # Must NOT be captured: netlink is SOCK_RAW by convention.
        netlink_sock = socket.socket(af_netlink, socket.SOCK_RAW, netlink_route)
        # Must be captured: the packet-sniffer socket.
        packet_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)

        records: list[dict] = []
        for _ in range(10):
            records.extend(stream.poll(200))
            if any(r["pid"] == os.getpid() and r["family_name"] == "AF_PACKET" for r in records):
                break

        mine = [r for r in records if r["pid"] == os.getpid()]
        packets = [r for r in mine if r["family_name"] == "AF_PACKET"]
        assert packets, f"no AF_PACKET record captured; got {records}"
        assert packets[0]["comm"], f"record carries no comm: {packets[0]}"
        assert packets[0]["uid"] == 0
        # The base type is SOCK_RAW once the 0xf mask strips the flag bits —
        # the same mask the BPF filter applies. The record stores the type
        # *unmasked*, though, so the flags survive as evidence: CPython opens
        # every socket with SOCK_CLOEXEC, which is exactly what makes the
        # masked-vs-stored distinction observable here.
        assert packets[0]["type"] & 0xF == socket.SOCK_RAW, packets[0]
        assert packets[0]["type"] & socket.SOCK_CLOEXEC, (
            f"flag bits were masked out of the stored type: {packets[0]}"
        )

        # The reason the filter is family-scoped at all.
        assert not [r for r in mine if r["family"] == af_netlink], (
            f"AF_NETLINK SOCK_RAW leaked past the family scope: {mine}"
        )
        # A plain AF_INET SOCK_STREAM socket is not raw and must not appear.
        assert not [r for r in mine if r["family_name"] == "AF_INET"], (
            f"non-raw AF_INET socket leaked past the type check: {mine}"
        )
    finally:
        for sock in (tcp_sock, netlink_sock, packet_sock):
            if sock is not None:
                sock.close()
        stream.close()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_exec_stream_captures_full_argv_not_just_argv0() -> None:
    """The exec program captures the whole argv range, not just argv[0].

    process_exec copies `mm->arg_start .. mm->arg_end` with a runtime-computed
    length via the raw `bpf_probe_read_user` helper, precisely because the safe
    `bpf_probe_read_user_str_bytes` wrapper stops at the first NUL — which would
    yield argv[0] alone. That is useless for LOLBin detection, where the
    suspicious string lives in a later argument of an outer `sh -c '...'`.

    This test pins that behaviour: it execs `sh -c 'echo <needle>'` and asserts
    the captured cmdline contains the needle, which lives in argv[2]. If the
    capture ever degrades to first-NUL semantics, only `/bin/sh` survives and
    this fails.
    """
    needle = f"needle-in-argv-{uuid.uuid4().hex}"

    stream = ProcessExecStream()
    try:
        time.sleep(0.2)
        stream.poll(200)  # drain anything unrelated

        subprocess.run(
            ["/bin/sh", "-c", f"echo {needle}"],
            check=True,
            capture_output=True,
        )

        records: list[dict] = []
        for _ in range(10):
            records.extend(stream.poll(200))
            if any(needle in r["cmdline"] for r in records):
                break

        matches = [r for r in records if needle in r["cmdline"]]
        assert matches, (
            f"no exec record carried {needle!r}; the argv capture is truncated to "
            f"argv[0]. Records seen: {[r['cmdline'] for r in records]}"
        )
        cmdline = matches[0]["cmdline"]
        # argv[0] is still first, so this is a superset of the old behaviour...
        assert cmdline.split()[0] == "/bin/sh", f"unexpected argv[0] in {cmdline!r}"
        # ...and argv[1] / argv[2] are present, i.e. we read past the first NUL.
        assert cmdline.split()[1] == "-c", f"argv[1] missing from {cmdline!r}"
        assert cmdline.endswith(needle), f"argv[2] truncated in {cmdline!r}"
        assert matches[0]["ppid"] == os.getpid(), f"wrong ppid on {matches[0]}"
    finally:
        stream.close()
