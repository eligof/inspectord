"""Root-only end-to-end test: real module-load syscalls become Events.

The other module-load tests stop at a boundary — `tests/test_native_loader.py`
proves both tracepoints reach the ring buffer at the stream level, and
`tests/workers/test_process_collector_module_load_worker.py` proves the
translation works against a fake stream. Neither exercises the whole path, so
this test drives the real `ProcessModuleLoadStream` through the real worker and
asserts on the NDJSON the worker writes.

Both syscalls are invoked with deliberately invalid arguments. `sys_enter`
fires before the kernel validates the fd or the module image, so the
tracepoints record the attempt and **no module is ever loaded**.

Run with:
  sudo .venv/bin/python -m pytest -m ebpf_load \
    tests/workers/test_process_collector_module_load_live.py
"""

from __future__ import annotations

import ctypes
import json
import os
import time
from io import BytesIO
from typing import Any

import pytest

from inspectord.workers.process_collector_module_load.__main__ import (
    ProcessCollectorModuleLoadWorker,
)

SYS_INIT_MODULE = 175
SYS_FINIT_MODULE = 313


def _events_since(sink: BytesIO, offset: int) -> list[dict[str, Any]]:
    """Parse the NDJSON the worker appended past `offset`."""
    sink.seek(offset)
    return [json.loads(line) for line in sink.read().splitlines() if line]


@pytest.mark.ebpf_load
@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_both_module_load_syscalls_are_emitted_as_events() -> None:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    sink = BytesIO()
    worker = ProcessCollectorModuleLoadWorker(sink=sink, host_name="test-host")
    worker.start()

    # Run the syscalls off CPU 0 on purpose, for the same reason
    # tests/test_native_loader.py::test_module_load_stream_captures_both_syscall_variants
    # does: aya attaches a tracepoint with a single perf event on CPU 0, and
    # these two tracepoints only invoke the kernel's perf handler on CPUs that
    # have an event registered. The loader registers prog-less per-CPU events
    # to un-gate them; running off CPU 0 is what proves that path works rather
    # than passing only when the scheduler happens to land us on CPU 0.
    original_affinity = os.sched_getaffinity(0)
    off_cpu0 = sorted(original_affinity)[-1]

    try:
        os.sched_setaffinity(0, {off_cpu0})
        time.sleep(0.2)
        worker.step(poll_timeout_ms=200)  # drain unrelated traffic
        baseline = sink.tell()  # only look at what the syscalls below produce

        # Invalid fd -> EBADF, but the tracepoint has already fired.
        libc.syscall(SYS_FINIT_MODULE, -1, b"", 0)
        # NULL image -> ENOEXEC, likewise after the tracepoint fired.
        libc.syscall(SYS_INIT_MODULE, None, 0, b"")

        events: list[dict[str, Any]] = []
        for _ in range(10):
            worker.step(poll_timeout_ms=200)
            events = _events_since(sink, baseline)
            mine = [e for e in events if e["process"]["pid"] == os.getpid()]
            variants = {e["process"]["module_load_variant"] for e in mine}
            if {"finit_module", "init_module"} <= variants:
                break

        mine = [e for e in events if e["process"]["pid"] == os.getpid()]
        finits = [e for e in mine if e["process"]["module_load_variant"] == "finit_module"]
        inits = [e for e in mine if e["process"]["module_load_variant"] == "init_module"]
        assert finits, f"no finit_module event emitted; got {events}"
        assert inits, f"no init_module event emitted; got {events}"

        for ev in (finits[0], inits[0]):
            assert ev["module"] == "process_collector_module_load"
            assert ev["action"] == "module_load_attempt"
            assert ev["kind"] == "event"
            assert ev["category"] == ["driver"]
            assert ev["type"] == ["installation"]
            assert ev["severity"] == "info"
            assert ev["host"]["name"] == "test-host"
            assert ev["user"]["id"] == "0"
            assert ev["process"]["pid"] == os.getpid()
            # The wall-clock conversion must land in the present, not at the
            # raw monotonic value reinterpreted as an epoch (which would be
            # ~1970).
            assert ev["ts"] > "2026-01-01", ev["ts"]

        assert finits[0]["raw"]["source"] == "ebpf:sys_enter_finit_module"
        assert finits[0]["raw"]["variant"] == 0
        # We passed fd -1 above, so that is what the record must carry.
        assert finits[0]["process"]["module_load_fd"] == -1
        assert finits[0]["process"]["module_load_flags"] == 0

        assert inits[0]["raw"]["source"] == "ebpf:sys_enter_init_module"
        assert inits[0]["raw"]["variant"] == 1
        # init_module has no fd at all; the native side reports -1.
        assert inits[0]["process"]["module_load_fd"] == -1
        assert inits[0]["process"]["module_load_flags"] == 0
    finally:
        os.sched_setaffinity(0, original_affinity)
        worker.stop()
