"""Root-only end-to-end test: a real PTRACE_ATTACH becomes a ptrace_call Event.

The other ptrace tests stop at a boundary — `tests/test_native_loader.py`
proves the in-BPF filter works at the stream level, and
`tests/workers/test_process_collector_ptrace_worker.py` proves the translation
works against a fake stream. Neither exercises the whole path, so this test
drives the real `ProcessPtraceStream` through the real worker and asserts on
the NDJSON the worker writes.

Run with:
  sudo .venv/bin/python -m pytest -m ebpf_load tests/workers/test_process_collector_ptrace_live.py
"""

from __future__ import annotations

import ctypes
import json
import os
import time
from io import BytesIO
from typing import Any

import pytest

from inspectord.workers.process_collector_ptrace.__main__ import (
    ProcessCollectorPtraceWorker,
)

PTRACE_CONT = 7
PTRACE_ATTACH = 16
PTRACE_DETACH = 17


@pytest.mark.ebpf_load
@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_real_attach_is_emitted_as_a_ptrace_call_event() -> None:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    sink = BytesIO()
    worker = ProcessCollectorPtraceWorker(sink=sink, host_name="test-host")
    worker.start()

    # The child must not call PTRACE_TRACEME — that would make this process its
    # tracer implicitly and the attach below would then fail EPERM.
    child = os.fork()
    if child == 0:  # child: live long enough to be attached to
        time.sleep(5)
        os._exit(0)

    try:
        time.sleep(0.2)
        worker.step(poll_timeout_ms=200)  # drain unrelated traffic
        sink.seek(0)
        sink.truncate()

        rc = libc.ptrace(PTRACE_ATTACH, child, 0, 0)
        assert rc == 0, f"PTRACE_ATTACH failed: errno {ctypes.get_errno()}"
        os.waitpid(child, 0)  # wait for the attach-stop

        events: list[dict[str, Any]] = []
        for _ in range(10):
            worker.step(poll_timeout_ms=200)
            sink.seek(0)
            events = [json.loads(line) for line in sink.read().splitlines() if line]
            if any(e["process"]["ptrace_request"] == "PTRACE_ATTACH" for e in events):
                break

        attaches = [e for e in events if e["process"]["ptrace_request"] == "PTRACE_ATTACH"]
        assert attaches, f"no PTRACE_ATTACH event emitted; got {events}"
        ev = attaches[0]
        assert ev["module"] == "process_collector_ptrace"
        assert ev["action"] == "ptrace_call"
        assert ev["severity"] == "info"
        assert ev["process"]["target_pid"] == child
        assert ev["process"]["target"] == {"pid": child}
        assert ev["process"]["pid"] == os.getpid()
        assert ev["user"]["id"] == "0"
        assert ev["raw"]["source"] == "ebpf:sys_enter_ptrace"
        assert ev["raw"]["request"] == PTRACE_ATTACH
        # The wall-clock conversion must land in the present, not at the raw
        # monotonic value reinterpreted as an epoch (which would be ~1970).
        assert ev["ts"] > "2026-01-01"
    finally:
        try:
            libc.ptrace(PTRACE_CONT, child, 0, 0)
            libc.ptrace(PTRACE_DETACH, child, 0, 0)
            os.kill(child, 9)
            os.waitpid(child, 0)
        except (ProcessLookupError, ChildProcessError):
            pass
        worker.stop()
