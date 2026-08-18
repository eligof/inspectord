# ptrace tracepoint worker (PR2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consume the `ProcessPtraceStream` PyO3 class shipped in PR1 (#116) from a new Python worker, wire it into the dev config, and ship the `proc.ptrace_injection` starter-pack rule so cross-process ptrace attaches alert end-to-end.

**Architecture:** A new `inspectord/workers/process_collector_ptrace/` package mirroring `process_collector_exit` exactly — stream-factory + sink injection, `_wall_offset_ns` monotonic→wall conversion, one `build_event` per record written as NDJSON to the sink. One `WorkerSpec` entry in `dev_config`. One YAML rule in `inspectord/rules/starter_pack/` that matches only the attach family (`PTRACE_ATTACH` / `PTRACE_SEIZE`), leaving write-family requests as events-only.

**Tech Stack:** Python 3.14, pydantic `Event` schema (`inspectord/schemas/event.py`), `build_event` (`inspectord/parsers/base.py`), YAML rule loader (`inspectord/rules/yaml_loader.py`), pytest.

**Spec:** `docs/superpowers/specs/2026-07-15-process-syscall-tracepoints-design.md` §3.2 (this PR), §3.1 (the native side already merged), §2 (shared mechanism).

**Predecessor:** PR1 = #116 (`feat(native): sys_enter_ptrace tracepoint program + ProcessPtraceStream`). This plan assumes #116 is merged into `main`.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `inspectord/workers/process_collector_ptrace/__init__.py` | Package docstring only (mirrors sibling workers). |
| `inspectord/workers/process_collector_ptrace/__main__.py` | `ProcessCollectorPtraceWorker` + `main()` entry point: polls the stream, translates records to Events, writes NDJSON. |
| `inspectord/config.py` | Add the `process_collector_ptrace` `WorkerSpec` dict to the dev config worker list, immediately after `process_collector_exit`. |
| `inspectord/rules/starter_pack/proc_ptrace_injection.yaml` | The `proc.ptrace_injection` detection rule (attach family only). |
| `tests/workers/test_process_collector_ptrace_worker.py` | Worker unit tests against a fake stream (event shape, timestamp conversion, request-name passthrough, close-on-stop). |
| `tests/test_dev_config_process_collector_ptrace.py` | Dev-config presence test. |
| `tests/rules/starter_pack/test_proc_ptrace_injection.py` | Rule fires on ATTACH/SEIZE; does not fire on write-family or on other modules. |

**Record contract from PR1** — `ProcessPtraceStream.poll(timeout_ms)` returns a list of dicts with exactly these keys (source: `crates/inspectord_native/src/lib.rs`, `ProcessPtraceStream::poll`):

```python
{
    "timestamp_ns": int,   # bpf_ktime_get_ns(), monotonic
    "pid": int,            # caller TGID
    "uid": int,            # caller uid
    "comm": str,           # caller comm, already decoded
    "request": int,        # raw i32 ptrace request
    "request_name": str,   # e.g. "PTRACE_ATTACH"; unknown -> "PTRACE_<decimal>"
    "target_pid": int,     # namespace-relative TID of the target
}
```

---

### Task 1: Worker package + event translation

**Files:**
- Create: `inspectord/workers/process_collector_ptrace/__init__.py`
- Create: `inspectord/workers/process_collector_ptrace/__main__.py`
- Test: `tests/workers/test_process_collector_ptrace_worker.py`

- [ ] **Step 1: Write the failing test**

Create `tests/workers/test_process_collector_ptrace_worker.py`:

```python
"""Tests the ProcessCollectorPtraceWorker independently of the BPF runtime.

Mirror of the process_collector_exit worker test: a fake stream stands in for
inspectord._native.ProcessPtraceStream so the translation logic is exercised
without loading eBPF programs.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.process_collector_ptrace.__main__ import (
    ProcessCollectorPtraceWorker,
)


class FakeStream:
    """Stand-in for inspectord._native.ProcessPtraceStream."""

    def __init__(self, batches: list[list[dict[str, Any]]]) -> None:
        self._batches = batches
        self._closed = False

    def poll(self, timeout_ms: int) -> list[dict[str, Any]]:
        if not self._batches:
            return []
        return self._batches.pop(0)

    def close(self) -> None:
        self._closed = True


def _read_events(buf: BytesIO) -> list[dict[str, Any]]:
    buf.seek(0)
    return [json.loads(line) for line in buf.read().splitlines() if line]


def _ptrace_record(
    *,
    pid: int = 1234,
    uid: int = 1000,
    comm: str = "gdb",
    request: int = 16,
    request_name: str = "PTRACE_ATTACH",
    target_pid: int = 5678,
) -> dict[str, Any]:
    return {
        "timestamp_ns": 1_700_000_000_000_000_000,
        "pid": pid,
        "uid": uid,
        "comm": comm,
        "request": request,
        "request_name": request_name,
        "target_pid": target_pid,
    }


def test_worker_emits_ptrace_call_event() -> None:
    sink = BytesIO()
    stream = FakeStream([[_ptrace_record()]])
    worker = ProcessCollectorPtraceWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    events = _read_events(sink)
    assert len(events) == 1, events
    ev = events[0]
    assert ev["module"] == "process_collector_ptrace"
    assert ev["action"] == "ptrace_call"
    assert ev["kind"] == "event"
    assert ev["category"] == ["process"]
    assert ev["type"] == ["access"]
    assert ev["severity"] == "info"
    assert ev["host"]["name"] == "test-host"
    assert ev["user"]["id"] == "1000"
    assert ev["process"]["pid"] == 1234
    assert ev["process"]["name"] == "gdb"
    assert ev["process"]["ptrace_request"] == "PTRACE_ATTACH"
    assert ev["process"]["target_pid"] == 5678
    assert ev["process"]["target"] == {"pid": 5678}
    assert ev["raw"]["source"] == "ebpf:sys_enter_ptrace"
    assert ev["raw"]["request"] == 16


def test_worker_passes_through_write_family_request_name() -> None:
    sink = BytesIO()
    stream = FakeStream(
        [[_ptrace_record(request=0x4205, request_name="PTRACE_SETREGSET")]]
    )
    worker = ProcessCollectorPtraceWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=10)
    worker.stop()

    ev = _read_events(sink)[0]
    assert ev["process"]["ptrace_request"] == "PTRACE_SETREGSET"
    assert ev["raw"]["request"] == 0x4205


def test_worker_converts_monotonic_timestamp_to_wall_clock() -> None:
    sink = BytesIO()
    stream = FakeStream([[_ptrace_record()]])
    worker = ProcessCollectorPtraceWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    # The record's monotonic timestamp is offset by the wall/monotonic delta
    # captured in start(); the emitted ts must not be the raw 1.7e18 ns value
    # interpreted directly as a wall-clock epoch.
    worker.step(poll_timeout_ms=10)
    worker.stop()

    ev = _read_events(sink)[0]
    assert not ev["ts"].startswith("2023-11-14T22:13:20"), ev["ts"]


def test_worker_empty_poll_is_a_noop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = ProcessCollectorPtraceWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=1)
    worker.stop()
    assert _read_events(sink) == []


def test_worker_closes_stream_on_stop() -> None:
    sink = BytesIO()
    stream = FakeStream([])
    worker = ProcessCollectorPtraceWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/workers/test_process_collector_ptrace_worker.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'inspectord.workers.process_collector_ptrace'`

- [ ] **Step 3: Write the package `__init__.py`**

Create `inspectord/workers/process_collector_ptrace/__init__.py`:

```python
"""process_collector_ptrace worker — translates eBPF ptrace records into Events."""
```

- [ ] **Step 4: Write the worker**

Create `inspectord/workers/process_collector_ptrace/__main__.py`:

```python
"""inspectord-process-collector-ptrace worker entry point.

Loads the sys_enter_ptrace syscall tracepoint via the inspectord_native Rust
extension, polls the PTRACE_EVENTS ring buffer, and emits one normalized
ptrace_call Event per record. Only cross-process calls in the
injection-relevant request set reach userspace; the filtering happens in-BPF
(see docs/superpowers/specs/2026-07-15-process-syscall-tracepoints-design.md
section 3.1).

Run standalone (for debugging):
  sudo python -m inspectord.workers.process_collector_ptrace --sink-path -

Or under the supervisor (the normal case).
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, Protocol

from inspectord.parsers.base import build_event


class _StreamProtocol(Protocol):
    def poll(self, timeout_ms: int) -> list[dict[str, Any]]: ...
    def close(self) -> None: ...


_DEFAULT_HOSTNAME = socket.gethostname()


def _default_stream_factory() -> _StreamProtocol:
    from inspectord._native import ProcessPtraceStream  # noqa: PLC0415

    stream: _StreamProtocol = ProcessPtraceStream()
    return stream


class ProcessCollectorPtraceWorker:
    """Polls a ProcessPtraceStream and writes one Event per record.

    The stream_factory + sink injection makes the worker unit-testable
    without loading real eBPF programs.
    """

    def __init__(
        self,
        *,
        stream_factory: Callable[[], _StreamProtocol] = _default_stream_factory,
        sink: IO[bytes],
        host_name: str = _DEFAULT_HOSTNAME,
    ) -> None:
        self._stream_factory = stream_factory
        self._sink = sink
        self._host_name = host_name
        self._stream: _StreamProtocol | None = None
        self._wall_offset_ns: int = 0

    def start(self) -> None:
        self._stream = self._stream_factory()
        wall_ns = int(datetime.now(tz=UTC).timestamp() * 1e9)
        mono_ns = time.monotonic_ns()
        self._wall_offset_ns = wall_ns - mono_ns

    def step(self, *, poll_timeout_ms: int = 200) -> None:
        if self._stream is None:
            raise RuntimeError("worker not started")
        for record in self._stream.poll(poll_timeout_ms):
            event = self._record_to_event(record)
            self._sink.write(json.dumps(event).encode() + b"\n")
            self._sink.flush()

    def stop(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def _record_to_event(self, record: dict[str, Any]) -> dict[str, Any]:
        ts_ns = int(record["timestamp_ns"]) + self._wall_offset_ns
        ts = datetime.fromtimestamp(ts_ns / 1e9, tz=UTC)
        target_pid = int(record["target_pid"])
        # target_pid is a TID in the *caller's* pid namespace, so for
        # namespaced callers (flatpak/bwrap/docker) it is not a host pid.
        # Rule templates say "as seen by the caller" rather than asserting one.
        process: dict[str, Any] = {
            "pid": int(record["pid"]),
            "name": str(record["comm"]),
            "ptrace_request": str(record["request_name"]),
            "target_pid": target_pid,
            "target": {"pid": target_pid},
        }
        event = build_event(
            module="process_collector_ptrace",
            action="ptrace_call",
            category=["process"],
            type_=["access"],
            severity="info",
            ts=ts,
            host={"name": self._host_name},
            user={"id": str(record["uid"])},
            process=process,
            raw={
                "source": "ebpf:sys_enter_ptrace",
                "request": int(record["request"]),
            },
        )
        return event.model_dump(mode="json", exclude_none=True)


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="inspectord-process-collector-ptrace",
        description="eBPF cross-process ptrace collector; writes NDJSON Events to a sink.",
    )
    parser.add_argument(
        "--sink-path",
        default="-",
        help="Path to write NDJSON events (default: stdout, '-' = stdout)",
    )
    parser.add_argument(
        "--poll-timeout-ms",
        type=int,
        default=200,
        help="Ring-buffer poll timeout per iteration",
    )
    args = parser.parse_args(argv)

    sink = _open_sink(args.sink_path)
    worker = ProcessCollectorPtraceWorker(sink=sink)
    worker.start()
    try:
        while True:
            worker.step(poll_timeout_ms=args.poll_timeout_ms)
    except KeyboardInterrupt:
        pass
    finally:
        worker.stop()
        if sink not in (sys.stdout.buffer, sys.stderr.buffer):
            sink.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/workers/test_process_collector_ptrace_worker.py -v`
Expected: PASS — 5 passed.

- [ ] **Step 6: Run the lint/type gates**

Run:
```sh
.venv/bin/ruff check inspectord tests && \
.venv/bin/ruff format --check inspectord tests && \
.venv/bin/mypy inspectord
```
Expected: `All checks passed!`, `N files already formatted`, `Success: no issues found`.

- [ ] **Step 7: Commit**

```bash
git add inspectord/workers/process_collector_ptrace tests/workers/test_process_collector_ptrace_worker.py
git commit -m "feat(workers): process_collector_ptrace worker

Translates ProcessPtraceStream records into ptrace_call Events."
```

---

### Task 2: Dev-config wiring

**Files:**
- Modify: `inspectord/config.py` (the dev-config worker list — insert directly after the `process_collector_exit` entry, currently around lines 100-104)
- Test: `tests/test_dev_config_process_collector_ptrace.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_dev_config_process_collector_ptrace.py`:

```python
"""dev_config must include a process_collector_ptrace worker entry."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_contains_process_collector_ptrace(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "process_collector_ptrace" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "process_collector_ptrace")
    assert worker.module == "inspectord.workers.process_collector_ptrace", worker.module
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_dev_config_process_collector_ptrace.py -v`
Expected: FAIL — `AssertionError: ['healthcheck', ..., 'process_collector_exit', ...]` (name absent).

- [ ] **Step 3: Add the worker entry**

In `inspectord/config.py`, find this existing block in the dev-config worker list:

```python
                {
                    "name": "process_collector_exit",
                    "module": "inspectord.workers.process_collector_exit",
                    "config": {},
                },
```

Insert immediately after it:

```python
                {
                    "name": "process_collector_ptrace",
                    "module": "inspectord.workers.process_collector_ptrace",
                    "config": {},
                },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_dev_config_process_collector_ptrace.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add inspectord/config.py tests/test_dev_config_process_collector_ptrace.py
git commit -m "feat(config): register process_collector_ptrace worker in dev config"
```

---

### Task 3: `proc.ptrace_injection` starter-pack rule

**Files:**
- Create: `inspectord/rules/starter_pack/proc_ptrace_injection.yaml`
- Test: `tests/rules/starter_pack/test_proc_ptrace_injection.py`

Per the locked severity split (spec §1, §3.2), the rule matches **only** the attach family. Write-family requests (`PTRACE_POKETEXT`, `PTRACE_POKEDATA`, `PTRACE_POKEUSR`, `PTRACE_SETREGS`, `PTRACE_SETREGSET`) stay events-only — the user debugs daily and `rr`/legacy tooling produces write bursts that must not become alert streams.

- [ ] **Step 1: Write the failing test**

Create `tests/rules/starter_pack/test_proc_ptrace_injection.py`:

```python
"""Tests for the proc.ptrace_injection rule (attach family only)."""

from __future__ import annotations

from importlib.resources import files

import yaml as _yaml

from inspectord.parsers.base import build_event
from inspectord.rules.base import EvalContext
from inspectord.rules.yaml_loader import evaluate_yaml_rule, load_yaml_rule_from_dict


def _rule():
    pkg = files("inspectord.rules.starter_pack")
    path = pkg / "proc_ptrace_injection.yaml"
    return load_yaml_rule_from_dict(
        _yaml.safe_load(path.read_text(encoding="utf-8")),
        source=path.name,
    )


def _event(
    request_name: str,
    *,
    module: str = "process_collector_ptrace",
    action: str = "ptrace_call",
):
    return build_event(
        module=module,
        action=action,
        category=["process"],
        type_=["access"],
        severity="info",
        user={"id": "1000"},
        process={
            "pid": 1234,
            "name": "gdb",
            "ptrace_request": request_name,
            "target_pid": 5678,
            "target": {"pid": 5678},
        },
        raw={"source": "ebpf:sys_enter_ptrace", "request": 16},
    )


def test_fires_on_attach() -> None:
    matches = evaluate_yaml_rule(
        _rule(), EvalContext(event=_event("PTRACE_ATTACH"), history=[])
    )
    assert matches
    assert matches[0].severity == "medium"


def test_fires_on_seize() -> None:
    matches = evaluate_yaml_rule(
        _rule(), EvalContext(event=_event("PTRACE_SEIZE"), history=[])
    )
    assert matches
    assert matches[0].severity == "medium"


def test_does_not_fire_on_poketext() -> None:
    assert (
        evaluate_yaml_rule(
            _rule(), EvalContext(event=_event("PTRACE_POKETEXT"), history=[])
        )
        == []
    )


def test_does_not_fire_on_setregset() -> None:
    assert (
        evaluate_yaml_rule(
            _rule(), EvalContext(event=_event("PTRACE_SETREGSET"), history=[])
        )
        == []
    )


def test_does_not_fire_on_other_module() -> None:
    ev = _event("PTRACE_ATTACH", module="process_collector")
    assert evaluate_yaml_rule(_rule(), EvalContext(event=ev, history=[])) == []


def test_does_not_fire_on_other_action() -> None:
    ev = _event("PTRACE_ATTACH", action="process_start")
    assert evaluate_yaml_rule(_rule(), EvalContext(event=ev, history=[])) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/rules/starter_pack/test_proc_ptrace_injection.py -v`
Expected: FAIL — `FileNotFoundError` / `NotADirectoryError` for `proc_ptrace_injection.yaml`.

- [ ] **Step 3: Write the rule**

Create `inspectord/rules/starter_pack/proc_ptrace_injection.yaml` with exactly this content (from spec §3.2):

```yaml
version: 1.0.0
id: proc.ptrace_injection
name: "cross-process ptrace attach"
severity: medium
category: process
why: |
  A process attached to another process via ptrace. Debuggers do this
  legitimately, but it is also a common process-injection primitive on
  Linux — an attacker attaches, then writes memory or registers.
false_positives:
  - "You were debugging with gdb/strace/lldb/rr (attach to a running process)."
  - "A crash reporter attached to a crashing process (Chromium/Electron crashpad, coredump helpers)."
  - "An IDE-embedded debugger (VS Code, JetBrains) attached to a process."
detect:
  any_of:
    - event.module == "process_collector_ptrace" AND event.action == "ptrace_call" AND process.ptrace_request == "PTRACE_ATTACH"
    - event.module == "process_collector_ptrace" AND event.action == "ptrace_call" AND process.ptrace_request == "PTRACE_SEIZE"
short: "ptrace {process.ptrace_request} from {process.name} to pid {process.target_pid}"
detail: "{process.name} (pid {process.pid}, uid {user.id}) issued {process.ptrace_request} against pid {process.target_pid} (as seen by the caller)."
labels: [process, injection, ptrace]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/rules/starter_pack/test_proc_ptrace_injection.py -v`
Expected: PASS — 6 passed.

If a registry test enumerates the starter-pack rule set, update it too. Check with:
`grep -rn "starter_pack" tests/rules/test_registry.py`

- [ ] **Step 5: Commit**

```bash
git add inspectord/rules/starter_pack/proc_ptrace_injection.yaml tests/rules/starter_pack/test_proc_ptrace_injection.py
git commit -m "feat(rules): proc.ptrace_injection starter-pack rule

Attach family only (ATTACH/SEIZE) at medium; write-family ptrace requests
stay events-only per the locked severity split."
```

---

### Task 4: Full gates + live verification

**Files:** none (verification only).

- [ ] **Step 1: Run the complete Python gate set**

Run:
```sh
.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q && \
.venv/bin/ruff check inspectord inspectorctl tests && \
.venv/bin/ruff format --check inspectord inspectorctl tests && \
.venv/bin/mypy inspectord
```
Expected: exit 0 from each; mypy prints `Success: no issues found`.

- [ ] **Step 2: Live end-to-end check as root**

The worker is the first consumer of the PR1 stream, so verify a real record flows end to end.

Run:
```sh
sudo .venv/bin/python -m inspectord.workers.process_collector_ptrace --sink-path /tmp/ptrace-events.ndjson &
sleep 3
sudo .venv/bin/python -c "
import ctypes, os, signal, time
pid = os.fork()
if pid == 0:
    signal.pause()
    os._exit(0)
libc = ctypes.CDLL('libc.so.6', use_errno=True)
time.sleep(0.5)
libc.ptrace(16, pid, 0, 0)   # PTRACE_ATTACH
time.sleep(0.5)
libc.ptrace(17, pid, 0, 0)   # PTRACE_DETACH
os.kill(pid, signal.SIGKILL)
os.waitpid(pid, 0)
print('attached to', pid)
"
sleep 2
sudo pkill -f "inspectord.workers.process_collector_ptrace"
cat /tmp/ptrace-events.ndjson
```

Expected: at least one NDJSON line with `"action": "ptrace_call"`, `"ptrace_request": "PTRACE_ATTACH"`, and `"target_pid"` equal to the forked child's pid printed by the trigger script.

If nothing is emitted, do **not** patch the worker blindly — check in this order: (1) is the tracepoint attached (`sudo bpftool prog list | grep -i tracepoint`), (2) does the root filter test still pass (`sudo .venv/bin/python -m pytest tests/test_native_loader.py -k ptrace`), (3) does `/sys/kernel/tracing/events/syscalls/sys_enter_ptrace/format` still show the args at offsets 16 and 24.

- [ ] **Step 3: Commit any fixes, then push and open the PR**

```bash
git push -u origin ptrace-tracepoint-worker
gh pr create --base main --head ptrace-tracepoint-worker \
  --title "feat(workers): process_collector_ptrace worker + proc.ptrace_injection rule (PR2)" \
  --body "<summary of the worker, wiring, rule, severity split, and the live verification output>"
```

- [ ] **Step 4: Watch CI, then squash-merge**

```bash
gh pr checks <N> --watch
gh pr merge <N> --squash --delete-branch
```
Expected: `lint-and-test`, CodeQL, RustSec, dependency-review all pass.

---

## Self-Review notes

- **Spec coverage:** §3.2's three deliverables (worker, dev-config wiring, rule) map to Tasks 1–3; §6's testing requirements (worker event-shape tests with a fake stream, rule fires/does-not-fire tests, full gate set) map to Tasks 1, 3, and 4. §3.1 is already merged as PR1. §4 and §5 (kernel-module and raw-socket slices) are explicitly out of scope for this plan and get their own plans.
- **Namespace caveat** (spec §3.1 caveat b) is honored in two places: a comment in `_record_to_event` and the "as seen by the caller" wording in the rule's `detail` template.
- **Type consistency:** the record keys used in Task 1's implementation (`timestamp_ns`, `pid`, `uid`, `comm`, `request`, `request_name`, `target_pid`) match the PR1 `poll()` dict exactly, and the `process.ptrace_request` / `process.target_pid` field names used by the Task 3 rule match what Task 1 writes.
