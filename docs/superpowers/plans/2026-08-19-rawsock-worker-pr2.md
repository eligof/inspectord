# raw-socket tracepoint worker (PR2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consume the `ProcessRawSocketStream` PyO3 class shipped in PR1 (#122) from a new Python worker, wire it into the dev config and the example config, and ship the `proc.raw_socket_unprivileged` starter-pack rule from spec §5 so raw-socket creation alerts end-to-end. This closes the third and last slice of the syscall-tracepoint design.

**Architecture:** A new `inspectord/workers/process_collector_raw_socket/` package mirroring `process_collector_module_load` exactly — stream-factory + sink injection, `_wall_offset_ns` monotonic→wall conversion, one `build_event` per record written as NDJSON to the sink. One `WorkerSpec` entry in `dev_config` plus the matching `[[workers]]` block in `packaging/config.example.toml` (an existing test asserts the two name sets are equal). One YAML rule in `inspectord/rules/starter_pack/`: `proc.raw_socket_unprivileged` (medium, `user.id != "0"`).

**Tech Stack:** Python 3.14, pydantic `Event` schema (`inspectord/schemas/event.py`), `build_event` (`inspectord/parsers/base.py`), YAML rule loader (`inspectord/rules/yaml_loader.py`), pytest.

**Spec:** `docs/superpowers/specs/2026-07-15-process-syscall-tracepoints-design.md` §5 (this PR, including the "Resolved 2026-08-19: no outcome or capability signal in v1" decision), §2 (shared tracepoint mechanism), §1 (locked decisions). Rule id promised by parent spec §21.

**Predecessor:** PR1 = #122 (`feat(native): sys_enter_socket tracepoint + ProcessRawSocketStream`). Merged into `main`.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `inspectord/workers/process_collector_raw_socket/__init__.py` | Package docstring only (mirrors sibling workers). |
| `inspectord/workers/process_collector_raw_socket/__main__.py` | `ProcessCollectorRawSocketWorker` + `main()` entry point: polls the stream, translates records to Events, writes NDJSON. |
| `inspectord/config.py` | Add the `process_collector_raw_socket` `WorkerSpec` dict to the dev-config worker list, immediately after `process_collector_module_load`. |
| `packaging/config.example.toml` | Matching `[[workers]]` block (kept in lockstep by `tests/test_config_example.py::test_example_config_worker_names_match_dev_config`). |
| `inspectord/rules/starter_pack/proc_raw_socket_unprivileged.yaml` | `proc.raw_socket_unprivileged` — medium — raw-socket creation by a non-root uid. |
| `tests/workers/test_process_collector_raw_socket_worker.py` | Worker unit tests against a fake stream (AF_PACKET + AF_INET/SOCK_RAW, unmasked flag bits, timestamp conversion, empty poll, close-on-stop). |
| `tests/test_dev_config_process_collector_raw_socket.py` | Dev-config presence test. |
| `tests/rules/starter_pack/test_proc_raw_socket_rules.py` | Rule fires / does-not-fire matrix. |
| `tests/workers/test_process_collector_raw_socket_live.py` | Root-only (`ebpf_load`) end-to-end test through the real `ProcessRawSocketStream`. |

**Record contract from PR1** — `ProcessRawSocketStream.poll(timeout_ms)` returns a list of dicts with exactly these keys:

```python
{
    "timestamp_ns": int,   # bpf_ktime_get_ns(), monotonic
    "pid": int,            # caller TGID
    "uid": int,
    "comm": str,           # caller comm, already decoded
    "family": int,         # 2 = AF_INET, 10 = AF_INET6, 17 = AF_PACKET
    "family_name": str,    # "AF_INET" | "AF_INET6" | "AF_PACKET" | "AF_<decimal>"
    "type": int,           # socket type AS PASSED — flag bits NOT masked off
    "protocol": int,
}
```

Note the key is `type`, not `type_`. The flag bits (`SOCK_CLOEXEC`, `SOCK_NONBLOCK`) are
deliberately preserved by the native side as evidence and MUST survive into the event
unmasked; the `0xf` mask exists only inside the BPF filter.

---

### Task 1: Worker package + event translation

**Files:**
- Create: `inspectord/workers/process_collector_raw_socket/__init__.py`
- Create: `inspectord/workers/process_collector_raw_socket/__main__.py`
- Test: `tests/workers/test_process_collector_raw_socket_worker.py`

- [ ] **Step 1: Write the failing test**

Create `tests/workers/test_process_collector_raw_socket_worker.py`, mirroring
`tests/workers/test_process_collector_module_load_worker.py`:

```python
"""Tests the ProcessCollectorRawSocketWorker independently of the BPF runtime.

Mirror of the process_collector_module_load worker test: a fake stream stands in
for inspectord._native.ProcessRawSocketStream so the translation logic is
exercised without loading eBPF programs.
"""

from __future__ import annotations

import json
import socket
from io import BytesIO
from typing import Any

from inspectord.workers.process_collector_raw_socket.__main__ import (
    ProcessCollectorRawSocketWorker,
)


class FakeStream:
    """Stand-in for inspectord._native.ProcessRawSocketStream."""

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


def _packet_record(...)/_inet_raw_record(...)  # helpers building the PR1 dict shape
```

Tests:
- `test_worker_emits_raw_socket_created_event_for_af_packet`
- `test_worker_emits_raw_socket_created_event_for_af_inet_sock_raw`
- `test_worker_preserves_socket_type_flag_bits` — a record whose `type` is
  `SOCK_RAW | SOCK_CLOEXEC` must reach the event with both bits set, in
  `network.socket_type` and in `raw.type`.
- `test_worker_emits_one_event_per_record_in_a_batch`
- `test_worker_converts_monotonic_timestamp_to_wall_clock`
- `test_worker_empty_poll_is_a_noop`
- `test_worker_closes_stream_on_stop`

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/workers/test_process_collector_raw_socket_worker.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Write the package `__init__.py`**

```python
"""process_collector_raw_socket worker — eBPF raw-socket records into Events."""
```

- [ ] **Step 4: Write the worker**

`inspectord/workers/process_collector_raw_socket/__main__.py`, identical in shape to the
module-load worker (`_StreamProtocol`, `_DEFAULT_HOSTNAME`, `_default_stream_factory`
importing `ProcessRawSocketStream`, `start`/`step`/`stop`, `_open_sink`, `main()` with
`--sink-path` and `--poll-timeout-ms`), with `_record_to_event` producing:

```python
type_value = int(record["type"])  # flag bits intentionally NOT masked
family = int(record["family"])
protocol = int(record["protocol"])
build_event(
    module="process_collector_raw_socket",
    action="raw_socket_created",
    category=["network"],
    type_=["start"],
    severity="info",
    ts=ts,
    host={"name": self._host_name},
    user={"id": str(record["uid"])},
    process={"pid": int(record["pid"]), "name": str(record["comm"])},
    network={
        "socket_family": str(record["family_name"]),
        "socket_type": type_value,
        "socket_protocol": protocol,
    },
    raw={
        "source": "ebpf:sys_enter_socket",
        "family": family,
        "type": type_value,
        "protocol": protocol,
    },
)
```

- [ ] **Step 5: Run tests to verify they pass** (7 passed)
- [ ] **Step 6: Run the lint/type gates**
- [ ] **Step 7: Commit** — `feat(workers): process_collector_raw_socket worker`

---

### Task 2: Dev-config + example-config wiring

**Files:**
- Modify: `inspectord/config.py` (insert after the `process_collector_module_load` entry)
- Modify: `packaging/config.example.toml` (matching `[[workers]]` block)
- Test: `tests/test_dev_config_process_collector_raw_socket.py`

`tests/test_config_example.py::test_example_config_worker_names_match_dev_config` asserts
the two worker-name sets are equal, so both files MUST change together.

- [ ] **Step 1: Write the failing dev-config presence test**

```python
"""dev_config must include a process_collector_raw_socket worker entry."""

from __future__ import annotations

from pathlib import Path

from inspectord.config import dev_config


def test_dev_config_contains_process_collector_raw_socket(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "process_collector_raw_socket" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "process_collector_raw_socket")
    assert worker.module == "inspectord.workers.process_collector_raw_socket", worker.module
```

- [ ] **Step 2: Run it; expect FAIL (name absent)**
- [ ] **Step 3: Add the `config.py` entry and the TOML block**

```python
{
    "name": "process_collector_raw_socket",
    "module": "inspectord.workers.process_collector_raw_socket",
    "config": {},
},
```

```toml
[[workers]]
name = "process_collector_raw_socket"
module = "inspectord.workers.process_collector_raw_socket"
```

- [ ] **Step 4: Run `tests/test_dev_config_process_collector_raw_socket.py` and `tests/test_config_example.py`; expect PASS**
- [ ] **Step 5: Commit** — `feat(config): register process_collector_raw_socket worker`

---

### Task 3: the `proc.raw_socket_unprivileged` starter-pack rule

**Files:**
- Create: `inspectord/rules/starter_pack/proc_raw_socket_unprivileged.yaml`
- Test: `tests/rules/starter_pack/test_proc_raw_socket_rules.py`

- [ ] **Step 1: Write the failing tests** — matrix:
  - fires for `user.id == "1000"` at severity `medium`, rule id `proc.raw_socket_unprivileged`
  - fires for an `AF_INET`/`SOCK_RAW` event as well as an `AF_PACKET` one
  - does NOT fire for `user.id == "0"` (the accepted root blind spot, asserted so the
    blind spot is a tested property rather than an accident)
  - does NOT fire for a different module
  - does NOT fire for a different action

- [ ] **Step 2: Run; expect FAIL (missing YAML file)**

- [ ] **Step 3: Write `proc_raw_socket_unprivileged.yaml`**

The `false_positives` block must state both v1 blind spots recorded in spec §5 plainly —
the CAP_NET_RAW proxy and the root-sniffer non-alert — alongside the ordinary benign
matches:

```yaml
version: 1.0.0
id: proc.raw_socket_unprivileged
name: "raw socket created by a non-root process"
severity: medium
category: process
why: |
  A process running as a non-root uid created a raw socket (AF_PACKET, or
  AF_INET/AF_INET6 with SOCK_RAW). Raw sockets read frames off the wire and
  send crafted packets, so they are what packet sniffers and packet-crafting
  tools open.

  Read this alert knowing exactly what it can and cannot tell you. The uid is
  only a *proxy* for CAP_NET_RAW: the tracepoint fires on syscall entry, before
  the kernel checks the capability or returns a result, so the event carries no
  outcome and no capability. Two consequences, both accepted in v1:
  a non-root process that legitimately holds CAP_NET_RAW through file or
  ambient capabilities creates the socket successfully and still matches this
  rule; and a raw socket opened by root — the higher-privilege and more
  dangerous case — is recorded as an event but never alerts here. Root-run
  sniffers are NOT covered by this rule.
false_positives:
  - "A non-root process holding CAP_NET_RAW via file or ambient capabilities: mtr, dumpcap/wireshark's capture helper, and some ping builds open raw sockets by design and match this rule."
  - "A network diagnostic you ran yourself (ping, traceroute, mtr, tcpdump/dumpcap, nmap, arping)."
  - "A container, VM, or VPN networking helper (docker/podman network setup, libvirt or VirtualBox NAT/DHCP helpers, dhcpcd/dhclient, wpa_supplicant) opening AF_PACKET sockets under a non-root service account."
detect:
  any_of:
    - event.module == "process_collector_raw_socket" AND event.action == "raw_socket_created" AND user.id != "0"
short: "raw socket ({network.socket_family}) created by {process.name} (pid {process.pid})"
detail: "{process.name} (pid {process.pid}, uid {user.id}) created a {network.socket_family} raw socket. The uid is a proxy for CAP_NET_RAW, not proof of it, and the syscall's outcome is unknown — this fires on the attempt."
labels: [process, network, raw_socket]
```

- [ ] **Step 4: Run the rule tests; expect PASS**
- [ ] **Step 5: Commit** — `feat(rules): proc.raw_socket_unprivileged starter-pack rule`

---

### Task 4: root-only live end-to-end test

**Files:**
- Create: `tests/workers/test_process_collector_raw_socket_live.py`

Mirrors `tests/workers/test_process_collector_module_load_live.py`, but the trigger is an
ordinary `socket.socket(AF_PACKET, SOCK_RAW, 0)` — the same trigger the merged native test
`tests/test_native_loader.py::test_raw_socket_stream_captures_af_packet_but_filters_the_rest`
uses.

Two deliberate differences from the module-load live test, both taken from that native test:

- **No CPU pinning.** `sys_enter_socket` takes three scalar ints and copies nothing from
  userspace, so it is not one of the faultable tracepoints whose kernel handler is gated
  on a per-CPU perf event. The module-load test pins off CPU 0 precisely because
  `finit_module`/`init_module` are gated that way; here it would be noise.
- **Ordering makes the negative assertion race-free.** Create the sockets that must be
  filtered out first (a plain TCP socket, an `AF_NETLINK` `SOCK_RAW` socket) and the
  `AF_PACKET` one last; once the `AF_PACKET` event arrives, the earlier two syscalls have
  provably already run, so their absence is an assertion rather than a race.

Every socket is closed in a `finally`, together with `worker.stop()`.

- [ ] **Step 1: Write the test** — `@pytest.mark.ebpf_load` +
  `@pytest.mark.skipif(os.geteuid() != 0, ...)`, drive the real `ProcessRawSocketStream`
  through the real `ProcessCollectorRawSocketWorker` into a `BytesIO` sink, then assert on
  the emitted NDJSON:
  - one `raw_socket_created` event with `process.pid == os.getpid()` and
    `network.socket_family == "AF_PACKET"`
  - `module`, `kind`, `category == ["network"]`, `type == ["start"]`, `severity == "info"`,
    `host.name == "test-host"`, `user.id == "0"`
  - `network.socket_type & 0xF == socket.SOCK_RAW` **and**
    `network.socket_type & socket.SOCK_CLOEXEC` — CPython sets `SOCK_CLOEXEC` on every
    socket it opens, so this proves the flag bits survived unmasked all the way to the
    event
  - `raw.source == "ebpf:sys_enter_socket"` and `raw.family == 17`
  - `ts > "2026-01-01"` (wall-clock conversion landed in the present, not ~1970)
  - no event for the `AF_NETLINK` socket and none with
    `network.socket_family == "AF_INET"`

- [ ] **Step 2: Run it as root**

```sh
sudo .venv/bin/python -m pytest -m ebpf_load tests/workers/test_process_collector_raw_socket_live.py -v
```

Expected: 1 passed.

- [ ] **Step 3: Commit** — `test(workers): root-only live raw-socket end-to-end test`

---

### Task 5: full gates

- [ ] **Step 1:**

```sh
.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q && \
.venv/bin/ruff check inspectord tests && \
.venv/bin/ruff format --check inspectord tests && \
.venv/bin/mypy inspectord
```

Expected: exit 0 from each; mypy prints `Success: no issues found`.

- [ ] **Step 2:** report; do not push, do not open a PR (out of scope for this run).

---

## Self-Review notes

- **Spec coverage:** §5's deliverables map to Task 1 (worker + `raw_socket_created`),
  Task 2 (wiring), Task 3 (the rule with the honest `false_positives`). The §5 "Resolved
  2026-08-19" decision (no outcome/capability signal in v1) is honored by consuming exactly
  the PR1 record and adding nothing — no `sys_exit_socket` pairing, no `cap_effective` read.
- **Rule id:** `proc.raw_socket_unprivileged` is the id promised by parent spec §21.
- **Two-file wiring:** `config.py` and `config.example.toml` change in the same commit
  because `test_config_example.py` asserts set equality.
- **Unmasked type:** the flag-bit preservation is asserted at both levels (fake-stream unit
  test and the root live test) because it is the one place where a well-meaning
  "normalization" in the worker would silently destroy evidence.
- **Root blind spot is tested, not just documented:** the "does not fire for uid 0" test
  encodes the accepted v1 behavior so a later change to it is a deliberate decision.
