# kernel-module tracepoint worker (PR2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consume the `ProcessModuleLoadStream` PyO3 class shipped in PR1 (#119) from a new Python worker, wire it into the dev config and the example config, and ship the two starter-pack rules from spec §4 so kernel-module load attempts alert end-to-end.

**Architecture:** A new `inspectord/workers/process_collector_module_load/` package mirroring `process_collector_ptrace` exactly — stream-factory + sink injection, `_wall_offset_ns` monotonic→wall conversion, one `build_event` per record written as NDJSON to the sink. One `WorkerSpec` entry in `dev_config` plus the matching `[[workers]]` block in `packaging/config.example.toml` (an existing test asserts the two name sets are equal). Two YAML rules in `inspectord/rules/starter_pack/`: `proc.kernel_module_from_memory` (high, `init_module`) and `proc.kernel_module_loaded_unknown` (medium, `finit_module` from an unknown loader).

**Tech Stack:** Python 3.14, pydantic `Event` schema (`inspectord/schemas/event.py`), `build_event` (`inspectord/parsers/base.py`), YAML rule loader (`inspectord/rules/yaml_loader.py`), pytest.

**Spec:** `docs/superpowers/specs/2026-07-15-process-syscall-tracepoints-design.md` §4 (this PR, including the rules reworked 2026-08-18), §2 (shared tracepoint mechanism), §1 (locked decisions).

**Predecessor:** PR1 = #119 (`feat(native): finit_module + init_module tracepoints + ProcessModuleLoadStream`). Merged into `main`.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `inspectord/workers/process_collector_module_load/__init__.py` | Package docstring only (mirrors sibling workers). |
| `inspectord/workers/process_collector_module_load/__main__.py` | `ProcessCollectorModuleLoadWorker` + `main()` entry point: polls the stream, translates records to Events, writes NDJSON. |
| `inspectord/config.py` | Add the `process_collector_module_load` `WorkerSpec` dict to the dev-config worker list, immediately after `process_collector_ptrace`. |
| `packaging/config.example.toml` | Matching `[[workers]]` block (kept in lockstep by `tests/test_config_example.py::test_example_config_worker_names_match_dev_config`). |
| `inspectord/rules/yaml_loader.py` | Bug fix: make the advertised `NOT IN` leaf operator actually reachable (see Task 3). |
| `inspectord/rules/starter_pack/proc_kernel_module_from_memory.yaml` | `proc.kernel_module_from_memory` — high — `init_module` (fd-avoidant load from anonymous memory). |
| `inspectord/rules/starter_pack/proc_kernel_module_loaded_unknown.yaml` | `proc.kernel_module_loaded_unknown` — medium — `finit_module` from a caller not in the known-loader list. |
| `tests/workers/test_process_collector_module_load_worker.py` | Worker unit tests against a fake stream (both variants, timestamp conversion, empty poll, close-on-stop). |
| `tests/test_dev_config_process_collector_module_load.py` | Dev-config presence test. |
| `tests/rules/test_yaml_loader.py` | Regression test for the `NOT IN` tokenizer fix. |
| `tests/rules/starter_pack/test_proc_kernel_module_rules.py` | Both rules: fires / does-not-fire matrix. |
| `tests/workers/test_process_collector_module_load_live.py` | Root-only (`ebpf_load`) end-to-end test through the real `ProcessModuleLoadStream`. |

**Record contract from PR1** — `ProcessModuleLoadStream.poll(timeout_ms)` returns a list of dicts with exactly these keys:

```python
{
    "timestamp_ns": int,   # bpf_ktime_get_ns(), monotonic
    "pid": int,            # caller TGID
    "uid": int,
    "comm": str,           # caller comm, already decoded
    "variant": int,        # 0 = finit_module, 1 = init_module
    "variant_name": str,   # "finit_module" | "init_module"
    "fd": int,             # finit_module's fd; -1 for init_module
    "flags": int,          # finit_module's flags; 0 for init_module
}
```

---

### Task 1: Worker package + event translation

**Files:**
- Create: `inspectord/workers/process_collector_module_load/__init__.py`
- Create: `inspectord/workers/process_collector_module_load/__main__.py`
- Test: `tests/workers/test_process_collector_module_load_worker.py`

- [ ] **Step 1: Write the failing test**

Create `tests/workers/test_process_collector_module_load_worker.py`:

```python
"""Tests the ProcessCollectorModuleLoadWorker independently of the BPF runtime.

Mirror of the process_collector_ptrace worker test: a fake stream stands in for
inspectord._native.ProcessModuleLoadStream so the translation logic is
exercised without loading eBPF programs.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from inspectord.workers.process_collector_module_load.__main__ import (
    ProcessCollectorModuleLoadWorker,
)


class FakeStream:
    """Stand-in for inspectord._native.ProcessModuleLoadStream."""

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


def _finit_record(...)/_init_record(...)  # helpers building the PR1 dict shape
```

Tests: `test_worker_emits_module_load_attempt_event_for_finit`,
`test_worker_emits_module_load_attempt_event_for_init`,
`test_worker_converts_monotonic_timestamp_to_wall_clock`,
`test_worker_empty_poll_is_a_noop`, `test_worker_closes_stream_on_stop`.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/workers/test_process_collector_module_load_worker.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Write the package `__init__.py`**

```python
"""process_collector_module_load worker — eBPF module-load records into Events."""
```

- [ ] **Step 4: Write the worker**

`inspectord/workers/process_collector_module_load/__main__.py`, identical in shape to
the ptrace worker, with `_record_to_event` producing:

```python
build_event(
    module="process_collector_module_load",
    action="module_load_attempt",
    category=["driver"],
    type_=["installation"],
    severity="info",
    ts=ts,
    host={"name": self._host_name},
    user={"id": str(record["uid"])},
    process={
        "pid": int(record["pid"]),
        "name": str(record["comm"]),
        "module_load_variant": variant_name,
        "module_load_fd": fd,
        "module_load_flags": flags,
    },
    raw={
        "source": f"ebpf:sys_enter_{variant_name}",
        "variant": int(record["variant"]),
        "fd": fd,
        "flags": flags,
    },
)
```

- [ ] **Step 5: Run tests to verify they pass** (5 passed)
- [ ] **Step 6: Run the lint/type gates**
- [ ] **Step 7: Commit** — `feat(workers): process_collector_module_load worker`

---

### Task 2: Dev-config + example-config wiring

**Files:**
- Modify: `inspectord/config.py` (insert after the `process_collector_ptrace` entry)
- Modify: `packaging/config.example.toml` (matching `[[workers]]` block)
- Test: `tests/test_dev_config_process_collector_module_load.py`

`tests/test_config_example.py::test_example_config_worker_names_match_dev_config` asserts
the two worker-name sets are equal, so both files MUST change together.

- [ ] **Step 1: Write the failing dev-config presence test**
- [ ] **Step 2: Run it; expect FAIL (name absent)**
- [ ] **Step 3: Add the `config.py` entry and the TOML block**
- [ ] **Step 4: Run `tests/test_dev_config_process_collector_module_load.py` and `tests/test_config_example.py`; expect PASS**
- [ ] **Step 5: Commit** — `feat(config): register process_collector_module_load worker`

---

### Task 3: `NOT IN` tokenizer fix in the YAML rule loader

**Files:**
- Modify: `inspectord/rules/yaml_loader.py`
- Test: `tests/rules/test_yaml_loader.py`

`_LEAF_OP` advertises `NOT\s+IN` as a leaf operator, but `_BOOL_TOKEN_RE`
(`\bAND\b|\bOR\b|\bNOT\b`) splits the expression on `NOT` *before* leaves are
evaluated, so a `path NOT IN [...]` leaf never reaches `_eval_leaf` intact.
Verified broken on `main`: `process.name NOT IN ["modprobe"]` evaluates to
`False` for `process.name == "curl"` (it should be `True`), because the
tokenizer yields `["process.name", "NOT", 'IN ["modprobe"]']` and both halves
resolve to `False`/`True` folded under AND.

Task 4's `proc.kernel_module_loaded_unknown` rule needs this operator, so fix it.

- [ ] **Step 1: Write the failing regression test** in `tests/rules/test_yaml_loader.py`:
  a `NOT IN` leaf must be true for an absent value and false for a present one,
  both standalone and as the tail of an `AND` chain; the existing `NOT <leaf>`
  prefix form must keep working.
- [ ] **Step 2: Run; expect FAIL**
- [ ] **Step 3: Fix** — make the boolean tokenizer not claim a `NOT` that begins a
  `NOT IN` operator:

```python
_BOOL_TOKEN_RE = re.compile(r"\bAND\b|\bOR\b|\bNOT\b(?!\s+IN\b)")
```

- [ ] **Step 4: Run the whole rules test suite; expect PASS**
- [ ] **Step 5: Commit** — `fix(rules): make the advertised NOT IN leaf operator reachable`

---

### Task 4: the two kernel-module starter-pack rules

**Files:**
- Create: `inspectord/rules/starter_pack/proc_kernel_module_from_memory.yaml`
- Create: `inspectord/rules/starter_pack/proc_kernel_module_loaded_unknown.yaml`
- Test: `tests/rules/starter_pack/test_proc_kernel_module_rules.py`

- [ ] **Step 1: Write the failing tests** — matrix:
  - `from_memory` fires on `init_module` at severity `high`
  - `from_memory` does NOT fire on `finit_module`
  - `loaded_unknown` fires on `finit_module` + `curl` at severity `medium`
  - `loaded_unknown` does NOT fire for `modprobe` or `systemd-udevd`
  - `loaded_unknown` does NOT fire on `init_module`
  - neither fires for a different module or a different action

- [ ] **Step 2: Run; expect FAIL (missing YAML files)**

- [ ] **Step 3: Write `proc_kernel_module_from_memory.yaml`**

```yaml
version: 1.0.0
id: proc.kernel_module_from_memory
name: "kernel module loaded from memory"
severity: high
category: process
why: |
  A process loaded a kernel module image straight from anonymous memory via
  init_module(2), with no file descriptor. Since kernel 3.8 every normal
  loader — kmod/modprobe, systemd-udevd, dracut — uses finit_module(2) with a
  file descriptor, so this is the fd-avoidant path a rootkit loader picks
  precisely to avoid leaving a file on disk.
false_positives:
  - "Very old or bespoke tooling that still calls init_module(2) directly (pre-3.8-era loaders, some embedded or vendor installers)."
  - "A test harness or fuzzer deliberately exercising init_module(2) — the tracepoint fires before the kernel validates the image, so failed calls are recorded too."
detect:
  any_of:
    - event.module == "process_collector_module_load" AND event.action == "module_load_attempt" AND process.module_load_variant == "init_module"
short: "kernel module loaded from memory by {process.name} (pid {process.pid})"
detail: "{process.name} (pid {process.pid}, uid {user.id}) called init_module(2), loading a kernel module image from anonymous memory with no file descriptor."
labels: [process, kernel_module, rootkit]
```

- [ ] **Step 4: Write `proc_kernel_module_loaded_unknown.yaml`**

```yaml
version: 1.0.0
id: proc.kernel_module_loaded_unknown
name: "kernel module loaded by an unknown loader"
severity: medium
category: process
why: |
  A process outside the usual set of module loaders (modprobe, insmod, kmod,
  systemd-udevd, systemd, dracut, mkinitcpio) called finit_module(2) to load a
  kernel module. Kernel modules run with full kernel privilege, so an
  unexpected loader is worth a look at who it was and what it loaded.
false_positives:
  - "A package install or a pacman hook loading a module through a helper binary not in the known-loader list."
  - "A hypervisor or container runtime (libvirtd, dockerd, VirtualBox/VMware setup helpers) loading its kernel modules directly."
  - "A manual modprobe run through a wrapper or shell function, so the caller comm is the wrapper rather than modprobe."
detect:
  any_of:
    - event.module == "process_collector_module_load" AND event.action == "module_load_attempt" AND process.module_load_variant == "finit_module" AND process.name NOT IN ["modprobe", "insmod", "kmod", "systemd-udevd", "systemd", "dracut", "mkinitcpio"]
short: "kernel module loaded by {process.name} (pid {process.pid})"
detail: "{process.name} (pid {process.pid}, uid {user.id}) called finit_module(2); this is not one of the usual module loaders on this host."
labels: [process, kernel_module]
```

- [ ] **Step 5: Run the rule tests; expect PASS**
- [ ] **Step 6: Commit** — `feat(rules): kernel-module load starter-pack rules`

---

### Task 5: root-only live end-to-end test

**Files:**
- Create: `tests/workers/test_process_collector_module_load_live.py`

Mirrors `tests/workers/test_process_collector_ptrace_live.py`, but the trigger is
the pair of raw syscalls used by the merged native test
`tests/test_native_loader.py::test_module_load_stream_captures_both_syscall_variants`:

- `libc.syscall(313, -1, b"", 0)` — `finit_module` with an invalid fd → `EBADF`
- `libc.syscall(175, None, 0, b"")` — `init_module` with a NULL image → `ENOEXEC`

`sys_enter` fires before the kernel validates anything, so **no module is ever
loaded**. The test also pins itself off CPU 0 for the same reason the native
test does: aya attaches the tracepoint with a single perf event on CPU 0, and
these tracepoints only invoke the kernel's perf handler on CPUs with a
registered event — the loader registers prog-less per-CPU events to un-gate
them, and running off CPU 0 is what proves that path works rather than passing
by scheduler luck.

- [ ] **Step 1: Write the test** — `@pytest.mark.ebpf_load` +
  `@pytest.mark.skipif(os.geteuid() != 0, ...)`, drive the real
  `ProcessModuleLoadStream` through the real `ProcessCollectorModuleLoadWorker`
  into a `BytesIO` sink, then assert on the emitted NDJSON: one
  `module_load_attempt` event per variant with `process.pid == os.getpid()`,
  `user.id == "0"`, the right `raw.source` / `raw.variant`, `module_load_fd`
  of `-1` for both, and `ts > "2026-01-01"`.
- [ ] **Step 2: Run it as root**

```sh
sudo .venv/bin/python -m pytest -m ebpf_load tests/workers/test_process_collector_module_load_live.py -v
```

Expected: 1 passed.

- [ ] **Step 3: Commit** — `test(workers): root-only live module-load end-to-end test`

---

### Task 6: full gates

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

- **Spec coverage:** §4's deliverables map to Tasks 1 (worker + `module_load_attempt`), 2 (wiring), 4 (the two reworked rules). The §4 "resolved 2026-08-18" decisions (no module name, no params string) are honored by consuming exactly the PR1 record and adding nothing.
- **Two-file wiring:** `config.py` and `config.example.toml` change in the same commit because `test_config_example.py` asserts set equality.
- **Loader-not-module framing:** both rules key off the *caller*, never a module name — the collector does not have one, by design.
- **Out-of-plan change:** the `NOT IN` tokenizer fix (Task 3) is required for the second rule to be expressible. It is a real bug (the operator is in the grammar but unreachable), kept to a one-line regex change with its own regression test and its own commit.
