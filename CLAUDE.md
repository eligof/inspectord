# inspectord — project guide

Personal Linux endpoint security console: Python core + Rust/eBPF hot paths. Single-user,
privacy-first (no telemetry, no data egress, minimal attack surface). The design spec is the
source of truth — reference its section numbers when discussing design:
`docs/superpowers/specs/2026-05-24-local-inspection-design.md`; implementation plans live in
`docs/superpowers/plans/`. Phases 0–1 are complete; the project is currently in **Phase 2**
(behavioral & state collectors).

## Build & test

Python (use the project venv):

- Unit tests: `.venv/bin/python -m pytest -m "not integration and not ebpf_load"`
- Lint / format / types: `.venv/bin/ruff check inspectord tests` ·
  `.venv/bin/ruff format --check inspectord tests` · `.venv/bin/mypy inspectord`
- Rebuild the native extension after Rust changes: `.venv/bin/maturin develop`

Rust (the toolchain is managed under puccinialin and is **not on PATH by default**):

```sh
export CARGO_HOME=/home/eli/.cache/puccinialin/cargo RUSTUP_HOME=/home/eli/.cache/puccinialin/rustup
export PATH="/home/eli/.cache/puccinialin/cargo/bin:$HOME/.cargo/bin:$PATH"
cargo test -p inspectord-native --lib   # also compiles the eBPF crate via build.rs
cargo fmt --all -- --check
cargo clippy -p inspectord-native --lib
```

Root-only eBPF verifier smoke tests are skipped as non-root; run e.g.
`sudo .venv/bin/python -m pytest tests/test_native_loader.py -k <name>`.

## Development workflow

- **`main` is PR-only** (enforced branch protection: the `lint-and-test` check must pass, no
  direct pushes, no admin bypass). Flow: branch → push → `gh pr create` → wait for CI →
  `gh pr merge --squash --delete-branch`.
- **Build features with `superpowers:subagent-driven-development`**: write a short plan derived
  from the spec, then per task dispatch a fresh implementer subagent → spec-compliance review →
  code-quality review. Right-size it — a small single-worker feature is ~2 tasks; apply trivial
  review nits inline rather than spawning extra subagents.
  - Harness caveat: continuing a prior subagent (`SendMessage`) is unavailable here, so
    review-fix loops dispatch a *fresh* fix-subagent with the findings.
- **New eBPF collectors land as two PRs**: native (BPF program + PyO3 stream class) first, then
  the Python worker + `dev_config` wiring. Pure-Python collectors (e.g. `kmod_watcher`,
  `listening_socket_snapshotter`) are a single PR. Mirror an existing worker — the
  `outbound_connection_tracker` worker is the cleanest template.
- **TDD throughout.** All CI gates must be green before merge: `lint-and-test`, CodeQL,
  cargo-audit, dependency-review. Dependabot is enabled (grouped weekly update PRs).
