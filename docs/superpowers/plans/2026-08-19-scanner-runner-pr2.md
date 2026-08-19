# scanner_runner — rkhunter + YARA adapters (PR2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the **rkhunter** and **YARA** adapters to the `scanner_runner` worker shipped in PR1,
wired into the dev config and disabled by default, with parsers that are pure functions over
**output captured from the tools actually installed on this machine**.

**Architecture:** Unchanged from PR1 — the runner owns scheduling, single-flight, timeouts and
process-group cleanup; adapters own scanner-specific knowledge. This PR **does change the adapter
Protocol**, twice, because measuring the real tools proved the PR1 surface cannot express them
(see "The two Protocol changes" below).

**Tech Stack:** Python 3.14 stdlib only (`re`, `os`, `pathlib`), pytest. **No new third-party
dependencies. No network access of any kind** (design decision 8: no `rkhunter --update`, no
`freshclam`, and no `--propupd` either — that rewrites a system baseline file, which is not a
scanner's job).

**Spec:** `docs/superpowers/specs/2026-08-19-scanner-runner-design.md` — §3 decisions 8, 10, 11,
13, 14; §4.1 (adapters), §4.2 (events), §6 (the PR2 line), §8 (testing).

**Explicitly NOT in this PR:** the `av.*` detection rules (PR3), ClamAV, quarantine, on-demand
runs, cron, state tables, panels, `--propupd`, any scanner-database update.

---

## Measured behavior — three spec assumptions in §4.1 are wrong

Every claim below was reproduced on this machine (yara 4.5.7, AIDE 0.19.3, rkhunter as root via
`sudo .venv/bin/python -m pytest`, since `/usr/bin/rkhunter` is `0700 root:root`).

### rkhunter — the exit code cannot distinguish a detection from a refusal

`man rkhunter`: *"rkhunter will return a non-zero exit code if any error or warning occurs."*
So §4.1's "Exit 0 = no warnings, 1 = warnings found, 2 = error" is wrong. Measured, all with
`--check --sk --nocolors --rwo --nomow --logfile <tmp>`:

| invocation | exit | stdout |
| --- | --- | --- |
| `--enable properties` | **1** | 5 `Warning: ` blocks (a real detection) |
| `--enable passwd_changes` | **1** | 1 `Warning: ` block |
| `--enable hidden_ports` / `promisc` / `immutable` | **0** | *(empty)* |
| `--disable all` (invalid argument) | **1** | `'all' cannot be used in the disabled test list.` |
| `--enable bogus_test` | **1** | `Unknown enabled test name given: bogus_test` |
| `--configfile /nonexistent/rk.conf` | **1** | `Unable to find configuration file: /nonexistent/rk.conf` |
| `--nolog` **with** `--rwo` | **1** | `The logfile has been disabled - unable to report warnings.` |

A misconfigured scan and a rootkit detection are **both exit 1**. Classifying on the code alone
would report "the scanner refused to run" as "the scanner found something" — the exact inverse of
the bug decision 10 exists to prevent.

The discriminator is the **output**: with `--report-warnings-only` a healthy run prints *only*
`Warning: ` blocks, and every refusal prints a diagnostic with no `Warning: ` line at all.

> Note the last row: **`--nolog` is incompatible with `--report-warnings-only`.** rkhunter needs
> its log file to report warnings from. The adapter therefore never passes `--nolog`; the log
> destination is a config key instead (`logfile`), which is also what lets the live tests keep
> their log out of `/var/log`.

### YARA — §4.1's argv does not work at all

`yara -r -w <rules-dir> <target>` fails: the rules argument must be **file(s)**, never a directory
(`rules(1): error: input in flex scanner failed`, exit 1). The real grammar is
`yara [OPTIONS] RULES_FILE... FILE|DIR|PID` — many rules files, **exactly one** target, last.
Passing two targets makes yara read the second as a rules file and fail to compile it.

| observation | measured |
| --- | --- |
| plain match line | `Demo_Rule /abs/path/hit.txt` |
| with `-m` | `Demo_Rule [severity="high",description="demo, with spaces and \"quotes\"",score =42] /abs/path/hit.txt` |
| empty meta with `-m` | `Second_Rule [] /abs/path/both.txt` |
| with `-s` | adds indented `0x6:$a: SUSPICIOUS_MARKER` lines — **not** findings |
| no match | exit 0, no output |
| matches | exit **0** |
| unreadable file inside a scanned directory | `error scanning …: could not open file` on **stderr**, exit **0** |
| missing target / rules compile error / missing rules file | exit **1** |
| empty rules *file* | exit 0, no output (harmless) |

Note `score =42`: yara prints integer meta as `name =value` and string meta as `name="value"`, and
a meta string can contain commas and escaped quotes. Note also the measured path
`/…/tgt3/we ird/a]b c.txt` — a matched path can contain spaces **and** `]`, so the meta block must
be split with a quote-aware scanner, not a greedy/lazy `\[.*\]` regex.

### AIDE — the docstring is two codes short

Installed AIDE is **0.19.3**; its `man aide` `EXIT STATUS` documents **24 (Database error)** and
**25 (received SIGINT, SIGTERM or SIGHUP)** on top of 14–23. `interpret_exit`'s
`0 → clean / 1..7 → findings / else → failure` range check already handles both, so **no behavior
changes** — but the enumerated list in the module docstring stops at 23. Fixed here, and the table
test grows two rows. Also verified: `aide --config /nonexistent --check` exits **18**, and an
invalid flag exits **15**.

---

## The two Protocol changes (and why the PR1 surface cannot work)

`ScannerAdapter` in `scanners/base.py` changes from three methods to four:

```python
def argv(self, config: Mapping[str, Any]) -> list[str]: ...
def preflight(self, config: Mapping[str, Any]) -> str | None: ...          # NEW
def interpret_outcome(self, code: int, stdout: str, stderr: str) -> ScanOutcome: ...  # was interpret_exit(code)
def parse(self, stdout: str, stderr: str) -> list[Finding]: ...
```

**1. `interpret_exit(code)` → `interpret_outcome(code, stdout, stderr)`.** Forced by the rkhunter
measurement above: exit 1 means both "found rootkit evidence" and "refused to run", and only the
output separates them. The rename is deliberate rather than a silent signature widening — the old
name would be a lie, and renaming makes every call site and test fail loudly instead of quietly
passing the wrong thing. AIDE's implementation takes the two new parameters and `del`s them, with
a docstring saying why it does not need them (its bitmask is self-describing).

**2. New `preflight(config) -> str | None`** — `None` means "ready to run", any string is a
**skip reason**. Forced by YARA: the rules directory we ship (`/var/lib/inspectord/yara/`, §30.6)
can be missing or empty, and there is no argv that expresses "nothing to do". Without preflight the
choices are a crash inside `argv()` or an argv that makes yara read the *target* as a rules file
and exit 1 — a confusing `failure` for a perfectly ordinary state. With it, the runner emits
`scan_skipped` with `reason="rules_empty"`, which is exactly the shape decision 14 already
established for a missing binary. AIDE and rkhunter return `None`.

Runner changes are correspondingly small, in `runner.py` only:

- `_start_run`: after the `shutil.which` probe, call `adapter.preflight(config)`; a non-`None`
  reason takes the `_skip_slot(name, reason, now)` path (already written, already tested), and an
  exception from `preflight` becomes `reason="preflight_error"` — adapters promise not to raise,
  and the runner assumes they will anyway.
- `_classify`: pass `result.stdout` / `result.stderr` into `interpret_outcome`.

Everything else — scheduling, single-flight, timeouts, process-group kill, the finding cap, the
event shapes — is untouched.

### The shared outcome principle for output-driven adapters

Both new adapters classify identically, and the symmetry is deliberate:

| output has findings? | exit code | outcome |
| --- | --- | --- |
| yes | anything | `findings` |
| no | `0` | `clean` |
| no | non-zero | `failure` |

"Parsed findings win over the exit code" fails toward reporting a detection, never toward hiding
one; "no findings + non-zero" is the refusal/misconfiguration case and is always a `failure`, never
a silent clean. AIDE keeps its own bitmask logic — its exit status is unambiguous and needs no
output.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `inspectord/workers/scanner_runner/scanners/base.py` | Protocol: rename `interpret_exit` → `interpret_outcome(code, stdout, stderr)`, add `preflight`. Document the shared outcome principle. |
| `inspectord/workers/scanner_runner/scanners/aide.py` | Rename the method; add `preflight` returning `None`; docstring gains exit codes 24 and 25 and the "verified against installed AIDE 0.19.3" note. **No behavior change.** |
| `inspectord/workers/scanner_runner/scanners/rkhunter.py` | **New.** `RkhunterAdapter`: argv, preflight (`None`), output-driven `interpret_outcome`, warning-block parser. |
| `inspectord/workers/scanner_runner/scanners/yara.py` | **New.** `YaraAdapter`: rules-dir → rules-file argv, preflight (missing/empty rules dir, missing target), `interpret_outcome`, match-line parser with quote-aware meta splitting. |
| `inspectord/workers/scanner_runner/scanners/__init__.py` | Register both in `default_adapters()`. |
| `inspectord/workers/scanner_runner/runner.py` | The two call-site changes above. |
| `inspectord/config.py` + `packaging/config.example.toml` | `rkhunter` and `yara` scanner blocks, **`enabled = false`** (kept in lockstep by `tests/test_config_example.py`). |
| `tests/workers/test_scanner_runner_aide_adapter.py` | Method rename; exit-code table gains 24 and 25; a `preflight` test. |
| `tests/workers/test_scanner_runner_runner.py`, `…_process_group.py` | Fake adapters follow the Protocol. New tests: preflight skip, preflight error. |
| `tests/workers/test_scanner_runner_rkhunter_adapter.py` | **New.** Pure-function tests over the captured fixtures. |
| `tests/workers/test_scanner_runner_yara_adapter.py` | **New.** Pure-function tests over the captured fixtures. |
| `tests/workers/test_scanner_runner_live_scanners.py` | **New.** Live tests: yara (no root, guarded by `shutil.which`), rkhunter (root-only). |
| `tests/test_dev_config_scanner_runner.py` | Both new scanners present and disabled. |

**Root-only marking:** the repo has exactly two pytest markers (`integration`, `ebpf_load`) and
neither fits — nothing here loads eBPF, and mismarking would make `-m ebpf_load` runs fail on a
host without rkhunter. The repo's own convention for a root-only non-eBPF test is
`@pytest.mark.skipif(os.geteuid() != 0, reason=…)` (used throughout `tests/test_native_loader.py`),
so that is what the rkhunter live tests use. They therefore **skip**, not fail, under the CI gate
`-m "not integration and not ebpf_load"`. As a second guard they also skip when
`shutil.which("rkhunter") is None`, which is automatically true as a non-root user because the
binary is `0700 root:root`.

---

### Task 1: the plan itself

- [x] Write this document and commit it before touching code.

---

### Task 2: Protocol change + AIDE follow-through

**Files:** `scanners/base.py`, `scanners/aide.py`, `runner.py`,
`tests/workers/test_scanner_runner_aide_adapter.py`, `tests/workers/test_scanner_runner_runner.py`,
`tests/workers/test_scanner_runner_process_group.py`

- [ ] **Step 1: Update the AIDE tests first** — call `interpret_outcome(code, "", "")`, add the
      `(24, failure)` and `(25, failure)` rows, and add
      `test_preflight_is_none_because_aide_needs_no_setup`.
- [ ] **Step 2: Run; expect FAIL** (`AttributeError: 'AideAdapter' object has no attribute
      'interpret_outcome'`).
- [ ] **Step 3: Change `base.py`** (rename + `preflight`, with the rationale in the docstrings),
      **`aide.py`** (rename, `del stdout, stderr`, `preflight` → `None`, docstring: codes 24/25,
      "verified against installed AIDE 0.19.3", the measured 18/15), and **`runner.py`** (pass the
      output to `interpret_outcome`; call `preflight` in `_start_run` with a `preflight_error`
      guard).
- [ ] **Step 4: Update the two fake adapters** in the runner tests, and add
      `test_preflight_reason_skips_the_scanner` (asserting `scan_skipped` with that exact reason
      and that the slot is consumed) plus `test_preflight_raising_is_reported_as_a_skip`.
- [ ] **Step 5:** full unit gate green. Commit — `refactor(scanner_runner): output-aware
      interpret_outcome + adapter preflight`.

---

### Task 3: the rkhunter adapter

**Files:** `scanners/rkhunter.py` (new), `scanners/__init__.py`,
`tests/workers/test_scanner_runner_rkhunter_adapter.py` (new)

**argv** — `rkhunter --check --skip-keypress --nocolors --report-warnings-only
--no-mail-on-warning` plus, from config: `--enable a,b`, `--disable a,b`, `--configfile <p>`,
`--logfile <p>`. Notes:

- `--report-warnings-only` makes stdout the exact finding set (decision 13: read stdout, never the
  log file).
- `--no-mail-on-warning` is **not optional**: a host `rkhunter.conf` with `MAIL-ON-WARNING` set
  would make our scan send mail off the box. That is egress, and §18.1/decision 8 do not permit
  inspectord to cause any. It is passed on every run.
- `--nolog` is never passed (it breaks `--rwo`, measured above); `logfile` redirects instead.
- No `--update`, no `--propupd`, ever (decision 8).

**interpret_outcome** — the shared principle: parse first; findings ⇒ `findings`; else `0` ⇒
`clean`; else ⇒ `failure`.

**parse** — a warning **block**, not a line:

- A block opens on a line starting at column 0 with `Warning:`.
- A **continuation line is indented**; while a block is open, indented non-empty lines are folded
  into that block's message. They must never become separate findings (the captured `--propupd`
  advisory is one warning spanning five lines).
- Any other non-indented line closes the block and is ignored (this is what drops
  `'all' cannot be used in the disabled test list.` — and dropping it is precisely what makes
  `interpret_outcome` call that run a failure).
- stderr is ignored entirely: it carries unrelated `grep: warning: stray \ before -` noise from
  rkhunter's own shell internals on this machine.
- `Checking for prerequisites               [ Warning ]` ⇒ `indicator_value` is the check name
  (`"Checking for prerequisites"`); otherwise the collapsed warning text, truncated. The first
  single-quoted absolute path in the header (`'/usr/bin/egrep'`) becomes `file.path` with
  `category="file"`; with no path the finding is `category="process"` per §4.2.
- `severity=None` — rkhunter grades nothing; every report is a "Warning". Decision 7 says the
  runner must not invent one, so the key is simply absent from `threat.indicator`.
- Value/message/raw are length-capped; scanner output is untrusted and a single line is
  attacker-influenceable.

- [ ] **Step 1: Write the failing tests**, fixtures verbatim from the captured runs:
      `PROPERTIES_WARNINGS` (5 blocks / continuations), `CLEAN` (empty), `DISABLE_ALL_ERROR`,
      `UNKNOWN_TEST_ERROR`, `NOLOG_ERROR`, `STDERR_NOISE`.
  - `test_argv_*` — the five mandatory flags; `--enable` joins a list with commas; a string is
    accepted as-is; `configfile`/`logfile` appear only when configured; **never `--nolog`,
    `--update` or `--propupd`**.
  - `test_interpret_outcome_table` — `(PROPERTIES_WARNINGS, 1) → findings`,
    `(DISABLE_ALL_ERROR, 1) → failure`, `(UNKNOWN_TEST_ERROR, 1) → failure`,
    `(NOLOG_ERROR, 1) → failure`, `("", 0) → clean`, `("", 1) → failure`,
    `(PROPERTIES_WARNINGS, 0) → findings`, `(PROPERTIES_WARNINGS, -9) → findings`.
  - `test_warning_exit_1_is_findings_not_failure` and
    `test_misconfiguration_exit_1_is_failure_not_findings` — the two named bugs, spelled out.
  - `test_parse_counts_five_warnings_not_nine` — the continuation-line trap.
  - `test_parse_extracts_the_check_name` / `…_the_quoted_path` / `…_category_process_without_path`.
  - `test_parse_ignores_stderr_noise`.
  - malformed: empty, `"\n\n\n"`, NUL/high bytes, a block truncated mid-continuation, a lone
    continuation line with no header, a 100 kB single line, `"Warning:"` with nothing after it.
- [ ] **Step 2: Run; expect FAIL** (`ModuleNotFoundError`).
- [ ] **Step 3: Write the adapter. Step 4:** tests green. **Step 5:** register in
      `default_adapters()`; gates; commit — `feat(scanner_runner): rkhunter adapter`.

---

### Task 4: the YARA adapter

**Files:** `scanners/yara.py` (new), `scanners/__init__.py`,
`tests/workers/test_scanner_runner_yara_adapter.py` (new)

**Resolving the rules-directory problem.** §30.6 ships rulesets in a *directory*; yara refuses a
directory. The adapter therefore expands the directory itself: every `*.yar` / `*.yara` file under
`rules_dir` (recursively, `sorted()` for a deterministic argv), each passed as its own
`RULES_FILE`, then exactly one target last:

```
yara -r -m -w <rules…> <target>
```

`-r` recursive, `-m` print meta (this is where `threat.indicator.severity` comes from — §4.2),
`-w` suppress compile warnings so stdout stays exactly the match set.

**One target, not a list.** §4.4's example config shows `"targets": ["/home", "/tmp"]`, which yara
cannot express: a second path is read as a rules file. Scanning N paths means N subprocesses, and
the runner is deliberately one-subprocess-per-run. So the adapter takes **`target`** (singular,
default `/home`) and multi-target support waits for a runner that can sequence sub-runs.
**Recorded as a deliberate deviation from §4.4**; an operator with two trees to scan points
`target` at a common ancestor. Silently scanning only `targets[0]` was rejected — a config key
that is half-ignored is worse than one that does not exist.

**preflight** returns `"rules_missing"` (no rules dir), `"rules_empty"` (no `*.yar`/`*.yara` in
it), `"target_missing"` (the target path does not exist — measured to be a bare exit 1, which would
otherwise be an unexplained `failure`), else `None`. `argv()` is defensive on its own too: an
`OSError` while listing yields no rule files rather than an exception.

**interpret_outcome** — the shared principle again. Non-zero with no matches is a compile error or
a bad target ⇒ `failure`. Exit 0 with matches ⇒ `findings`. Exit 0 with nothing ⇒ `clean`. And
unreadable files inside a scanned tree, measured as stderr-only with exit 0, do **not** fail the
run (scanning `/home` unprivileged always hits some).

**parse** — a match line starts at column 0 (indented lines are `-s` string matches and are
skipped): rule name, optional `[meta]`, absolute path. The meta block is split by a small
quote-aware scanner (`"` … `\"` aware) so that a `]` in a path or a `,` inside a meta string cannot
break it — both measured as real possibilities. `severity` from meta becomes `Finding.severity`
(the *scanner's* severity, preserved as data — decision 7); `indicator_type="yara_rule"`,
`indicator_value` = the rule name, `path` = the matched file, `category="file"`.

- [ ] **Step 1: Write the failing tests** with the captured fixtures (plain, `-m`, `[]`-meta,
      `-s`-with-string-lines, the `we ird/a]b c.txt` path, the stderr `error scanning …` line).
  - `test_argv_expands_the_rules_directory_to_files` (sorted, `.yar` **and** `.yara`, non-rule
    files ignored, target last, exactly one target).
  - `test_argv_never_passes_a_directory_as_rules` — the §4.1 bug, named.
  - `test_preflight_*` — missing dir, empty dir, missing target, ready.
  - `test_interpret_outcome_table` — matches/0 ⇒ findings, empty/0 ⇒ clean, empty/1 ⇒ failure,
    matches/1 ⇒ findings.
  - `test_parse_reads_severity_from_meta`, `test_parse_handles_empty_meta`,
    `test_parse_skips_indented_string_match_lines`,
    `test_parse_handles_a_path_with_spaces_and_a_bracket`,
    `test_parse_handles_commas_and_escaped_quotes_inside_meta`.
  - malformed: empty, NUL bytes, `"Rule"` alone, `"Rule ["` truncated, a relative path, a 100 kB
    line, a line that is only brackets.
- [ ] **Step 2: FAIL. Step 3:** write it. **Step 4:** green. **Step 5:** register; gates; commit —
      `feat(scanner_runner): YARA adapter`.

---

### Task 5: dev-config + example-config wiring

**Files:** `inspectord/config.py`, `packaging/config.example.toml`,
`tests/test_dev_config_scanner_runner.py`

Both new scanners ship **`enabled = false`**, exactly like AIDE: a full `rkhunter --check` takes
minutes and a `/home` YARA sweep is unbounded I/O, so neither may run on a developer's machine
without an explicit opt-in. `interval_s = 86400`, `timeout_s = 1800` (spec §4.4), plus
`rules_dir`/`target` for yara so the shipped config documents where rules live.

- [ ] **Step 1:** failing presence + `enabled is False` tests for both. **Step 2:** FAIL.
      **Step 3:** wire both files in one commit (`test_config_example.py` asserts set equality).
      **Step 4:** green. **Step 5:** commit — `feat(config): register the rkhunter and yara
      scanners (disabled)`.

---

### Task 6: live tests

**File:** `tests/workers/test_scanner_runner_live_scanners.py` (new)

- **YARA, no root** (`shutil.which("yara")` guard only, so it runs in the ordinary gate): build a
  temp rules file with a `severity = "high"` meta and a temp target tree, drive the **whole
  worker** (`ScannerRunnerWorker` + real subprocess), and assert a `scan_finding` event carrying
  `threat.indicator.severity == "high"` and the matched path, followed by `scan_completed` with
  `outcome="success"`. A second test points `rules_dir` at an empty directory and asserts
  `scan_skipped` with `reason="rules_empty"` — the preflight path, end to end.
- **rkhunter, root-only** (`os.geteuid() != 0` skipif + `shutil.which` guard), adapter-level and
  bounded:
  - `--enable properties` with `--logfile` in `tmp_path` (measured 6.2 s; a full `--check` is
    minutes and is **not** run). Assert `interpret_outcome(...) is findings` and that a real
    `Warning:` became a `Finding` with a message. If this host genuinely has no warnings, skip
    with that reason rather than assert something untrue.
  - `--disable all` (invalid, measured 0.4 s): assert `interpret_outcome(...) is failure` and
    `parse(...) == []`. This is the regression test for the whole point of the PR — an ambiguous
    exit 1 that must **not** look like a detection.
  - Neither test writes to `/var/log`; nothing runs `--propupd` or `--update`.
- [ ] **Step 1:** write. **Step 2:** run non-root (yara passes, rkhunter skips). **Step 3:** run
      `sudo .venv/bin/python -m pytest tests/workers/test_scanner_runner_live_scanners.py -v` and
      record the real output in the report. **Step 4:** commit — `test(scanner_runner): live
      rkhunter and YARA adapter tests`.

---

### Task 7: full gates

- [ ] `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` (exit 0) ·
      `.venv/bin/ruff check inspectord tests` · `.venv/bin/ruff format --check inspectord tests` ·
      `.venv/bin/mypy inspectord`. Then report. **Do not push, do not open a PR, do not merge.**

---

## Self-Review notes

- **The rkhunter dependency manifest is NOT in this PR.** Spec §6's PR2 line owes one, and
  `inspectord/dependencies/manifest_files/` indeed has no `rkhunter.yaml` (only aide, auditd,
  ebpf_features, journald, libudev, yara) — but the task brief for this PR states the manifest
  already exists and explicitly forbids adding one. The explicit instruction wins; the gap is
  reported rather than silently filled.
- **Two Protocol changes in one PR** is the part a reviewer should push back on hardest. Both are
  forced by measurement, not taste: without `interpret_outcome` the rkhunter adapter cannot be
  written correctly at all, and without `preflight` the ordinary "no rules shipped yet" state is
  reported as a scanner failure. Neither can be deferred to PR3 without shipping a knowingly wrong
  adapter first.
- **Deliberate deviation from §4.4:** yara takes `target` (one path), not `targets` (a list).
- **Not done, deliberately:** §4.3 scanner-data staleness (still deferred from PR1 — rkhunter's
  mirror-db age would fit here, but it has no consumer until the `av.*` rules); yara options that
  are tempting but unrequested (`--skip-larger`, `--threads`, `--timeout`); rkhunter `--dbdir` /
  `--tmpdir` config keys. `-r` follows symlinks and yara 4.5.7 offers no flag to stop it — noted,
  not worked around.
