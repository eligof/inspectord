# scanner_runner — the `av.*` starter rules (PR3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the `scan_finding` events the scanner adapters already emit into alerts, by adding
the three `av.*` rules parent spec §21 names: `av.rkhunter_warning_or_worse`,
`av.yara_high_confidence_hit` (both YAML) and `av.aide_change_outside_pkgmgr` (Python, because it
needs a time window).

**Architecture:** Unchanged. Nothing in the worker, the runner or the adapters is touched. The
starter pack is auto-discovered — `supervisor.py` walks `inspectord/rules/starter_pack` for
`*.yaml` and `python_loader.load_python_rules` imports every module exporting `RULE` — so there is
no registry file, no `__init__` list and no packaging change (`pyproject.toml` already globs
`inspectord/rules/starter_pack/**/*`).

**Tech Stack:** Python 3.14 stdlib only, the existing YAML rule grammar, pytest. **No new
third-party dependencies.**

**Spec:** `docs/superpowers/specs/2026-08-19-scanner-runner-design.md` — §3 decision 7 (severity
comes from rules, not the worker), decision 8 (no scanner-database updates, ever), §4.2 (the event
shape), §6 (the PR3 line). Parent spec `docs/superpowers/specs/2026-05-24-local-inspection-design.md`
§21 fixes the three rule ids.

**Explicitly NOT in this PR:** `av.clamav_signature_hit` (§21 lists it; ClamAV is out of scope per
design §7), the `scan_run` state table, the Antivirus panel, staleness rules (§4.3 has no producer
yet), any change to an adapter or to the runner.

---

## The constraint that shapes all three rules

The three parsers were hardened on this branch's predecessor because **a filename can forge a
parser line**. Each adapter's module docstring records what was measured:

| adapter | a forged line can… | it cannot… |
| --- | --- | --- |
| rkhunter | add one attacker-worded finding beside a genuine one | flip `failure`→`findings`, or suppress a real warning |
| YARA | add a finding with attacker-chosen **rule name, meta and `file.path`**; truncate a genuine one | change the outcome classification, or suppress a real match |
| AIDE | invent a finding on an attacker-chosen path/change kind, mislabel a section, **suppress** entries after it | change the outcome (the verdict is the exit bitmask, never the report) |

So `threat.indicator.value`, `event.message`, `raw.line` and (for YARA) `file.path` and
`threat.indicator.severity` are all **attacker-influenceable text**. The rules therefore key on
**structural** fields wherever possible:

- `event.module == "scanner_runner"` — set by the runner, not by a parser.
- `event.action == "scan_finding"` — likewise.
- `threat.indicator.source` — set by the runner from `run.scanner`, i.e. **which adapter ran**,
  never from scanner output. This is the field that says "rkhunter said so", and it is
  unforgeable from inside a scan.

Only rule 2 must look at scanner-supplied text, because "high confidence" has no other
representation in the data. That is stated in its `why` and `false_positives` rather than papered
over. All three rules interpolate scanner text into their `short`/`detail` — unavoidable, since an
alert that will not say *what* was found is useless — and the display text is already stripped of
control characters by `scanners/base.sanitize_text`, so it can mislead a reader but cannot
re-program a terminal or a log consumer.

---

## Rule 1 — `av.rkhunter_warning_or_worse` (YAML)

**"or worse" does not exist.** rkhunter grades nothing: every report is a `Warning:` block, and the
adapter sets `Finding.severity = None` for exactly that reason (decision 7 — the worker invents no
severity). So the rule is "any rkhunter finding", keyed purely structurally:

```
event.module == "scanner_runner" AND event.action == "scan_finding"
  AND threat.indicator.source == "rkhunter"
```

**Severity `medium`, not `high`** — measured, not guessed. `rkhunter --check --enable properties`
run as root on this host (rkhunter 1.4.6-4, 2026-08-19) reports **five** warnings on a machine with
nothing wrong with it. Firing `high` five times a day on a healthy Arch box teaches the user to
ignore the rule, which is worse than not shipping it.

`false_positives` records exactly what was measured here, because that is what the user reads at
03:00 during an incident:

1. `/usr/bin/egrep`, `/usr/bin/fgrep` and `/usr/bin/ldd` "has been replaced by a script" — on Arch
   these genuinely **are** shell scripts (`egrep`/`fgrep` are POSIX-shell wrappers shipped by
   `grep`, `ldd` is a bash script shipped by `glibc`). Three warnings, every run, on a clean system.
2. `Checking for prerequisites [ Warning ]` — "The file of stored file properties (rkhunter.dat)
   does not exist". The file-properties baseline has never been initialised, and inspectord will
   never initialise it: `--propupd` rewrites a system baseline file, which decision 8 and the
   adapter both forbid. Until the user runs it themselves, this warns on every run.
3. The standing `--propupd` responsibility banner rkhunter prints next to (2) is itself a
   `Warning:` block, so it becomes its own finding.
4. rkhunter's mirror database is never updated (decision 8: no egress), so warnings driven by
   stale bundled data are expected and are not evidence of anything.
5. The forgery bound: the warning **text** in `short`/`detail` can carry one attacker-chosen
   fabricated block riding inside a genuine detection. The *fact that rkhunter warned* is
   trustworthy; the wording is not.

## Rule 2 — `av.yara_high_confidence_hit` (YAML)

**"High confidence" = the matching YARA rule declared `severity` meta of `high` or `critical`.**
That is the only confidence signal in the data: `-m` prints the rule's meta, the adapter lifts
`severity` verbatim into `threat.indicator.severity` (decision 7, "the SCANNER's own severity,
preserved as data"), and nothing else in a `scan_finding` distinguishes a strong hit from a weak
one. Rule *name* wording was rejected as a discriminator — it is exactly the field a forged match
line controls, and it would also hard-code one naming convention onto rulesets the user writes.

Comparison is `MATCHES "^(?i:high|critical)$"` rather than `IN ["high", "critical"]`: no rulesets
ship yet (`/var/lib/inspectord/yara` is empty in this build), the user will import third-party
`.yar` files, and `severity = "High"` is common enough that a case-sensitive `IN` would silently
never fire. The regex is anchored and fixed, so it is a literal set membership test, not a pattern
matched against attacker input in any interesting sense.

**When a rule declares no `severity` meta, this rule does not fire — at all.** The key is simply
absent from `threat.indicator` (the runner omits it when `Finding.severity is None`), the leaf
resolves to `None`, and `MATCHES` is false. That is deliberate — "high confidence" cannot be
asserted about a rule that asserts nothing — but it is a **silent** non-detection, so it is stated
in the first line of `why` and repeated in `false_positives`: the hit is still recorded as a
`scan_finding` event and is visible in the events view; only the alert is withheld. A numeric
convention (`severity = 3`, which yara prints as `severity =3`) is likewise not recognised.

Severity `high`; the rule only fires when a ruleset author already said the hit is severe.

**This is the rule that depends on scanner-supplied text**, and its `why` says so plainly: both the
matched rule name and the meta block arrive on the same untrusted stdout line as the matched path.
Per the adapter docstring, a forged line needs a *genuine* match to ride on — but a genuine match
is cheap to self-plant (write a file that trips a shipped rule), so an unprivileged local user who
can `mkdir` inside the scanned tree can manufacture an alert naming an attacker-chosen rule,
severity and path. Recorded as a false positive, in those words.

## Rule 3 — `av.aide_change_outside_pkgmgr` (Python)

An AIDE-reported change is interesting when **no package-manager transaction happened around it**;
a change during a `pacman` upgrade is expected. The YAML grammar has no time-window syntax and
only Python rules receive `EvalContext.history`, so this is a Python rule.

Suppressing actions (emitted by `parsers/pacman.py` via `log_tailer`, each carrying `package.name`
and pacman's own timestamp): `package_installed`, `package_upgraded`, `package_removed`,
**`package_reinstalled`**. The parser emits the fourth and a reinstall rewrites files exactly like
an upgrade, so leaving it out would alert on every `pacman -S <installed-pkg>`.

**Window: 300 s, as a module-level constant, and it is the whole horizon rather than a guess.**
`RuleEngine._HISTORY_WINDOW` is `timedelta(seconds=300)` and `_trim_history` drops anything older
on every event, so 300 s is the widest window this rule can *actually answer*; a larger constant
would read as a promise the engine cannot keep, and would silently behave as 300. Within that
ceiling, using all of it is right rather than conservative: a `pacman -Syu` writes its ALPM lines
across the minutes it spends unpacking, and an AIDE scan running concurrently can report a changed
file several minutes after the transaction line that explains it. A unit test pins
`_PKGMGR_WINDOW_S <= rule_engine._HISTORY_WINDOW` so the coupling cannot rot.

The honest limitation, which goes in `false_positives` in these terms: this suppresses the
**overlap** case (a scan running during or just after a transaction), not the general one. A change
caused by an upgrade that finished *hours* before the nightly scan is **not** suppressed and will
alert. Closing that needs a persisted package-transaction index, which does not exist; until it
does, expect the morning after a `pacman -Syu` to be noisy.

Direction is backwards-only: `EvalContext.recent_events` compares against `ctx.event.ts - window`
and history holds only events already seen, so "around" reduces to "shortly before". Package events
carry **pacman's own** timestamp, not their arrival time, which is the correct clock for this
comparison and worth a comment.

Severity `medium`, category `integrity`; keyed structurally on
`module == "scanner_runner"`, `action == "scan_finding"`, `threat.indicator.source == "aide"`, and
never on the report wording — which matters more here than anywhere else, since AIDE's parser is
the one whose forged line can *suppress* a genuine entry.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `inspectord/rules/starter_pack/av_rkhunter_warning_or_worse.yaml` | **New.** Rule 1. |
| `inspectord/rules/starter_pack/av_yara_high_confidence_hit.yaml` | **New.** Rule 2. |
| `inspectord/rules/starter_pack/av_aide_change_outside_pkgmgr.py` | **New.** Rule 3, exporting `RULE`. |
| `tests/rules/starter_pack/test_av_scanner_rules.py` | **New.** Firing + non-firing cases for rules 1 and 2. |
| `tests/rules/starter_pack/test_av_aide_change_outside_pkgmgr.py` | **New.** Window, boundary, empty-history and structural cases for rule 3. |

Nothing else changes: no registry, no `__init__`, no `pyproject.toml`, no config. `tests/rules/test_registry.py` enumerates only its own fixture rules, so no rule-count test needs updating.

---

### Task 1: the plan itself

- [x] Write this document and commit it before touching code.

---

### Task 2: `av.rkhunter_warning_or_worse`

**Files:** `inspectord/rules/starter_pack/av_rkhunter_warning_or_worse.yaml` (new),
`tests/rules/starter_pack/test_av_scanner_rules.py` (new)

- [x] **Step 1: write the failing tests** — a `_finding_event(...)` helper mirroring
      `runner._emit_finding`'s exact output shape (module `scanner_runner`, action `scan_finding`,
      severity `low`, `threat={"indicator": {...}}`, `raw={"scanner":…, "run_id":…, "line":…}`):
  - fires on an rkhunter finding, `severity == "medium"`, `rule_id == "av.rkhunter_warning_or_worse"`;
  - fires on a path-less (`category="process"`) rkhunter finding too — the check-name shape;
  - does **not** fire on an `aide` finding, a `yara` finding (wrong `threat.indicator.source`);
  - does **not** fire on `module == "fim_watcher"` (wrong module);
  - does **not** fire on `action == "scan_completed"` / `scan_skipped` (wrong action);
  - the rendered `short`/`detail` carry the check name and the message.
- [x] **Step 2: run; expect FAIL** (the rule file does not exist).
- [x] **Step 3: write the YAML**, with the five measured `false_positives` above.
- [x] **Step 4:** green; full unit gate; **commit** — `feat(rules): av.rkhunter_warning_or_worse`.

### Task 3: `av.yara_high_confidence_hit`

**Files:** `inspectord/rules/starter_pack/av_yara_high_confidence_hit.yaml` (new), same test file.

- [x] **Step 1: extend the tests** —
  - fires for `threat.indicator.severity == "high"` and `"critical"`, `severity == "high"`;
  - fires for `"High"` / `"CRITICAL"` (the case-insensitivity decision, pinned);
  - does **not** fire for `"low"` / `"medium"` / `"informational"`;
  - does **not** fire when the `severity` key is **absent** — the documented behaviour, asserted so
    it cannot change silently;
  - does **not** fire for `"3"` (numeric meta), with a comment naming it as documented, not a bug;
  - does **not** fire on an rkhunter or aide finding carrying `severity="high"` (wrong source);
  - does **not** fire on another module or another action.
- [x] **Step 2: FAIL. Step 3: write the YAML. Step 4:** green; gate; **commit** —
      `feat(rules): av.yara_high_confidence_hit`.

### Task 4: `av.aide_change_outside_pkgmgr`

**Files:** `inspectord/rules/starter_pack/av_aide_change_outside_pkgmgr.py` (new),
`tests/rules/starter_pack/test_av_aide_change_outside_pkgmgr.py` (new)

- [x] **Step 1: write the failing tests** —
  - fires with an **empty** history;
  - fires when the nearest package event is **outside** the window;
  - does **not** fire when a package event sits **inside** the window;
  - **boundary, both sides**: at exactly `window` (inclusive — `recent_events` uses `>=`) it
    suppresses; one second past it does not. Parametrised over all four `package_*` actions;
  - does not fire for a `yara`/`rkhunter` finding, another module, another action;
  - a non-package event inside the window (e.g. `ssh_login_failed`) does not suppress;
  - `_PKGMGR_WINDOW_S <= rule_engine._HISTORY_WINDOW.total_seconds()` — the coupling guard;
  - the `Match` carries `primary_entity_kind == "file"` and the reported path.
- [x] **Step 2: FAIL. Step 3: write the module. Step 4:** green; gate; **commit** —
      `feat(rules): av.aide_change_outside_pkgmgr`.

### Task 5: full gates

- [x] `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q` (exit 0) ·
      `.venv/bin/ruff check inspectord tests` · `.venv/bin/ruff format --check inspectord tests` ·
      `.venv/bin/mypy inspectord`. Then report. **Do not push, do not open a PR, do not merge.**

---

## Self-Review notes

- **The rkhunter false positives were re-measured on this host**, not copied from the brief:
  `sudo .venv/bin/python -m pytest` driving `RkhunterAdapter` with `--enable properties` (rkhunter
  1.4.6-4, 2026-08-19) returned exactly five findings — prerequisites/`rkhunter.dat`, the
  `--propupd` banner, and egrep/fgrep/ldd. Nothing ran `--propupd`, `--update` or `--versioncheck`.
- **Rule 3's window is capped by the engine, not by taste.** If the 300 s ceiling is ever raised,
  the guard test fails loudly rather than the rule quietly under-correlating.
- **`av.clamav_signature_hit` is deliberately absent** — §21 lists it, design §7 puts ClamAV out of
  scope, and there is no adapter to produce its events.
- **No live/root test is added by this PR.** These rules are pure functions over Event objects; the
  live scanner behaviour they encode is already pinned by
  `tests/workers/test_scanner_runner_live_scanners.py`. The root run above was verification, not a
  new test.

---

## Execution notes (what actually changed vs. the plan)

Executed 2026-08-19 on branch `scanner-runner-pr3`. All five tasks done; four commits (plan, then
one per rule). Final gate: **1163 passed / 11 skipped / 8 deselected**, ruff check + format clean,
mypy clean over 138 source files. Registry discovery verified end-to-end: the starter pack now
loads 16 rules with unique ids, including all three `av.*` ones.

Deltas worth a reviewer's eye:

1. **The forward edge of rule 3's window was left unbounded, and a test now says so.** The plan
   described the window as "backwards only", assuming `recent_events` would exclude a package event
   timestamped *after* the finding. It does not — `EvalContext.recent_events` sets a lower bound
   only. Rather than adding an upper bound, the behaviour was kept and justified: a finding's `ts`
   is stamped when the runner emits it, at the **end** of a scan that took minutes, so a pacman
   line timestamped a few seconds later is still concurrent with that scan and explains the change
   just as well. `test_a_transaction_timestamped_just_after_the_finding_also_suppresses` pins it.
2. **`false_positives` on the Python rule is a module-level tuple**, not a class attribute list —
   ruff's `RUF012` rejects a mutable class-attribute default, and `ClassVar` would have been the
   only alternative. `Match` still receives a `list`.
3. **The rkhunter measurement found a fifth warning** the brief did not mention: rkhunter's standing
   `--propupd` responsibility notice is itself a `Warning:` block and therefore its own finding. It
   is in `false_positives` as its own entry.
4. **Not done, deliberately:** `av.clamav_signature_hit` (no adapter, ClamAV out of scope); any
   staleness rule (§4.3 has no producer); any live/root test — these rules are pure functions over
   `Event` objects, and the scanner behaviour they encode is already pinned by
   `tests/workers/test_scanner_runner_live_scanners.py`. The root rkhunter run performed here was
   verification of the false-positive text, not a new committed test.
