# Persistence collector (PR6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Follow TDD: write tests first, watch them fail, implement, watch pass, commit. Run gates before reporting done.

**Goal:** Ship the `persistence_snapshotter` collector — a pure-Python poll-snapshot worker that inventories the host's persistence mechanisms (cron, systemd timers, XDG autostart, `authorized_keys`) and emits `persistence_added`/`persistence_removed` delta Events.

**Architecture:** Mirror `listening_socket_snapshotter` (poll → diff → emit). `source.py` exposes a pure `snapshot()` returning `(entries, failed_kinds)`; the worker holds the previous snapshot, diffs (carrying forward entries of any source that failed this poll), and emits one Event per added/removed entry. No projection/panel in this PR (that's PR7).

**Tech Stack:** Python 3.14, pydantic Event model, pytest. No new deps; no subprocess use.

**Spec:** `docs/superpowers/specs/2026-06-19-persistence-panel-design.md` (§3 collector, §3.1 enumerators, §3.2 worker). This PR = §8 "PR6".

**Gates (run from repo root, all must pass before done):**
- `.venv/bin/python -m pytest -m "not integration and not ebpf_load" -q`
- `.venv/bin/ruff check inspectord tests` · `.venv/bin/ruff format --check inspectord tests`
- `.venv/bin/mypy inspectord`

**Branch:** `feat/persistence-collector` (already checked out; the spec is already committed here).

---

## File structure

- Create: `inspectord/workers/persistence_snapshotter/__init__.py`
- Create: `inspectord/workers/persistence_snapshotter/source.py` — the four enumerators + `snapshot()`. Pure, filesystem-only, never raises on bad input.
- Create: `inspectord/workers/persistence_snapshotter/__main__.py` — the worker (poll/diff/emit + CLI entry), mirroring `listening_socket_snapshotter/__main__.py`.
- Modify: `inspectord/schemas/event.py` — add the `persistence` field.
- Modify: `inspectord/parsers/base.py` — add the `persistence` kwarg to `build_event`.
- Modify: `inspectord/config.py` — add the `persistence_snapshotter` dev_config worker entry.
- Test: `tests/workers/persistence_snapshotter/test_source.py`, `tests/workers/persistence_snapshotter/test_worker.py`, plus a small assertion in the existing event/build_event tests.

---

## Task 1: Event-schema two-part change (`persistence` field + `build_event` kwarg)

This is foundational — the worker cannot set `event.persistence` without both halves (the `Event` model is `extra="forbid"`, and the worker emits via `build_event`).

**Files:**
- Modify: `inspectord/schemas/event.py` (the optional-entity-field block, alongside `device`/`file`)
- Modify: `inspectord/parsers/base.py` (`build_event` signature + the `Event(...)` body)
- Test: `tests/test_build_event.py` (or wherever build_event is tested — search first; else add a focused test file)

- [ ] **Step 1: Write the failing test.** Assert `build_event(..., persistence={"kind": "cron", "key": "persist:cron:/etc/crontab:abc123"})` produces an Event whose `.persistence["key"]` round-trips. Example:

```python
def test_build_event_carries_persistence_block():
    ev = build_event(
        module="persistence_snapshotter",
        action="persistence_added",
        category=["host"],
        type_=["start"],
        severity="low",
        persistence={"kind": "cron", "name": "backup", "source_path": "/etc/crontab",
                     "details": "@daily root backup", "key": "persist:cron:/etc/crontab:abc123"},
    )
    assert ev.persistence is not None
    assert ev.persistence["key"] == "persist:cron:/etc/crontab:abc123"
```

- [ ] **Step 2: Run it — expect failure** (`build_event() got an unexpected keyword argument 'persistence'`).

- [ ] **Step 3: Implement.** In `inspectord/schemas/event.py`, add to the optional-entity block (after `device`):

```python
    persistence: dict[str, Any] | None = None
```

In `inspectord/parsers/base.py`, add the kwarg to `build_event` (after `device: dict[str, Any] | None = None,`):

```python
    persistence: dict[str, Any] | None = None,
```

and forward it in the `Event(...)` body (after `device=device,`):

```python
        persistence=persistence,
```

- [ ] **Step 4: Run the test — expect pass.** Also run `.venv/bin/mypy inspectord` (the field is typed) and the full suite to confirm no regression (other `build_event` callers are unaffected — new kwarg defaults to `None`).

- [ ] **Step 5: Commit.** `feat(schema): add persistence entity field to Event + build_event`.

---

## Task 2: `source.py` — four enumerators + `snapshot()`

Pure, filesystem-only. **Robustness contract (spec §3.1):** a parse error on readable content skips that entry; a missing/unreadable source yields zero entries for that source and adds its `kind` to `failed_kinds` (logged), never raises. Make the source roots injectable (default to real paths, override in tests) so tests use `tmp_path` fixtures, not the real host.

**Public interface (lock these signatures):**

```python
# kind constants
CRON, TIMER, AUTOSTART, AUTHKEY = "cron", "timer", "autostart", "authorized_key"

def snapshot(roots: "Roots | None" = None) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Return ({persist_key: attrs}, failed_kinds).

    attrs = {"kind", "name", "source_path", "details", "key"}  # key == the dict key, duplicated for the event block
    failed_kinds ⊆ {CRON, TIMER, AUTOSTART, AUTHKEY}: kinds whose source was unreadable this call.
    """
```

`Roots` is a small dataclass of overridable base paths (e.g. `etc_crontab`, `cron_d_dir`, `run_parts_dirs`, `user_crontab`, `timer_wants_dirs`, `autostart_dirs`, `authorized_keys`). Provide a `default_roots()` factory with the real paths from spec §3.1.

`_DETAILS_MAX = 256` — bound `details` (spec §6.2): `details[:256]` with a trailing `…` when truncated. Apply in every enumerator.

**Files:**
- Create: `inspectord/workers/persistence_snapshotter/__init__.py` (empty)
- Create: `inspectord/workers/persistence_snapshotter/source.py`
- Test: `tests/workers/persistence_snapshotter/test_source.py` (+ `__init__.py` in the test dir)

### 2a — Cron (three sub-parsers, spec §3.1.1)

- [ ] **Step 1: Write failing tests** over `tmp_path` fixtures:
  - System crontab line `@daily root /usr/bin/backup` and `0 3 * * * root /usr/bin/backup` in `/etc/crontab` → entries with `kind=cron`, `name` = command, `details` = full line (bounded), key `persist:cron:<path>:<sha256(schedule+command)[:12]>`. `ENV=FOO=bar`, blank, and `# comment` lines are skipped.
  - `/etc/cron.d/job` parsed identically (has user field).
  - User crontab `/var/spool/cron/<user>` line `*/5 * * * * /home/u/run.sh` → no user field; key as above.
  - Run-parts: a file `/etc/cron.daily/logrotate` → key `persist:cron:<path>` (NO content hash), `name` = `logrotate`, `details` = `run-parts /etc/cron.daily`.
  - A missing cron source dir/file → contributes nothing and (if ALL cron sources missing) `CRON` in `failed_kinds`; a malformed line never raises.

- [ ] **Step 2: Run — expect failure** (no `source` module).

- [ ] **Step 3: Implement** `_enum_cron(roots) -> tuple[dict, bool]` (returns entries + a "readable?" flag). Helpers:
  - `_parse_cron_line(line, has_user_field)` → `(schedule, command) | None`. Strip; skip empty/`#`/`ENV=`-assignment (a line matching `^\w+=` with no schedule). Support `@`-shortcuts (`@reboot`/`@daily`/… → schedule is the shortcut token, rest is command, minus user field if `has_user_field`). Otherwise the first 5 whitespace fields are the schedule; if `has_user_field` the 6th is user and the remainder is command, else the remainder after 5 fields is command. Return `None` on too-few fields.
  - `_cron_key(path, schedule, command)` = `f"persist:cron:{path}:{hashlib.sha256(f'{schedule} {command}'.encode()).hexdigest()[:12]}"`.
  - run-parts entries: iterate files in each run-parts dir; key `persist:cron:{path}`, details `run-parts {dir}`.
  - Wrap each file/dir read in try/except (OSError) → on failure, that source contributes nothing; track readability.

- [ ] **Step 4: Run — expect pass.**

- [ ] **Step 5: Commit.** `feat(persistence): cron enumerator (3 sub-parsers)`.

### 2b — Timers (enabled-only, spec §3.1.2)

- [ ] **Step 1: Write failing tests** over `tmp_path`:
  - An enabled timer = a symlink `…/timers.target.wants/foo.timer` → resolved unit file with `OnCalendar=daily`. Expect entry `kind=timer`, `scope` per dir, key `persist:timer:<scope>:foo.timer`, `name=foo.timer`, `details` containing `OnCalendar=daily`.
  - A masked timer (symlink → `/dev/null`) is skipped.
  - A template unit `bar@.timer` is skipped.
  - system vs user scope from the `*.wants` dir.
  - Missing wants dirs → no entries; all missing → `TIMER` in `failed_kinds`.

- [ ] **Step 2: Run — expect failure.**

- [ ] **Step 3: Implement** `_enum_timers(roots) -> tuple[dict, bool]`: for each `(scope, wants_dir)`, list `*.timer` symlinks; `os.path.realpath` the target; skip if target is `/dev/null` (masked) or basename matches `*@.timer` (template); read the resolved file, extract `OnCalendar=`/`OnBootSec=` lines into `details` (bounded), key `persist:timer:{scope}:{unit}`.

- [ ] **Step 4: Run — expect pass.**

- [ ] **Step 5: Commit.** `feat(persistence): enabled-timer enumerator`.

### 2c — Autostart + authorized_keys + `snapshot()` merge

- [ ] **Step 1: Write failing tests** over `tmp_path`:
  - autostart: `~/.config/autostart/app.desktop` with `Name=App` / `Exec=/usr/bin/app --foo` → key `persist:autostart:<path>`, name `App`, details `Exec` value; a `.desktop` with no `Exec=` is skipped; `/etc/xdg/autostart` also scanned.
  - authorized_keys: a plain line `ssh-ed25519 AAAAC3Nza... user@host` → key `persist:authkey:ssh-ed25519:SHA256:<b64>`, name `user@host`, details `ssh-ed25519 SHA256:<b64>`. An options-prefixed line `command="x" ssh-ed25519 AAAAC3Nza... c` parses (keytype detected as the `ssh-ed25519` token). Blank/`#` lines skipped; a garbage line is skipped (no raise). Fingerprint matches `ssh-keygen -E sha256` format (`SHA256:` + base64(sha256(blob)) without padding).
  - `snapshot()` merges all four; each entry's `attrs["key"]` equals its dict key; `failed_kinds` aggregates per-kind readability; calling `snapshot()` with all roots pointing at empty/missing dirs returns `({}, {all four kinds})` and never raises.

- [ ] **Step 2: Run — expect failure.**

- [ ] **Step 3: Implement** `_enum_autostart`, `_enum_authorized_keys`, and `snapshot()`:
  - autostart: parse `.desktop` minimally — read lines, pick first `Name=`/`Exec=` (top-level; ignore action groups is fine for v1). Skip if no `Exec`.
  - authorized_keys: for each non-blank/non-`#` line, scan tokens for the first matching a known keytype prefix (`ssh-rsa`, `ssh-ed25519`, `ssh-dss`, `ecdsa-sha2-nistp256/384/521`, `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`); the next token is base64; `import base64, hashlib`; `blob = base64.b64decode(b64field, validate=True)`; validate the leading length-prefixed type string equals the keytype (parse the first 4-byte big-endian length + that many bytes); `fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")`. Comment = remaining tokens joined (or fp). Skip on any decode/validate error.
  - `snapshot()`: call all four; collect entries; for each enumerator returning "unreadable", add its kind to `failed_kinds`; ensure each `attrs` includes `"key"` = its key. Apply `_DETAILS_MAX` everywhere.

- [ ] **Step 4: Run — expect pass.** Run ruff + mypy on the new module.

- [ ] **Step 5: Commit.** `feat(persistence): autostart + authorized_keys enumerators + snapshot()`.

---

## Task 3: Worker (`__main__.py`) + dev_config wiring

Mirror `listening_socket_snapshotter/__main__.py`. **Two deliberate divergences (spec §3.2):** start with an EMPTY previous snapshot (so the first poll emits all current entries as `persistence_added`), and diff **per-source** (carry forward entries of any kind in `failed_kinds`).

**Files:**
- Create: `inspectord/workers/persistence_snapshotter/__main__.py`
- Modify: `inspectord/config.py` (add the worker to dev_config)
- Test: `tests/workers/persistence_snapshotter/test_worker.py`

- [ ] **Step 1: Write failing tests** with an injected fake `snapshot` callable and an in-memory sink (mirror `test` patterns in the listener worker tests):
  - First `step()` with snapshot `({k1: a1, k2: a2}, set())` writes two `persistence_added` events (one per key), each with `event["persistence"]["key"]` set and `module="persistence_snapshotter"`.
  - Next `step()` with `({k1: a1}, set())` writes one `persistence_removed` for `k2` only (k1 unchanged → no event).
  - **Carry-forward:** after the two-key snapshot, a `step()` returning `({}, {"cron"})` where k1/k2 are `cron` kind emits NO `persistence_removed` (failed source carried forward); a subsequent genuine `({k1:a1}, set())` then emits removed for k2.
  - `authkey`-kind added event has `severity="medium"`; others `"low"`.

- [ ] **Step 2: Run — expect failure** (no worker).

- [ ] **Step 3: Implement** the worker:

```python
class PersistenceSnapshotterWorker:
    def __init__(self, *, snapshot_fn=snapshot, sink, host_name=_DEFAULT_HOSTNAME):
        self._snapshot_fn = snapshot_fn
        self._sink = sink
        self._host_name = host_name
        self._prev: dict[str, dict] = {}   # EMPTY init → first poll emits all as added

    def step(self) -> None:
        current, failed = self._snapshot_fn()
        effective = dict(current)
        # carry forward entries whose kind's source failed this poll
        for key, attrs in self._prev.items():
            if attrs["kind"] in failed and key not in effective:
                effective[key] = attrs
        for key in effective.keys() - self._prev.keys():
            self._emit("persistence_added", effective[key])
        for key in self._prev.keys() - effective.keys():
            self._emit("persistence_removed", self._prev[key])
        self._prev = effective

    def _emit(self, action, attrs):
        sev = "medium" if attrs["kind"] == AUTHKEY else "low"
        ev = build_event(
            module="persistence_snapshotter", action=action,
            category=["host"], type_=["start" if action == "persistence_added" else "end"],
            severity=sev, host={"name": self._host_name},
            persistence={"kind": attrs["kind"], "name": attrs.get("name"),
                         "source_path": attrs.get("source_path"), "details": attrs.get("details"),
                         "key": attrs["key"]},
            labels=["persistence", f"persist:{attrs['kind']}"],
            message=f"{action} {attrs['kind']} {attrs.get('name','')}",
            raw={"source": attrs.get("source_path")},
        )
        self._sink.write(json.dumps(ev.model_dump(mode="json", exclude_none=True)).encode() + b"\n")
        self._sink.flush()
```

  Add the `main()`/argparse/`_open_sink`/`step_interval` scaffolding by copying the listener worker's structure (default poll ~30s). Match the `Worker` base-class integration the listener worker uses so the supervisor can run it.

- [ ] **Step 4: Run tests — expect pass.**

- [ ] **Step 5: Wire dev_config.** In `inspectord/config.py`, add to the `workers` list (after `udev_monitor`):

```python
                {
                    "name": "persistence_snapshotter",
                    "module": "inspectord.workers.persistence_snapshotter",
                    "config": {},
                },
```

- [ ] **Step 6: Run all gates** (full pytest, ruff check + format, mypy). Confirm green.

- [ ] **Step 7: Commit.** `feat(persistence): persistence_snapshotter worker + dev_config wiring`.

---

## Self-review checklist (run before handoff)

- [ ] Spec §3.1 coverage: cron 3 sub-parsers, enabled-only timers, autostart, authorized_keys — each has a task + tests. ✓ (Tasks 2a–2c)
- [ ] Spec §3.2: two-part Event change (Task 1), empty-init first poll + per-source carry-forward (Task 3), `severity="medium"` for authkey (Task 3). ✓
- [ ] Robustness: missing/unreadable source → zero entries + `failed_kinds`, never raises (Task 2 tests). ✓
- [ ] Privacy: `_DETAILS_MAX` bound applied in every enumerator (Task 2). ✓
- [ ] No subprocess anywhere (filesystem reads only). ✓
- [ ] Out of scope for PR6 (do NOT build): migration 0005, projector branch, `capture_baseline`/`list_persistence`, web panel — all PR7.
- [ ] Signature consistency: `snapshot() -> (dict, set[str])` used identically in source and worker; `attrs` keys `{kind,name,source_path,details,key}` consistent across enumerators, worker, and the event block.
