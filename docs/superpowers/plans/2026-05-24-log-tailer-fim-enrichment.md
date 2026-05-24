# Log Tailer + FIM Watcher + Enrichment Slice — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the first real collector slice for `inspectord`. After this plan, the daemon tails journald and `/var/log/pacman.log` (plus `/var/log/auth.log` opportunistically), watches a hardcoded set of filesystem paths via inotify, enriches every event with process / file / user metadata, persists to DuckDB, and exposes `inspectorctl events tail` / `inspectorctl events search` so the user can watch real events flow through.

**Architecture:** Two new workers run as supervisor children — `log_tailer` (sources: journald via `journalctl --follow --output=json`, file-tail of pacman + auth.log; each line is fed through a per-source parser that emits a normalized `Event`) and `fim_watcher` (a single inotify watcher on the hardcoded path set emitting file-change Events). Enrichment is a **library** (`inspectord.enrichment.enrich`) that the supervisor invokes between parsing a worker's NDJSON line and publishing to the router — process / file / user enrichers add `process.*`, `file.hash.sha256`, `user.name` fields. CLI uses a new read-only IPC method `list_events` to poll DuckDB.

**Tech Stack:** Python 3.12 · Pydantic v2 · DuckDB · `inotify_simple` (new runtime dep, ~100 lines of pure-Python ctypes around inotify syscalls) · subprocess (`journalctl --follow --output=json`) · existing Phase 0 supervisor + router + journal + IPC + worker base class.

**Scope discipline:** No rule engine, no allowlist, no notifier dispatcher (Phase 1 next plan handles those). No auditd/nftables/iptables/ufw/kmsg parsers — they ship with their own collectors later. fanotify is deferred (requires `CAP_SYS_ADMIN`; inotify covers the v1 path set without the extra privilege). No GeoIP / threat-intel / first-sighting enrichers — those arrive with the network collector.

---

## Repository state at the start

`/home/eli/Development/inspectord` on `main` after PR #32. Phase 0 + dep_manager merged. 139 tests passing, CI green. Existing pieces this plan depends on:

- `inspectord/schemas/event.py`: `Event`, `EventKind`, `Severity`, `Outcome`.
- `inspectord/schemas/versions.py`: `EVENT_SCHEMA_VERSION`.
- `inspectord/ids.py`: `uuid7`.
- `inspectord/workers/contract.py`: `Worker` base class with `setup`/`step`/`teardown`, `emit_event`, `emit_heartbeat`, `request_stop`, `run`.
- `inspectord/supervisor.py`: spawns workers as subprocesses, parses NDJSON from stdout into `Event`s, publishes to `EventRouter`.
- `inspectord/router.py`: `EventRouter` + drop-policy subscriptions.
- `inspectord/storage/db.py`: DuckDB (with `SET TimeZone='UTC'` at connect time).
- `inspectord/storage/migrations.py`: numbered SQL migration runner. Last migration is `0002_deps.sql`.
- `inspectord/ipc_server.py`: JSON-RPC 2.0 over Unix socket, `Method(name, handler, mutates)`.
- `inspectorctl/ipc_client.py`: `IpcClient.call(method, params)`.
- `inspectorctl/cli/app.py`: mounts `status`, `self-test`, `version`, `deps`.

## File structure produced by this plan

```
inspectord/
├── parsers/
│   ├── __init__.py
│   ├── base.py                          # ParsedLine helper + Parser protocol
│   ├── pacman.py                        # /var/log/pacman.log line → Event
│   ├── auth_log.py                      # /var/log/auth.log line → Event
│   └── journald.py                      # journalctl --output=json line → Event
├── sources/
│   ├── __init__.py
│   ├── file_tail.py                     # append-mode reader with rotation handling
│   └── journal_source.py                # subprocess wrapper around journalctl --follow
├── workers/
│   ├── log_tailer/
│   │   ├── __init__.py
│   │   └── __main__.py                  # LogTailerWorker
│   └── fim_watcher/
│       ├── __init__.py
│       ├── __main__.py                  # FimWatcherWorker
│       └── paths.py                     # the hardcoded watched-path set
├── enrichment/
│   ├── __init__.py                      # `enrich(ev)` entry point
│   ├── process.py                       # pid → exe + sha256 + parent
│   ├── file.py                          # path → sha256 (cached) + owner/mode
│   └── user.py                          # uid → name + groups
└── (modified)
    ├── supervisor.py                    # wire enrich() into _read_stdout
    ├── config.py                        # add log_tailer + fim_watcher workers
    └── __main__.py                      # add list_events IPC method

inspectorctl/cli/
└── events.py                            # new: tail + search subcommands

tests/
├── parsers/
│   ├── __init__.py
│   ├── fixtures/                        # sample log lines used by tests
│   │   ├── pacman.log
│   │   ├── auth.log
│   │   └── journald.jsonl
│   ├── test_pacman_parser.py
│   ├── test_auth_log_parser.py
│   └── test_journald_parser.py
├── sources/
│   ├── __init__.py
│   ├── test_file_tail.py
│   └── test_journal_source.py
├── enrichment/
│   ├── __init__.py
│   ├── test_process_enricher.py
│   ├── test_file_enricher.py
│   ├── test_user_enricher.py
│   └── test_enrich_integration.py
├── test_log_tailer_worker.py
├── test_fim_watcher_worker.py
├── test_cli_events.py
└── integration/
    └── test_log_tailer_e2e.py
```

Total new: 22 source modules + 22 test modules + 3 log fixtures + 1 polkit edit (none). Approximately 16 tasks, similar size to Phase 0 / dep_manager.

## Workflow

Same as Phase 0 and dep_manager. Each task lands on its own feature branch `task-logs-NN-<slug>` and goes through a PR with CI gating. Squash-merge after CI green. TDD throughout. Bundle adjacent tiny tasks at the controller's discretion during execution.

---

## Task 1: Parser framework (Protocol + ParsedLine helper)

**Files:**
- Create: `inspectord/parsers/__init__.py`
- Create: `inspectord/parsers/base.py`
- Create: `tests/parsers/__init__.py`
- Create: `tests/parsers/test_base.py`

**Branch:** `task-logs-01-parser-base`

A parser is a callable: `(line: str | bytes, source: str) -> Event | None`. `None` means "this line doesn't produce an event" (e.g., empty line, comment, parse failure that should be silently dropped). For test friendliness and consistency we also expose a `ParsedLine` dataclass that wraps the raw line + optional structured fields the parser can populate.

- [ ] **Step 1: Failing tests**

Write `tests/parsers/test_base.py`:

```python
"""Tests for the parser framework."""

from __future__ import annotations

from inspectord.parsers.base import ParsedLine, build_event


def test_parsedline_carries_raw_and_fields() -> None:
    pl = ParsedLine(raw="hello", fields={"k": "v"})
    assert pl.raw == "hello"
    assert pl.fields == {"k": "v"}


def test_build_event_minimum_fields() -> None:
    ev = build_event(
        module="log_tailer",
        action="package_installed",
        category=["package"],
        type_=["installation"],
        severity="info",
        message="installed audit",
        raw={"source_file": "/var/log/pacman.log", "line": "..."},
    )
    assert ev.module == "log_tailer"
    assert ev.action == "package_installed"
    assert ev.severity.value == "info"
    assert ev.message == "installed audit"
    assert ev.raw == {"source_file": "/var/log/pacman.log", "line": "..."}


def test_build_event_includes_uuidv7_event_id() -> None:
    ev = build_event(
        module="log_tailer",
        action="x",
        category=["host"],
        type_=["info"],
        severity="info",
    )
    # uuid7 ids are time-sortable; two consecutive calls should produce a > b
    import time
    ev2 = build_event(module="log_tailer", action="x", category=["host"], type_=["info"], severity="info")
    time.sleep(0.005)
    ev3 = build_event(module="log_tailer", action="x", category=["host"], type_=["info"], severity="info")
    assert ev2.event_id < ev3.event_id
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest tests/parsers/test_base.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement**

Write `inspectord/parsers/__init__.py`:

```python
"""Per-source log parsers (spec §4.3)."""
```

Write `inspectord/parsers/base.py`:

```python
"""Parser helpers.

A parser is a callable: ``(line: str, source: str) -> Event | None``.
It MUST return ``None`` for unparseable / empty / comment lines rather than
raise — bad input is normal in log streams.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from inspectord.ids import uuid7
from inspectord.schemas.event import Event, EventKind, Severity
from inspectord.schemas.versions import EVENT_SCHEMA_VERSION


@dataclass
class ParsedLine:
    raw: str
    fields: dict[str, Any] = field(default_factory=dict)


class Parser(Protocol):
    """A parser turns one raw line into one Event (or None to drop the line)."""

    def __call__(self, line: str, source: str) -> Event | None: ...


def build_event(
    *,
    module: str,
    action: str,
    category: list[str],
    type_: list[str],
    severity: str,
    kind: str = "event",
    outcome: str | None = None,
    message: str | None = None,
    process: dict[str, Any] | None = None,
    file: dict[str, Any] | None = None,
    user: dict[str, Any] | None = None,
    source: dict[str, Any] | None = None,
    destination: dict[str, Any] | None = None,
    network: dict[str, Any] | None = None,
    service: dict[str, Any] | None = None,
    package: dict[str, Any] | None = None,
    device: dict[str, Any] | None = None,
    raw: dict[str, Any] | None = None,
    labels: list[str] | None = None,
    ts: datetime | None = None,
) -> Event:
    """Construct a normalized Event with sensible defaults."""
    return Event(
        schema_version=EVENT_SCHEMA_VERSION,
        ts=ts if ts is not None else datetime.now(UTC),
        event_id=str(uuid7()),
        kind=EventKind(kind),
        category=category,
        type=type_,
        action=action,
        outcome=None if outcome is None else None,
        severity=Severity(severity),
        module=module,
        message=message,
        process=process,
        file=file,
        user=user,
        source=source,
        destination=destination,
        network=network,
        service=service,
        package=package,
        device=device,
        raw=raw,
        labels=labels or [],
    )
```

Note: the `outcome=None if outcome is None else None` line is intentional — the Event schema treats `outcome` as optional, so we don't construct an Outcome enum unless we have a real value. Update this if you want to support outcome strings; for now the parsers don't set outcome and `None` is fine.

Actually clean it up: rewrite that line as:

```python
        outcome=outcome,
```

and let Pydantic coerce the string to the `Outcome` enum.

- [ ] **Step 4: Run to confirm pass**

```bash
pytest tests/parsers/test_base.py -v
pytest tests/ -v
```

Expected: 3 new tests pass; total 142.

- [ ] **Step 5: Lint + branch + commit + PR**

```bash
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
git checkout main && git pull origin main
git checkout -b task-logs-01-parser-base
git add inspectord/parsers/ tests/parsers/__init__.py tests/parsers/test_base.py
git commit -m "feat(parsers): add Parser Protocol + build_event helper"
git push -u origin task-logs-01-parser-base
gh pr create --base main --head task-logs-01-parser-base \
  --title "feat(parsers): Parser Protocol + build_event helper" \
  --body $'Adds the inspectord.parsers package. A parser is a callable (line, source) -> Event | None. build_event constructs a normalized Event with uuidv7 id, current UTC timestamp, and all the right defaults so each concrete parser is a thin wrapper over a regex/JSON-load.'
```

Wait for CI green; do NOT merge — main thread handles merges.

---

## Task 2: pacman_parser

**Files:**
- Create: `inspectord/parsers/pacman.py`
- Create: `tests/parsers/fixtures/pacman.log`
- Create: `tests/parsers/test_pacman_parser.py`

**Branch:** `task-logs-02-pacman-parser`

`/var/log/pacman.log` lines look like:

```
[2026-05-24T14:23:10+0000] [ALPM] installed audit (3.1.5-1)
[2026-05-24T14:23:11+0000] [ALPM] removed yara (4.5.0-1)
[2026-05-24T14:23:12+0000] [ALPM] upgraded suricata (6.0.0-1 -> 7.0.0-1)
[2026-05-24T14:23:13+0000] [ALPM] reinstalled libudev (250-1)
[2026-05-24T14:23:14+0000] [PACMAN] Running 'pacman -S audit'
```

We care about `[ALPM] installed/removed/upgraded/reinstalled` lines. `[PACMAN]` and other classes produce no event (return None).

- [ ] **Step 1: Fixture**

Write `tests/parsers/fixtures/pacman.log`:

```
[2026-05-24T14:23:10+0000] [ALPM] installed audit (3.1.5-1)
[2026-05-24T14:23:11+0000] [ALPM] removed yara (4.5.0-1)
[2026-05-24T14:23:12+0000] [ALPM] upgraded suricata (6.0.0-1 -> 7.0.0-1)
[2026-05-24T14:23:13+0000] [ALPM] reinstalled libudev (250-1)
[2026-05-24T14:23:14+0000] [PACMAN] Running 'pacman -S audit'
```

- [ ] **Step 2: Failing tests**

Write `tests/parsers/test_pacman_parser.py`:

```python
"""Tests for the pacman.log parser."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from inspectord.parsers.pacman import parse_pacman_line


FIXTURE = Path(__file__).parent / "fixtures" / "pacman.log"


def _lines() -> list[str]:
    return FIXTURE.read_text(encoding="utf-8").splitlines()


def test_installed_line() -> None:
    ev = parse_pacman_line(_lines()[0], source="/var/log/pacman.log")
    assert ev is not None
    assert ev.action == "package_installed"
    assert ev.category == ["package"]
    assert ev.type == ["installation"]
    assert ev.severity.value == "info"
    assert ev.package == {
        "name": "audit",
        "version": "3.1.5-1",
        "action": "installed",
    }
    assert ev.ts == datetime(2026, 5, 24, 14, 23, 10, tzinfo=UTC)
    assert ev.raw is not None
    assert ev.raw["source_file"] == "/var/log/pacman.log"


def test_removed_line() -> None:
    ev = parse_pacman_line(_lines()[1], source="/var/log/pacman.log")
    assert ev is not None
    assert ev.action == "package_removed"
    assert ev.type == ["deletion"]
    assert ev.package == {
        "name": "yara",
        "version": "4.5.0-1",
        "action": "removed",
    }


def test_upgraded_line_captures_both_versions() -> None:
    ev = parse_pacman_line(_lines()[2], source="/var/log/pacman.log")
    assert ev is not None
    assert ev.action == "package_upgraded"
    assert ev.type == ["change"]
    assert ev.package == {
        "name": "suricata",
        "version": "7.0.0-1",
        "previous_version": "6.0.0-1",
        "action": "upgraded",
    }


def test_reinstalled_line() -> None:
    ev = parse_pacman_line(_lines()[3], source="/var/log/pacman.log")
    assert ev is not None
    assert ev.action == "package_reinstalled"
    assert ev.package == {
        "name": "libudev",
        "version": "250-1",
        "action": "reinstalled",
    }


def test_non_alpm_line_returns_none() -> None:
    assert parse_pacman_line(_lines()[4], source="/var/log/pacman.log") is None


def test_unparseable_line_returns_none() -> None:
    assert parse_pacman_line("not a pacman line", source="/var/log/pacman.log") is None
    assert parse_pacman_line("", source="/var/log/pacman.log") is None
```

- [ ] **Step 3: Run to confirm failure**

```bash
pytest tests/parsers/test_pacman_parser.py -v
```

Expected: ImportError.

- [ ] **Step 4: Implement**

Write `inspectord/parsers/pacman.py`:

```python
"""Parser for /var/log/pacman.log entries."""

from __future__ import annotations

import re
from datetime import datetime

from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event


# [2026-05-24T14:23:10+0000] [ALPM] installed audit (3.1.5-1)
# [2026-05-24T14:23:12+0000] [ALPM] upgraded suricata (6.0.0-1 -> 7.0.0-1)
_LINE_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<src>[A-Z]+)\]\s+"
    r"(?P<verb>installed|removed|upgraded|reinstalled)\s+"
    r"(?P<name>\S+)\s+\((?P<vers>[^)]+)\)\s*$"
)

_VERB_TO_TYPE: dict[str, list[str]] = {
    "installed": ["installation"],
    "removed": ["deletion"],
    "upgraded": ["change"],
    "reinstalled": ["change"],
}


def parse_pacman_line(line: str, source: str) -> Event | None:
    line = line.rstrip("\n")
    if not line:
        return None
    match = _LINE_RE.match(line)
    if match is None:
        return None
    if match.group("src") != "ALPM":
        return None

    verb = match.group("verb")
    name = match.group("name")
    vers_field = match.group("vers")

    try:
        ts = datetime.fromisoformat(match.group("ts"))
    except ValueError:
        return None

    if verb == "upgraded" and "->" in vers_field:
        prev, _, new = vers_field.partition("->")
        package = {
            "name": name,
            "version": new.strip(),
            "previous_version": prev.strip(),
            "action": "upgraded",
        }
    else:
        package = {"name": name, "version": vers_field.strip(), "action": verb}

    return build_event(
        module="log_tailer",
        action=f"package_{verb}",
        category=["package"],
        type_=_VERB_TO_TYPE[verb],
        severity="info",
        message=f"{verb} {name} {vers_field}",
        package=package,
        raw={"source_file": source, "line": line, "fields": {}},
        ts=ts,
    )
```

- [ ] **Step 5: Confirm pass**

```bash
pytest tests/parsers/test_pacman_parser.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 6 new tests pass; total 148.

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-02-pacman-parser
git add inspectord/parsers/pacman.py \
        tests/parsers/fixtures/pacman.log \
        tests/parsers/test_pacman_parser.py
git commit -m "feat(parsers): add pacman.log parser"
git push -u origin task-logs-02-pacman-parser
gh pr create --base main --head task-logs-02-pacman-parser \
  --title "feat(parsers): pacman.log parser" \
  --body "Parses [ALPM] installed/removed/upgraded/reinstalled lines into Events with the package.* block populated. Non-ALPM and unparseable lines return None — log streams routinely contain noise the parser must silently skip."
```

Wait for CI green; do NOT merge.

---

## Task 3: auth_log_parser

**Files:**
- Create: `inspectord/parsers/auth_log.py`
- Create: `tests/parsers/fixtures/auth.log`
- Create: `tests/parsers/test_auth_log_parser.py`

**Branch:** `task-logs-03-auth-log-parser`

`/var/log/auth.log` (Debian-family format) lines look like:

```
May 24 14:23:10 host sshd[1234]: Accepted publickey for eli from 1.2.3.4 port 51234 ssh2: ED25519 SHA256:...
May 24 14:23:11 host sshd[1234]: Failed password for invalid user root from 1.2.3.5 port 51234 ssh2
May 24 14:23:12 host sudo:     eli : TTY=pts/0 ; PWD=/home/eli ; USER=root ; COMMAND=/usr/bin/pacman -S audit
May 24 14:23:13 host CRON[1234]: pam_unix(cron:session): session opened for user root by (uid=0)
```

Phase 1 parses: ssh accepted, ssh failed, sudo invocations. CRON/pam_unix sessions return None (they generate too much noise without a rule engine).

Note: this file doesn't exist on Arch/CachyOS (auth goes to journald there). The parser still works for Debian users and we'll wire log_tailer to tail this path opportunistically (only if the file exists).

- [ ] **Step 1: Fixture**

Write `tests/parsers/fixtures/auth.log`:

```
May 24 14:23:10 host sshd[1234]: Accepted publickey for eli from 1.2.3.4 port 51234 ssh2: ED25519 SHA256:abc
May 24 14:23:11 host sshd[1234]: Failed password for invalid user root from 1.2.3.5 port 51234 ssh2
May 24 14:23:12 host sudo:     eli : TTY=pts/0 ; PWD=/home/eli ; USER=root ; COMMAND=/usr/bin/pacman -S audit
May 24 14:23:13 host CRON[1234]: pam_unix(cron:session): session opened for user root by (uid=0)
```

- [ ] **Step 2: Failing tests**

Write `tests/parsers/test_auth_log_parser.py`:

```python
"""Tests for the /var/log/auth.log parser."""

from __future__ import annotations

from pathlib import Path

from inspectord.parsers.auth_log import parse_auth_log_line


FIXTURE = Path(__file__).parent / "fixtures" / "auth.log"


def _lines() -> list[str]:
    return FIXTURE.read_text(encoding="utf-8").splitlines()


def test_ssh_accepted() -> None:
    ev = parse_auth_log_line(_lines()[0], source="/var/log/auth.log")
    assert ev is not None
    assert ev.action == "ssh_login_succeeded"
    assert ev.category == ["authentication"]
    assert ev.type == ["start"]
    assert ev.outcome is not None and ev.outcome.value == "success"
    assert ev.user == {"name": "eli"}
    assert ev.source == {"ip": "1.2.3.4", "port": 51234}
    assert ev.process is not None
    assert ev.process["name"] == "sshd"
    assert ev.process["pid"] == 1234


def test_ssh_failed() -> None:
    ev = parse_auth_log_line(_lines()[1], source="/var/log/auth.log")
    assert ev is not None
    assert ev.action == "ssh_login_failed"
    assert ev.outcome is not None and ev.outcome.value == "failure"
    assert ev.severity.value == "medium"
    assert ev.source == {"ip": "1.2.3.5", "port": 51234}


def test_sudo_invocation() -> None:
    ev = parse_auth_log_line(_lines()[2], source="/var/log/auth.log")
    assert ev is not None
    assert ev.action == "sudo_invoked"
    assert ev.category == ["iam"]
    assert ev.user == {"name": "eli", "effective": {"name": "root"}}
    assert ev.process is not None
    assert ev.process["command_line"].endswith("/usr/bin/pacman -S audit")


def test_cron_session_ignored() -> None:
    assert parse_auth_log_line(_lines()[3], source="/var/log/auth.log") is None


def test_unrelated_line_returns_none() -> None:
    assert parse_auth_log_line("garbage", source="/var/log/auth.log") is None
    assert parse_auth_log_line("", source="/var/log/auth.log") is None
```

- [ ] **Step 3: Run to confirm failure**

```bash
pytest tests/parsers/test_auth_log_parser.py -v
```

Expected: ImportError.

- [ ] **Step 4: Implement**

Write `inspectord/parsers/auth_log.py`:

```python
"""Parser for /var/log/auth.log (Debian-family format)."""

from __future__ import annotations

import re

from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event


# Note: auth.log timestamps lack a year. We use the parser's current year. Good
# enough for Phase 1; the corresponding journald entry carries an accurate
# timestamp which the daemon prefers when both are available.

_SSH_ACCEPTED_RE = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Accepted\s+\S+\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
_SSH_FAILED_RE = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Failed\s+password\s+for\s+"
    r"(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
_SUDO_RE = re.compile(
    r"sudo:\s*(?P<user>\S+)\s*:\s+TTY=\S+\s*;\s+PWD=\S+\s*;\s+USER=(?P<target>\S+)\s*;\s+COMMAND=(?P<cmd>.+)$"
)


def parse_auth_log_line(line: str, source: str) -> Event | None:
    line = line.rstrip("\n")
    if not line:
        return None

    m = _SSH_ACCEPTED_RE.search(line)
    if m is not None:
        return build_event(
            module="log_tailer",
            action="ssh_login_succeeded",
            category=["authentication"],
            type_=["start"],
            severity="info",
            outcome="success",
            message=f"sshd accepted login for {m.group('user')} from {m.group('ip')}",
            user={"name": m.group("user")},
            process={"name": "sshd", "pid": int(m.group("pid"))},
            source={"ip": m.group("ip"), "port": int(m.group("port"))},
            raw={"source_file": source, "line": line, "fields": {}},
        )

    m = _SSH_FAILED_RE.search(line)
    if m is not None:
        return build_event(
            module="log_tailer",
            action="ssh_login_failed",
            category=["authentication"],
            type_=["end"],
            severity="medium",
            outcome="failure",
            message=f"sshd failed login for {m.group('user')} from {m.group('ip')}",
            user={"name": m.group("user")},
            process={"name": "sshd", "pid": int(m.group("pid"))},
            source={"ip": m.group("ip"), "port": int(m.group("port"))},
            raw={"source_file": source, "line": line, "fields": {}},
        )

    m = _SUDO_RE.search(line)
    if m is not None:
        return build_event(
            module="log_tailer",
            action="sudo_invoked",
            category=["iam"],
            type_=["start"],
            severity="info",
            outcome="success",
            message=f"sudo: {m.group('user')} ran '{m.group('cmd')}' as {m.group('target')}",
            user={"name": m.group("user"), "effective": {"name": m.group("target")}},
            process={"name": "sudo", "command_line": m.group("cmd")},
            raw={"source_file": source, "line": line, "fields": {}},
        )

    return None
```

- [ ] **Step 5: Confirm pass + lint**

```bash
pytest tests/parsers/test_auth_log_parser.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 5 new tests pass; total 153.

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-03-auth-log-parser
git add inspectord/parsers/auth_log.py \
        tests/parsers/fixtures/auth.log \
        tests/parsers/test_auth_log_parser.py
git commit -m "feat(parsers): add auth.log parser (ssh + sudo)"
git push -u origin task-logs-03-auth-log-parser
gh pr create --base main --head task-logs-03-auth-log-parser \
  --title "feat(parsers): auth.log parser" \
  --body "Parses Debian-style /var/log/auth.log lines for sshd accepted/failed and sudo invocations. CRON / pam_unix session lines return None to keep noise out of v1. Unparseable lines also return None. The file rarely exists on Arch (auth goes via journald there) but the parser ships now so log_tailer's auth.log path is functional on Debian-family hosts as soon as the daemon comes up."
```

Wait for CI green; do NOT merge.

---

## Task 4: journald_parser

**Files:**
- Create: `inspectord/parsers/journald.py`
- Create: `tests/parsers/fixtures/journald.jsonl`
- Create: `tests/parsers/test_journald_parser.py`

**Branch:** `task-logs-04-journald-parser`

We invoke `journalctl --follow --output=json` which emits one JSON object per entry on stdout. Field names are prefixed with `_` for trusted fields (set by journald itself) and unprefixed for app-set ones. Sample entry:

```json
{
  "__REALTIME_TIMESTAMP": "1716576190123456",
  "__MONOTONIC_TIMESTAMP": "12345",
  "_BOOT_ID": "abcd",
  "_SYSTEMD_UNIT": "sshd.service",
  "_PID": "1234",
  "_UID": "0",
  "_GID": "0",
  "_COMM": "sshd",
  "_EXE": "/usr/sbin/sshd",
  "PRIORITY": "6",
  "MESSAGE": "Accepted publickey for eli from 1.2.3.4 port 51234 ssh2",
  "_HOSTNAME": "laptop"
}
```

PRIORITY is syslog severity (0=emerg .. 7=debug). Map to our severity:
- 0..3 (emerg/alert/crit/err) → `high`
- 4 (warning) → `medium`
- 5 (notice) → `low`
- 6..7 (info/debug) → `info`

- [ ] **Step 1: Fixture**

Write `tests/parsers/fixtures/journald.jsonl`:

```
{"__REALTIME_TIMESTAMP":"1716576190123456","_BOOT_ID":"boot-x","_SYSTEMD_UNIT":"sshd.service","_PID":"1234","_UID":"0","_COMM":"sshd","_EXE":"/usr/sbin/sshd","PRIORITY":"6","MESSAGE":"Accepted publickey for eli from 1.2.3.4 port 51234 ssh2","_HOSTNAME":"laptop"}
{"__REALTIME_TIMESTAMP":"1716576200456789","_BOOT_ID":"boot-x","_SYSTEMD_UNIT":"systemd.service","_PID":"1","_UID":"0","_COMM":"systemd","PRIORITY":"3","MESSAGE":"Something failed","_HOSTNAME":"laptop"}
{"__REALTIME_TIMESTAMP":"1716576210999999","_BOOT_ID":"boot-x","_SYSTEMD_UNIT":"audit.service","_PID":"2000","_UID":"0","_COMM":"auditd","_EXE":"/usr/sbin/auditd","PRIORITY":"5","MESSAGE":"audit daemon started"}
```

(Each is one line; PRIORITY 6=info, 3=err, 5=notice.)

- [ ] **Step 2: Failing tests**

Write `tests/parsers/test_journald_parser.py`:

```python
"""Tests for the journald JSON parser."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from inspectord.parsers.journald import parse_journald_entry


FIXTURE = Path(__file__).parent / "fixtures" / "journald.jsonl"


def _entries() -> list[dict[str, object]]:
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_priority_6_maps_to_info() -> None:
    ev = parse_journald_entry(_entries()[0], source="journald")
    assert ev is not None
    assert ev.severity.value == "info"
    assert ev.module == "log_tailer"
    assert ev.action == "journal_message"
    assert ev.service == {"name": "sshd", "unit": "sshd.service"}
    assert ev.process is not None
    assert ev.process["name"] == "sshd"
    assert ev.process["pid"] == 1234
    assert ev.process["executable"] == "/usr/sbin/sshd"
    assert ev.user == {"id": 0}
    assert ev.host == {"hostname": "laptop", "os": {"family": "linux"}}
    assert "Accepted publickey" in (ev.message or "")
    # __REALTIME_TIMESTAMP is microseconds since epoch.
    assert ev.ts == datetime.fromtimestamp(1716576190.123456, UTC)


def test_priority_3_maps_to_high() -> None:
    ev = parse_journald_entry(_entries()[1], source="journald")
    assert ev is not None
    assert ev.severity.value == "high"


def test_priority_5_maps_to_low() -> None:
    ev = parse_journald_entry(_entries()[2], source="journald")
    assert ev is not None
    assert ev.severity.value == "low"


def test_unparseable_dict_returns_none() -> None:
    # Missing required MESSAGE → drop (we don't want random structured-only entries).
    assert parse_journald_entry({"_PID": "1"}, source="journald") is None
    # Empty dict
    assert parse_journald_entry({}, source="journald") is None
```

- [ ] **Step 3: Run to confirm failure**

```bash
pytest tests/parsers/test_journald_parser.py -v
```

Expected: ImportError.

- [ ] **Step 4: Implement**

Write `inspectord/parsers/journald.py`:

```python
"""Parser for journalctl --output=json entries."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event


_PRIORITY_SEVERITY: dict[int, str] = {
    0: "high",
    1: "high",
    2: "high",
    3: "high",
    4: "medium",
    5: "low",
    6: "info",
    7: "info",
}


def _severity_from_priority(value: object) -> str:
    try:
        p = int(value) if value is not None else 6
    except (TypeError, ValueError):
        return "info"
    return _PRIORITY_SEVERITY.get(p, "info")


def _ts_from_realtime(value: object) -> datetime | None:
    try:
        micros = int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
    if micros is None:
        return None
    return datetime.fromtimestamp(micros / 1_000_000, UTC)


def parse_journald_entry(entry: dict[str, Any], source: str) -> Event | None:
    if not isinstance(entry, dict):
        return None
    message = entry.get("MESSAGE")
    if not isinstance(message, str) or not message:
        return None

    pid_raw = entry.get("_PID")
    uid_raw = entry.get("_UID")
    comm = entry.get("_COMM")
    exe = entry.get("_EXE")
    unit = entry.get("_SYSTEMD_UNIT")
    hostname = entry.get("_HOSTNAME")
    priority = entry.get("PRIORITY")

    process: dict[str, Any] | None = None
    if isinstance(comm, str) or pid_raw is not None or isinstance(exe, str):
        process = {}
        if isinstance(comm, str):
            process["name"] = comm
        if pid_raw is not None:
            try:
                process["pid"] = int(pid_raw)
            except (TypeError, ValueError):
                pass
        if isinstance(exe, str):
            process["executable"] = exe

    user: dict[str, Any] | None = None
    if uid_raw is not None:
        try:
            user = {"id": int(uid_raw)}
        except (TypeError, ValueError):
            user = None

    service: dict[str, Any] | None = None
    if isinstance(unit, str):
        name = unit
        if name.endswith(".service"):
            name = name[: -len(".service")]
        service = {"name": name, "unit": unit}

    host: dict[str, Any] | None = None
    if isinstance(hostname, str):
        host = {"hostname": hostname, "os": {"family": "linux"}}

    ts = _ts_from_realtime(entry.get("__REALTIME_TIMESTAMP"))

    return build_event(
        module="log_tailer",
        action="journal_message",
        category=["host"],
        type_=["info"],
        severity=_severity_from_priority(priority),
        message=message,
        process=process,
        user=user,
        service=service,
        raw={"source_file": source, "line": message, "fields": entry},
        ts=ts,
    )


def build_journald_event(entry: dict[str, Any], source: str = "journald") -> Event | None:
    """Public alias to keep the module's main API name consistent with other parsers."""
    return parse_journald_entry(entry, source)
```

We also need to attach the `host` dict — adjust `parse_journald_entry` to pass `host` to `build_event`. Edit `build_event` in `inspectord/parsers/base.py` to accept `host: dict[str, Any] | None = None` and pass it through:

In `inspectord/parsers/base.py`, add `host` to the signature and to the Event constructor call (find the `def build_event(...)` block and add `host: dict[str, Any] | None = None` between `kind=` and `outcome=`, then add `host=host,` to the Event(...) constructor).

Then in `inspectord/parsers/journald.py`, replace the final `return build_event(...)` block with one that passes `host=host` as well.

- [ ] **Step 5: Confirm pass + lint**

```bash
pytest tests/parsers/test_journald_parser.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 4 new tests pass; total 157.

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-04-journald-parser
git add inspectord/parsers/journald.py inspectord/parsers/base.py \
        tests/parsers/fixtures/journald.jsonl \
        tests/parsers/test_journald_parser.py
git commit -m "feat(parsers): add journald parser + host field on build_event"
git push -u origin task-logs-04-journald-parser
gh pr create --base main --head task-logs-04-journald-parser \
  --title "feat(parsers): journald JSON parser" \
  --body "Parses one dict per journalctl --output=json entry. Maps syslog PRIORITY (0–7) to our 5-level severity scale; pulls _PID/_UID/_COMM/_EXE into process+user blocks; turns _SYSTEMD_UNIT into the service block; preserves _HOSTNAME on host. build_event gains a host kwarg."
```

Wait for CI green; do NOT merge.

---

## Task 5: TailingFileSource

**Files:**
- Create: `inspectord/sources/__init__.py`
- Create: `inspectord/sources/file_tail.py`
- Create: `tests/sources/__init__.py`
- Create: `tests/sources/test_file_tail.py`

**Branch:** `task-logs-05-file-tail`

A reusable append-mode reader that yields lines from a file as they're written. Survives log rotation (file replaced with a new inode of the same name). Phase 1 supports the simple case: tail one file, detect rotation by checking inode + size on each read cycle, reopen if the inode changed.

- [ ] **Step 1: Failing tests**

Write `tests/sources/__init__.py`:

```python
```

Write `tests/sources/test_file_tail.py`:

```python
"""Tests for TailingFileSource."""

from __future__ import annotations

import os
import time
from pathlib import Path

from inspectord.sources.file_tail import TailingFileSource


def test_reads_lines_appended_after_open(tmp_path: Path) -> None:
    f = tmp_path / "log"
    f.write_text("line1\n")
    src = TailingFileSource(f, from_start=True)
    src.open()
    try:
        lines: list[str] = []
        # Drain initial content.
        for _ in range(10):
            ln = src.read_one(timeout=0.05)
            if ln is None:
                break
            lines.append(ln)
        assert lines == ["line1"]

        # Append new lines.
        with f.open("a") as fh:
            fh.write("line2\nline3\n")
            fh.flush()
        time.sleep(0.05)

        more: list[str] = []
        for _ in range(10):
            ln = src.read_one(timeout=0.05)
            if ln is None:
                break
            more.append(ln)
        assert more == ["line2", "line3"]
    finally:
        src.close()


def test_skips_existing_lines_when_from_start_false(tmp_path: Path) -> None:
    f = tmp_path / "log"
    f.write_text("old\n")
    src = TailingFileSource(f, from_start=False)
    src.open()
    try:
        assert src.read_one(timeout=0.05) is None
        with f.open("a") as fh:
            fh.write("new\n")
            fh.flush()
        time.sleep(0.05)
        assert src.read_one(timeout=0.2) == "new"
    finally:
        src.close()


def test_handles_rotation_by_inode_change(tmp_path: Path) -> None:
    f = tmp_path / "log"
    f.write_text("first\n")
    src = TailingFileSource(f, from_start=True)
    src.open()
    try:
        assert src.read_one(timeout=0.05) == "first"

        # Rotate: rename current file, write a NEW file at the same path.
        rotated = tmp_path / "log.1"
        os.rename(f, rotated)
        f.write_text("after_rotate\n")
        time.sleep(0.05)

        # Drain any leftover from the old fd (nothing in this case), then pick up the new file.
        got: list[str] = []
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline and len(got) < 1:
            ln = src.read_one(timeout=0.1)
            if ln is not None:
                got.append(ln)
        assert got == ["after_rotate"]
    finally:
        src.close()


def test_missing_file_returns_none_then_picks_up_when_created(tmp_path: Path) -> None:
    f = tmp_path / "later"
    src = TailingFileSource(f, from_start=True)
    src.open()
    try:
        assert src.read_one(timeout=0.05) is None
        f.write_text("appeared\n")
        time.sleep(0.05)
        deadline = time.monotonic() + 0.5
        got = None
        while time.monotonic() < deadline and got is None:
            got = src.read_one(timeout=0.1)
        assert got == "appeared"
    finally:
        src.close()
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest tests/sources/test_file_tail.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement**

Write `inspectord/sources/__init__.py`:

```python
"""Line-producing sources used by log_tailer (spec §4.3)."""
```

Write `inspectord/sources/file_tail.py`:

```python
"""Append-mode file tailer with simple inode-rotation handling.

Usage:
    src = TailingFileSource(Path("/var/log/pacman.log"), from_start=False)
    src.open()
    while True:
        line = src.read_one(timeout=1.0)
        if line is not None:
            handle(line)
"""

from __future__ import annotations

import os
import time
from io import TextIOWrapper
from pathlib import Path


class TailingFileSource:
    def __init__(self, path: Path, *, from_start: bool = False) -> None:
        self._path = Path(path)
        self._from_start = from_start
        self._fh: TextIOWrapper | None = None
        self._inode: int | None = None
        self._buffer = ""

    def open(self) -> None:
        self._reopen_if_needed(initial=True)

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None
        self._inode = None
        self._buffer = ""

    def _reopen_if_needed(self, *, initial: bool = False) -> None:
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
                self._inode = None
            return
        if self._inode == stat.st_ino and self._fh is not None:
            return
        # New inode or first open.
        if self._fh is not None:
            self._fh.close()
        self._fh = self._path.open("r", encoding="utf-8", errors="replace")
        self._inode = stat.st_ino
        if initial and not self._from_start:
            # Seek to EOF so existing content is ignored.
            self._fh.seek(0, os.SEEK_END)

    def read_one(self, *, timeout: float = 0.5) -> str | None:
        """Return the next complete line, or None after ``timeout`` seconds."""
        deadline = time.monotonic() + timeout
        while time.monotonic() <= deadline:
            self._reopen_if_needed()
            if self._fh is not None:
                chunk = self._fh.readline()
                if chunk:
                    self._buffer += chunk
                    if self._buffer.endswith("\n"):
                        line = self._buffer[:-1]
                        self._buffer = ""
                        return line
                    # Partial line — wait for more.
            time.sleep(0.02)
        return None
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/sources/test_file_tail.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 4 new tests pass; total 161.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-05-file-tail
git add inspectord/sources/__init__.py inspectord/sources/file_tail.py \
        tests/sources/__init__.py tests/sources/test_file_tail.py
git commit -m "feat(sources): add TailingFileSource with rotation handling"
git push -u origin task-logs-05-file-tail
gh pr create --base main --head task-logs-05-file-tail \
  --title "feat(sources): append-mode file tailer" \
  --body "TailingFileSource yields one line at a time from a file growing in append mode. Handles simple log rotation by checking the file's inode on each read cycle and reopening when it changes. Survives the watched file being absent at open time (returns None until it appears). Used by log_tailer for pacman.log + auth.log."
```

Wait for CI green; do NOT merge.

---

## Task 6: JournalSource (journalctl --follow --output=json)

**Files:**
- Create: `inspectord/sources/journal_source.py`
- Create: `tests/sources/test_journal_source.py`

**Branch:** `task-logs-06-journal-source`

Spawns `journalctl --follow --output=json --no-pager` and yields each line (one JSON object per line) as the systemd journal emits new entries. Uses an injectable command runner so tests can substitute a fake.

- [ ] **Step 1: Failing tests**

Write `tests/sources/test_journal_source.py`:

```python
"""Tests for JournalSource."""

from __future__ import annotations

import io
import json
import threading
import time

from inspectord.sources.journal_source import JournalSource


class _FakeProc:
    """Minimal Popen-like object whose stdout produces scripted lines."""

    def __init__(self, lines: list[bytes]) -> None:
        self.stdout = io.BytesIO(b"".join(lines))
        self.stderr = io.BytesIO(b"")
        self.returncode: int | None = None
        self._terminated = threading.Event()

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 0
        self._terminated.set()

    def kill(self) -> None:
        self.returncode = -9
        self._terminated.set()

    def wait(self, timeout: float | None = None) -> int:
        self._terminated.wait(timeout)
        return self.returncode if self.returncode is not None else 0


def test_journal_source_yields_parsed_entries() -> None:
    entries = [
        {"__REALTIME_TIMESTAMP": "1", "MESSAGE": "first"},
        {"__REALTIME_TIMESTAMP": "2", "MESSAGE": "second"},
    ]
    lines = [(json.dumps(e) + "\n").encode("utf-8") for e in entries]
    fake = _FakeProc(lines)

    def spawn(_argv: list[str]) -> _FakeProc:
        return fake

    src = JournalSource(spawn=spawn)
    src.open()
    try:
        got = []
        deadline = time.monotonic() + 1.0
        while len(got) < 2 and time.monotonic() < deadline:
            entry = src.read_one(timeout=0.05)
            if entry is not None:
                got.append(entry)
        assert got == entries
    finally:
        src.close()


def test_journal_source_silently_drops_invalid_json_lines() -> None:
    lines = [
        b"not json\n",
        json.dumps({"MESSAGE": "ok"}).encode("utf-8") + b"\n",
    ]
    fake = _FakeProc(lines)
    src = JournalSource(spawn=lambda _argv: fake)
    src.open()
    try:
        deadline = time.monotonic() + 1.0
        entry = None
        while entry is None and time.monotonic() < deadline:
            entry = src.read_one(timeout=0.1)
        assert entry == {"MESSAGE": "ok"}
    finally:
        src.close()


def test_journal_source_close_terminates_subprocess() -> None:
    fake = _FakeProc([])
    src = JournalSource(spawn=lambda _argv: fake)
    src.open()
    src.close()
    assert fake.returncode is not None
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/sources/test_journal_source.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement**

Write `inspectord/sources/journal_source.py`:

```python
"""journalctl --follow --output=json subprocess wrapper."""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable
from typing import Any, Protocol


class _Proc(Protocol):
    stdout: Any
    stderr: Any
    returncode: int | None

    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None = None) -> int: ...


def _default_spawn(argv: list[str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0
    )


class JournalSource:
    """Spawns ``journalctl --follow --output=json`` and yields parsed entries."""

    def __init__(
        self,
        *,
        argv: list[str] | None = None,
        spawn: Callable[[list[str]], _Proc] | None = None,
    ) -> None:
        self._argv = argv or [
            "journalctl",
            "--follow",
            "--output=json",
            "--no-pager",
        ]
        self._spawn = spawn if spawn is not None else _default_spawn  # type: ignore[assignment]
        self._proc: _Proc | None = None

    def open(self) -> None:
        if self._proc is not None:
            return
        self._proc = self._spawn(self._argv)

    def close(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._proc.wait(timeout=2.0)
        except Exception:  # noqa: BLE001
            try:
                self._proc.kill()
            except Exception:  # noqa: BLE001
                pass
        self._proc = None

    def read_one(self, *, timeout: float = 0.5) -> dict[str, Any] | None:
        if self._proc is None or self._proc.stdout is None:
            return None
        deadline = time.monotonic() + timeout
        while time.monotonic() <= deadline:
            line = self._proc.stdout.readline()
            if not line:
                if self._proc.poll() is not None:
                    return None
                time.sleep(0.02)
                continue
            try:
                obj = json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                return obj
        return None
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/sources/test_journal_source.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 3 new tests pass; total 164.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-06-journal-source
git add inspectord/sources/journal_source.py tests/sources/test_journal_source.py
git commit -m "feat(sources): add JournalSource (journalctl subprocess wrapper)"
git push -u origin task-logs-06-journal-source
gh pr create --base main --head task-logs-06-journal-source \
  --title "feat(sources): journalctl follow source" \
  --body "Spawns journalctl --follow --output=json and yields parsed dicts. Invalid JSON lines are silently skipped (journal sometimes emits non-JSON metadata). Injectable spawn callable for tests."
```

Wait for CI green; do NOT merge.

---

## Task 7: LogTailerWorker

**Files:**
- Create: `inspectord/workers/log_tailer/__init__.py`
- Create: `inspectord/workers/log_tailer/__main__.py`
- Create: `tests/test_log_tailer_worker.py`

**Branch:** `task-logs-07-log-tailer-worker`

The worker holds three sources — `JournalSource`, `TailingFileSource("/var/log/pacman.log")`, and (opportunistic) `TailingFileSource("/var/log/auth.log")` — and pipes each line through the matching parser. Implements `step()` non-blocking with a short poll on each source.

- [ ] **Step 1: Failing tests**

Write `tests/test_log_tailer_worker.py`:

```python
"""Tests for the log_tailer worker."""

from __future__ import annotations

import io
import json
import threading
import time
from pathlib import Path

from inspectord.workers.log_tailer.__main__ import LogTailerWorker


class _NeverProducingJournalSource:
    def open(self) -> None: ...
    def close(self) -> None: ...

    def read_one(self, *, timeout: float = 0.5) -> dict[str, object] | None:
        time.sleep(timeout)
        return None


def test_worker_emits_event_from_pacman_log(tmp_path: Path) -> None:
    pacman_path = tmp_path / "pacman.log"
    pacman_path.write_text("")
    auth_path = tmp_path / "auth.log"

    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = LogTailerWorker(
        name="log_tailer",
        stdout=stdout,
        stderr=stderr,
        config={
            "pacman_log_path": str(pacman_path),
            "auth_log_path": str(auth_path),
        },
        journal_source=_NeverProducingJournalSource(),
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.1)
    with pacman_path.open("a") as fh:
        fh.write("[2026-05-24T14:23:10+0000] [ALPM] installed audit (3.1.5-1)\n")
        fh.flush()
    time.sleep(0.4)
    w.request_stop()
    t.join(timeout=2.0)

    events = [
        json.loads(line)
        for line in stdout.getvalue().decode("utf-8").splitlines()
        if line.strip()
    ]
    assert any(ev["action"] == "package_installed" for ev in events)
    assert all(ev["module"] == "log_tailer" for ev in events)


def test_worker_skips_missing_auth_log(tmp_path: Path) -> None:
    """When auth.log doesn't exist (e.g. on Arch), the worker continues without error."""
    pacman_path = tmp_path / "pacman.log"
    pacman_path.write_text("")
    auth_path = tmp_path / "auth.log"  # do not create

    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = LogTailerWorker(
        name="log_tailer",
        stdout=stdout,
        stderr=stderr,
        config={
            "pacman_log_path": str(pacman_path),
            "auth_log_path": str(auth_path),
        },
        journal_source=_NeverProducingJournalSource(),
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.3)
    w.request_stop()
    t.join(timeout=2.0)
    # Worker did not crash; stderr should contain at least one heartbeat (from teardown).
    hbs = [
        json.loads(line)
        for line in stderr.getvalue().decode("utf-8").splitlines()
        if line.strip()
    ]
    assert hbs
    assert hbs[-1]["worker"] == "log_tailer"
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_log_tailer_worker.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement**

Write `inspectord/workers/log_tailer/__init__.py`:

```python
"""log_tailer worker package."""
```

Write `inspectord/workers/log_tailer/__main__.py`:

```python
"""log_tailer worker (spec §5.1)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from inspectord.parsers.auth_log import parse_auth_log_line
from inspectord.parsers.journald import parse_journald_entry
from inspectord.parsers.pacman import parse_pacman_line
from inspectord.schemas.event import Event
from inspectord.sources.file_tail import TailingFileSource
from inspectord.sources.journal_source import JournalSource
from inspectord.workers.contract import Worker, read_config_from_stdin


class _JournalSource(Protocol):
    def open(self) -> None: ...
    def close(self) -> None: ...
    def read_one(self, *, timeout: float = 0.5) -> dict[str, Any] | None: ...


_DEFAULT_PACMAN_LOG = "/var/log/pacman.log"
_DEFAULT_AUTH_LOG = "/var/log/auth.log"


class LogTailerWorker(Worker):
    def __init__(
        self,
        *,
        name: str,
        journal_source: _JournalSource | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(name=name, **kwargs)
        self._pacman_path = Path(self.config.get("pacman_log_path", _DEFAULT_PACMAN_LOG))
        self._auth_path = Path(self.config.get("auth_log_path", _DEFAULT_AUTH_LOG))
        self._journal_source: _JournalSource = (
            journal_source if journal_source is not None else JournalSource()
        )
        self._pacman_source = TailingFileSource(self._pacman_path, from_start=False)
        self._auth_source = TailingFileSource(self._auth_path, from_start=False)

    def step_interval_s(self) -> float:
        # The worker does its own internal polling on each source.
        return 0.0

    def setup(self) -> None:
        self._journal_source.open()
        self._pacman_source.open()
        self._auth_source.open()

    def teardown(self) -> None:
        for src in (self._journal_source, self._pacman_source, self._auth_source):
            try:
                src.close()
            except Exception:  # noqa: BLE001
                pass

    def _emit(self, ev: Event | None) -> None:
        if ev is None:
            return
        self.emit_event(json.loads(ev.model_dump_json()))

    def step(self) -> None:
        entry = self._journal_source.read_one(timeout=0.1)
        if entry is not None:
            self._emit(parse_journald_entry(entry, source="journald"))
        pacman_line = self._pacman_source.read_one(timeout=0.05)
        if pacman_line is not None:
            self._emit(parse_pacman_line(pacman_line, source=str(self._pacman_path)))
        auth_line = self._auth_source.read_one(timeout=0.05)
        if auth_line is not None:
            self._emit(parse_auth_log_line(auth_line, source=str(self._auth_path)))


def main() -> None:
    cfg: dict[str, Any] = read_config_from_stdin()
    LogTailerWorker(name="log_tailer", config=cfg).run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/test_log_tailer_worker.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 2 new tests pass; total 166.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-07-log-tailer-worker
git add inspectord/workers/log_tailer/ tests/test_log_tailer_worker.py
git commit -m "feat(workers): add log_tailer worker (journald + pacman + auth.log)"
git push -u origin task-logs-07-log-tailer-worker
gh pr create --base main --head task-logs-07-log-tailer-worker \
  --title "feat(workers): log_tailer worker" \
  --body "Polls JournalSource + TailingFileSource(/var/log/pacman.log) + TailingFileSource(/var/log/auth.log) in step(), feeds each line through the matching parser, emits NDJSON Events. Missing auth.log is harmless — the source returns None until the file appears, so Arch hosts see no auth.log events while Debian hosts get them automatically."
```

Wait for CI green; do NOT merge.

---

## Task 8: FimWatcherWorker (inotify)

**Files:**
- Create: `inspectord/workers/fim_watcher/__init__.py`
- Create: `inspectord/workers/fim_watcher/paths.py`
- Create: `inspectord/workers/fim_watcher/__main__.py`
- Create: `tests/test_fim_watcher_worker.py`
- Modify: `pyproject.toml` (add `inotify_simple` runtime dep)

**Branch:** `task-logs-08-fim-watcher`

A worker that watches the hardcoded path set via inotify and emits file-change Events. Phase 1 uses `inotify_simple` (small pure-Python ctypes wrapper, no system dependency beyond Linux kernel inotify). fanotify is deferred.

- [ ] **Step 1: Add the dependency**

In `/home/eli/Development/inspectord/pyproject.toml`, add `"inotify_simple>=1.3,<2"` to the runtime dependencies list.

Then reinstall:

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pip install -e '.[dev]'
```

- [ ] **Step 2: Failing tests**

Write `tests/test_fim_watcher_worker.py`:

```python
"""Tests for the fim_watcher worker."""

from __future__ import annotations

import io
import json
import threading
import time
from pathlib import Path

from inspectord.workers.fim_watcher.__main__ import FimWatcherWorker


def test_worker_emits_event_on_file_create(tmp_path: Path) -> None:
    watched_dir = tmp_path / "etc"
    watched_dir.mkdir()
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = FimWatcherWorker(
        name="fim_watcher",
        stdout=stdout,
        stderr=stderr,
        config={"watch_paths": [str(watched_dir)]},
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.1)
    target = watched_dir / "new"
    target.write_text("hello")
    time.sleep(0.3)
    w.request_stop()
    t.join(timeout=2.0)

    events = [
        json.loads(line)
        for line in stdout.getvalue().decode("utf-8").splitlines()
        if line.strip()
    ]
    actions = {ev["action"] for ev in events}
    assert {"file_created"} & actions
    assert all(ev["module"] == "fim_watcher" for ev in events)


def test_worker_emits_event_on_file_modify(tmp_path: Path) -> None:
    watched = tmp_path / "watched.txt"
    watched.write_text("v1")
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = FimWatcherWorker(
        name="fim_watcher",
        stdout=stdout,
        stderr=stderr,
        config={"watch_paths": [str(watched)]},
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.1)
    watched.write_text("v2")
    time.sleep(0.3)
    w.request_stop()
    t.join(timeout=2.0)

    events = [
        json.loads(line)
        for line in stdout.getvalue().decode("utf-8").splitlines()
        if line.strip()
    ]
    actions = {ev["action"] for ev in events}
    assert {"file_modified"} & actions


def test_worker_skips_missing_paths(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist"
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    w = FimWatcherWorker(
        name="fim_watcher",
        stdout=stdout,
        stderr=stderr,
        config={"watch_paths": [str(missing)]},
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.2)
    w.request_stop()
    t.join(timeout=2.0)
    # No crash; at least one heartbeat in stderr from teardown.
    hbs = [
        json.loads(line)
        for line in stderr.getvalue().decode("utf-8").splitlines()
        if line.strip()
    ]
    assert hbs
```

- [ ] **Step 3: Run to confirm failure**

```bash
pytest tests/test_fim_watcher_worker.py -v
```

Expected: ImportError.

- [ ] **Step 4: Implement the path set + worker**

Write `inspectord/workers/fim_watcher/__init__.py`:

```python
"""fim_watcher worker package."""
```

Write `inspectord/workers/fim_watcher/paths.py`:

```python
"""Hardcoded watched-path set (spec §0.1 / §5.1).

We watch directories where security-sensitive changes happen. Adding new paths
is intentional — kept in code, not config, until the FIM-tuning UI exists.
"""

from __future__ import annotations

import os
from pathlib import Path


def default_watch_paths() -> list[str]:
    paths: list[str] = [
        "/etc",
        "/usr/bin",
        "/usr/sbin",
        "/boot",
        "/etc/sudoers",
        "/etc/sudoers.d",
    ]
    home = os.environ.get("HOME")
    if home:
        for rel in (".bashrc", ".zshrc", ".profile", ".zprofile", ".config/autostart"):
            paths.append(str(Path(home) / rel))
    return paths
```

Write `inspectord/workers/fim_watcher/__main__.py`:

```python
"""fim_watcher worker — inotify-based file integrity monitor (spec §5.1)."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inotify_simple import INotify, flags

from inspectord.ids import uuid7
from inspectord.schemas.event import Event
from inspectord.schemas.versions import EVENT_SCHEMA_VERSION
from inspectord.workers.contract import Worker, read_config_from_stdin
from inspectord.workers.fim_watcher.paths import default_watch_paths


_WATCH_MASK = (
    flags.CREATE
    | flags.DELETE
    | flags.MODIFY
    | flags.ATTRIB
    | flags.MOVED_FROM
    | flags.MOVED_TO
    | flags.DELETE_SELF
    | flags.MOVE_SELF
)


def _action_from_flags(event_flags: int) -> str:
    if event_flags & flags.CREATE or event_flags & flags.MOVED_TO:
        return "file_created"
    if event_flags & flags.DELETE or event_flags & flags.MOVED_FROM or event_flags & flags.DELETE_SELF or event_flags & flags.MOVE_SELF:
        return "file_deleted"
    if event_flags & flags.MODIFY:
        return "file_modified"
    if event_flags & flags.ATTRIB:
        return "file_attributes_changed"
    return "file_event"


class FimWatcherWorker(Worker):
    def __init__(self, *, name: str, **kwargs: Any) -> None:
        super().__init__(name=name, **kwargs)
        self._watch_paths: list[str] = self.config.get("watch_paths") or default_watch_paths()
        self._inotify: INotify | None = None
        self._wd_to_path: dict[int, str] = {}

    def step_interval_s(self) -> float:
        return 0.0  # blocking read inside step()

    def setup(self) -> None:
        self._inotify = INotify()
        for raw in self._watch_paths:
            p = Path(raw)
            if not p.exists():
                continue
            try:
                wd = self._inotify.add_watch(str(p), _WATCH_MASK)
                self._wd_to_path[wd] = str(p)
            except (OSError, PermissionError):
                continue

    def teardown(self) -> None:
        if self._inotify is not None:
            try:
                self._inotify.close()
            except Exception:  # noqa: BLE001
                pass
            self._inotify = None

    def _emit(self, action: str, path: str, severity: str = "low") -> None:
        ev = Event.model_validate({
            "schema_version": EVENT_SCHEMA_VERSION,
            "ts": datetime.now(UTC).isoformat(),
            "event_id": str(uuid7()),
            "kind": "event",
            "category": ["file"],
            "type": ["change"],
            "action": action,
            "severity": severity,
            "module": "fim_watcher",
            "file": {"path": path},
            "host": {"hostname": os.uname().nodename, "os": {"family": "linux"}},
            "labels": [f"fim:{Path(path).name}"],
            "message": f"{action} {path}",
        })
        self.emit_event(json.loads(ev.model_dump_json()))

    def step(self) -> None:
        if self._inotify is None:
            return
        # Block briefly for events. inotify_simple's read accepts a timeout in ms.
        events = self._inotify.read(timeout=200)
        for ev in events:
            base_path = self._wd_to_path.get(ev.wd, "?")
            full_path = (
                str(Path(base_path) / ev.name) if ev.name else base_path
            )
            self._emit(_action_from_flags(ev.mask), full_path)


def main() -> None:
    cfg: dict[str, Any] = read_config_from_stdin()
    FimWatcherWorker(name="fim_watcher", config=cfg).run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Confirm pass + lint**

```bash
pytest tests/test_fim_watcher_worker.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 3 new tests pass; total 169.

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-08-fim-watcher
git add inspectord/workers/fim_watcher/ pyproject.toml tests/test_fim_watcher_worker.py
git commit -m "feat(workers): add fim_watcher inotify worker"
git push -u origin task-logs-08-fim-watcher
gh pr create --base main --head task-logs-08-fim-watcher \
  --title "feat(workers): fim_watcher (inotify)" \
  --body "Watches a hardcoded path set (/etc, /usr/bin, /usr/sbin, /boot, sudoers, shell rc files, XDG autostart) via inotify_simple. Emits file_created / file_deleted / file_modified / file_attributes_changed events. Paths that don't exist (e.g. /boot in a chroot or no ~/.zprofile) are silently skipped. fanotify is deferred."
```

Wait for CI green; do NOT merge.

---

## Task 9: Process enricher

**Files:**
- Create: `inspectord/enrichment/__init__.py`
- Create: `inspectord/enrichment/process.py`
- Create: `tests/enrichment/__init__.py`
- Create: `tests/enrichment/test_process_enricher.py`

**Branch:** `task-logs-09-process-enricher`

Given a `process.pid` on an Event, fill in `process.executable`, `process.hash.sha256`, `process.command_line`, and `process.parent.{pid, name}`. Reads `/proc/<pid>/` files. Caches by `(pid, starttime)` because PIDs are reused. Failures (process gone, /proc unreadable) leave the Event unchanged.

For testability, the enricher takes a `ProcReader` Protocol so tests can inject fakes; in production it reads from the real `/proc`.

- [ ] **Step 1: Failing tests**

Write `tests/enrichment/__init__.py`:

```python
```

Write `tests/enrichment/test_process_enricher.py`:

```python
"""Tests for the process enricher."""

from __future__ import annotations

from datetime import UTC, datetime

from inspectord.enrichment.process import ProcReader, enrich_process
from inspectord.parsers.base import build_event


class _FakeProcReader:
    def __init__(self, data: dict[int, dict[str, object]]) -> None:
        self._data = data

    def read_pid(self, pid: int) -> dict[str, object] | None:
        return self._data.get(pid)


def _ev(pid: int) -> object:
    return build_event(
        module="log_tailer",
        action="ssh_login",
        category=["authentication"],
        type_=["start"],
        severity="info",
        process={"pid": pid},
    )


def test_enrich_attaches_exe_and_hash() -> None:
    reader = _FakeProcReader({
        1234: {
            "exe": "/usr/sbin/sshd",
            "exe_sha256": "deadbeef" * 8,
            "cmdline": "/usr/sbin/sshd -D",
            "ppid": 1,
            "parent_comm": "systemd",
        }
    })
    ev = _ev(1234)
    out = enrich_process(ev, reader=reader)
    assert out.process is not None
    assert out.process["executable"] == "/usr/sbin/sshd"
    assert out.process["hash"]["sha256"] == "deadbeef" * 8
    assert out.process["command_line"] == "/usr/sbin/sshd -D"
    assert out.process["parent"] == {"pid": 1, "name": "systemd"}


def test_enrich_is_noop_when_pid_unknown() -> None:
    reader = _FakeProcReader({})
    ev = _ev(99999)
    out = enrich_process(ev, reader=reader)
    assert out.process == {"pid": 99999}  # unchanged


def test_enrich_skips_when_event_has_no_pid() -> None:
    ev = build_event(
        module="log_tailer",
        action="x",
        category=["host"],
        type_=["info"],
        severity="info",
    )
    out = enrich_process(ev, reader=_FakeProcReader({}))
    assert out.process is None
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest tests/enrichment/test_process_enricher.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement**

Write `inspectord/enrichment/__init__.py`:

```python
"""Event enrichment (spec §11.1)."""
```

Write `inspectord/enrichment/process.py`:

```python
"""Process enricher.

Given an Event with ``process.pid`` set, fills in:
  - ``process.executable`` (from /proc/<pid>/exe symlink)
  - ``process.hash.sha256`` (SHA-256 of the executable; cached)
  - ``process.command_line`` (from /proc/<pid>/cmdline)
  - ``process.parent`` (pid + name from /proc/<pid>/stat)

A missing process is a no-op — by the time we're enriching, the process may
have exited and that's fine.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Protocol

from inspectord.schemas.event import Event


class ProcReader(Protocol):
    def read_pid(self, pid: int) -> dict[str, object] | None: ...


class _RealProcReader:
    """Reads /proc/<pid>/ directly. SHA-256 cached by (path, mtime)."""

    def __init__(self) -> None:
        self._hash_cache: dict[tuple[str, float], str] = {}

    def read_pid(self, pid: int) -> dict[str, object] | None:
        base = Path(f"/proc/{pid}")
        if not base.exists():
            return None
        out: dict[str, object] = {}
        try:
            exe = (base / "exe").resolve()
            if exe.exists():
                out["exe"] = str(exe)
                stat = exe.stat()
                key = (str(exe), stat.st_mtime)
                if key not in self._hash_cache:
                    self._hash_cache[key] = self._sha256(exe)
                out["exe_sha256"] = self._hash_cache[key]
        except (PermissionError, FileNotFoundError):
            pass
        try:
            cmdline = (base / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            if cmdline:
                out["cmdline"] = cmdline
        except (PermissionError, FileNotFoundError):
            pass
        try:
            stat_text = (base / "stat").read_text(encoding="utf-8", errors="replace")
            # /proc/<pid>/stat: pid (comm) state ppid ...
            # comm is in parens and may contain spaces; find the last ')'.
            close = stat_text.rfind(")")
            if close > 0:
                fields = stat_text[close + 1 :].strip().split()
                if len(fields) >= 2:
                    out["ppid"] = int(fields[1])
        except (PermissionError, FileNotFoundError, ValueError):
            pass
        if out.get("ppid"):
            parent = Path(f"/proc/{out['ppid']}")
            try:
                pcomm = (parent / "comm").read_text(encoding="utf-8", errors="replace").strip()
                if pcomm:
                    out["parent_comm"] = pcomm
            except (PermissionError, FileNotFoundError):
                pass
        return out or None

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


_default_reader = _RealProcReader()


def enrich_process(ev: Event, *, reader: ProcReader | None = None) -> Event:
    """Return a new Event with process fields filled in where possible."""
    proc = ev.process
    if not proc or "pid" not in proc:
        return ev
    pid_raw = proc.get("pid")
    try:
        pid = int(pid_raw) if pid_raw is not None else None
    except (TypeError, ValueError):
        return ev
    if pid is None:
        return ev
    data = (reader or _default_reader).read_pid(pid)
    if data is None:
        return ev
    new_process: dict[str, Any] = dict(proc)
    if "exe" in data and "executable" not in new_process:
        new_process["executable"] = data["exe"]
    if "exe_sha256" in data:
        hash_block = dict(new_process.get("hash", {}))
        hash_block["sha256"] = data["exe_sha256"]
        new_process["hash"] = hash_block
    if "cmdline" in data and "command_line" not in new_process:
        new_process["command_line"] = data["cmdline"]
    if "ppid" in data:
        new_process["parent"] = {"pid": data["ppid"]}
        if "parent_comm" in data:
            new_process["parent"]["name"] = data["parent_comm"]
    return ev.model_copy(update={"process": new_process})
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/enrichment/test_process_enricher.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 3 new tests pass; total 172.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-09-process-enricher
git add inspectord/enrichment/__init__.py inspectord/enrichment/process.py \
        tests/enrichment/__init__.py tests/enrichment/test_process_enricher.py
git commit -m "feat(enrichment): add process enricher"
git push -u origin task-logs-09-process-enricher
gh pr create --base main --head task-logs-09-process-enricher \
  --title "feat(enrichment): process enricher" \
  --body "Given an Event carrying process.pid, fills in process.executable / process.hash.sha256 / process.command_line / process.parent.{pid,name} by reading /proc. SHA-256 cached by (path, mtime). PID race conditions are tolerated: a missing process is a no-op enrichment."
```

Wait for CI green; do NOT merge.

---

## Task 10: File + user enrichers

**Files:**
- Create: `inspectord/enrichment/file.py`
- Create: `inspectord/enrichment/user.py`
- Create: `tests/enrichment/test_file_enricher.py`
- Create: `tests/enrichment/test_user_enricher.py`

**Branch:** `task-logs-10-file-user-enrichers`

Two small enrichers bundled. `enrich_file` computes a SHA-256 of `file.path` (cached by inode+mtime) and adds owner/mode/setuid metadata. `enrich_user` resolves `user.id` (uid) to `user.name`.

- [ ] **Step 1: Failing tests**

Write `tests/enrichment/test_file_enricher.py`:

```python
"""Tests for the file enricher."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from inspectord.enrichment.file import enrich_file
from inspectord.parsers.base import build_event


def _ev_for(path: Path) -> object:
    return build_event(
        module="fim_watcher",
        action="file_created",
        category=["file"],
        type_=["change"],
        severity="info",
        file={"path": str(path)},
    )


def test_enrich_attaches_sha256(tmp_path: Path) -> None:
    target = tmp_path / "x"
    target.write_text("hello")
    expected = hashlib.sha256(b"hello").hexdigest()
    out = enrich_file(_ev_for(target))
    assert out.file is not None
    assert out.file["hash"]["sha256"] == expected
    assert out.file["size"] == 5


def test_enrich_marks_setuid(tmp_path: Path) -> None:
    target = tmp_path / "x"
    target.write_text("ok")
    os.chmod(target, stat.S_IRUSR | stat.S_IXUSR | stat.S_ISUID)
    out = enrich_file(_ev_for(target))
    assert out.file is not None
    assert out.file.get("setuid") is True


def test_enrich_skips_when_path_missing() -> None:
    ev = build_event(
        module="fim_watcher",
        action="x",
        category=["file"],
        type_=["change"],
        severity="info",
    )
    out = enrich_file(ev)
    assert out.file is None


def test_enrich_skips_when_file_does_not_exist(tmp_path: Path) -> None:
    out = enrich_file(_ev_for(tmp_path / "missing"))
    assert out.file == {"path": str(tmp_path / "missing")}
```

Write `tests/enrichment/test_user_enricher.py`:

```python
"""Tests for the user enricher."""

from __future__ import annotations

import os
import pwd

from inspectord.enrichment.user import enrich_user
from inspectord.parsers.base import build_event


def test_enrich_attaches_name_for_current_uid() -> None:
    uid = os.getuid()
    name = pwd.getpwuid(uid).pw_name
    ev = build_event(
        module="log_tailer",
        action="x",
        category=["authentication"],
        type_=["start"],
        severity="info",
        user={"id": uid},
    )
    out = enrich_user(ev)
    assert out.user is not None
    assert out.user["name"] == name


def test_enrich_skips_when_no_user_block() -> None:
    ev = build_event(
        module="log_tailer",
        action="x",
        category=["host"],
        type_=["info"],
        severity="info",
    )
    out = enrich_user(ev)
    assert out.user is None


def test_enrich_skips_unknown_uid() -> None:
    ev = build_event(
        module="log_tailer",
        action="x",
        category=["authentication"],
        type_=["start"],
        severity="info",
        user={"id": 999_999},
    )
    out = enrich_user(ev)
    assert out.user == {"id": 999_999}
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/enrichment/test_file_enricher.py tests/enrichment/test_user_enricher.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement file enricher**

Write `inspectord/enrichment/file.py`:

```python
"""File enricher — adds hash/size/owner/mode/setuid where the path exists."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from inspectord.schemas.event import Event


_HASH_CACHE: dict[tuple[str, int, float, int], str] = {}


def _sha256(path: Path) -> str:
    st = path.stat()
    key = (str(path), st.st_ino, st.st_mtime, st.st_size)
    if key in _HASH_CACHE:
        return _HASH_CACHE[key]
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    digest = h.hexdigest()
    _HASH_CACHE[key] = digest
    return digest


def enrich_file(ev: Event) -> Event:
    f = ev.file
    if not f:
        return ev
    raw_path = f.get("path")
    if not isinstance(raw_path, str):
        return ev
    p = Path(raw_path)
    if not p.exists() or not p.is_file():
        return ev
    new_file: dict[str, Any] = dict(f)
    try:
        st = p.stat()
        new_file["size"] = st.st_size
        new_file["mtime"] = st.st_mtime
        new_file["mode"] = oct(st.st_mode & 0o7777)
        new_file["owner"] = st.st_uid
        new_file["setuid"] = bool(st.st_mode & stat.S_ISUID)
        new_file["setgid"] = bool(st.st_mode & stat.S_ISGID)
        try:
            digest = _sha256(p)
            existing_hash = dict(new_file.get("hash", {}))
            existing_hash["sha256"] = digest
            new_file["hash"] = existing_hash
        except (PermissionError, OSError):
            pass
    except (PermissionError, OSError):
        return ev
    return ev.model_copy(update={"file": new_file})


def reset_hash_cache() -> None:
    """For tests."""
    _HASH_CACHE.clear()
```

- [ ] **Step 4: Implement user enricher**

Write `inspectord/enrichment/user.py`:

```python
"""User enricher — resolves uid → name (and groups, in a future patch)."""

from __future__ import annotations

import pwd
from typing import Any

from inspectord.schemas.event import Event


def enrich_user(ev: Event) -> Event:
    u = ev.user
    if not u:
        return ev
    uid_raw = u.get("id")
    if uid_raw is None:
        return ev
    try:
        uid = int(uid_raw)
    except (TypeError, ValueError):
        return ev
    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        return ev
    new_user: dict[str, Any] = dict(u)
    new_user.setdefault("name", pw.pw_name)
    return ev.model_copy(update={"user": new_user})
```

- [ ] **Step 5: Confirm pass + lint**

```bash
pytest tests/enrichment/test_file_enricher.py tests/enrichment/test_user_enricher.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 7 new tests pass; total 179.

- [ ] **Step 6: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-10-file-user-enrichers
git add inspectord/enrichment/file.py inspectord/enrichment/user.py \
        tests/enrichment/test_file_enricher.py tests/enrichment/test_user_enricher.py
git commit -m "feat(enrichment): add file + user enrichers"
git push -u origin task-logs-10-file-user-enrichers
gh pr create --base main --head task-logs-10-file-user-enrichers \
  --title "feat(enrichment): file + user enrichers" \
  --body "file: hash (SHA-256 cached by inode+mtime+size), size, mtime, mode, owner, setuid/setgid flags. user: uid→name via pwd. Both skip cleanly when the relevant data is unavailable (file gone, uid not in passwd)."
```

Wait for CI green; do NOT merge.

---

## Task 11: enrich() entry point + supervisor integration

**Files:**
- Modify: `inspectord/enrichment/__init__.py` (add the unified `enrich` function)
- Modify: `inspectord/supervisor.py` (call `enrich()` between parse and publish)
- Create: `tests/enrichment/test_enrich_integration.py`

**Branch:** `task-logs-11-enrich-integration`

The supervisor's `_read_stdout` currently does `Event.model_validate(payload)` then `router.publish(ev)`. Insert `ev = enrich(ev)` between those steps. Tests verify that events flowing through a real Supervisor end up enriched.

- [ ] **Step 1: Add `enrich(ev)` entry point**

Replace `inspectord/enrichment/__init__.py` with:

```python
"""Event enrichment (spec §11.1).

The supervisor invokes ``enrich(ev)`` after parsing each NDJSON line from a
worker's stdout and before publishing the Event to the router. Phase 1 wires
three enrichers in order: process → file → user.
"""

from __future__ import annotations

from inspectord.enrichment.file import enrich_file
from inspectord.enrichment.process import enrich_process
from inspectord.enrichment.user import enrich_user
from inspectord.schemas.event import Event


def enrich(ev: Event) -> Event:
    ev = enrich_process(ev)
    ev = enrich_file(ev)
    ev = enrich_user(ev)
    return ev
```

- [ ] **Step 2: Wire into supervisor**

In `inspectord/supervisor.py`, find the `_read_stdout` method. Replace the relevant block:

```python
            try:
                payload = json.loads(raw.decode("utf-8"))
                ev = Event.model_validate(payload)
                self._router.publish(ev)
            except Exception as exc:  # noqa: BLE001
                log.error("worker %s emitted invalid event: %r", wp.spec.name, exc)
```

with:

```python
            try:
                payload = json.loads(raw.decode("utf-8"))
                ev = Event.model_validate(payload)
                ev = enrich(ev)
                self._router.publish(ev)
            except Exception as exc:  # noqa: BLE001
                log.error("worker %s emitted invalid event: %r", wp.spec.name, exc)
```

And add the import at the top of `supervisor.py`:

```python
from inspectord.enrichment import enrich
```

- [ ] **Step 3: Integration test**

Write `tests/enrichment/test_enrich_integration.py`:

```python
"""End-to-end enrichment integration through the Supervisor."""

from __future__ import annotations

import time
from pathlib import Path

from inspectord.config import dev_config
from inspectord.supervisor import Supervisor


def test_supervisor_enriches_events_before_publish(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        captured = []

        def listener(ev: object) -> None:
            captured.append(ev)

        sup.attach_listener(listener)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not captured:
            time.sleep(0.05)
        # We don't assert exact field values — both healthcheck and dep_manager
        # workers emit events that carry no pid/path/uid, so enrichment is a no-op
        # but the path must run without exception.
        assert captured
    finally:
        sup.stop(timeout=5.0)
```

- [ ] **Step 4: Confirm pass + lint**

```bash
pytest tests/enrichment/test_enrich_integration.py tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 1 new test passes; total 180.

- [ ] **Step 5: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-11-enrich-integration
git add inspectord/enrichment/__init__.py inspectord/supervisor.py \
        tests/enrichment/test_enrich_integration.py
git commit -m "feat(supervisor): wire enrich() into the publish pipeline"
git push -u origin task-logs-11-enrich-integration
gh pr create --base main --head task-logs-11-enrich-integration \
  --title "feat(supervisor): wire enrichment into publish pipeline" \
  --body "Adds enrich(ev) as the unified entry point that the supervisor invokes between parsing a worker's NDJSON line and publishing the Event to the router. Order: process → file → user. Integration test asserts the path runs end-to-end via a real supervisor + healthcheck/dep_manager workers."
```

Wait for CI green; do NOT merge.

---

## Task 12: IPC method `list_events` + `inspectorctl events` CLI

**Files:**
- Modify: `inspectord/__main__.py` (add `list_events` method)
- Create: `inspectorctl/cli/events.py`
- Modify: `inspectorctl/cli/app.py` (mount the events subapp)
- Create: `tests/test_cli_events.py`

**Branch:** `task-logs-12-events-cli`

Adds a polling-based live tail. The IPC method `list_events(since_id?, module?, limit)` queries `events_enriched` and returns rows newer than `since_id`. The CLI calls it in a loop.

- [ ] **Step 1: Failing tests**

Write `tests/test_cli_events.py`:

```python
"""Tests for inspectorctl events CLI."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from inspectord.ipc_server import IpcServer, Method
from inspectorctl.cli.app import app


runner = CliRunner()


def test_events_search_calls_ipc(tmp_path: Path) -> None:
    sock_path = tmp_path / "ipc.sock"

    def list_events(_params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "events": [
                {
                    "event_id": "01900000-0000-7000-8000-000000000000",
                    "ts": "2026-05-24T14:23:10+00:00",
                    "module": "log_tailer",
                    "action": "package_installed",
                    "severity": "info",
                    "message": "installed audit",
                }
            ],
        }

    server = IpcServer(
        socket_path=sock_path,
        methods=[Method(name="list_events", handler=list_events, mutates=False)],
        allowed_uids=[],
    )
    server.start()
    try:
        result = runner.invoke(app, ["events", "search", "--socket", str(sock_path), "--limit", "5"])
        assert result.exit_code == 0
        assert "package_installed" in result.stdout
    finally:
        server.stop()
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_cli_events.py -v
```

Expected: ImportError (no `events` subapp yet).

- [ ] **Step 3: Add `list_events` IPC method**

In `inspectord/__main__.py`, inside the `_ipc_methods()` function, append a new method registration. Find the existing `apply_dependency_plan` registration. After it, add:

```python
        Method(
            name="list_events",
            handler=lambda params: _list_events_handler(params, cfg.storage.db_path),
            mutates=False,
        ),
```

Above the `_ipc_methods` function definition, add the helper:

```python
def _list_events_handler(params: dict[str, Any], db_path: Path) -> dict[str, Any]:
    from inspectord.storage.db import Database

    since_id = params.get("since_id")
    module = params.get("module")
    limit = int(params.get("limit", 100))
    where = "WHERE 1=1"
    args: list[Any] = []
    if since_id:
        where += " AND event_id > ?"
        args.append(str(since_id))
    if module:
        where += " AND module = ?"
        args.append(str(module))
    with Database(db_path) as db:
        rows = db.query(
            "SELECT event_id, ts, kind, module, action, severity, payload_json "
            f"FROM events_enriched {where} ORDER BY event_id ASC LIMIT ?",
            [*args, limit],
        ).fetchall()
    import json as _json
    return {
        "schema_version": "1.0.0",
        "events": [
            {
                "event_id": r[0],
                "ts": r[1].isoformat() if r[1] else None,
                "kind": r[2],
                "module": r[3],
                "action": r[4],
                "severity": r[5],
                **_json.loads(r[6]),
            }
            for r in rows
        ],
    }
```

The merge `**_json.loads(r[6])` lets the rendered row carry the full event payload (message, host, process, etc.) so the CLI can render details without a second IPC round-trip.

- [ ] **Step 4: Implement the CLI**

Write `inspectorctl/cli/events.py`:

```python
"""inspectorctl events subcommands."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Annotated

import typer
from rich import print as rprint

from inspectorctl.ipc_client import IpcClient, IpcError


app = typer.Typer(no_args_is_help=True, add_completion=False, help="Browse events flowing through the daemon.")


_DEFAULT_SOCKET = Path("var") / "inspectord.sock"


def _client(socket: Path) -> IpcClient:
    return IpcClient(socket_path=socket)


def _render(ev: dict[str, object]) -> str:
    ts = ev.get("ts") or ""
    module = ev.get("module") or "?"
    severity = ev.get("severity") or "?"
    action = ev.get("action") or "?"
    message = ev.get("message") or ""
    return f"{ts}  [{severity:<6}] {module:<18} {action:<28} {message}"


@app.command("search")
def search_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    module: Annotated[str | None, typer.Option("--module")] = None,
    limit: Annotated[int, typer.Option("--limit")] = 100,
) -> None:
    """Print the most recent events (one-shot)."""
    params: dict[str, object] = {"limit": limit}
    if module:
        params["module"] = module
    try:
        result = _client(socket).call("list_events", params)
    except IpcError as exc:
        rprint(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc
    for ev in result.get("events", []):
        rprint(_render(ev))


@app.command("tail")
def tail_cmd(
    socket: Annotated[Path, typer.Option("--socket", "-s")] = _DEFAULT_SOCKET,
    module: Annotated[str | None, typer.Option("--module")] = None,
    poll_interval: Annotated[float, typer.Option("--poll-interval")] = 1.0,
) -> None:
    """Stream new events as they arrive (polling)."""
    client = _client(socket)
    since: str | None = None
    try:
        while True:
            params: dict[str, object] = {"limit": 200}
            if module:
                params["module"] = module
            if since:
                params["since_id"] = since
            try:
                result = client.call("list_events", params)
            except IpcError as exc:
                rprint(f"[red]ERROR[/red] {exc}")
                raise typer.Exit(code=1) from exc
            for ev in result.get("events", []):
                rprint(_render(ev))
                since = ev.get("event_id") or since
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        rprint("\n[dim]stopped[/dim]")
```

- [ ] **Step 5: Mount the subapp**

In `inspectorctl/cli/app.py`, add to the imports and registrations:

```python
from inspectorctl.cli import deps, events, self_test, status, version

...

app.add_typer(events.app, name="events")
```

- [ ] **Step 6: Confirm pass + lint**

```bash
pytest tests/test_cli_events.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 1 new test passes; total 181.

- [ ] **Step 7: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-12-events-cli
git add inspectord/__main__.py inspectorctl/cli/events.py inspectorctl/cli/app.py \
        tests/test_cli_events.py
git commit -m "feat(cli): add inspectorctl events tail/search + list_events IPC method"
git push -u origin task-logs-12-events-cli
gh pr create --base main --head task-logs-12-events-cli \
  --title "feat(cli): events tail/search" \
  --body "Adds a list_events IPC method that queries events_enriched (filtered by module, paginated by since_id) and an inspectorctl events subapp with search (one-shot) and tail (polling) commands. UUIDv7 ids are lexicographically time-sortable so pagination is dirt-cheap."
```

Wait for CI green; do NOT merge.

---

## Task 13: Register log_tailer + fim_watcher in dev_config

**Files:**
- Modify: `inspectord/config.py`
- Modify: `tests/test_supervisor.py`

**Branch:** `task-logs-13-register-collectors`

- [ ] **Step 1: Update dev_config**

In `inspectord/config.py`, replace the `"workers"` list inside `dev_config(*, base)` with:

```python
        "workers": [
            {
                "name": "healthcheck",
                "module": "inspectord.workers.healthcheck",
                "config": {"interval_s": 1.0},
            },
            {
                "name": "dependency_manager",
                "module": "inspectord.workers.dependency_manager",
                "config": {"interval_s": 30.0},
            },
            {
                "name": "log_tailer",
                "module": "inspectord.workers.log_tailer",
                "config": {
                    # Dev-mode tail of pacman.log + auth.log + journalctl.
                    # Missing files are skipped silently.
                    "pacman_log_path": "/var/log/pacman.log",
                    "auth_log_path": "/var/log/auth.log",
                },
            },
            {
                "name": "fim_watcher",
                "module": "inspectord.workers.fim_watcher",
                "config": {},  # uses default_watch_paths() in the worker
            },
        ],
```

- [ ] **Step 2: Extend supervisor test**

Append to `tests/test_supervisor.py`:

```python
def test_supervisor_starts_log_tailer_and_fim_watcher(tmp_path: Path) -> None:
    cfg = dev_config(base=tmp_path)
    sup = Supervisor(cfg)
    sup.start()
    try:
        # All four workers should be present in the supervisor's process list.
        names = {wp.spec.name for wp in sup._procs}  # type: ignore[attr-defined]
        assert {"healthcheck", "dependency_manager", "log_tailer", "fim_watcher"} <= names
    finally:
        sup.stop(timeout=5.0)
```

- [ ] **Step 3: Confirm pass + lint**

```bash
pytest tests/test_supervisor.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 1 new test passes; total 182.

- [ ] **Step 4: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-13-register-collectors
git add inspectord/config.py tests/test_supervisor.py
git commit -m "feat(config): register log_tailer + fim_watcher in dev_config"
git push -u origin task-logs-13-register-collectors
gh pr create --base main --head task-logs-13-register-collectors \
  --title "feat(config): wire log_tailer + fim_watcher into the supervisor" \
  --body "dev_config now spawns four workers: healthcheck, dependency_manager, log_tailer, fim_watcher. Supervisor test asserts all four are alive."
```

Wait for CI green; do NOT merge.

---

## Task 14: End-to-end integration test

**Files:**
- Create: `tests/integration/test_log_tailer_e2e.py`

**Branch:** `task-logs-14-e2e`

Spawns `inspectord --dev`, lets the collectors run for ~3 seconds, SIGTERMs the daemon (DuckDB lock), and queries `events_enriched` to confirm events landed.

The test cannot rely on actual journald emitting anything (CI runners may be sparse on journal traffic), so it has two paths:

1. If running on a system with journald active, expect at least one `log_tailer` event.
2. Always create a file under a temporary watch directory to provoke the fim_watcher.

To make this test deterministic on CI, we override the `dev_config` paths to point at temp directories the test controls.

- [ ] **Step 1: Write the test**

Write `tests/integration/test_log_tailer_e2e.py`:

```python
"""End-to-end test: log_tailer + fim_watcher events land in DuckDB."""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from inspectord.storage.db import Database


@pytest.mark.integration
def test_collectors_emit_events_into_db(tmp_path: Path) -> None:
    var = tmp_path / "var"
    var.mkdir()
    fake_pacman = tmp_path / "pacman.log"
    fake_pacman.write_text("")
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()

    config_path = tmp_path / "inspectord.toml"
    config_path.write_text(
        f"""
version = "1.0.0"

[storage]
db_path = "{var / 'inspectord.duckdb'}"
journal_dir = "{var / 'journal'}"

[ipc]
socket_path = "{var / 'inspectord.sock'}"
allowed_uids = []

[[workers]]
name = "log_tailer"
module = "inspectord.workers.log_tailer"

[workers.config]
pacman_log_path = "{fake_pacman}"
auth_log_path = "{tmp_path / 'auth.log'}"

[[workers]]
name = "fim_watcher"
module = "inspectord.workers.fim_watcher"

[workers.config]
watch_paths = ["{watch_dir}"]
""".strip()
    )

    proc = subprocess.Popen(
        [sys.executable, "-m", "inspectord", "--config", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    socket_path = var / "inspectord.sock"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not socket_path.exists():
        time.sleep(0.1)
    assert socket_path.exists(), "daemon never created its IPC socket"

    try:
        # Provoke fim_watcher.
        (watch_dir / "newfile").write_text("hello")
        # Provoke log_tailer's pacman parser.
        with fake_pacman.open("a") as fh:
            fh.write("[2026-05-24T14:23:10+0000] [ALPM] installed audit (3.1.5-1)\n")
            fh.flush()
        # Give workers time to pick them up.
        time.sleep(2.5)
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    db_path = var / "inspectord.duckdb"
    deadline = time.monotonic() + 10
    log_tailer_rows = fim_watcher_rows = 0
    while time.monotonic() < deadline:
        if db_path.exists():
            with Database(db_path) as db:
                log_tailer_rows = db.query(
                    "SELECT COUNT(*) FROM events_enriched WHERE module = 'log_tailer'"
                ).fetchall()[0][0]
                fim_watcher_rows = db.query(
                    "SELECT COUNT(*) FROM events_enriched WHERE module = 'fim_watcher'"
                ).fetchall()[0][0]
            if log_tailer_rows >= 1 and fim_watcher_rows >= 1:
                break
        time.sleep(0.2)

    assert log_tailer_rows >= 1, "log_tailer never wrote a pacman event to DuckDB"
    assert fim_watcher_rows >= 1, "fim_watcher never wrote a file event to DuckDB"
```

- [ ] **Step 2: Run**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
pytest -m integration tests/integration/test_log_tailer_e2e.py -v
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: 1 new integration test passes; total 183.

- [ ] **Step 3: Commit + PR**

```bash
git checkout main && git pull origin main
git checkout -b task-logs-14-e2e
git add tests/integration/test_log_tailer_e2e.py
git commit -m "test(integration): collectors emit events into DuckDB end-to-end"
git push -u origin task-logs-14-e2e
gh pr create --base main --head task-logs-14-e2e \
  --title "test(integration): collectors → enrichment → DuckDB e2e" \
  --body "Boots a real inspectord process with a custom TOML config that points log_tailer at a temp pacman.log and fim_watcher at a temp directory. Appends one pacman line and creates one file; asserts both events land in events_enriched."
```

Wait for CI green; do NOT merge.

---

## Task 15: Manual sanity check

**Files:** none (no commit, no PR — manual checklist for the controller / human).

After all 14 prior PRs are merged, run this on the user's CachyOS host (one-time verification, no CI equivalent):

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
git checkout main && git pull origin main

# Fresh slate.
rm -rf var/

# Make sure dep_manager has installed auditd (Phase 1 of dep_manager plan).
# If you haven't done the manual acceptance for dep_manager yet, skip this step —
# the test still works without auditd; journald emits its own events.

inspectord --dev &
sleep 3
inspectorctl events tail --module log_tailer &
TAIL_PID=$!
sleep 2

# Provoke a few real events.
sudo pacman -Q audit > /dev/null   # creates pacman.log lock acquisition entries via journald
touch /etc/inspectord-manual-test
sudo rm /etc/inspectord-manual-test

# Stop the tail and the daemon.
kill "$TAIL_PID" 2>/dev/null || true
sleep 1
inspectorctl events search --module fim_watcher --limit 10
kill %1
wait %1 2>/dev/null || true
```

Expected: live tail prints journald entries from systemd; the FIM search shows `file_created` and `file_deleted` events for `/etc/inspectord-manual-test`.

No commit. If anything fails, open a follow-up task.

---

## Task 16: Final sweep + spec changelog bump

**Files:**
- Modify: `docs/superpowers/specs/2026-05-24-local-inspection-design.md`

**Branch:** `task-logs-16-spec-bump`

- [ ] **Step 1: Verify the tree is green**

```bash
cd /home/eli/Development/inspectord
source .venv/bin/activate
git checkout main && git pull origin main
pytest tests/ -v
ruff check inspectord inspectorctl tests
ruff format --check inspectord inspectorctl tests
mypy inspectord inspectorctl
```

Expected: all checks green; ~183 tests pass.

- [ ] **Step 2: Bump spec to v0.2.2**

In `docs/superpowers/specs/2026-05-24-local-inspection-design.md`:

Change the `Spec version` header line to `0.2.2` and append a new changelog row:

```
| 0.2.2 | 2026-05-24 | First real collector slice landed: log_tailer (journald + pacman + auth.log), fim_watcher (inotify on a hardcoded path set), and the enrichment library (process / file / user). New IPC method `list_events`; new CLI `inspectorctl events tail/search`. No rule engine yet — that's the next plan. |
```

- [ ] **Step 3: Commit + PR**

```bash
git checkout -b task-logs-16-spec-bump
git add docs/superpowers/specs/2026-05-24-local-inspection-design.md
git commit -m "docs(spec): bump to v0.2.2 — log_tailer + fim_watcher + enrichment landed"
git push -u origin task-logs-16-spec-bump
gh pr create --base main --head task-logs-16-spec-bump \
  --title "docs(spec): bump to v0.2.2" \
  --body "Marks the log_tailer + fim_watcher + enrichment slice as implemented."
```

Wait for CI green; do NOT merge.

---

## Acceptance criteria (this plan complete)

After Task 14 merges and the manual sanity check in Task 15 passes:

```bash
$ pytest tests/                     → ~183 passed
$ ruff / mypy                       → clean
$ inspectord --dev &
$ inspectorctl events tail          → live journald + pacman + fim events
$ inspectorctl events search --module fim_watcher --limit 5
                                    → recent file events with enriched fields
```

DuckDB's `events_enriched` table now carries real events from journald, pacman, auth.log (where present), and inotify, each enriched with process / file / user metadata via the supervisor's pipeline.

## What this plan deliberately defers

- **auditd / nftables / iptables / ufw / kmsg parsers** — they ship with the collectors that use them in later plans.
- **fanotify** in fim_watcher — requires `CAP_SYS_ADMIN`; inotify covers the v1 path set.
- **GeoIP / threat-intel / first-sighting enrichers** — arrive with the network collector and threat-intel feed updater.
- **DNS query collection** — Phase 2.
- **Rule engine + allowlist + notifier** — next plan.
- **Web dashboard panels** — final plan in Phase 1.

## Next plan after this one

`rule_engine + allowlist + notifier + starter rule pack` — the layer that turns enriched events into Alerts, with Sigma + YAML correlation + Python plugins, an allowlist with scope evaluation, and the first batch of starter rules from spec §21. After that lands, the daemon goes from "telemetry collector" to "active monitor."
