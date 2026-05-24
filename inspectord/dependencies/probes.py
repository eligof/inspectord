"""Health probes (spec §30.7)."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from inspectord.dependencies.schemas import HealthProbe, ProbeKind


@dataclass
class ProbeResult:
    ok: bool
    detail: str


class _Runner(Protocol):
    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]: ...


class _DefaultRunner:
    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(argv, timeout=timeout, check=check, capture_output=True)


_GROW_LAST_MTIME: dict[str, float] = {}


def run_probe(
    probe: HealthProbe,
    *,
    binary_paths: list[str] | None = None,
    version_cmd: list[str] | None = None,
    runner: _Runner | None = None,
) -> ProbeResult:
    r = runner if runner is not None else _DefaultRunner()
    return _dispatch(probe, binary_paths=binary_paths, version_cmd=version_cmd, runner=r)


def _dispatch(
    probe: HealthProbe,
    *,
    binary_paths: list[str] | None,
    version_cmd: list[str] | None,
    runner: _Runner,
) -> ProbeResult:
    kind = probe.kind
    match kind:
        case ProbeKind.binary_exists_and_runs:
            return _probe_binary(binary_paths or [], version_cmd, runner)
        case ProbeKind.service_active:
            return _probe_service(probe.unit, runner)
        case ProbeKind.file_exists | ProbeKind.file_exists_and_growing:
            return _probe_file(probe)
        case ProbeKind.command_exit_zero:
            return _probe_command_zero(probe.command, runner)
        case ProbeKind.journal_pattern_recent:
            return _probe_journal(probe.pattern, probe.window_s, runner)
        case _:
            return ProbeResult(False, f"unknown probe kind: {kind}")


def _probe_binary(
    paths: list[str],
    version_cmd: list[str] | None,
    runner: _Runner,
) -> ProbeResult:
    existing = [p for p in paths if Path(p).exists() and os.access(p, os.X_OK)]
    if not existing:
        return ProbeResult(False, f"no executable binary in {paths}")
    if version_cmd:
        result = runner.run(version_cmd)
        if result.returncode != 0:
            return ProbeResult(False, f"version command exit {result.returncode}")
        return ProbeResult(True, result.stdout.decode("utf-8", "replace").strip()[:200])
    return ProbeResult(True, f"binary found at {existing[0]}")


def _probe_service(unit: str | None, runner: _Runner) -> ProbeResult:
    if not unit:
        return ProbeResult(False, "service_active probe requires unit")
    result = runner.run(["systemctl", "is-active", unit])
    if result.returncode == 0:
        return ProbeResult(True, f"{unit} active")
    return ProbeResult(False, f"{unit} returned {result.stdout.decode().strip()}")


def _probe_file(probe: HealthProbe) -> ProbeResult:
    if probe.kind is ProbeKind.file_exists_and_growing:
        return _probe_file_growing(probe.path, probe.grow_window_s)
    return _probe_file_exists(probe.path)


def _probe_file_exists(path: str | None) -> ProbeResult:
    if path is None:
        return ProbeResult(False, "file_exists requires path")
    p = Path(path)
    return ProbeResult(p.exists(), f"{path} {'present' if p.exists() else 'missing'}")


def _probe_file_growing(path: str | None, window_s: int) -> ProbeResult:
    if path is None:
        return ProbeResult(False, "file_exists_and_growing requires path")
    p = Path(path)
    if not p.exists():
        _GROW_LAST_MTIME.pop(path, None)
        return ProbeResult(False, f"{path} missing")
    now = p.stat().st_mtime
    prev = _GROW_LAST_MTIME.get(path)
    _GROW_LAST_MTIME[path] = now
    if prev is None:
        return ProbeResult(False, f"{path} mtime sample captured (waiting for next probe)")
    if now > prev:
        return ProbeResult(True, f"{path} mtime advanced from {prev} to {now}")
    age = time.time() - now
    if age > window_s:
        return ProbeResult(False, f"{path} has not grown in {age:.0f}s (> {window_s}s)")
    return ProbeResult(False, f"{path} mtime unchanged ({now})")


def _probe_command_zero(command: list[str] | None, runner: _Runner) -> ProbeResult:
    if not command:
        return ProbeResult(False, "command_exit_zero requires command")
    result = runner.run(command)
    return ProbeResult(
        result.returncode == 0,
        f"{' '.join(command)} exit {result.returncode}",
    )


def _probe_journal(pattern: str | None, window_s: int, runner: _Runner) -> ProbeResult:
    if not pattern:
        return ProbeResult(False, "journal_pattern_recent requires pattern")
    since = f"{max(1, window_s // 60)} minute ago"
    result = runner.run(
        ["journalctl", "--since", since, "--no-pager", "--quiet", "--grep", pattern]
    )
    if result.returncode != 0:
        return ProbeResult(False, f"journalctl exit {result.returncode}")
    out = result.stdout.decode("utf-8", "replace")
    if out.strip():
        return ProbeResult(True, f"matched in journal: {out.splitlines()[0][:200]}")
    return ProbeResult(False, "no matching journal lines")
