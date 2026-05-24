"""Tests for health probes."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from inspectord.dependencies.probes import run_probe
from inspectord.dependencies.schemas import HealthProbe, ProbeKind


class _FakeRunner:
    def __init__(
        self,
        scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]],
    ) -> None:
        self._scripts = scripts

    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        return self._scripts.get(
            tuple(argv),
            subprocess.CompletedProcess(args=argv, returncode=1, stdout=b"", stderr=b"unscripted"),
        )


def _ok(code: int = 0, out: bytes = b"", err: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=out, stderr=err)


def test_binary_exists_and_runs_true(tmp_path: Path) -> None:
    bin_path = tmp_path / "auditctl"
    bin_path.write_text("")
    bin_path.chmod(0o755)
    runner = _FakeRunner({(str(bin_path), "--version"): _ok(out=b"auditctl version 3.1.5")})
    probe = HealthProbe(kind=ProbeKind.binary_exists_and_runs)
    result = run_probe(
        probe,
        binary_paths=[str(bin_path)],
        version_cmd=[str(bin_path), "--version"],
        runner=runner,
    )
    assert result.ok is True


def test_binary_exists_but_not_runnable() -> None:
    runner = _FakeRunner({})
    probe = HealthProbe(kind=ProbeKind.binary_exists_and_runs)
    result = run_probe(probe, binary_paths=["/nonexistent/bin"], runner=runner)
    assert result.ok is False


def test_service_active(tmp_path: Path) -> None:
    runner = _FakeRunner(
        {
            ("systemctl", "is-active", "auditd.service"): _ok(out=b"active\n"),
        }
    )
    probe = HealthProbe(kind=ProbeKind.service_active, unit="auditd.service")
    assert run_probe(probe, runner=runner).ok is True


def test_service_inactive() -> None:
    runner = _FakeRunner(
        {
            ("systemctl", "is-active", "auditd.service"): _ok(code=3, out=b"inactive\n"),
        }
    )
    probe = HealthProbe(kind=ProbeKind.service_active, unit="auditd.service")
    assert run_probe(probe, runner=runner).ok is False


def test_file_exists(tmp_path: Path) -> None:
    f = tmp_path / "x"
    f.write_text("")
    probe = HealthProbe(kind=ProbeKind.file_exists, path=str(f))
    assert run_probe(probe).ok is True


def test_file_missing(tmp_path: Path) -> None:
    probe = HealthProbe(kind=ProbeKind.file_exists, path=str(tmp_path / "missing"))
    assert run_probe(probe).ok is False


def test_file_exists_and_growing(tmp_path: Path) -> None:
    f = tmp_path / "x"
    f.write_text("a")
    probe = HealthProbe(kind=ProbeKind.file_exists_and_growing, path=str(f), grow_window_s=1)
    first = run_probe(probe)
    time.sleep(0.05)
    f.write_text("ab")
    second = run_probe(probe)
    assert first.ok is False
    assert second.ok is True


def test_command_exit_zero() -> None:
    runner = _FakeRunner({("true",): _ok(code=0)})
    probe = HealthProbe(kind=ProbeKind.command_exit_zero, command=["true"])
    assert run_probe(probe, runner=runner).ok is True


def test_command_exit_nonzero() -> None:
    runner = _FakeRunner({("false",): _ok(code=1)})
    probe = HealthProbe(kind=ProbeKind.command_exit_zero, command=["false"])
    assert run_probe(probe, runner=runner).ok is False


def test_journal_pattern_recent_found() -> None:
    runner = _FakeRunner(
        {
            (
                "journalctl",
                "--since",
                "1 minute ago",
                "--no-pager",
                "--quiet",
                "--grep",
                "audit",
            ): _ok(out=b"Jan 1 audit: foo\n"),
        }
    )
    probe = HealthProbe(kind=ProbeKind.journal_pattern_recent, pattern="audit", window_s=60)
    assert run_probe(probe, runner=runner).ok is True


def test_journal_pattern_recent_missing() -> None:
    runner = _FakeRunner(
        {
            (
                "journalctl",
                "--since",
                "1 minute ago",
                "--no-pager",
                "--quiet",
                "--grep",
                "needle",
            ): _ok(out=b""),
        }
    )
    probe = HealthProbe(kind=ProbeKind.journal_pattern_recent, pattern="needle", window_s=60)
    assert run_probe(probe, runner=runner).ok is False
