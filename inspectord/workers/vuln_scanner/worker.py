"""The vuln_scanner worker (vuln-scanner design §3-§6).

A contract worker: ``step()`` is a cheap per-poll tick that watches the scan
triggers (interval, advisory-file ``(mtime, size)``, ``/var/lib/pacman/local``
mtime) and runs at most one synchronous scan when one is due. The worker never
touches the DB — every scan emits the **entire current match set** as
``vulnerability_found`` events plus one ``vuln_scan_completed`` summary, and
the projector's sweep derives resolution from that (full-set emission, §5).

Failure honesty (§6): any scan that cannot run or complete emits exactly one
``vuln_scan_failed`` with a ``raw.reason`` — at the scan cadence, never per
poll. The pacman ``db.lck`` guard is the one deferral: the pending trigger is
kept and retried on every poll (a mid-upgrade ``pacman -Q`` reads torn state),
reported once per attempt rather than once per retry.

Everything host-shaped — paths, ``pacman -Q``, the vercmp subprocess, the
monotonic clock — is injectable, so tests drive the scheduler with a fake
clock and never touch the real pacman database.
"""

from __future__ import annotations

import functools
import socket
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from inspectord.parsers.base import build_event
from inspectord.schemas.event import Event
from inspectord.vuln.advisories import MAX_FILE_BYTES, AdvisoryLoadError, load_advisories
from inspectord.vuln.matching import (
    RunFn,
    VercmpUnavailableError,
    match_advisories,
    parse_installed,
    vercmp,
)
from inspectord.workers.contract import Worker

_DEFAULT_HOSTNAME = socket.gethostname()

DEFAULT_ADVISORY_PATH = "/var/lib/inspectord/advisories.json"
DEFAULT_INTERVAL_S = 86400.0
DEFAULT_POLL_S = 60.0
#: A mid-`mv` flap cannot thrash: at most one file-triggered scan per window.
FILE_TRIGGER_MIN_INTERVAL_S = 300.0
#: More skips than this means the file is broken — the scan fails outright,
#: because a truncated skipped list would let the sweep resolve rows that the
#: unlisted skipped AVGs still own (§5).
MAX_SKIPPED_AVG_IDS = 500

PACMAN_LOCAL_DIR = Path("/var/lib/pacman/local")
PACMAN_LOCK_PATH = Path("/var/lib/pacman/db.lck")
_PACMAN_Q_TIMEOUT_S = 120.0

PacmanQFn = Callable[[], tuple[int, str]]


def _default_pacman_q() -> tuple[int, str]:
    """Run ``pacman -Q``: ``(exit_code, stdout)``. shell=False, bounded."""
    try:
        proc = subprocess.run(
            ["pacman", "-Q"],
            capture_output=True,
            text=True,
            timeout=_PACMAN_Q_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return proc.returncode, proc.stdout


class _ScanFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class VulnScannerWorker(Worker):
    def __init__(
        self,
        *,
        name: str = "vuln_scanner",
        host_name: str = _DEFAULT_HOSTNAME,
        pacman_q: PacmanQFn = _default_pacman_q,
        pacman_local_dir: Path = PACMAN_LOCAL_DIR,
        pacman_lock_path: Path = PACMAN_LOCK_PATH,
        monotonic: Callable[[], float] = time.monotonic,
        vercmp_run: RunFn = subprocess.run,
        **kwargs: Any,
    ) -> None:
        super().__init__(name=name, **kwargs)
        self._host_name = host_name
        self._pacman_q = pacman_q
        self._pacman_local_dir = pacman_local_dir
        self._pacman_lock_path = pacman_lock_path
        self._monotonic = monotonic
        #: Worker-lifetime: vercmp is a pure function of its two strings, so
        #: steady-state rescans fork almost nothing (§4).
        self._vercmp_cache: dict[tuple[str, str], int] = {}
        self._vercmp = functools.partial(vercmp, cache=self._vercmp_cache, run=vercmp_run)
        #: None until the first successful scan; its keys drive the `new` flag.
        self._prev_keys: set[tuple[str, str, str]] | None = None
        self._next_interval_due: float | None = None  # None = scan on start
        self._pending_file_trigger = False
        self._last_file_scan: float | None = None
        self._advisory_stat: tuple[float, int] | None = None
        self._pacman_db_mtime: float | None = None
        self._stats_observed = False
        self._lock_reported = False

    # -- config ------------------------------------------------------------

    def step_interval_s(self) -> float:
        return _as_float(self.config.get("poll_s"), DEFAULT_POLL_S)

    def _advisory_path(self) -> Path:
        return Path(str(self.config.get("advisory_path", DEFAULT_ADVISORY_PATH)))

    def _interval_s(self) -> float:
        return _as_float(self.config.get("interval_s"), DEFAULT_INTERVAL_S)

    def _advisory_max_bytes(self) -> int:
        # A test hook, not an operator knob: the 64 MB cap is design-pinned.
        raw = self.config.get("advisory_max_bytes", MAX_FILE_BYTES)
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            return MAX_FILE_BYTES

    # -- the tick ----------------------------------------------------------

    def step(self) -> None:
        now = self._monotonic()
        self._observe_files()
        if not self._scan_due(now):
            return
        if self._pacman_lock_path.exists():
            # A mid-upgrade `pacman -Q` reads torn state: keep the trigger
            # pending and retry next poll, reported once per attempt (§3).
            if not self._lock_reported:
                self._lock_reported = True
                self._emit_failed("pacman_db_locked")
            return
        self._run_scan(now)

    def _scan_due(self, now: float) -> bool:
        if self._next_interval_due is None or now >= self._next_interval_due:
            return True
        if self._pending_file_trigger:
            return self._last_file_scan is None or (
                now - self._last_file_scan >= FILE_TRIGGER_MIN_INTERVAL_S
            )
        return False

    def _observe_files(self) -> None:
        advisory_stat = self._stat_advisory()
        pacman_mtime = self._stat_pacman_db()
        if self._stats_observed and (
            advisory_stat != self._advisory_stat or pacman_mtime != self._pacman_db_mtime
        ):
            self._pending_file_trigger = True
        self._advisory_stat = advisory_stat
        self._pacman_db_mtime = pacman_mtime
        self._stats_observed = True

    def _stat_advisory(self) -> tuple[float, int] | None:
        try:
            st = self._advisory_path().stat()
        except OSError:
            return None
        return (st.st_mtime, st.st_size)

    def _stat_pacman_db(self) -> float | None:
        try:
            return self._pacman_local_dir.stat().st_mtime
        except OSError:
            return None

    # -- one scan ----------------------------------------------------------

    def _run_scan(self, now: float) -> None:
        file_triggered = self._pending_file_trigger
        # Whatever happens below counts as the attempt: reschedule first so a
        # failure fires at the scan cadence, never once per poll (§6).
        self._pending_file_trigger = False
        self._lock_reported = False
        self._next_interval_due = now + self._interval_s()
        if file_triggered:
            self._last_file_scan = now

        started_wall = datetime.now(UTC)
        started_perf = time.perf_counter()
        try:
            self._scan(started_wall, started_perf)
        except _ScanFailure as failure:
            self._emit_failed(failure.reason)

    def _scan(self, started_wall: datetime, started_perf: float) -> None:
        advisory_mtime = self._stat_advisory()
        try:
            parsed = load_advisories(self._advisory_path(), max_bytes=self._advisory_max_bytes())
        except AdvisoryLoadError as exc:
            raise _ScanFailure(exc.reason) from exc

        exit_code, output = self._pacman_q()
        if exit_code != 0:
            # Never partial data: a failed -Q fails the scan (§3).
            raise _ScanFailure("pacman_failed")
        installed, unparseable_lines = parse_installed(output)

        try:
            result = match_advisories(parsed.advisories, installed, vercmp=self._vercmp)
        except VercmpUnavailableError as exc:
            raise _ScanFailure("vercmp_missing") from exc

        skipped = list(parsed.skipped_avg_ids) + result.skipped_avg_ids
        if len(skipped) > MAX_SKIPPED_AVG_IDS:
            raise _ScanFailure("parse_failed")
        warnings = parsed.warnings + result.warnings + unparseable_lines

        first_scan = self._prev_keys is None
        keys = {(m.avg_id, m.cve_id, m.package) for m in result.matches}
        prev = self._prev_keys if self._prev_keys is not None else set()
        new_keys: set[tuple[str, str, str]] = set() if first_scan else keys - prev

        for match in result.matches:
            key = (match.avg_id, match.cve_id, match.package)
            self._emit(
                build_event(
                    module=self.name,
                    action="vulnerability_found",
                    category=["package"],
                    type_=["info"],
                    severity="low",
                    kind="state",
                    host={"name": self._host_name},
                    message=(
                        f"{match.package} {match.installed_version} affected by"
                        f" {match.cve_id} ({match.avg_id}, {match.severity})"
                    ),
                    labels=["vuln"],
                    vulnerability={
                        "avg_id": match.avg_id,
                        "cve_id": match.cve_id,
                        "package": match.package,
                        "installed_version": match.installed_version,
                        "fixed_version": match.fixed_version,
                        "severity": match.severity,
                        "status": match.status,
                        "fix_in_testing": match.fix_in_testing,
                        "new": key in new_keys,
                        "advisory_url": match.advisory_url,
                    },
                    # First scan of a worker lifetime is baseline catch-up: the
                    # rule engine drops these, so a restart never re-alerts (§5).
                    first_seen=first_scan,
                )
            )

        duration_ms = int((time.perf_counter() - started_perf) * 1000)
        self._emit(
            build_event(
                module=self.name,
                action="vuln_scan_completed",
                category=["package"],
                type_=["end"],
                severity="info",
                outcome="success",
                host={"name": self._host_name},
                message=f"vulnerability scan completed: {len(result.matches)} matched",
                labels=["vuln"],
                raw={
                    "scan_started_at": started_wall.isoformat(),
                    "advisories": len(parsed.advisories),
                    "matched": len(result.matches),
                    "new": len(new_keys),
                    "warnings": warnings,
                    "skipped_avg_ids": skipped,
                    "advisory_mtime": (
                        datetime.fromtimestamp(advisory_mtime[0], tz=UTC).isoformat()
                        if advisory_mtime is not None
                        else None
                    ),
                    "duration_ms": duration_ms,
                },
            )
        )
        self._prev_keys = keys

    # -- emission ----------------------------------------------------------

    def _emit(self, event: Event) -> None:
        self.emit_event(event.model_dump(mode="json", exclude_none=True))

    def _emit_failed(self, reason: str) -> None:
        self._emit(
            build_event(
                module=self.name,
                action="vuln_scan_failed",
                category=["package"],
                type_=["end"],
                severity="info",
                outcome="failure",
                host={"name": self._host_name},
                message=f"vulnerability scan failed: {reason}",
                labels=["vuln"],
                raw={"reason": reason},
            )
        )


def _as_float(raw: Any, default: float) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default
