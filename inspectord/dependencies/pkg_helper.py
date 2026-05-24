"""Privileged package-manager helper. Spec §30.12.

Runnable as `python -m inspectord.dependencies.pkg_helper --plan-id <uuid> --db <path>`.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.schemas import DEPS_HELPER_PROTOCOL_VERSION, DependencyPlanItem
from inspectord.storage.db import Database


class PkgHelperError(RuntimeError):
    pass


@dataclass
class HelperResult:
    plan_id: str
    exit_code: int
    stdout: str
    stderr: str


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


def _load_plan(db: Database, plan_id: str) -> tuple[str, str, list[DependencyPlanItem]]:
    rows = db.query(
        "SELECT distro, package_manager, items_json, expires_at, status "
        "FROM pending_dep_plans WHERE plan_id = ?",
        [plan_id],
    ).fetchall()
    if not rows:
        raise PkgHelperError(f"plan not found: {plan_id}")
    distro, pm, items_json, expires_at, status = rows[0]
    if status != "pending":
        raise PkgHelperError(f"plan status is {status!r}, expected 'pending'")
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    # DuckDB returns naive datetimes adjusted to local time; compare apples-to-apples.
    now = datetime.now() if expires_at.tzinfo is None else datetime.now(UTC)
    if expires_at < now:
        raise PkgHelperError(f"plan {plan_id} expired at {expires_at.isoformat()}")
    items = [DependencyPlanItem.model_validate(i) for i in json.loads(items_json)]
    return distro, pm, items


def _validate_against_manifest(items: list[DependencyPlanItem]) -> None:
    manifests = load_packaged_manifests()
    for item in items:
        if item.name not in manifests:
            raise PkgHelperError(
                f"plan references unknown dep {item.name!r}; not in static manifest"
            )
        allowed = set(manifests[item.name].distro_packages.get("arch", []))
        allowed |= set(manifests[item.name].distro_packages.get("cachyos", []))
        for pkg in item.packages:
            if pkg not in allowed:
                raise PkgHelperError(
                    f"package {pkg!r} for dep {item.name!r} is not in the static manifest"
                )


def _audit(
    db: Database,
    *,
    action: str,
    plan_id: str,
    target: str | None,
    command: str | None,
    exit_code: int | None,
    stderr_tail: str | None,
) -> None:
    db.execute(
        "INSERT INTO dep_audit "
        "(ts, actor, action, target, plan_id, command, exit_code, stderr_tail) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            datetime.now(UTC),
            "pkg-helper",
            action,
            target,
            plan_id,
            command,
            exit_code,
            (stderr_tail or "")[:2000],
        ],
    )


def run_helper(*, plan_id: str, db_path: Path, runner: _Runner | None = None) -> HelperResult:
    runner = runner if runner is not None else _DefaultRunner()
    with Database(db_path) as db:
        distro, pm, items = _load_plan(db, plan_id)
        if pm != "pacman":
            raise PkgHelperError(f"helper only handles pacman, plan says {pm!r}")
        if distro != "arch":
            raise PkgHelperError(f"pacman backend requires arch family; got distro={distro!r}")
        _validate_against_manifest(items)

        refresh = runner.run(["pacman", "-Sy"])
        _audit(
            db,
            action="metadata_refresh",
            plan_id=plan_id,
            target=None,
            command="pacman -Sy",
            exit_code=refresh.returncode,
            stderr_tail=refresh.stderr.decode("utf-8", "replace"),
        )
        if refresh.returncode != 0:
            return HelperResult(
                plan_id=plan_id,
                exit_code=refresh.returncode,
                stdout=refresh.stdout.decode("utf-8", "replace"),
                stderr=refresh.stderr.decode("utf-8", "replace"),
            )

        last_stdout = last_stderr = ""
        for item in items:
            if item.action != "install" or not item.packages:
                continue
            argv = ["pacman", "-S", "--noconfirm", "--needed", *item.packages]
            result = runner.run(argv)
            last_stdout = result.stdout.decode("utf-8", "replace")
            last_stderr = result.stderr.decode("utf-8", "replace")
            _audit(
                db,
                action="install" if result.returncode == 0 else "install_failed",
                plan_id=plan_id,
                target=item.name,
                command=" ".join(argv),
                exit_code=result.returncode,
                stderr_tail=last_stderr,
            )
            if result.returncode != 0:
                return HelperResult(
                    plan_id=plan_id,
                    exit_code=result.returncode,
                    stdout=last_stdout,
                    stderr=last_stderr,
                )

        db.execute("UPDATE pending_dep_plans SET status = 'applied' WHERE plan_id = ?", [plan_id])
        _audit(
            db,
            action="plan_applied",
            plan_id=plan_id,
            target=None,
            command=None,
            exit_code=0,
            stderr_tail=None,
        )
        return HelperResult(plan_id=plan_id, exit_code=0, stdout=last_stdout, stderr=last_stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="inspectord-pkg-helper")
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--db", default="/var/lib/inspectord/inspectord.duckdb")
    parser.add_argument("--protocol-version", default=DEPS_HELPER_PROTOCOL_VERSION)
    args = parser.parse_args(argv)
    if args.protocol_version != DEPS_HELPER_PROTOCOL_VERSION:
        print(
            f"pkg-helper: protocol mismatch (got {args.protocol_version}, "
            f"want {DEPS_HELPER_PROTOCOL_VERSION})",
            file=sys.stderr,
        )
        return 2
    try:
        result = run_helper(plan_id=args.plan_id, db_path=Path(args.db))
    except PkgHelperError as exc:
        print(f"pkg-helper: {exc}", file=sys.stderr)
        return 3
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
