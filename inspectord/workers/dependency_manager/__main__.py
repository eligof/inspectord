"""dependency_manager worker (spec §30.8).

Runs continuously, periodically verifying every declared dependency. Emits
state events whose `action` carries the verify result. Does not plan or
install — that happens via IPC.
"""

from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from typing import Any, Protocol

from inspectord.dependencies.manifest import load_packaged_manifests
from inspectord.dependencies.probes import ProbeResult, run_probe
from inspectord.ids import uuid7
from inspectord.schemas.versions import EVENT_SCHEMA_VERSION
from inspectord.workers.contract import Worker, read_config_from_stdin


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


class DependencyManagerWorker(Worker):
    def __init__(
        self,
        *,
        name: str,
        runner: _Runner | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(name=name, **kwargs)
        self._runner: _Runner = runner if runner is not None else _DefaultRunner()
        self._manifests = load_packaged_manifests()

    def step_interval_s(self) -> float:
        return float(self.config.get("interval_s", 300.0))

    def step(self) -> None:
        for name, manifest in sorted(self._manifests.items()):
            probe: ProbeResult = run_probe(
                manifest.verify.health_probe,
                binary_paths=manifest.verify.binary_paths,
                version_cmd=manifest.verify.version_cmd,
                runner=self._runner,
            )
            severity = "info" if probe.ok else "high"
            self.emit_event(
                {
                    "schema_version": EVENT_SCHEMA_VERSION,
                    "ts": datetime.now(UTC).isoformat(),
                    "event_id": str(uuid7()),
                    "kind": "state",
                    "category": ["host"],
                    "type": ["info"] if probe.ok else ["change"],
                    "action": "dep_verified" if probe.ok else "dep_misconfigured",
                    "severity": severity,
                    "module": "dependency_manager",
                    "host": {"hostname": os.uname().nodename, "os": {"family": "linux"}},
                    "labels": [f"dep:{name}"],
                    "message": f"{name}: {probe.detail}",
                }
            )


def main() -> None:
    cfg: dict[str, Any] = read_config_from_stdin()
    DependencyManagerWorker(name="dependency_manager", config=cfg).run()


if __name__ == "__main__":
    main()
