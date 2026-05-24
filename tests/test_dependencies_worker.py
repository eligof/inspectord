"""Tests for the dependency_manager worker."""

from __future__ import annotations

import io
import json
import subprocess
import threading
import time

from inspectord.workers.dependency_manager.__main__ import DependencyManagerWorker


class _Runner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess[bytes]]) -> None:
        self._scripts = scripts

    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        default: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess(
            args=argv, returncode=1, stdout=b"", stderr=b""
        )
        return self._scripts.get(tuple(argv), default)


def test_worker_emits_state_events() -> None:
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    runner = _Runner(
        {
            ("systemctl", "is-active", "auditd.service"): subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"active\n", stderr=b""
            ),
            ("systemctl", "is-active", "systemd-journald.service"): subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"active\n", stderr=b""
            ),
        }
    )
    w = DependencyManagerWorker(
        name="dependency_manager",
        stdout=stdout,
        stderr=stderr,
        runner=runner,
        config={"interval_s": 0.05},
    )
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    time.sleep(0.2)
    w.request_stop()
    t.join(timeout=2)

    lines = [
        json.loads(line) for line in stdout.getvalue().decode("utf-8").splitlines() if line.strip()
    ]
    assert lines
    actions = {ev["action"] for ev in lines}
    assert "dep_verified" in actions or "dep_misconfigured" in actions
    assert all(ev["module"] == "dependency_manager" for ev in lines)
