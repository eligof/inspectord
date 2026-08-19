"""Shared pytest fixtures."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest


def _fail_with_daemon_output(proc: subprocess.Popen, message: str) -> None:
    """Fail with the daemon's own output attached.

    Without this the CI failure is a bare ConnectionRefusedError with no clue
    why the daemon was unhealthy, which is the least useful shape a failure can
    take on a machine you cannot log into.
    """
    proc.kill()
    out, err = proc.communicate(timeout=10)
    raise AssertionError(
        f"{message}\n--- daemon stdout ---\n{out.decode(errors='replace')[-4000:]}"
        f"\n--- daemon stderr ---\n{err.decode(errors='replace')[-4000:]}"
    )


@pytest.fixture
def daemon(tmp_path: Path) -> Iterator[dict[str, object]]:
    """Spin up `inspectord --dev` rooted at tmp_path; tear it down after."""
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-m", "inspectord", "--dev"],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sock_path = tmp_path / "var" / "inspectord.sock"
    # Wait until the socket actually ACCEPTS a connection, not merely until the
    # path exists: a unix socket appears at bind() and only starts accepting at
    # listen(), so an existence check can hand the test a socket that answers
    # ECONNREFUSED. That race is invisible on a fast machine and shows up on a
    # loaded CI runner, which is exactly where a flake is most expensive.
    deadline = time.monotonic() + 30
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        if sock_path.exists():
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(1.0)
                    probe.connect(str(sock_path))
                break
            except OSError as exc:
                last_error = exc
        time.sleep(0.05)
    else:
        _fail_with_daemon_output(proc, f"daemon never accepted a connection: {last_error!r}")
    if proc.poll() is not None:
        _fail_with_daemon_output(proc, f"daemon exited early with code {proc.returncode}")
    try:
        yield {"socket_path": sock_path, "proc": proc, "tmp_path": tmp_path}
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
