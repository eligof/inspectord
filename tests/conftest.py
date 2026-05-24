"""Shared pytest fixtures."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest


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
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not sock_path.exists():
        time.sleep(0.05)
    assert sock_path.exists(), "daemon did not create its IPC socket"
    try:
        yield {"socket_path": sock_path, "proc": proc, "tmp_path": tmp_path}
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
