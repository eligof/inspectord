"""Shared fixtures for web dashboard tests."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from inspectorctl.web.app import create_app
from inspectord.ipc_server import IpcServer, Method


@pytest.fixture
def ipc_factory(tmp_path: Path) -> Iterator[Callable[[list[Method]], TestClient]]:
    """Spawn an IpcServer with the given methods; return a TestClient pointed at it."""

    server: IpcServer | None = None

    def make(methods: list[Method]) -> TestClient:
        nonlocal server
        sock_path = tmp_path / "ipc.sock"
        server = IpcServer(socket_path=sock_path, methods=methods, allowed_uids=[])
        server.start()
        app = create_app(socket_path=sock_path)
        return TestClient(app)

    yield make

    if server is not None:
        server.stop()
