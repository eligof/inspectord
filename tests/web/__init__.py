"""Shared helpers for the web dashboard tests.

The dashboard answers only to ``Host`` values it was configured for, and the
shipped default is loopback only (``inspectorctl.web.csrf``). ``TestClient``'s
own default base URL is ``http://testserver``, which is *not* loopback — so
every client in this package is pointed at a loopback base URL, rather than the
guard being widened to accept ``testserver``. The suite therefore exercises the
default allowlist the product actually ships, and a test that builds a bare
``TestClient(app)`` fails loudly with ``400`` instead of quietly bypassing.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

#: The URL a user's browser would be on. Supplies both ``Host`` and ``Origin``.
BASE_URL = "http://127.0.0.1:8765"

#: What a browser sitting on the dashboard sends with a form POST.
SAME_ORIGIN = {"Origin": BASE_URL}


def web_client(app: FastAPI, **kwargs: Any) -> TestClient:
    """A ``TestClient`` addressed the way a browser on the dashboard addresses it."""

    return TestClient(app, base_url=BASE_URL, **kwargs)
