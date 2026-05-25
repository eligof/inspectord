"""Smoke test: the Rust extension module exposes a callable hello()."""

from __future__ import annotations

from inspectord._native import hello


def test_native_hello_returns_expected_string() -> None:
    assert hello() == "hello from inspectord_native"
