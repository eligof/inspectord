"""Smoke test: the Rust extension module exposes a callable hello()."""

from __future__ import annotations


def test_native_hello_returns_expected_string() -> None:
    from inspectord._native import hello

    assert hello() == "hello from inspectord_native"
