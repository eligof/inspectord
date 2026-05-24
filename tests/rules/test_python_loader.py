"""Tests for the Python plugin rule loader."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

from inspectord.rules.python_loader import load_python_rules


def test_load_rules_from_package(tmp_path: Path) -> None:
    pkg = tmp_path / "fakepkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "rule_one.py").write_text(
        textwrap.dedent("""
        from inspectord.rules.base import EvalContext, Match


        class _R:
            rule_id = "fake.one"
            severity = "info"
            category = "test"

            def evaluate(self, ctx: EvalContext) -> list[Match]:
                return []


        RULE = _R()
    """)
    )
    sys.path.insert(0, str(tmp_path))
    try:
        rules = load_python_rules("fakepkg")
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("fakepkg", None)
        sys.modules.pop("fakepkg.rule_one", None)
    ids = [r.rule_id for r in rules]
    assert "fake.one" in ids


def test_loader_skips_modules_without_rule(tmp_path: Path) -> None:
    pkg = tmp_path / "fakepkg2"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "no_rule.py").write_text("X = 1\n")
    sys.path.insert(0, str(tmp_path))
    try:
        rules = load_python_rules("fakepkg2")
    finally:
        sys.path.remove(str(tmp_path))
        for k in list(sys.modules):
            if k.startswith("fakepkg2"):
                sys.modules.pop(k)
    assert rules == []
