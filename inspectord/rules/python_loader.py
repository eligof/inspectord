"""Discovers Python plugin rules under a package.

Any module-level identifier named ``RULE`` that satisfies the Rule Protocol is
collected. ``RULES`` (a list) is also recognised for modules exposing multiple
rules.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from inspectord.rules.base import Rule


def _is_rule_like(obj: Any) -> bool:
    return all(hasattr(obj, attr) for attr in ("rule_id", "severity", "category", "evaluate"))


def load_python_rules(package_name: str) -> list[Rule]:
    """Walk ``package_name`` (must be importable) collecting RULE / RULES exports."""
    try:
        package = importlib.import_module(package_name)
    except ModuleNotFoundError:
        return []
    out: list[Rule] = []
    paths = getattr(package, "__path__", None)
    if paths is None:
        return out
    for mod in pkgutil.iter_modules(paths):
        full = f"{package_name}.{mod.name}"
        try:
            module = importlib.import_module(full)
        except Exception:  # bad plugin shouldn't crash the loader
            continue
        single = getattr(module, "RULE", None)
        if single is not None and _is_rule_like(single):
            out.append(single)
        many = getattr(module, "RULES", None)
        if isinstance(many, list):
            for item in many:
                if _is_rule_like(item):
                    out.append(item)
    return out
