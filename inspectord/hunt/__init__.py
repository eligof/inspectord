"""Hunt — investigation queries over stored event history (hunt design).

The query language is the YAML rule engine's expression grammar, parsed by the
shared parser in `inspectord.expr`, so a hunt query and a detection rule are
written identically and a query that finds something can become a rule by
copy-paste.

PR1 is the compiler and its differential test: no storage, no IPC, no CLI, no
panel.
"""

from __future__ import annotations

from inspectord.hunt.compiler import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    CompiledQuery,
    compile_hunt_query,
)
from inspectord.hunt.errors import (
    HuntBoundsError,
    HuntError,
    HuntExecutionError,
    HuntNameError,
    HuntPathError,
    HuntQueryExists,
    HuntQueryNotFound,
    HuntSyntaxError,
    HuntUnsupportedError,
)
from inspectord.hunt.execute import HuntResult, HuntRow, run_hunt_query

__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "CompiledQuery",
    "HuntBoundsError",
    "HuntError",
    "HuntExecutionError",
    "HuntNameError",
    "HuntPathError",
    "HuntQueryExists",
    "HuntQueryNotFound",
    "HuntResult",
    "HuntRow",
    "HuntSyntaxError",
    "HuntUnsupportedError",
    "compile_hunt_query",
    "run_hunt_query",
]
