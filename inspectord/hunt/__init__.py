"""Hunt — investigation queries over stored event history (hunt design).

The query language is the YAML rule engine's expression grammar, parsed by the
shared parser in `inspectord.expr`, so a hunt query and a detection rule are
written identically and a query that finds something can become a rule by
copy-paste.

PR1 was the compiler and its differential test. PR2 adds the saved-query store
(`store`), the IPC handlers (`ipc_handlers`) and the `inspectorctl` verbs; both
are imported by module rather than re-exported here, because a handler needs a
`db_path` and belongs to the edge, not to the query language.
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
    HuntRequestError,
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
    "HuntRequestError",
    "HuntResult",
    "HuntRow",
    "HuntSyntaxError",
    "HuntUnsupportedError",
    "compile_hunt_query",
    "run_hunt_query",
]
