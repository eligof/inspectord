"""Typed hunt errors.

Rejection is a normal outcome (hunt design §6): a query that cannot be
compiled must produce a readable message, never a partial or silently-empty
result set. Every error below carries a message a human can act on without
reading the compiler.

These messages are shown to IPC clients verbatim, so each one is written for
the person who typed the query — it may quote their own text back at them, and
must never quote generated SQL, schema internals or filesystem paths.
"""

from __future__ import annotations

from inspectord.ipc_errors import ClientFacingError

__all__ = [
    "HuntBoundsError",
    "HuntError",
    "HuntExecutionError",
    "HuntNameError",
    "HuntPathError",
    "HuntQueryExists",
    "HuntQueryNotFound",
    "HuntRequestError",
    "HuntSyntaxError",
    "HuntUnsupportedError",
]


class HuntError(ClientFacingError, ValueError):
    """Base class for every hunt-query rejection.

    `ClientFacingError` is what lets these messages survive `IpcServer._dispatch`
    instead of being flattened into "internal error" — Hunt would be unusable if
    a syntax error did not say what was wrong. `ValueError` is kept because that
    is what these have always been: existing `except ValueError` call sites and
    tests still hold.
    """


class HuntSyntaxError(HuntError):
    """The query text does not parse as an expression."""


class HuntPathError(HuntError):
    """A field path contains a segment that cannot be interpolated into SQL."""


class HuntUnsupportedError(HuntError):
    """The query parses, but this backend refuses to compile it faithfully."""


class HuntBoundsError(HuntError):
    """The requested limit or time window is out of range."""


class HuntExecutionError(HuntError):
    """The database refused to run the compiled query.

    DuckDB's own message is deliberately *not* carried here: a catalog error
    quotes the failing statement (`LINE 2: FROM events_enriched`), so passing
    it through would hand an IPC client the generated SQL. The detail is logged
    daemon-side instead; the client gets its own query text back.
    """


class HuntNameError(HuntError):
    """A saved-query name is not a valid name."""


class HuntQueryExists(HuntError):
    """A saved query with this name already exists and `replace` was not set."""


class HuntQueryNotFound(HuntError):
    """No saved query with this name."""


class HuntRequestError(HuntError):
    """The request itself is malformed — a missing or contradictory parameter."""
