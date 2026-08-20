"""Typed hunt-compilation errors.

Rejection is a normal outcome (hunt design §6): a query that cannot be
compiled must produce a readable message, never a partial or silently-empty
result set. Every error below carries a message a human can act on without
reading the compiler.
"""

from __future__ import annotations

__all__ = [
    "HuntBoundsError",
    "HuntError",
    "HuntPathError",
    "HuntSyntaxError",
    "HuntUnsupportedError",
]


class HuntError(ValueError):
    """Base class for every hunt-query rejection."""


class HuntSyntaxError(HuntError):
    """The query text does not parse as an expression."""


class HuntPathError(HuntError):
    """A field path contains a segment that cannot be interpolated into SQL."""


class HuntUnsupportedError(HuntError):
    """The query parses, but this backend refuses to compile it faithfully."""


class HuntBoundsError(HuntError):
    """The requested limit or time window is out of range."""
