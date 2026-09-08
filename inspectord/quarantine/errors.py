"""Typed quarantine errors (quarantine design §3.2).

Each error carries a stable ``error_kind`` token so IPC handlers and audit
rows can name the refusal without string-matching messages. All of these are
``ClientFacingError``: the messages are written for the person who asked for
the operation and never quote store internals.
"""

from __future__ import annotations

from inspectord.ipc_errors import ClientFacingError

__all__ = [
    "QuarantineDenied",
    "QuarantineError",
    "QuarantineIOError",
    "QuarantineIsolationFailed",
    "QuarantineNotFound",
    "QuarantineNotRegular",
    "QuarantineSwapped",
    "QuarantineTooLarge",
]


class QuarantineError(ClientFacingError):
    """Base class for every quarantine refusal/failure."""

    error_kind: str = "error"


class QuarantineDenied(QuarantineError):
    """The path is on the quarantine deny-list (or otherwise refused outright)."""

    error_kind = "denied"


class QuarantineNotFound(QuarantineError):
    """No such file (or its parent directory is gone)."""

    error_kind = "not_found"


class QuarantineNotRegular(QuarantineError):
    """Not a regular file: directory, symlink, FIFO, device or socket."""

    error_kind = "not_regular"


class QuarantineTooLarge(QuarantineError):
    """The file exceeds the quarantine byte cap; refusal, never truncation."""

    error_kind = "too_large"


class QuarantineSwapped(QuarantineError):
    """The thing at the path is no longer the thing that was captured.

    dev/ino mismatch between the captured fd and a pre-unlink ``fstatat``
    through the held dirfd — a swapped file or parent. Nothing is unlinked.
    """

    error_kind = "swapped"


class QuarantineIsolationFailed(QuarantineError):
    """The capture succeeded but the original could not be removed.

    The copy IS in the forensic store; the row is kept in status ``failed``.
    """

    error_kind = "isolation_failed"


class QuarantineIOError(QuarantineError):
    """An OS-level failure that fits no more specific refusal."""

    error_kind = "io_error"
