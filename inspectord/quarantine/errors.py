"""Typed quarantine errors (quarantine design §3.2).

Each error carries a stable ``error_kind`` token so IPC handlers and audit
rows can name the refusal without string-matching messages. All of these are
``ClientFacingError``: the messages are written for the person who asked for
the operation and never quote store internals.
"""

from __future__ import annotations

from inspectord.ipc_errors import ClientFacingError

__all__ = [
    "QuarantineBadStatus",
    "QuarantineBlobMissing",
    "QuarantineDenied",
    "QuarantineError",
    "QuarantineIOError",
    "QuarantineIsolationFailed",
    "QuarantineNotActive",
    "QuarantineNotFound",
    "QuarantineNotRegular",
    "QuarantinePathOccupied",
    "QuarantineRestoreNoParent",
    "QuarantineShaMismatch",
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


class QuarantineNotActive(QuarantineError):
    """Restore requires an ``active`` row; the guarded CAS found otherwise (§3.3)."""

    error_kind = "not_active"


class QuarantineBadStatus(QuarantineError):
    """Delete requires ``active``/``restored``/``failed``; the CAS found otherwise (§3.4)."""

    error_kind = "bad_status"


class QuarantinePathOccupied(QuarantineError):
    """Something re-created the original path after quarantine (§3.3 step 4).

    The link-no-replace commit found the path occupied. That is evidence, not
    clobber-fodder: the existing file is left untouched and there is no
    ``--force``.
    """

    error_kind = "path_occupied"


class QuarantineRestoreNoParent(QuarantineError):
    """The original path's parent directory no longer exists (§3.3 step 3)."""

    error_kind = "restore_no_parent"


class QuarantineBlobMissing(QuarantineError):
    """The stored blob is gone from the forensic store (backup/store drift?)."""

    error_kind = "blob_missing"


class QuarantineShaMismatch(QuarantineError):
    """The stored blob's content no longer matches the recorded sha256."""

    error_kind = "sha_mismatch"
