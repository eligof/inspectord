"""Which exceptions are allowed to speak to an IPC client.

`IpcServer._dispatch` answers a failed handler in one of two ways, and this
module is the whole of the decision:

* a `ClientFacingError` — an exception whose message was *written for* the
  person on the other end — is sent through verbatim;
* anything else is replaced with `internal error (error_ref=…)`, and the real
  exception and traceback go to the daemon log under the same ref.

The default is the sanitized one, and that is the point. Inheriting from
`ClientFacingError` is a deliberate act at the place where the message is
worded, so a handler cannot leak by accident: a `duckdb.Error` (which quotes the
generated SQL and the database path), an `OSError` (which quotes a filesystem
path) or any future bug is sanitized without anyone having to remember a
registry. `grep -rn ClientFacingError inspectord` enumerates every class that is
allowed to reach a client.

Writing the message is therefore accepting responsibility for it: it may quote
the caller's own input back at them, and must never quote SQL, schema
internals, filesystem paths or anything else the client did not already know.
"""

from __future__ import annotations

import secrets

__all__ = ["ClientFacingError", "IpcParamError", "new_error_ref"]


class ClientFacingError(Exception):
    """An exception whose message is safe and intended for the IPC client."""


class IpcParamError(ClientFacingError):
    """A request parameter is missing or unusable.

    Shared across subsystems so "a required parameter is missing" reads the
    same whichever handler says it. The message names the parameter — a name
    the client itself chose, so echoing it discloses nothing.
    """


#: Bytes of randomness in an error ref. 64 bits: the ref's only job is to be
#: unique enough that a user quoting one gets exactly one log record back.
_REF_BYTES = 8


def new_error_ref() -> str:
    """A short id tying one client response to one daemon-log traceback.

    Uniformly random rather than the project's usual uuid7: a uuid7 prefix is a
    millisecond timestamp with only 12 random bits behind it, and two handlers
    failing in the same millisecond would then share a ref — which is precisely
    when correlation matters. The log record carries its own timestamp, so the
    ref does not need to; a random ref also tells a client nothing at all.
    """
    return secrets.token_hex(_REF_BYTES)
