"""Alert status state machine (spec §9.1)."""

from __future__ import annotations

from inspectord.ipc_errors import ClientFacingError
from inspectord.schemas.alert import AlertStatus


class InvalidTransitionError(ClientFacingError, RuntimeError):
    """A status change the state machine forbids.

    This escapes the alert handlers uncaught and is answered to the client, so
    it is `ClientFacingError`: "cannot transition 'resolved' -> 'acknowledged'"
    is the answer, and it quotes nothing but two status values.
    """


_ALLOWED: dict[AlertStatus, set[AlertStatus]] = {
    AlertStatus.new: {AlertStatus.acknowledged, AlertStatus.resolved, AlertStatus.suppressed},
    AlertStatus.acknowledged: {AlertStatus.resolved, AlertStatus.suppressed},
    AlertStatus.resolved: set(),
    AlertStatus.suppressed: set(),
}


def validate_transition(current: AlertStatus, target: AlertStatus) -> None:
    if target not in _ALLOWED.get(current, set()):
        raise InvalidTransitionError(f"cannot transition {current.value!r} → {target.value!r}")
