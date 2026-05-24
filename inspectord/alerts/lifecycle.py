"""Alert status state machine (spec §9.1)."""

from __future__ import annotations

from inspectord.schemas.alert import AlertStatus


class InvalidTransitionError(RuntimeError):
    pass


_ALLOWED: dict[AlertStatus, set[AlertStatus]] = {
    AlertStatus.new: {AlertStatus.acknowledged, AlertStatus.resolved, AlertStatus.suppressed},
    AlertStatus.acknowledged: {AlertStatus.resolved, AlertStatus.suppressed},
    AlertStatus.resolved: set(),
    AlertStatus.suppressed: set(),
}


def validate_transition(current: AlertStatus, target: AlertStatus) -> None:
    if target not in _ALLOWED.get(current, set()):
        raise InvalidTransitionError(f"cannot transition {current.value!r} → {target.value!r}")
