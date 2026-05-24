"""Tests for alert lifecycle transitions."""

from __future__ import annotations

import pytest

from inspectord.alerts.lifecycle import InvalidTransitionError, validate_transition
from inspectord.schemas.alert import AlertStatus


def test_new_to_acknowledged() -> None:
    validate_transition(AlertStatus.new, AlertStatus.acknowledged)


def test_new_to_resolved() -> None:
    validate_transition(AlertStatus.new, AlertStatus.resolved)


def test_new_to_suppressed() -> None:
    validate_transition(AlertStatus.new, AlertStatus.suppressed)


def test_acknowledged_to_resolved() -> None:
    validate_transition(AlertStatus.acknowledged, AlertStatus.resolved)


def test_resolved_is_terminal() -> None:
    with pytest.raises(InvalidTransitionError):
        validate_transition(AlertStatus.resolved, AlertStatus.acknowledged)


def test_suppressed_is_terminal() -> None:
    with pytest.raises(InvalidTransitionError):
        validate_transition(AlertStatus.suppressed, AlertStatus.resolved)


def test_acknowledged_cannot_go_back_to_new() -> None:
    with pytest.raises(InvalidTransitionError):
        validate_transition(AlertStatus.acknowledged, AlertStatus.new)
