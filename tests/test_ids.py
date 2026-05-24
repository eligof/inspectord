"""Tests for the UUIDv7 helper."""

import time
import uuid

from inspectord.ids import uuid7


def test_uuid7_returns_uuid_object() -> None:
    result = uuid7()
    assert isinstance(result, uuid.UUID)


def test_uuid7_version_is_7() -> None:
    result = uuid7()
    assert result.version == 7


def test_uuid7_is_unique() -> None:
    ids = {uuid7() for _ in range(1000)}
    assert len(ids) == 1000


def test_uuid7_sorts_by_creation_time() -> None:
    first = uuid7()
    time.sleep(0.005)
    second = uuid7()
    assert first.bytes < second.bytes
