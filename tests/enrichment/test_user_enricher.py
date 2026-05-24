"""Tests for the user enricher."""

from __future__ import annotations

import os
import pwd

from inspectord.enrichment.user import enrich_user
from inspectord.parsers.base import build_event


def test_enrich_attaches_name_for_current_uid() -> None:
    uid = os.getuid()
    name = pwd.getpwuid(uid).pw_name
    ev = build_event(
        module="log_tailer",
        action="x",
        category=["authentication"],
        type_=["start"],
        severity="info",
        user={"id": uid},
    )
    out = enrich_user(ev)
    assert out.user is not None
    assert out.user["name"] == name


def test_enrich_skips_when_no_user_block() -> None:
    ev = build_event(
        module="log_tailer",
        action="x",
        category=["host"],
        type_=["info"],
        severity="info",
    )
    out = enrich_user(ev)
    assert out.user is None


def test_enrich_skips_unknown_uid() -> None:
    ev = build_event(
        module="log_tailer",
        action="x",
        category=["authentication"],
        type_=["start"],
        severity="info",
        user={"id": 999_999},
    )
    out = enrich_user(ev)
    assert out.user == {"id": 999_999}
