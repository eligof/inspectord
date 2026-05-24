"""User enricher — resolves uid → name."""

from __future__ import annotations

import pwd
from typing import Any

from inspectord.schemas.event import Event


def enrich_user(ev: Event) -> Event:
    u = ev.user
    if not u:
        return ev
    uid_raw = u.get("id")
    if uid_raw is None:
        return ev
    try:
        uid = int(uid_raw)
    except (TypeError, ValueError):
        return ev
    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        return ev
    new_user: dict[str, Any] = dict(u)
    new_user.setdefault("name", pw.pw_name)
    return ev.model_copy(update={"user": new_user})
