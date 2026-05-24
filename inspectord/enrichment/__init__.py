"""Event enrichment (spec §11.1).

The supervisor invokes ``enrich(ev)`` after parsing each NDJSON line from a
worker's stdout and before publishing the Event to the router. Phase 1 wires
three enrichers in order: process → file → user.
"""

from __future__ import annotations

from inspectord.enrichment.file import enrich_file
from inspectord.enrichment.process import enrich_process
from inspectord.enrichment.user import enrich_user
from inspectord.schemas.event import Event


def enrich(ev: Event) -> Event:
    ev = enrich_process(ev)
    ev = enrich_file(ev)
    ev = enrich_user(ev)
    return ev
