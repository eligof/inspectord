"""Event → MetricSample extraction (spec §4.1).

Each enriched event contributes zero or more samples to the engine's current
minute buckets. Rates are per-minute counters (value 1.0 per occurrence);
egress is a byte sum and stays dormant until a collector emits
``network.bytes`` on outbound events.
"""

from __future__ import annotations

import posixpath

from inspectord.anomaly.stats import MetricSample
from inspectord.schemas.event import Event

# FIM actions that count as writes for the file_writes_per_min rate.
_FIM_WRITE_ACTIONS = ("file_created", "file_modified", "file_attributes_changed")


def extract_samples(ev: Event) -> list[MetricSample]:
    """Map one enriched event to zero or more §4.1 metric samples."""
    if ev.module == "anomaly_detector":
        # Never feed our own signals back into the baselines.
        return []
    out: list[MetricSample] = []
    proc_name = (ev.process or {}).get("name")
    if proc_name and ev.category:
        out.append(
            MetricSample(
                metric_kind="events_per_min",
                entity_key=f"{proc_name}:{ev.category[0]}",
                entity={"process": {"name": str(proc_name)}},
                value=1.0,
            )
        )
    if ev.action == "outbound_connection" and proc_name:
        out.append(
            MetricSample(
                metric_kind="new_conn_per_min",
                entity_key=str(proc_name),
                entity={"process": {"name": str(proc_name)}},
                value=1.0,
            )
        )
        raw_bytes = (ev.network or {}).get("bytes")
        if isinstance(raw_bytes, (int, float)):
            out.append(
                MetricSample(
                    metric_kind="egress_bytes_per_min",
                    entity_key=str(proc_name),
                    entity={"process": {"name": str(proc_name)}},
                    value=float(raw_bytes),
                )
            )
    user_name = (ev.user or {}).get("name")
    if ev.action == "ssh_login_succeeded" and user_name:
        out.append(
            MetricSample(
                metric_kind="logins_per_min",
                entity_key=str(user_name),
                entity={"user": {"name": str(user_name)}},
                value=1.0,
            )
        )
    if ev.action == "sudo_invoked" and user_name:
        out.append(
            MetricSample(
                metric_kind="sudo_per_min",
                entity_key=str(user_name),
                entity={"user": {"name": str(user_name)}},
                value=1.0,
            )
        )
    path = (ev.file or {}).get("path")
    if ev.module == "fim_watcher" and ev.action in _FIM_WRITE_ACTIONS and path:
        parent = posixpath.dirname(str(path))
        if not parent:
            # fim's unknown-wd fallback path ("?") and bare relative names have
            # no parent dir; a junk "" bucket is worse than no sample.
            return out
        out.append(
            MetricSample(
                metric_kind="file_writes_per_min",
                entity_key=parent,
                entity={"file": {"path": parent}},
                value=1.0,
            )
        )
    return out
