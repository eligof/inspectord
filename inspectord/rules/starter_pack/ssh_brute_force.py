"""sshd brute force — 5x ssh_login_failed from same source.ip within 60s."""

from __future__ import annotations

from inspectord.rules.base import EvalContext, Match

_WINDOW_S = 60.0
_THRESHOLD = 5


class _Rule:
    rule_id = "auth.ssh_brute_force"
    name = "sshd brute-force from same source"
    severity = "high"
    category = "intrusion_detection"
    why = (
        f"{_THRESHOLD}+ failed ssh logins from the same source IP within "
        f"{_WINDOW_S:.0f}s. Common signature of a credential-stuffing or "
        f"dictionary attack."
    )

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        ev = ctx.event
        if ev.action != "ssh_login_failed":
            return []
        src_ip = (ev.source or {}).get("ip")
        if not src_ip:
            return []
        recent = ctx.recent_events(window_s=_WINDOW_S)
        count = sum(
            1
            for e in recent
            if e.action == "ssh_login_failed" and (e.source or {}).get("ip") == src_ip
        )
        if count < _THRESHOLD:
            return []
        short = f"ssh brute-force: {count} failed logins from {src_ip} in <{_WINDOW_S:.0f}s"
        detail = (
            f"Observed {count} ssh_login_failed events from source.ip={src_ip} "
            f"within the last {_WINDOW_S:.0f} seconds. Threshold is {_THRESHOLD}."
        )
        return [
            Match(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                category=self.category,
                dedup_key=f"{self.rule_id}:ip:{src_ip}",
                primary_entity_kind="ip",
                primary_entity_key=str(src_ip),
                short=short,
                detail=detail,
                why=self.why,
                triggering_event_ids=[e.event_id for e in recent if e.action == "ssh_login_failed"],
                labels=["auth", "brute-force"],
            )
        ]


RULE = _Rule()
