"""YAML correlation-rule loader + evaluator (spec §8.2)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from inspectord.expr import (
    InvalidLeaf,
    Leaf,
    Node,
    ParsedExpression,
    parse_expression,
    parse_list,
    parse_literal,
    path_segments,
)
from inspectord.rules.base import EvalContext, Match
from inspectord.schemas.event import Event


class YamlRuleError(RuntimeError):
    pass


@dataclass
class YamlRule:
    rule_id: str
    name: str
    severity: str
    category: str
    why: str
    false_positives: list[str]
    detect_any_of: list[str]
    short_tpl: str
    detail_tpl: str
    version: str = "1.0.0"
    labels: list[str] = field(default_factory=list)


_FIELD_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_.]*)\}")


def load_yaml_rule(path: Path) -> YamlRule:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise YamlRuleError(f"rule not found: {path}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise YamlRuleError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise YamlRuleError(f"{path}: top-level YAML must be a mapping")
    return load_yaml_rule_from_dict(data, source=str(path))


def load_yaml_rule_from_dict(data: dict[str, Any], *, source: str = "<inline>") -> YamlRule:
    required = ("id", "name", "severity", "category", "detect", "short", "detail")
    for key in required:
        if key not in data:
            raise YamlRuleError(f"{source}: missing required field '{key}'")
    detect = data.get("detect") or {}
    if not isinstance(detect, dict) or "any_of" not in detect:
        raise YamlRuleError(f"{source}: detect must be a mapping with 'any_of'")
    any_of_raw = detect["any_of"]
    if not isinstance(any_of_raw, list) or not all(isinstance(e, str) for e in any_of_raw):
        raise YamlRuleError(f"{source}: detect.any_of must be a list of strings")
    return YamlRule(
        version=str(data.get("version", "1.0.0")),
        rule_id=str(data["id"]),
        name=str(data["name"]),
        severity=str(data["severity"]),
        category=str(data["category"]),
        why=str(data.get("why", "")),
        false_positives=list(data.get("false_positives") or []),
        detect_any_of=list(any_of_raw),
        short_tpl=str(data["short"]),
        detail_tpl=str(data["detail"]),
        labels=list(data.get("labels") or []),
    )


def evaluate_yaml_rule(rule: YamlRule, ctx: EvalContext) -> list[Match]:
    for expr in rule.detect_any_of:
        if evaluate_expression(expr, ctx.event):
            short = _interpolate(rule.short_tpl, ctx.event)
            detail = _interpolate(rule.detail_tpl, ctx.event)
            primary_kind, primary_key = _primary_entity_for(ctx.event)
            return [
                Match(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    category=rule.category,
                    dedup_key=f"{rule.rule_id}:{primary_kind}:{primary_key}",
                    primary_entity_kind=primary_kind,
                    primary_entity_key=primary_key,
                    short=short,
                    detail=detail,
                    rule_name=rule.name,
                    why=rule.why,
                    false_positives=rule.false_positives,
                    triggering_event_ids=[ctx.event.event_id],
                    labels=list(rule.labels),
                )
            ]
    return []


_STR_OPS: dict[str, Any] = {
    "STARTSWITH": lambda lhs, rhs: lhs.startswith(rhs),
    "ENDSWITH": lambda lhs, rhs: lhs.endswith(rhs),
    "CONTAINS": lambda lhs, rhs: rhs in lhs,
    "MATCHES": lambda lhs, rhs: re.search(rhs, lhs) is not None,
}


def evaluate_expression(expr: str, event: Event) -> bool:
    """Evaluate one grammar expression against one in-memory event.

    The parse comes from `inspectord.expr`, shared verbatim with the hunt
    compiler; only the *evaluation* below is specific to this backend.
    """
    return evaluate_parsed(parse_expression(expr), event)


def evaluate_parsed(parsed: ParsedExpression, event: Event) -> bool:
    # An empty AND group is vacuously true and no groups at all is false; both
    # fall out of `all`/`any` exactly as the previous hand-rolled fold did.
    return any(all(_eval_node(node, event) for node in group) for group in parsed.groups)


def _eval_node(node: Node, event: Event) -> bool:
    # An unparseable leaf is false here — long-standing behavior, and the reason
    # the shared parser carries it as a node instead of raising.
    result = False if isinstance(node, InvalidLeaf) else _eval_leaf(node, event)
    return not result if node.negated else result


def _eval_leaf(leaf: Leaf, event: Event) -> bool:
    lhs = _resolve_path(leaf.path, event)
    if leaf.op == "==":
        return bool(lhs == parse_literal(leaf.rhs))
    if leaf.op == "!=":
        return bool(lhs != parse_literal(leaf.rhs))
    if leaf.op in ("IN", "NOT IN"):
        result = lhs in parse_list(leaf.rhs)
        return result if leaf.op == "IN" else not result
    if leaf.op in _STR_OPS and isinstance(lhs, str):
        return bool(_STR_OPS[leaf.op](lhs, parse_literal(leaf.rhs)))
    return False


def _walk_dict(val: Any, segs: list[str]) -> Any:
    """Descend into nested dicts; return None on missing key or non-dict."""
    for seg in segs:
        if not isinstance(val, dict):
            return None
        val = val.get(seg)
    return val


def _resolve_path(path: str, event: Event) -> Any:
    parts = path_segments(path)
    head, *rest = parts
    if head == "event":
        if not rest:
            return None
        val: Any = getattr(event, rest[0], None)
        return _enum_value(_walk_dict(val, rest[1:]))
    block = getattr(event, head, None)
    if not isinstance(block, dict):
        return None
    return _enum_value(_walk_dict(block, rest))


def _enum_value(val: Any) -> Any:
    if hasattr(val, "value") and not isinstance(val, (str, bytes, int, float, bool, dict, list)):
        try:
            return val.value
        except Exception:  # pragma: no cover
            return val
    return val


def _interpolate(tpl: str, event: Event) -> str:
    def replace(m: re.Match[str]) -> str:
        val = _resolve_path(m.group(1), event)
        return "" if val is None else str(val)

    return _FIELD_RE.sub(replace, tpl)


def _primary_entity_for(event: Event) -> tuple[str, str]:
    if event.process and "pid" in event.process:
        return "process", f"pid:{event.process['pid']}"
    if event.file and "path" in event.file:
        return "file", str(event.file["path"])
    if event.user and "name" in event.user:
        return "user", str(event.user["name"])
    if event.source and "ip" in event.source:
        return "ip", str(event.source["ip"])
    return "event", event.event_id
