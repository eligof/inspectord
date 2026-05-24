"""YAML correlation-rule loader + evaluator (spec §8.2)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

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
        if _eval_expr(expr, ctx.event):
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


_LEAF_OP = re.compile(
    r"""
    ^\s*
    (?P<path>[a-zA-Z_][a-zA-Z0-9_.]*)
    \s+
    (?P<op>==|!=|IN|NOT\s+IN|STARTSWITH|ENDSWITH|CONTAINS|MATCHES)
    \s+
    (?P<rhs>.+?)
    \s*$
    """,
    re.VERBOSE,
)
_BOOL_TOKEN_RE = re.compile(r"\bAND\b|\bOR\b|\bNOT\b")


def _eval_expr(expr: str, event: Event) -> bool:
    return _eval_tokens(_tokenize(expr), event)


def _tokenize(expr: str) -> list[str]:
    parts: list[str] = []
    last = 0
    for m in _BOOL_TOKEN_RE.finditer(expr):
        if m.start() > last:
            parts.append(expr[last : m.start()].strip())
        parts.append(m.group(0))
        last = m.end()
    if last < len(expr):
        parts.append(expr[last:].strip())
    return [p for p in parts if p]


def _resolve_atoms(tokens: list[str], event: Event) -> list[bool | str]:
    """First pass: resolve leaf predicates and NOT; keep AND/OR as strings."""
    resolved: list[bool | str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "NOT":
            nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
            resolved.append(not _eval_leaf(nxt, event))
            i += 2
        elif tok in ("AND", "OR"):
            resolved.append(tok)
            i += 1
        else:
            resolved.append(_eval_leaf(tok, event))
            i += 1
    return resolved


def _fold_and_or(resolved: list[bool | str]) -> bool:
    """Second pass: fold AND then OR over the resolved list."""
    out_or: list[bool] = []
    cur_and: bool = True
    has_first = False
    for tok in resolved:
        if isinstance(tok, bool):
            cur_and = tok if not has_first else (cur_and and tok)
            has_first = True
        elif tok == "OR":
            out_or.append(cur_and)
            cur_and = True
            has_first = False
    if has_first:
        out_or.append(cur_and)
    return any(out_or)


def _eval_tokens(tokens: list[str], event: Event) -> bool:
    return _fold_and_or(_resolve_atoms(tokens, event))


_STR_OPS: dict[str, Any] = {
    "STARTSWITH": lambda lhs, rhs: lhs.startswith(rhs),
    "ENDSWITH": lambda lhs, rhs: lhs.endswith(rhs),
    "CONTAINS": lambda lhs, rhs: rhs in lhs,
    "MATCHES": lambda lhs, rhs: re.search(rhs, lhs) is not None,
}


def _eval_leaf(leaf: str, event: Event) -> bool:
    m = _LEAF_OP.match(leaf)
    if m is None:
        return False
    path = m.group("path")
    op = re.sub(r"\s+", " ", m.group("op"))
    rhs_raw = m.group("rhs").strip()
    lhs = _resolve_path(path, event)
    if op == "==":
        return bool(_coerce(lhs) == _parse_literal(rhs_raw))
    if op == "!=":
        return bool(_coerce(lhs) != _parse_literal(rhs_raw))
    if op in ("IN", "NOT IN"):
        result = lhs in _parse_list(rhs_raw)
        return result if op == "IN" else not result
    if op in _STR_OPS and isinstance(lhs, str):
        return bool(_STR_OPS[op](lhs, _parse_literal(rhs_raw)))
    return False


def _walk_dict(val: Any, segs: list[str]) -> Any:
    """Descend into nested dicts; return None on missing key or non-dict."""
    for seg in segs:
        if not isinstance(val, dict):
            return None
        val = val.get(seg)
    return val


def _resolve_path(path: str, event: Event) -> Any:
    parts = path.split(".")
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


def _coerce(val: Any) -> Any:
    return _enum_value(val)


def _parse_literal(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw == "true":
        return True
    if raw == "false":
        return False
    try:
        return int(raw)
    except ValueError:
        return raw


def _parse_list(raw: str) -> list[Any]:
    raw = raw.strip()
    if not (raw.startswith("[") and raw.endswith("]")):
        return []
    inner = raw[1:-1].strip()
    if not inner:
        return []
    return [_parse_literal(p.strip()) for p in inner.split(",")]


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
