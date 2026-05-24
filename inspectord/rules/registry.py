"""Rule registry — combines YAML rules and Python rules."""

from __future__ import annotations

from dataclasses import dataclass, field

from inspectord.rules.base import EvalContext, Match, Rule
from inspectord.rules.yaml_loader import YamlRule, evaluate_yaml_rule


@dataclass
class Registry:
    yaml_rules: list[YamlRule] = field(default_factory=list)
    python_rules: list[Rule] = field(default_factory=list)

    def evaluate(self, ctx: EvalContext) -> list[Match]:
        out: list[Match] = []
        for yr in self.yaml_rules:
            try:
                out.extend(evaluate_yaml_rule(yr, ctx))
            except Exception:  # a bad rule should not poison the run
                continue
        for pr in self.python_rules:
            try:
                out.extend(pr.evaluate(ctx))
            except Exception:  # a bad rule should not poison the run
                continue
        return out

    def rule_ids(self) -> list[str]:
        ids = [yr.rule_id for yr in self.yaml_rules]
        ids += [pr.rule_id for pr in self.python_rules]
        return ids
