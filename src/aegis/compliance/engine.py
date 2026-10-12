"""Runs the CIS rules and aggregates the results into a report."""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.compliance import checks
from aegis.compliance.rule_loader import load_ruleset

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class RuleOutcome:
    rule_id: str
    title: str
    severity: str
    passed: bool
    detail: str = ""


@dataclass
class ComplianceReport:
    outcomes: list[RuleOutcome] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def passed_count(self) -> int:
        return sum(1 for o in self.outcomes if o.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for o in self.outcomes if not o.passed)

    def has_failures_at_or_above(self, severity: str) -> bool:
        threshold = _SEVERITY_ORDER.get(severity, 99)
        return any(
            not o.passed and _SEVERITY_ORDER.get(o.severity, 0) >= threshold
            for o in self.outcomes
        )


def run(config) -> ComplianceReport:
    report = ComplianceReport()
    for rule in load_ruleset(config.ruleset):
        handler = checks.CHECK_HANDLERS.get(rule.check.get("type"))
        if handler is None:
            report.outcomes.append(RuleOutcome(
                rule.id, rule.title, rule.severity, False,
                f"unknown check type: {rule.check.get('type')!r}",
            ))
            continue
        try:
            result = handler(rule.check)
        except Exception as exc:
            report.outcomes.append(RuleOutcome(
                rule.id, rule.title, rule.severity, False, f"error while checking: {exc}",
            ))
            continue
        report.outcomes.append(RuleOutcome(
            rule.id, rule.title, rule.severity, result.passed, result.detail,
        ))
    return report
