from __future__ import annotations

import subprocess
from dataclasses import dataclass

from aegis.compliance import checks
from aegis.compliance.rule_loader import load_ruleset


@dataclass
class Remediation:
    rule_id: str
    title: str
    command: str
    risky: bool
    status: str = ""


def _check_fails(rule) -> bool:
    handler = checks.CHECK_HANDLERS.get(rule.check.get("type"))
    if handler is None:
        return False
    try:
        return not handler(rule.check).passed
    except (OSError, ValueError, KeyError):
        return True


def _run_powershell(command: str, timeout: int = 90) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=timeout,
    )


def plan(config) -> list[Remediation]:
    out: list[Remediation] = []
    for rule in load_ruleset(config.ruleset):
        if not _check_fails(rule):
            continue
        rem = rule.remediation or {}
        cmd = rem.get("powershell", "")
        out.append(Remediation(
            rule.id, rule.title, cmd, bool(rem.get("risky", False)),
            "would-fix" if cmd else "no-remediation",
        ))
    return out


def apply(config, include_risky: bool = False, only: str | None = None) -> list[Remediation]:
    rems = plan(config)
    rules_by_id = {r.id: r for r in load_ruleset(config.ruleset)}
    for r in rems:
        if only is not None and r.rule_id != only:
            r.status = "skipped-filter"
            continue
        if r.status != "would-fix":
            continue
        if r.risky and not include_risky:
            r.status = "skipped-risky"
            continue
        try:
            proc = _run_powershell(r.command)
        except (subprocess.SubprocessError, OSError):
            r.status = "failed"
            continue
        if proc.returncode != 0:
            r.status = "failed"
            continue
        rule = rules_by_id.get(r.rule_id)
        r.status = "fixed" if (rule and not _check_fails(rule)) else "still-failing"
    return rems
