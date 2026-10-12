"""Loads the CIS rules from the YAML files (cis_rules/windows/)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_WINDOWS_RULES_DIR = "cis_rules/windows"


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    check: dict[str, Any]
    section: str = ""
    rationale: str = ""
    level: int = 1
    profile: str = ""
    remediation: dict[str, Any] = field(default_factory=dict)


def load_ruleset(ruleset: str) -> list[Rule]:
    """Load rules from a file or a directory (merged).

    `ruleset='auto'` uses the Windows ruleset.
    """
    if ruleset == "auto":
        ruleset = _WINDOWS_RULES_DIR

    target = Path(ruleset)
    if not target.exists():
        raise FileNotFoundError(f"Ruleset does not exist: {target}")

    rules: list[Rule] = []
    if target.is_dir():
        for yaml_file in sorted(target.glob("*.yaml")):
            rules.extend(_load_rules_file(str(yaml_file)))
    else:
        rules.extend(_load_rules_file(str(target)))
    return rules


def _load_rules_file(path: str) -> list[Rule]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    rules: list[Rule] = []
    for raw in data.get("rules", []) or []:
        if "id" not in raw or "check" not in raw:
            raise ValueError(f"Invalid rule in {path}: missing 'id' or 'check'")
        rules.append(Rule(
            id=str(raw["id"]),
            title=raw.get("title", ""),
            severity=raw.get("severity", "medium"),
            check=raw["check"],
            section=raw.get("section", ""),
            rationale=raw.get("rationale", ""),
            level=int(raw.get("level", 1)),
            profile=raw.get("profile", ""),
            remediation=raw.get("remediation", {}) or {},
        ))
    return rules
