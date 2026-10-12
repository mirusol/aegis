import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import import_cis_rules as imp  # noqa: E402

from aegis.compliance.rule_loader import load_ruleset  # noqa: E402


def test_import_json_then_load_with_rule_loader(tmp_path):
    rules = [
        {"id": "1.1.1", "title": "Enforce password history", "section": "1 Account Policies",
         "severity": "high", "level": 1,
         "check": {"type": "registry", "key": "HKLM\\SYSTEM\\...", "name": "X", "value": 24}},
        {"id": "9.1.1", "title": "Firewall Domain On", "section": "9 Firewall",
         "severity": "high",
         "check": {"type": "command", "command": "echo True", "expect_contains": "True"}},
    ]
    src = tmp_path / "rules.json"
    src.write_text(json.dumps(rules), encoding="utf-8")
    out = tmp_path / "out"

    n_files = imp.write_rules(imp.import_rules("json", str(src)), str(out), "windows")
    assert n_files == 2

    loaded = load_ruleset(str(out))
    assert sorted(r.id for r in loaded) == ["1.1.1", "9.1.1"]


def test_import_invalid_rule_raises(tmp_path):
    src = tmp_path / "bad.json"
    src.write_text(json.dumps([{"title": "no id and no check"}]), encoding="utf-8")
    with pytest.raises(ValueError):
        imp.import_rules("json", str(src))
