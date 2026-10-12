"""Extracts CIS Windows rules from the ansible-lockdown/Windows-11-CIS role.

Reads the `win_regedit` tasks from the role and produces JSON in the format accepted by
tools/import_cis_rules.py (`registry` check + `reg add` remediation).

    git clone https://github.com/ansible-lockdown/Windows-11-CIS
    python tools/import_from_ansible_lockdown.py --repo Windows-11-CIS --out win_rules.json
    python tools/import_cis_rules.py --source json --input win_rules.json --os windows --out cis_rules/windows/
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

import yaml


def _walk(node):
    if isinstance(node, dict):
        if any(k.endswith("win_regedit") for k in node):
            yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def _resolve(data, defaults):
    if isinstance(data, bool):
        return None
    if isinstance(data, int):
        return data
    if isinstance(data, str):
        s = data.strip()
        m = re.fullmatch(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", s)
        if m:
            val = defaults.get(m.group(1))
            return val if isinstance(val, (int, str)) and not isinstance(val, bool) else None
        if re.fullmatch(r"-?\d+", s):
            return int(s)
        if "{{" in s or len(s) > 64:
            return None
        return s
    return None


def extract(repo: str) -> list[dict]:
    with open(os.path.join(repo, "defaults", "main.yml"), encoding="utf-8") as f:
        defaults = yaml.safe_load(f) or {}

    rules: dict[str, dict] = {}
    for task_file in glob.glob(os.path.join(repo, "tasks", "**", "*.yml"), recursive=True):
        try:
            with open(task_file, encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))
        except yaml.YAMLError:
            continue
        for doc in docs:
            for task in _walk(doc):
                reg = next((v for k, v in task.items() if k.endswith("win_regedit")), None)
                if not isinstance(reg, dict) or reg.get("state") == "absent":
                    continue
                key, name, data = reg.get("path"), reg.get("name"), reg.get("data")
                if not key or not name or data is None:
                    continue
                value = _resolve(data, defaults)
                if value is None:
                    continue
                parts = [p.strip() for p in str(task.get("name", "")).split("|")]
                cid = parts[0] if parts else ""
                if not re.match(r"^\d+(\.\d+)+$", cid):
                    continue
                title = parts[2] if len(parts) >= 3 else task.get("name", "")
                keypath = re.sub(r"^(HK[A-Z]+):", r"\1", key)
                reg_type = "REG_DWORD" if str(reg.get("type", "dword")).lower() == "dword" else "REG_SZ"
                rules.setdefault(cid, {
                    "id": cid,
                    "title": title,
                    "section": cid.split(".")[0],
                    "severity": "medium",
                    "level": 1,
                    "check": {"type": "registry", "key": keypath, "name": name, "value": value},
                    "remediation": {"powershell": f"reg add '{keypath}' /v {name} /t {reg_type} /d {value} /f"},
                })
    return sorted(rules.values(), key=lambda r: [int(x) for x in r["id"].split(".")])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", required=True, help="Directorul rolului ansible-lockdown/Windows-11-CIS.")
    p.add_argument("--out", required=True, help="Output JSON file.")
    args = p.parse_args(argv)
    rules = extract(args.repo)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False, indent=1)
    print(f"{len(rules)} rules extracted to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
