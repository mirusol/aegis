from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

import yaml


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, choices=["json", "csv"])
    p.add_argument("--input", required=True)
    p.add_argument("--os", required=True, choices=["linux", "windows", "macos"])
    p.add_argument("--out", required=True)
    return p.parse_args(argv)


def _normalize(raw: dict) -> dict:
    if "id" not in raw or "check" not in raw:
        raise ValueError(f"Invalid rule (missing 'id' or 'check'): {raw!r}")
    return {
        "id": str(raw["id"]),
        "title": raw.get("title", ""),
        "section": raw.get("section", "General"),
        "severity": raw.get("severity", "medium"),
        "level": int(raw.get("level", 1)),
        "profile": raw.get("profile", ""),
        "check": raw["check"],
        "remediation": raw.get("remediation", {}) or {},
    }


def import_rules(source: str, input_path: str) -> list[dict]:
    if source == "json":
        data = json.loads(Path(input_path).read_text(encoding="utf-8"))
        rules = data.get("rules", data) if isinstance(data, dict) else data
        return [_normalize(r) for r in rules]

    with open(input_path, newline="", encoding="utf-8") as f:
        out = []
        for row in csv.DictReader(f):
            raw = dict(row)
            raw["check"] = json.loads(row["check_json"])
            if row.get("ansible_task"):
                raw["remediation"] = {"ansible_task": row["ansible_task"]}
            out.append(_normalize(raw))
        return out


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "general"


def write_rules(rules: list[dict], out_dir: str, target_os: str) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    groups: dict[str, list[dict]] = {}
    for rule in rules:
        groups.setdefault(rule["section"], []).append(rule)
    for section, group in groups.items():
        payload = {"metadata": {"os": target_os, "section": section}, "rules": group}
        (out / f"{_slug(section)}.yaml").write_text(
            yaml.safe_dump(payload, allow_unicode=True, sort_keys=False), encoding="utf-8"
        )
    return len(groups)


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = parse_args(argv)
    rules = import_rules(args.source, args.input)
    n = write_rules(rules, args.out, args.os)
    print(f"Import: {len(rules)} rules in {n} files ({args.out})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
