from __future__ import annotations

import argparse
import subprocess
import sys

from aegis.config import load_config


def _force_utf8_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description=__doc__)
    parser.add_argument("-c", "--config", default="config/config.yaml",
                        help="Path to the configuration file (YAML).")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("baseline", help="Create/update the file fingerprint baseline.")
    sub.add_parser("scan", help="Run the CIS compliance check.")
    sub.add_parser("monitor", help="Start continuous monitoring.")
    sub.add_parser("verify", help="Verify the integrity of the database.")

    p_harden = sub.add_parser("harden", help="Show which CIS fixes are missing; with --apply, apply them.")
    p_harden.add_argument("--apply", action="store_true",
                          help="Actually apply (default: only show what would change).")
    p_harden.add_argument("--include-risky", action="store_true",
                          help="Include risky remediations (disabling Administrator, blocking RDP).")
    p_harden.add_argument("--only", help="Apply only the rule with this id.")
    p_harden.add_argument("--playbook",
                          help="(optional) run an Ansible playbook instead of native remediation.")

    p_report = sub.add_parser("report", help="Write a CIS report to a file (JSON/HTML).")
    p_report.add_argument("--format", choices=["json", "html"], default="html")
    p_report.add_argument("--out", default=None)
    return parser


def _cmd_baseline(config) -> int:
    from aegis.core.baseline import build_baseline
    from aegis.core.database import Database
    count = build_baseline(config, Database(config.database_path))
    print(f"✓ Baseline created: {count} files recorded in {config.database_path}")
    return 0


def _cmd_scan(config) -> int:
    from aegis.compliance import engine
    from aegis.reporting import report as report_mod
    result = engine.run(config)
    report_mod.to_console(result)
    if result.has_failures_at_or_above(config.fail_on):
        print(f"\n✗ There are failures with severity >= '{config.fail_on}'.")
        return 1
    return 0


def _cmd_monitor(config) -> int:
    from aegis.alerting.notifier import Notifier
    from aegis.core.database import Database
    from aegis.core.monitor import run_loop
    run_loop(config, Database(config.database_path), Notifier(config.alerting))
    return 0


def _cmd_verify(config) -> int:
    from aegis.core import integrity
    from aegis.core.database import Database
    db = Database(config.database_path)
    db.init_schema()
    res = integrity.verify_seal(db, config.integrity_key)
    symbol = {"ok": "✓", "unset": "•", "tampered": "✗"}.get(res.status, "?")
    print(f"{symbol} Integritate baseline: {res.status.upper()} — {res.detail}")
    return 0 if res.ok else 1


def _cmd_harden(config, args) -> int:
    if args.playbook:
        print(f"→ Rulez: ansible-playbook {args.playbook}")
        try:
            return subprocess.run(["ansible-playbook", args.playbook]).returncode
        except FileNotFoundError:
            print("✗ 'ansible-playbook' not found. Install Ansible (on Windows: inside WSL2).")
            return 1

    from aegis import platform_utils
    from aegis.hardening import remediator

    if not args.apply:
        rems = remediator.plan(config)
        if not rems:
            print("✓ Nothing to remediate: all rules pass.")
            return 0
        print("DRY-RUN: failing rules that WOULD be remediated (nothing was changed):\n")
        for r in rems:
            if r.status == "no-remediation":
                print(f"  [{r.rule_id}] {r.title}\n        (no automatic command: manual remediation)")
            else:
                mark = " ⚠ RISC" if r.risky else ""
                print(f"  [{r.rule_id}]{mark} {r.title}\n        → {r.command.splitlines()[0]}")
        print("\nApply with: aegis harden --apply   "
              "(risky rules only with --include-risky; a single rule with --only <id>)")
        return 0

    if not platform_utils.is_admin():
        print("⚠ Not running as Administrator: some fixes will fail.\n")
    print("Applying remediations...\n")
    rems = remediator.apply(config, include_risky=args.include_risky, only=args.only)
    symbols = {"fixed": "✓", "still-failing": "✗", "failed": "✗",
               "skipped-risky": "•", "skipped-filter": "·", "no-remediation": "•"}
    for r in rems:
        print(f"  {symbols.get(r.status, '·')} [{r.rule_id}] {r.status}: {r.title}")
    print(f"\nReparate: {sum(1 for r in rems if r.status == 'fixed')}")
    return 0


def _cmd_report(config, fmt: str, out: str | None) -> int:
    from aegis.compliance import engine
    from aegis.reporting import report as report_mod
    result = engine.run(config)
    out = out or f"reports/cis_report.{fmt}"
    if fmt == "json":
        report_mod.to_json(result, out)
    else:
        report_mod.to_html(result, out)
    print(f"✓ Report written to {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    args = build_parser().parse_args(argv)

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"✗ Invalid configuration: {exc}", file=sys.stderr)
        return 2

    if args.command == "baseline":
        return _cmd_baseline(config)
    if args.command == "scan":
        return _cmd_scan(config)
    if args.command == "monitor":
        return _cmd_monitor(config)
    if args.command == "verify":
        return _cmd_verify(config)
    if args.command == "harden":
        return _cmd_harden(config, args)
    if args.command == "report":
        return _cmd_report(config, args.format, args.out)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
