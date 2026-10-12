from __future__ import annotations

import json
import time
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    _console = Console()
except ImportError:
    _console = None


def to_console(report) -> None:
    if _console is not None:
        _to_console_rich(report)
    else:
        _to_console_plain(report)


def _to_console_rich(report) -> None:
    table = Table(title="Raport conformitate CIS")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Rule")
    table.add_column("Sev.", no_wrap=True)
    table.add_column("Rezultat", no_wrap=True)
    for o in report.outcomes:
        status = "[green]PASS[/]" if o.passed else "[red]FAIL[/]"
        table.add_row(o.rule_id, o.title, o.severity, status)
    _console.print(table)
    _console.print(
        f"\nTotal: {report.total}  |  [green]PASS: {report.passed_count}[/]  |  "
        f"[red]FAIL: {report.failed_count}[/]"
    )


def _to_console_plain(report) -> None:
    print("\n=== Raport conformitate CIS ===")
    for o in report.outcomes:
        status = "PASS" if o.passed else "FAIL"
        print(f"  [{status}] {o.rule_id:<10} ({o.severity}) {o.title}")
        if not o.passed and o.detail:
            print(f"         → {o.detail}")
    print(f"\nTotal: {report.total} | PASS: {report.passed_count} | FAIL: {report.failed_count}")


def to_json(report, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total": report.total,
            "passed": report.passed_count,
            "failed": report.failed_count,
        },
        "outcomes": [
            {"id": o.rule_id, "title": o.title, "severity": o.severity,
             "passed": o.passed, "detail": o.detail}
            for o in report.outcomes
        ],
    }
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def to_html(report, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(
        f"<tr class='{'pass' if o.passed else 'fail'}'>"
        f"<td>{o.rule_id}</td><td>{o.title}</td><td>{o.severity}</td>"
        f"<td>{'PASS' if o.passed else 'FAIL'}</td></tr>"
        for o in report.outcomes
    )
    html = f"""<!doctype html>
<html lang="ro"><head><meta charset="utf-8"><title>Raport CIS — Aegis</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:2rem;color:#222}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}}
 tr.pass td:last-child{{color:#137333;font-weight:600}}
 tr.fail td:last-child{{color:#c5221f;font-weight:600}}
 .summary{{margin:1rem 0;font-size:1.1rem}}
</style></head><body>
<h1>Raport conformitate CIS — Aegis</h1>
<p class="summary">Total: {report.total} &nbsp;|&nbsp; PASS: {report.passed_count}
 &nbsp;|&nbsp; FAIL: {report.failed_count} &nbsp;|&nbsp; {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<table><thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Result</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
    with open(p, "w", encoding="utf-8") as f:
        f.write(html)
