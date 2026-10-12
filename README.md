# Aegis

A Windows file integrity monitor and CIS compliance checker, written in Python.

Aegis does three things:

1. **File integrity monitoring (FIM).** It stores a SHA-256 fingerprint of every file you care about and alerts when a file is modified, deleted or added. It can poll on an interval or react to filesystem events in real time.
2. **CIS compliance scanning.** It evaluates 415 CIS Windows 11 rules (registry values and commands) and produces a PASS/FAIL report in the console, JSON or HTML.
3. **Hardening.** Failing rules can be fixed locally through PowerShell (`aegis harden`), or across many machines with an Ansible role over WinRM.

It also protects its own state: the baseline database is sealed with an HMAC, so editing a stored hash by hand is detected by `aegis verify`.

## Quick start

```
pip install -e ".[dev]"
copy config\config.example.yaml config\config.yaml     # then edit the paths to monitor

aegis -c config/config.yaml baseline    # record reference fingerprints
aegis -c config/config.yaml monitor     # watch for changes (Ctrl+C to stop)
aegis -c config/config.yaml scan        # CIS compliance check
aegis -c config/config.yaml verify      # is the baseline database still intact?
aegis -c config/config.yaml report --format html
aegis -c config/config.yaml harden      # dry run: shows what would change
```

Requires Python 3.10+. The registry checks and PowerShell remediation need Windows; the FIM core and the tests run anywhere. Run the tests with `python -m pytest`.

## Design decisions

**Hardening is a dry run by default.** `aegis harden` only prints what it would change. Nothing is touched without `--apply`, and rules marked `risky` (for example disabling the built-in Administrator or blocking RDP) are skipped unless you also pass `--include-risky`. `--only <id>` applies a single rule.

**Changes are reported once.** After a change is alerted, the baseline moves to the new state, so later cycles only report new differences instead of repeating the same alert.

**The baseline database is tamper-evident.** `aegis verify` recomputes a seal over the stored fingerprints. Without a key the seal only detects accidental or naive changes. With `integrity.key` set it is an HMAC, so an attacker who edits the database cannot recompute a valid seal without the key. `tools/tamper_demo.py` simulates that edit so you can watch the detection work.

**Rules are data, not code.** CIS rules are YAML files in `cis_rules/windows/`, each with a `check` and a `remediation`. Check types are `registry`, `command`, `file_exists`, `file_content` and `file_permission`. Adding a rule needs no Python.

**Large folders stay fast.** With `trust_mtime: true`, files whose size and modification time are unchanged are not re-hashed. This is off by default because a determined attacker can preserve mtimes.

## Limitations

- The baseline is trust-on-first-use. If a system is already compromised when you run `aegis baseline`, Aegis will faithfully protect the compromised state.
- Polling can miss a change that is made and reverted between two cycles. Real-time mode (via `watchdog`) narrows that window but depends on the OS delivering the event.
- The sealing key sits next to the database unless you store it elsewhere. Keep it off the monitored host if the host is what you do not trust.
- 407 of the 415 rules are registry checks. Many CIS items (audit policy, user rights assignment, services) are not covered yet.
- Remediation edits the registry through `reg add`. Test on a VM before applying to a machine you care about.

## Layout

```
src/aegis/         the engine (CLI, core FIM, compliance, hardening, alerting, reporting)
cis_rules/windows/ CIS rules as YAML
ansible/           role and playbook for hardening at scale over WinRM
tools/             rule importers and the tamper demo
config/            example configuration
test-sandbox/      small tree used to demo detection (placeholder files, not malware)
tests/             pytest suite
docs/              architecture, rule format, Ansible/WinRM setup, credits
```

More detail is in [docs/architecture.md](docs/architecture.md).

## Credits

Most CIS rules were derived from [ansible-lockdown/Windows-11-CIS](https://github.com/ansible-lockdown/Windows-11-CIS) (MIT). See [docs/CREDITS.md](docs/CREDITS.md). The CIS Benchmarks themselves are the property of the Center for Internet Security and are not redistributed here.

## License

MIT, see [LICENSE](LICENSE).
