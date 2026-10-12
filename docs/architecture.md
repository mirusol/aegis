# Architecture

## Components

```
CLI (aegis): baseline · scan · monitor · verify · harden · report
   │
   ├── Core FIM      : hashing · scanner · database (SQLite) · baseline · monitor · integrity
   ├── Compliance    : rule_loader · checks · engine
   ├── Hardening     : remediator (PowerShell)
   ├── Alerting      : notifier (console · logfile · email)
   └── Reporting     : console · JSON · HTML
```

## Data flow

- **baseline**: `scanner` walks the monitored paths, `hashing` computes SHA-256, `database` stores the fingerprints.
- **monitor**: compares the current state to the baseline (polling), or reacts to filesystem events (realtime, through `watchdog`). Any difference raises an alert, then the baseline is moved forward.
- **scan**: `rule_loader` loads the CIS rules, `checks` evaluates them, `engine` builds the report.
- **harden**: for every failing rule, `remediator` runs the PowerShell remediation command.

## Data model (SQLite)

- `files`: the baseline. `path` (PK), `hash`, `size`, `permissions`, `owner`, `mtime`, timestamps.
- `events`: change history. `path`, `change`, `old_hash`, `new_hash`, `timestamp`.
- `meta`: the integrity seal over the baseline.

## CIS rules

Rules are YAML in `cis_rules/windows/` (`id`, `title`, `severity`, `check`, `remediation`). The current set has 415 rules, most derived from the open-source `ansible-lockdown/Windows-11-CIS` project (see `CREDITS.md`). They were extracted with `tools/import_from_ansible_lockdown.py` and converted with `tools/import_cis_rules.py`.

Check types (`checks.py`): `registry`, `command`, `file_exists`, `file_content`, `file_permission`. See [cis_mapping.md](cis_mapping.md) for the rule format.

## Hardening

- **Local (PowerShell):** `aegis harden` runs the commands in `remediation.powershell`. Without `--apply` it only shows what would change. With `--apply` it applies them, skipping rules marked `risky` unless `--include-risky` is given.
- **At scale (Ansible):** the `ansible/roles/cis_baseline` role applies the remediations to several Windows machines over WinRM. On Windows the control node runs in WSL2 (see [ansible-winrm-setup.md](ansible-winrm-setup.md)).

## Stack

Python 3.10+, SQLite (`sqlite3`), PyYAML, `watchdog` (realtime), `rich` (console output).
