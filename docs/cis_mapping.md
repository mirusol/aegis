# CIS rules

CIS rules for Windows are modelled as YAML in `cis_rules/windows/`. `rule_loader` loads every `.yaml` file in the directory and merges them.

## Rule format

```yaml
- id: "18.9.8.1"
  title: "Ensure AutoRun is disabled for all drives"
  section: "18.9 AutoPlay Policies"
  severity: "medium"       # low | medium | high | critical
  level: 1                 # 1 | 2
  check:
    type: "registry"
    key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
    name: "NoDriveTypeAutoRun"
    value: 255
  remediation:
    powershell: |-
      reg add 'HKLM\SOFTWARE\...\Explorer' /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
```

## Check types (see `checks.py`)

| type              | verifies                                          |
|-------------------|---------------------------------------------------|
| `registry`        | the value of a registry key (`winreg`)            |
| `command`         | output / exit code of a command (e.g. PowerShell) |
| `file_exists`     | whether a file exists                             |
| `file_content`    | whether a text is present or absent in a file     |
| `file_permission` | the permissions of a file                         |

## Where the rules come from

The current set has 415 rules, mostly derived from the open-source project **`ansible-lockdown/Windows-11-CIS`** (MIT). `tools/import_from_ansible_lockdown.py` extracts the role's `win_regedit` tasks into JSON, then `tools/import_cis_rules.py` converts that JSON into the YAML files in `cis_rules/windows/`.

To bring in more rules or your own export, `tools/import_cis_rules.py` accepts `json` and `csv` sources. Attribution: see [CREDITS.md](CREDITS.md).
