# Sources

The Windows CIS rules in `cis_rules/windows/` (`1.yaml`, `2.yaml`, `9.yaml`, `18.yaml`, `19.yaml`) were derived from the open-source project:

- **ansible-lockdown / Windows-11-CIS**: https://github.com/ansible-lockdown/Windows-11-CIS (MIT license)

The registry keys and recommended values were taken from the role's tasks (`tasks/section_*`) and converted into this project's own format (a `registry` check plus a `reg add` remediation) with `tools/import_cis_rules.py`.

The CIS Benchmarks are published by the Center for Internet Security. The benchmark document itself is not included in this repository.
