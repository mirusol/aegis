# Ansible: CIS hardening for Windows at scale

`aegis harden` applies the CIS remediations locally (PowerShell). Ansible does the same on **several Windows machines at once**, over WinRM, from a control node.

## Layout

```
ansible/
├── ansible.cfg
├── requirements.yml            # ansible.windows + community.windows collections
├── inventory/hosts.example.ini # copy to hosts.ini and fill in
├── playbooks/harden_windows.yml
└── roles/cis_baseline/
    ├── defaults/main.yml        # switches
    ├── meta/main.yml
    └── tasks/{main,windows}.yml
```

## Requirements

- The **control node** runs in **WSL2** (Ansible has no native control node on Windows).
- The **Windows target** needs **WinRM** enabled.
- Step by step: [../docs/ansible-winrm-setup.md](../docs/ansible-winrm-setup.md).

## Running

```bash
ansible-galaxy collection install -r ansible/requirements.yml
cp ansible/inventory/hosts.example.ini ansible/inventory/hosts.ini   # fill in
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/harden_windows.yml --check --diff
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/harden_windows.yml
```

`hosts.ini` is git-ignored because it holds addresses and credentials.
