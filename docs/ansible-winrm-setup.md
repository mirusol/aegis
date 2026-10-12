# Running Ansible against Windows (WSL2 + WinRM)

`aegis harden` hardens a machine locally (PowerShell). Ansible does the same **across several Windows machines** over WinRM, from a control node. On Windows the control node runs in **WSL2**.

> ⚠️ **Lab use only.** Do this against a **Windows virtual machine**, not your daily laptop. Enabling WinRM with Basic auth over plain HTTP (below) sends credentials unencrypted and is acceptable only on an isolated lab network. For anything real, use HTTPS or Kerberos/NTLM with a proper certificate.

## 1. Control node: WSL2 + Ansible

In PowerShell (as Administrator):
```powershell
wsl --install -d Ubuntu
```
After the reboot, inside Ubuntu (WSL2):
```bash
sudo apt update && sudo apt install -y python3-pip
pip install --user ansible pywinrm
ansible-galaxy collection install ansible.windows community.windows
```

## 2. Windows target: enable WinRM

On the target, in PowerShell **as Administrator** (lab/VM only):
```powershell
Enable-PSRemoting -Force
winrm set winrm/config/service/Auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'   # HTTP only, lab
New-NetFirewallRule -DisplayName "WinRM HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow
```
Connect with a local account that has a password (for example `Administrator`).

## 3. Target address (from WSL2)

If the target is the host machine itself, its IP as seen from WSL2:
```bash
ip route | grep default | awk '{print $3}'
```

## 4. Inventory

`ansible/inventory/hosts.ini` (git-ignored):
```ini
[windows]
win-target ansible_host=<IP_from_above>

[windows:vars]
ansible_connection=winrm
ansible_winrm_transport=basic
ansible_port=5985
ansible_winrm_scheme=http
ansible_winrm_server_cert_validation=ignore
ansible_user=Administrator
ansible_password=<password>
```
Do not commit real credentials. Prefer `ansible-vault` for the password.

## 5. Test the connection

From the repository root, inside WSL2:
```bash
ansible -i ansible/inventory/hosts.ini windows -m ansible.windows.win_ping
```
Expected: `"ping": "pong"`.

## 6. Run the playbook

Dry run first:
```bash
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/harden_windows.yml --check --diff
```
Then for real:
```bash
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/harden_windows.yml
```

## 7. Clean up (after testing)

On the target, undo the lab WinRM setup:
```powershell
Disable-PSRemoting -Force
Remove-NetFirewallRule -DisplayName "WinRM HTTP"
winrm set winrm/config/service '@{AllowUnencrypted="false"}'
```
