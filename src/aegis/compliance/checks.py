"""CIS checks, one per `check` type."""

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass

from aegis import platform_utils


@dataclass
class CheckResult:
    passed: bool
    detail: str = ""


def _normalize_mode(mode: str | int) -> int:
    if isinstance(mode, int):
        return mode
    return int(str(mode), 8)


def check_file_exists(params: dict) -> CheckResult:
    path = params["path"]
    should_exist = params.get("should_exist", True)
    exists = os.path.exists(path)
    if exists == should_exist:
        return CheckResult(True, f"{path} {'exists' if exists else 'missing'} (ok)")
    return CheckResult(False, f"{path}: exists={exists}, expected={should_exist}")


def check_file_permission(params: dict) -> CheckResult:
    path = params["path"]
    if not os.path.exists(path):
        return CheckResult(False, f"{path} does not exist")
    expected = _normalize_mode(params["mode"])
    actual = stat.S_IMODE(os.stat(path).st_mode)
    if params.get("comparison", "max") == "max":
        ok = (actual & ~expected) == 0
    else:
        ok = actual == expected
    return CheckResult(ok, f"{path}: mode {actual:04o}, expected {expected:04o}")


def check_file_content(params: dict) -> CheckResult:
    path = params["path"]
    if not os.path.exists(path):
        return CheckResult(False, f"{path} does not exist")
    try:
        text = open(path, "r", encoding="utf-8", errors="ignore").read()
    except OSError as exc:
        return CheckResult(False, f"{path}: cannot be read ({exc})")
    if "contains" in params:
        needle = params["contains"]
        return CheckResult(needle in text, f"'{needle}' {'found' if needle in text else 'missing'}")
    if "not_contains" in params:
        needle = params["not_contains"]
        return CheckResult(needle not in text, f"'{needle}' {'absent (ok)' if needle not in text else 'PREZENT'}")
    return CheckResult(False, "file_content check without 'contains'/'not_contains'")


def check_command(params: dict) -> CheckResult:
    command = params["command"]
    try:
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
    except (subprocess.SubprocessError, OSError) as exc:
        return CheckResult(False, f"command failed: {exc}")
    output = (proc.stdout or "") + (proc.stderr or "")
    if "expect_exit_code" in params:
        ok = proc.returncode == params["expect_exit_code"]
        return CheckResult(ok, f"exit={proc.returncode}, expected={params['expect_exit_code']}")
    if "expect_contains" in params:
        needle = params["expect_contains"]
        return CheckResult(needle in output, f"output {'contains' if needle in output else 'does NOT contain'} '{needle}'")
    if "expect_not_contains" in params:
        needle = params["expect_not_contains"]
        return CheckResult(needle not in output, f"output {'does not contain (ok)' if needle not in output else 'CONTAINS'} '{needle}'")
    return CheckResult(proc.returncode == 0, f"exit={proc.returncode}")


def check_registry(params: dict) -> CheckResult:
    if not platform_utils.is_windows():
        return CheckResult(False, "'registry' check is only available on Windows")
    import winreg

    hives = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    }
    key_path = params["key"]
    hive_name, _, sub = key_path.replace("/", "\\").partition("\\")
    hive = hives.get(hive_name)
    if hive is None:
        return CheckResult(False, f"hive necunoscut: {hive_name}")
    try:
        with winreg.OpenKey(hive, sub) as handle:
            value, _ = winreg.QueryValueEx(handle, params["name"])
    except FileNotFoundError:
        return CheckResult(False, f"key/value does not exist: {key_path}\\{params.get('name')}")
    except OSError as exc:
        return CheckResult(False, f"registry error: {exc}")
    ok = str(value) == str(params["value"])
    return CheckResult(ok, f"{params['name']}={value}, expected={params['value']}")


CHECK_HANDLERS = {
    "file_exists": check_file_exists,
    "file_permission": check_file_permission,
    "file_content": check_file_content,
    "command": check_command,
    "registry": check_registry,
}
