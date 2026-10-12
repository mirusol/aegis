from __future__ import annotations

import os
import platform
import stat
from enum import Enum


class OS(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    UNKNOWN = "unknown"


def detect_os() -> OS:
    system = platform.system().lower()
    if system == "linux":
        return OS.LINUX
    if system == "windows":
        return OS.WINDOWS
    if system == "darwin":
        return OS.MACOS
    return OS.UNKNOWN


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if is_windows():
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def get_file_permissions(path: str) -> str:
    return f"{stat.S_IMODE(os.stat(path).st_mode):04o}"


def get_file_owner(path: str) -> str | None:
    if is_windows():
        return None
    try:
        import pwd
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except (ImportError, KeyError, OSError):
        return None
