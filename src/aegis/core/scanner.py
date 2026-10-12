from __future__ import annotations

import fnmatch
import os
from typing import Iterator

from aegis import platform_utils
from aegis.core import hashing


def normalize_path(path: str) -> str:
    return os.path.normpath(os.path.abspath(path))


def _is_excluded(path: str, exclude: list[str]) -> bool:
    normalized = path.replace(os.sep, "/")
    basename = os.path.basename(path)
    for pattern in exclude:
        pat = pattern.replace(os.sep, "/")
        if fnmatch.fnmatch(normalized, pat) or fnmatch.fnmatch(basename, pat):
            return True
    return False


def iter_files(paths: list[str], exclude: list[str]) -> Iterator[str]:
    for base in paths:
        if not os.path.exists(base):
            continue
        if os.path.isfile(base):
            if not _is_excluded(base, exclude):
                yield normalize_path(base)
            continue
        for root, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if not _is_excluded(os.path.join(root, d), exclude)]
            for name in files:
                full = os.path.join(root, name)
                if not _is_excluded(full, exclude):
                    yield normalize_path(full)


def collect_metadata(path: str, algorithm: str = "sha256",
                     chunk_size: int = 65536) -> dict | None:
    try:
        st = os.stat(path)
        return {
            "path": path,
            "hash": hashing.hash_file(path, algorithm, chunk_size),
            "algorithm": algorithm,
            "size": st.st_size,
            "permissions": platform_utils.get_file_permissions(path),
            "owner": platform_utils.get_file_owner(path),
            "mtime": st.st_mtime,
        }
    except (OSError, ValueError):
        return None
