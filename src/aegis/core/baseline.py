from __future__ import annotations

import os
from dataclasses import dataclass

from aegis.core import integrity, scanner


@dataclass
class Change:
    path: str
    kind: str
    old_hash: str | None = None
    new_hash: str | None = None

    def describe(self) -> str:
        labels = {
            "created": "NEW FILE",
            "modified": "MODIFICAT",
            "deleted": "DELETED",
            "permission_change": "PERMISIUNI SCHIMBATE",
        }
        return f"[{labels.get(self.kind, self.kind)}] {self.path}"


def build_baseline(config, database) -> int:
    """Scan the monitored paths, store the fingerprints and return how many there are."""
    database.init_schema()
    count = 0
    for path in scanner.iter_files(config.paths, config.exclude):
        record = scanner.collect_metadata(path, config.hash_algorithm, config.chunk_size)
        if record is not None:
            database.upsert_file(record)
            count += 1
    if config.integrity_enabled:
        integrity.update_seal(database, config.integrity_key)
    return count


def _mtime_equal(a: float | None, b: float | None) -> bool:
    if a is None or b is None:
        return False
    return abs(a - b) < 1e-6


def compare_to_baseline(config, database) -> list[Change]:
    """Differences against the baseline: created / modified / deleted / permission_change.

    With `config.trust_mtime`, files whose size+mtime match are considered
    unchanged without re-hashing them (faster on large folders).
    """
    known = {rec["path"]: rec for rec in database.all_files()}
    changes: list[Change] = []
    seen: set[str] = set()

    for path in scanner.iter_files(config.paths, config.exclude):
        seen.add(path)
        old = known.get(path)

        if old is not None and config.trust_mtime:
            try:
                st = os.stat(path)
            except OSError:
                continue
            if int(st.st_size) == (old["size"] or -1) and _mtime_equal(st.st_mtime, old["mtime"]):
                continue

        record = scanner.collect_metadata(path, config.hash_algorithm, config.chunk_size)
        if record is None:
            continue
        if old is None:
            changes.append(Change(path, "created", None, record["hash"]))
        elif record["hash"] != old["hash"]:
            changes.append(Change(path, "modified", old["hash"], record["hash"]))
        elif record["permissions"] != old["permissions"]:
            changes.append(Change(path, "permission_change", old["hash"], record["hash"]))

    for path in known:
        if path not in seen:
            changes.append(Change(path, "deleted", known[path]["hash"], None))

    return changes
