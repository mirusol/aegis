from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

_SEAL_KEY = "baseline_seal"
_ALGO_KEY = "seal_algo"
_SEP = "\x1f"


def _canonical(records) -> bytes:
    lines = sorted(f"{r['path']}{_SEP}{r['hash']}" for r in records)
    return "\n".join(lines).encode("utf-8")


def compute_seal(records, key: str | None) -> tuple[str, str]:
    data = _canonical(records)
    if key:
        return hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest(), "hmac-sha256"
    return hashlib.sha256(data).hexdigest(), "sha256"


def update_seal(database, key: str | None) -> None:
    seal, algo = compute_seal(database.all_files(), key)
    database.set_meta(_SEAL_KEY, seal)
    database.set_meta(_ALGO_KEY, algo)


@dataclass
class SealResult:
    status: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "unset")


def verify_seal(database, key: str | None) -> SealResult:
    stored = database.get_meta(_SEAL_KEY)
    if stored is None:
        return SealResult("unset", "No seal stored yet.")
    current, _ = compute_seal(database.all_files(), key)
    if hmac.compare_digest(stored, current):
        return SealResult("ok", "Baseline-ul e intact.")
    return SealResult("tampered", "The database was modified outside the application.")
