from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_MODES = {"polling", "realtime"}
_SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass
class AegisConfig:
    database_path: str = "data/aegis.db"
    hash_algorithm: str = "sha256"
    chunk_size: int = 65536
    monitor_mode: str = "polling"
    interval_seconds: int = 300
    paths: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    ruleset: str = "auto"
    fail_on: str = "high"
    alerting: list[dict[str, Any]] = field(default_factory=list)
    log_level: str = "INFO"
    trust_mtime: bool = False
    integrity_enabled: bool = True
    integrity_key: str | None = None


def load_config(path: str | Path) -> AegisConfig:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file does not exist: {path}")

    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    db = raw.get("database", {}) or {}
    hashing = raw.get("hashing", {}) or {}
    mon = raw.get("monitoring", {}) or {}
    comp = raw.get("compliance", {}) or {}
    alert = raw.get("alerting", {}) or {}
    integ = raw.get("integrity", {}) or {}

    cfg = AegisConfig(
        database_path=db.get("path", AegisConfig.database_path),
        hash_algorithm=hashing.get("algorithm", AegisConfig.hash_algorithm),
        chunk_size=int(hashing.get("chunk_size", AegisConfig.chunk_size)),
        trust_mtime=bool(hashing.get("trust_mtime", AegisConfig.trust_mtime)),
        monitor_mode=mon.get("mode", AegisConfig.monitor_mode),
        interval_seconds=int(mon.get("interval_seconds", AegisConfig.interval_seconds)),
        paths=list(mon.get("paths", []) or []),
        exclude=list(mon.get("exclude", []) or []),
        ruleset=comp.get("ruleset", AegisConfig.ruleset),
        fail_on=comp.get("fail_on", AegisConfig.fail_on),
        alerting=list(alert.get("channels", []) or []),
        log_level=raw.get("log_level", AegisConfig.log_level),
        integrity_enabled=bool(integ.get("enabled", AegisConfig.integrity_enabled)),
        integrity_key=integ.get("key", AegisConfig.integrity_key),
    )
    _validate(cfg)
    return cfg


def _validate(cfg: AegisConfig) -> None:
    import hashlib
    try:
        hashlib.new(cfg.hash_algorithm)
    except ValueError as exc:
        raise ValueError(f"Algoritm de hash necunoscut: {cfg.hash_algorithm!r}") from exc
    if cfg.monitor_mode not in _MODES:
        raise ValueError(f"monitor mode invalid: {cfg.monitor_mode!r}")
    if cfg.fail_on not in _SEVERITIES:
        raise ValueError(f"fail_on invalid: {cfg.fail_on!r}")
    if cfg.interval_seconds <= 0:
        raise ValueError("interval_seconds must be > 0")
