from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    path         TEXT PRIMARY KEY,
    hash         TEXT NOT NULL,
    algorithm    TEXT NOT NULL,
    size         INTEGER,
    permissions  TEXT,
    owner        TEXT,
    mtime        REAL,
    first_seen   REAL,
    last_checked REAL
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    path      TEXT NOT NULL,
    change    TEXT NOT NULL,
    old_hash  TEXT,
    new_hash  TEXT,
    timestamp REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)

    def init_schema(self) -> None:
        parent = Path(self.path).parent
        if parent and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def upsert_file(self, record: dict) -> None:
        now = time.time()
        record = {**record}
        record.setdefault("first_seen", now)
        record.setdefault("last_checked", now)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO files
                    (path, hash, algorithm, size, permissions, owner, mtime, first_seen, last_checked)
                VALUES
                    (:path, :hash, :algorithm, :size, :permissions, :owner, :mtime, :first_seen, :last_checked)
                ON CONFLICT(path) DO UPDATE SET
                    hash=excluded.hash,
                    algorithm=excluded.algorithm,
                    size=excluded.size,
                    permissions=excluded.permissions,
                    owner=excluded.owner,
                    mtime=excluded.mtime,
                    last_checked=excluded.last_checked
                """,
                record,
            )

    def get_file(self, path: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM files WHERE path = ?", (path,)).fetchone()
        return dict(row) if row else None

    def all_files(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM files").fetchall()
        return [dict(r) for r in rows]

    def delete_file(self, path: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM files WHERE path = ?", (path,))

    def count_files(self) -> int:
        with self.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    def log_event(self, path: str, change: str,
                  old_hash: str | None, new_hash: str | None) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO events (path, change, old_hash, new_hash, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (path, change, old_hash, new_hash, time.time()),
            )

    def recent_events(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def set_meta(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_meta(self, key: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None
