import sqlite3
from pathlib import Path
from typing import Iterator

from .settings import get_settings


SCHEMA = """
CREATE TABLE IF NOT EXISTS peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    assigned_ip TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token_digest TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_peers_disabled ON peers(disabled);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
"""


def connect(path: Path | None = None) -> sqlite3.Connection:
    db_path = path or get_settings().database_path
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


def get_db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()
