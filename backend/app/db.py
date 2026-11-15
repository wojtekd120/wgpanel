import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .settings import get_settings


SCHEMA = """
CREATE TABLE IF NOT EXISTS peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    public_key TEXT NOT NULL,
    assigned_ip TEXT NOT NULL,
    server_allowed_ips TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    managed INTEGER NOT NULL DEFAULT 1,
    peer_type TEXT NOT NULL DEFAULT 'private',
    tunnel_mode TEXT NOT NULL DEFAULT 'split',
    client_allowed_ips TEXT NOT NULL DEFAULT '',
    client_dns TEXT NOT NULL DEFAULT '',
    interface_name TEXT NOT NULL DEFAULT 'wg0'
);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deleted_peers (
    interface_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    deleted_at TEXT NOT NULL,
    PRIMARY KEY (interface_name, public_key)
);

CREATE TABLE IF NOT EXISTS setup_tokens (
    token_digest TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token_digest TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_peers_disabled ON peers(disabled);
CREATE INDEX IF NOT EXISTS idx_peers_interface ON peers(interface_name);
CREATE INDEX IF NOT EXISTS idx_deleted_peers_interface ON deleted_peers(interface_name);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
"""


def connect(path: Path | None = None) -> sqlite3.Connection:
    db_path = path or get_settings().database_path
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def backup_database(path: Path) -> Path:
    backup_dir = path.parent / "backups"
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    backup_path = backup_dir / f"{path.name}.{timestamp}.bak"
    with sqlite3.connect(path) as source, sqlite3.connect(backup_path) as destination:
        source.backup(destination)
    backup_path.chmod(0o600)
    return backup_path


def init_db() -> None:
    db_path = get_settings().database_path
    existed = db_path.exists() and db_path.stat().st_size > 0
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(peers)").fetchall()}
        migrations = {
            "notes": "ALTER TABLE peers ADD COLUMN notes TEXT NOT NULL DEFAULT ''",
            "managed": "ALTER TABLE peers ADD COLUMN managed INTEGER NOT NULL DEFAULT 1",
            "tunnel_mode": "ALTER TABLE peers ADD COLUMN tunnel_mode TEXT NOT NULL DEFAULT 'split'",
            "client_allowed_ips": "ALTER TABLE peers ADD COLUMN client_allowed_ips TEXT NOT NULL DEFAULT ''",
            "client_dns": "ALTER TABLE peers ADD COLUMN client_dns TEXT NOT NULL DEFAULT ''",
            "interface_name": f"ALTER TABLE peers ADD COLUMN interface_name TEXT NOT NULL DEFAULT '{get_settings().interface}'",
            "server_allowed_ips": "ALTER TABLE peers ADD COLUMN server_allowed_ips TEXT NOT NULL DEFAULT ''",
            "peer_type": "ALTER TABLE peers ADD COLUMN peer_type TEXT NOT NULL DEFAULT 'private'",
        }
        if existed and any(column not in columns for column in migrations):
            backup_database(db_path)
        for column, statement in migrations.items():
            if column not in columns:
                conn.execute(statement)
        conn.commit()


def get_db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()
