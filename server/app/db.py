import sqlite3
import threading

from .config import DB_PATH

# Один лок на все изменения сети: выдача IP, wg, iptables
write_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS companies (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    login             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name              TEXT NOT NULL DEFAULT '',
    cabinet_pass_hash TEXT NOT NULL,
    join_pass_hash    TEXT NOT NULL,
    subnet_index      INTEGER NOT NULL UNIQUE,
    max_devices       INTEGER NOT NULL DEFAULT 20,
    require_approval  INTEGER NOT NULL DEFAULT 0,
    full_lan          INTEGER NOT NULL DEFAULT 0,
    share_name        TEXT NOT NULL DEFAULT 'share',
    share_ports       TEXT NOT NULL DEFAULT '445',
    is_active         INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id      INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    hostname        TEXT NOT NULL DEFAULT '',
    public_key      TEXT NOT NULL UNIQUE,
    ip              TEXT NOT NULL UNIQUE,
    token_hash      TEXT UNIQUE,
    is_share_host   INTEGER NOT NULL DEFAULT 0,
    is_blocked      INTEGER NOT NULL DEFAULT 0,
    is_approved     INTEGER NOT NULL DEFAULT 1,
    client_version  TEXT NOT NULL DEFAULT '',
    last_handshake  INTEGER NOT NULL DEFAULT 0,
    endpoint        TEXT NOT NULL DEFAULT '',
    last_seen       TEXT,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_devices_company ON devices(company_id);

-- сообщения между ПК одной компании (меню «Сообщение» в клиенте)
CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id      INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    from_device_id  INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    to_device_id    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    text            TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    delivered       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_messages_to ON messages(to_device_id, delivered);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id  INTEGER,
    action      TEXT NOT NULL,
    details     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def init() -> None:
    conn = connect()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def get_db():
    """FastAPI dependency."""
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()
