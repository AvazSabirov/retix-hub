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
    require_approval  INTEGER NOT NULL DEFAULT 1,
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
    token_next_hash TEXT,                       -- выдан клиенту, станет token_hash, когда клиент им воспользуется
    token_next_at   INTEGER NOT NULL DEFAULT 0,
    token_set_at    INTEGER NOT NULL DEFAULT 0,
    is_share_host   INTEGER NOT NULL DEFAULT 0,
    is_blocked      INTEGER NOT NULL DEFAULT 0,
    is_approved     INTEGER NOT NULL DEFAULT 1,
    show_peers      INTEGER NOT NULL DEFAULT 1,  -- видит в программе другие ПК компании и может им писать
    client_version  TEXT NOT NULL DEFAULT '',
    last_handshake  INTEGER NOT NULL DEFAULT 0,
    rx_bytes        INTEGER NOT NULL DEFAULT 0,  -- принято от ПК по WireGuard (из wg show dump)
    last_rx_at      INTEGER NOT NULL DEFAULT 0,  -- когда rx_bytes последний раз вырос: ПК реально на связи
    endpoint        TEXT NOT NULL DEFAULT '',
    last_seen       TEXT,
    update_state    TEXT NOT NULL DEFAULT '',   -- что ПК сообщает об обновлении: downloading:1.0.6 …
    update_state_at TEXT,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_devices_company ON devices(company_id);

-- версии клиента, загруженные суперадмином (/admin/updates)
CREATE TABLE IF NOT EXISTS app_releases (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    version       TEXT NOT NULL UNIQUE,           -- из свойств exe: 1.0.6
    file_name     TEXT NOT NULL,                  -- RetixHub_Setup_1.0.6.exe (для ПК и сайта)
    stored_name   TEXT NOT NULL,                  -- файл в DATA_DIR/updates
    size          INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    manifest      TEXT NOT NULL,                  -- base64 JSON {app, kind, version, file, size, sha256}
    signature     TEXT NOT NULL,                  -- base64 Ed25519 манифеста
    notes         TEXT NOT NULL DEFAULT '',       -- что нового
    companies     TEXT NOT NULL DEFAULT '',       -- '' — всем, иначе JSON [id компаний]
    published     INTEGER NOT NULL DEFAULT 0,
    published_at  TEXT,
    publish_at    TEXT,                           -- опубликовать в это время (TZ), иначе NULL
    downloads     INTEGER NOT NULL DEFAULT 0,
    site_downloads INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    created_by    TEXT NOT NULL DEFAULT ''
);

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

-- прежние токены устройств: если такой токен пришёл снова — его скопировали на другой ПК
CREATE TABLE IF NOT EXISTS token_history (
    token_hash  TEXT PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    revoked_at  INTEGER NOT NULL
);

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


# столбцы, добавленные после первых установок: (таблица, столбец, определение)
MIGRATIONS = [
    ("devices", "token_next_hash", "TEXT"),
    ("devices", "token_next_at", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "token_set_at", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "update_state", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "update_state_at", "TEXT"),
    ("devices", "show_peers", "INTEGER NOT NULL DEFAULT 1"),
    ("devices", "rx_bytes", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "last_rx_at", "INTEGER NOT NULL DEFAULT 0"),
]


def init() -> None:
    conn = connect()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        for table, column, definition in MIGRATIONS:
            have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            if column not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_devices_token_next ON devices(token_next_hash)")
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
