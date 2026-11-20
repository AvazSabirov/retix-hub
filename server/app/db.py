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
    speed_limit       INTEGER NOT NULL DEFAULT 0,  -- Мбит/с через сервер на всю компанию, 0 — без ограничения
    remote_mode       TEXT NOT NULL DEFAULT 'off', -- удалённое управление (RustDesk): off, ask — с согласием, auto — без
    remote_cloud      INTEGER NOT NULL DEFAULT 0,  -- RustDesk и через облако RustDesk (по ID, из-за пределов VPN)
    tg_chat_id        TEXT NOT NULL DEFAULT '',    -- группа Telegram компании: запросы на подключение ПК
    tg_chat_title     TEXT NOT NULL DEFAULT '',
    tg_link_code      TEXT NOT NULL DEFAULT '',    -- одноразовый код из кабинета: /link@бот КОД в группе
    tg_link_at        INTEGER NOT NULL DEFAULT 0,
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
    lan_addrs       TEXT NOT NULL DEFAULT '',   -- JSON ["192.168.1.15/24", …]: адреса ПК в его локальной сети
    wg_port         INTEGER NOT NULL DEFAULT 0, -- UDP-порт WireGuard на ПК (для прямого пути по локальной сети)
    lan_at          INTEGER NOT NULL DEFAULT 0, -- когда ПК последний раз сообщил lan_addrs / wg_port
    direct_ids      TEXT NOT NULL DEFAULT '',   -- JSON [id ПК], с которыми связь сейчас идёт напрямую
    wan_ok          INTEGER NOT NULL DEFAULT 0, -- клиент умеет прямой путь через интернет (1.0.12+)
    speed_limit     INTEGER NOT NULL DEFAULT 0, -- Мбит/с через сервер для этого ПК (приём и отправка), 0 — без
    radmin_server   INTEGER NOT NULL DEFAULT 0, -- на ПК стоит Radmin Server (сообщает клиент 1.0.12+)
    remote_ok       INTEGER NOT NULL DEFAULT 0, -- RustDesk на ПК установлен и настроен Retix Hub (клиент 1.0.16+)
    remote_pw       TEXT NOT NULL DEFAULT '',   -- пароль RustDesk этого ПК, зашифрован (services.seal)
    remote_used_at  INTEGER NOT NULL DEFAULT 0, -- когда пароль выдан другому ПК: после сеанса ПК сменит его сам
    remote_control  INTEGER NOT NULL DEFAULT 0, -- может управлять другими ПК компании (решает администратор)
    remote_access   TEXT NOT NULL DEFAULT 'company', -- управление ЭТИМ ПК: company (как в компании), off, ask
    remote_local    TEXT NOT NULL DEFAULT '',   -- что выбрал пользователь ПК в программе: '', ask, own, off
    rustdesk_id     TEXT NOT NULL DEFAULT '',   -- ID RustDesk этого ПК (клиент 1.0.28+): подключение через облако RustDesk
    log_requested_at INTEGER NOT NULL DEFAULT 0, -- администратор запросил журнал программы: ПК пришлёт его (/api/log)
    nics            TEXT NOT NULL DEFAULT '',   -- JSON [{addr, mac}]: сетевые карты ПК (включение по сети, клиент 1.0.21+)
    nics_at         INTEGER NOT NULL DEFAULT 0, -- когда ПК последний раз сообщил nics
    role_id         INTEGER NOT NULL DEFAULT 0, -- роль (группа) ПК в компании: roles.id, 0 — без роли
    last_seen       TEXT,
    update_state    TEXT NOT NULL DEFAULT '',   -- что ПК сообщает об обновлении: downloading:1.0.6 …
    update_state_at TEXT,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_devices_company ON devices(company_id);

-- роли (группы) компьютеров компании: «Склад», «Администраторы» … — по ним группируется список в программе
CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id  INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    position    INTEGER NOT NULL DEFAULT 0,      -- порядок групп в программе
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (company_id, name COLLATE NOCASE)
);

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

-- журналы программы, которые ПК прислали по запросу администратора (сжаты gzip)
CREATE TABLE IF NOT EXISTS device_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id  INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    size        INTEGER NOT NULL,               -- байт текста (без сжатия)
    data        BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_device_logs_device ON device_logs(device_id);

-- включение по сети (Wake-on-LAN): команда включённому ПК той же локальной сети разбудить выключенный
CREATE TABLE IF NOT EXISTS wake_requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id    INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    target_id     INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    helper_id     INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    mac           TEXT NOT NULL,
    broadcast     TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    delivered_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_wake_helper ON wake_requests(helper_id, delivered_at);

-- настройки сервера, которые суперадмин меняет на странице «Настройки» (секреты — зашифрованы, services.seal)
CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
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
    ("devices", "lan_addrs", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "wg_port", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "lan_at", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "direct_ids", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "wan_ok", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "speed_limit", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "radmin_server", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "remote_ok", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "remote_pw", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "remote_used_at", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "remote_control", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "remote_access", "TEXT NOT NULL DEFAULT 'company'"),
    ("devices", "remote_local", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "log_requested_at", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "nics", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "nics_at", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "role_id", "INTEGER NOT NULL DEFAULT 0"),
    ("companies", "speed_limit", "INTEGER NOT NULL DEFAULT 0"),
    ("companies", "remote_mode", "TEXT NOT NULL DEFAULT 'off'"),
    ("companies", "remote_cloud", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "rustdesk_id", "TEXT NOT NULL DEFAULT ''"),
    ("companies", "tg_chat_id", "TEXT NOT NULL DEFAULT ''"),
    ("companies", "tg_chat_title", "TEXT NOT NULL DEFAULT ''"),
    ("companies", "tg_link_code", "TEXT NOT NULL DEFAULT ''"),
    ("companies", "tg_link_at", "INTEGER NOT NULL DEFAULT 0"),
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
        conn.execute("CREATE INDEX IF NOT EXISTS ix_audit_company ON audit_log(company_id, action, id)")
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
