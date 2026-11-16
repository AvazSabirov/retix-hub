import os
import secrets

APP_NAME = "Retix Hub"
APP_VERSION = "1.0.0"
PUBLIC_URL = os.getenv("PUBLIC_URL", "https://hub.retix.uz")

DATA_DIR = os.getenv("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "vpn.db")
SERVER_KEY_FILE = os.path.join(DATA_DIR, "server.key")
DOWNLOADS_DIR = os.path.join(DATA_DIR, "downloads")  # сюда кладётся RetixHub_Setup_<версия>.exe (или RetixHub.exe) для скачивания

# WireGuard
WG_IF = os.getenv("WG_IF", "wg0")
WG_PORT = int(os.getenv("WG_PORT", "51820"))
WG_ENDPOINT = os.getenv("WG_ENDPOINT", "hub.retix.uz:51820")  # что увидит клиент
WG_KEEPALIVE = 25

# Адресация: сервер 10.66.0.1, компания N -> 10.66.N.0/24
NET_PREFIX = "10.66"
SERVER_IP = f"{NET_PREFIX}.0.1"
SERVER_CIDR = f"{SERVER_IP}/16"

# Через сколько секунд без handshake устройство считается offline
ONLINE_SECONDS = int(os.getenv("ONLINE_SECONDS", "180"))

# API (слушает только localhost, наружу — через nginx)
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8100"))

SUPERADMIN_LOGIN = os.getenv("SUPERADMIN_LOGIN", "admin")
SUPERADMIN_PASSWORD = os.getenv("SUPERADMIN_PASSWORD", "")

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "1") == "1"

# WG_DRY_RUN=1 — не трогать wg/iptables, только логировать (для разработки)
DRY_RUN = os.getenv("WG_DRY_RUN", "0") == "1"
IPTABLES = os.getenv("IPTABLES", "iptables")  # или iptables-legacy


def _secret_key() -> str:
    env = os.getenv("SECRET_KEY")
    if env:
        return env
    path = os.path.join(DATA_DIR, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_urlsafe(48))
        os.chmod(path, 0o600)
    with open(path) as f:
        return f.read().strip()


SECRET_KEY = _secret_key()
