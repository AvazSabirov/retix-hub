"""
Retix Hub — клиент для Windows (окно в стиле Radmin VPN, значок в трее).

* регистрируется на сервере по логину/паролю компании (ключ генерируется локально);
* ставит туннель через официальный WireGuard for Windows (служба WireGuardTunnel$retixhub);
* следит за сервером: если сервер пропал — ждёт, когда появится — переподключается;
* показывает компьютеры компании (online/offline), открывает их общие папки (\\\\10.66.x.y),
  подключает сетевой диск; файл hosts не трогает;
* открывает в firewall Windows общие папки (SMB) и ping из подсети компании;
* обновляется сам: версию публикует суперадмин, клиент проверяет подпись и ставит её тихо.

Работает с правами администратора (перезапускает себя через UAC).
Журнал: <папка программы>\\logs\\client.log, аварийные падения — logs\\crash.log.
"""
import base64
import faulthandler
import ctypes
import hashlib
import ipaddress
import json
import logging
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from logging.handlers import RotatingFileHandler
from pathlib import Path
from tkinter import messagebox, simpledialog, ttk
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

VERSION = "1.0.7"
APP_NAME = "RetixHub"          # служебное имя: папки, задачи, мьютекс
APP_TITLE = "Retix Hub"        # то, что видит пользователь
TUNNEL = "retixhub"
DEFAULT_SERVER = "https://hub.retix.uz"  # можно переопределить client_config.json рядом с exe

WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if WINDOWS else 0

DATA_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / APP_NAME
STATE_FILE = DATA_DIR / "state.json"
CONF_FILE = DATA_DIR / f"{TUNNEL}.conf"

WG_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WireGuard"
WIREGUARD_EXE = WG_DIR / "wireguard.exe"
WG_EXE = WG_DIR / "wg.exe"
SERVICE = f"WireGuardTunnel${TUNNEL}"
FW_RULE = "RetixHub SMB"          # входящие общие папки (SMB) и Radmin Server (4899) из подсети компании
FW_RULE_PING = "RetixHub Ping"    # входящий ping из подсети компании

CHECK_EVERY = 8          # сек — основной цикл
HANDSHAKE_OK = 180       # сек — handshake свежее этого = туннель жив
HEARTBEAT_EVERY = 60

UPDATE_FIRST = 60        # сек после запуска — первая проверка новой версии
UPDATE_EVERY = 600       # сек — дальше каждые 10 минут
UPDATE_RETRY = 3600      # та же версия не встала — снова не раньше чем через час
UPDATE_MAX_SIZE = 300 * 1024 * 1024
UPDATE_DIR = DATA_DIR / "update"   # внутри DATA_DIR: доступ только SYSTEM и администраторам

TOKEN_HEADER = "X-Retix-Token"     # сервер присылает новый токен — старый после этого не действует

log = logging.getLogger("retixhub")


def app_dir() -> Path:
    return Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent


def log_dir() -> Path:
    """Журнал — рядом с программой (C:\\Program Files\\RetixHub\\logs): его легко найти и открыть
    без прав администратора. При запуске из исходников — %ProgramData%\\RetixHub\\logs."""
    return app_dir() / "logs" if getattr(sys, "frozen", False) else DATA_DIR / "logs"


def resource_dir() -> Path:
    """Файлы, вложенные в сборку (иконка): в onedir-сборке PyInstaller это папка _internal."""
    return Path(getattr(sys, "_MEIPASS", app_dir()))


def run(args: list, timeout: int = 60) -> tuple[int, str]:
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
        out = (r.stdout or b"") + (r.stderr or b"")
        for enc in ("utf-8", "cp866", "cp1251"):
            try:
                return r.returncode, out.decode(enc)
            except UnicodeDecodeError:
                pass
        return r.returncode, out.decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


# ====================================================================== DPAPI

if WINDOWS:
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _to_blob(data: bytes):
        buf = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _crypt(func, data: bytes) -> bytes:
        inp, _keep = _to_blob(data)
        out = _Blob()
        # 0x4 = CRYPTPROTECT_LOCAL_MACHINE, 0x1 = UI_FORBIDDEN
        if not func(ctypes.byref(inp), None, None, None, None, 0x5, ctypes.byref(out)):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)


def protect(text: str) -> str:
    if not text:
        return ""
    if WINDOWS:
        enc = _crypt(ctypes.windll.crypt32.CryptProtectData, text.encode())
        return "dpapi:" + base64.b64encode(enc).decode()
    return "plain:" + text


def unprotect(value: str) -> str:
    if not value:
        return ""
    kind, _, data = value.partition(":")
    if kind == "dpapi" and WINDOWS:
        try:
            return _crypt(ctypes.windll.crypt32.CryptUnprotectData, base64.b64decode(data)).decode()
        except OSError:
            return ""
    return data if kind == "plain" else ""


# ====================================================================== state

class State:
    """Настройки клиента в %ProgramData%\\RetixHub\\state.json (доступ только админам/SYSTEM).

    Несколько компаний: текущая — в основных полях (server_url, company_login, token, private_key…),
    остальные — в "profiles" (те же поля, секреты так же зашифрованы DPAPI). У каждой компании свой
    ключ WireGuard и свой вход: для сервера это разные компьютеры. В сети — одна компания за раз."""

    FIELDS = {"server_url": "", "company_login": "", "company_name": "", "device_name": "", "token": "",
              "private_key": "", "join_password": "", "last_conf_hash": "", "fw_subnet": "",
              "autostart_done": False, "enabled": True, "auto_update": True, "update_attempt": {},
              "update_state": "none", "update_pubkey": "", "update_pins": {}, "profiles": {}}
    PROFILE_FIELDS = ("server_url", "company_login", "company_name", "device_name", "token", "private_key",
                      "join_password")

    def __init__(self, path: Path | None = None):
        self.path = path or STATE_FILE
        self.data = dict(self.FIELDS)
        self.lock = threading.Lock()
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text("utf-8")))
            except Exception:
                log.exception("state.json повреждён — начинаем заново")
        if not self.data["server_url"]:
            self.data["server_url"] = self._default_server()

    @staticmethod
    def _default_server() -> str:
        cfg = app_dir() / "client_config.json"
        if cfg.exists():
            try:
                return json.loads(cfg.read_text("utf-8")).get("server_url", DEFAULT_SERVER)
            except Exception:
                pass
        return DEFAULT_SERVER

    def get(self, key):
        with self.lock:
            v = self.data.get(key)
        return unprotect(v) if key in ("token", "private_key", "join_password") else v

    def set(self, **kw):
        with self.lock:
            for k, v in kw.items():
                self.data[k] = protect(v) if k in ("token", "private_key", "join_password") else v
            self._write()

    # --- компании (профили)
    @staticmethod
    def profile_key(server: str, company: str) -> str:
        return f"{(server or '').strip().rstrip('/').lower()}|{(company or '').strip().lower()}"

    def current_key(self) -> str:
        with self.lock:
            return self.profile_key(self.data.get("server_url"), self.data.get("company_login"))

    def profiles(self) -> list[dict]:
        """Компании этого ПК: текущая (с входом) первой, затем сохранённые."""
        with self.lock:
            cur = self.profile_key(self.data.get("server_url"), self.data.get("company_login"))
            out = []
            if self.data.get("company_login") and self.data.get("token"):
                out.append({"key": cur, "active": True, **{f: self.data.get(f, "") for f in
                                                          ("server_url", "company_login", "company_name")}})
            for key, p in sorted((self.data.get("profiles") or {}).items()):
                if key != cur:
                    out.append({"key": key, "active": False, **{f: p.get(f, "") for f in
                                                               ("server_url", "company_login", "company_name")}})
            return out

    def snapshot(self) -> dict:
        with self.lock:
            return json.loads(json.dumps(self.data))

    def restore(self, snap: dict) -> None:
        with self.lock:
            self.data = snap
            self._write()

    def stash_current(self) -> None:
        """Текущую компанию (если в ней есть вход) — в сохранённые; секреты остаются зашифрованными."""
        with self.lock:
            if self.data.get("company_login") and self.data.get("token"):
                key = self.profile_key(self.data.get("server_url"), self.data.get("company_login"))
                profiles = dict(self.data.get("profiles") or {})
                profiles[key] = {f: self.data.get(f, "") for f in self.PROFILE_FIELDS}
                self.data["profiles"] = profiles
                self._write()

    def activate(self, key: str) -> bool:
        """Сохранённую компанию — в текущие (вместо прежней: её сначала stash_current)."""
        with self.lock:
            profiles = dict(self.data.get("profiles") or {})
            p = profiles.pop(key, None)
            if p is None:
                return False
            for f in self.PROFILE_FIELDS:
                self.data[f] = p.get(f, "")
            self.data.update(profiles=profiles, last_conf_hash="", fw_subnet="", enabled=True)
            self._write()
            return True

    def forget(self, key: str) -> dict | None:
        """Убрать сохранённую компанию; вернуть её поля (токен — расшифрованным) или None."""
        with self.lock:
            profiles = dict(self.data.get("profiles") or {})
            p = profiles.pop(key, None)
            if p is None:
                return None
            self.data["profiles"] = profiles
            self._write()
        return {**p, "token": unprotect(p.get("token", ""))}

    def _write(self) -> None:
        """Записать на диск (вызывать под self.lock)."""
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), "utf-8")
        for attempt in range(5):  # антивирус может на миг держать файл
            try:
                tmp.replace(self.path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.2)

    def keypair(self) -> tuple[str, str]:
        priv_b64 = self.get("private_key")
        if priv_b64:
            priv = X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
        else:
            priv = X25519PrivateKey.generate()
            raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                     serialization.NoEncryption())
            priv_b64 = base64.b64encode(raw).decode()
            self.set(private_key=priv_b64)
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return priv_b64, base64.b64encode(pub).decode()


def secure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if WINDOWS:
        # только SYSTEM (S-1-5-18) и Администраторы (S-1-5-32-544): там приватный ключ
        run(["icacls", str(DATA_DIR), "/inheritance:r", "/grant:r",
             "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])


# ====================================================================== API

class ServerUnreachable(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class Api:
    def __init__(self, state: State):
        self.state = state
        self.http = requests.Session()
        self.http.headers["User-Agent"] = f"{APP_NAME}/{VERSION}"
        # запросы по одному: иначе окно сообщений могло бы отправить уже заменённый токен,
        # а старый токен сервер считает признаком копии входа на другом ПК
        self.lock = threading.Lock()
        self.on_hint = None   # Updater.note_hint: подсказка сервера X-Retix-Update

    def _req(self, method: str, path: str, auth: bool = True, **kw):
        with self.lock:
            return self._req_locked(method, path, auth, **kw)

    def _req_locked(self, method: str, path: str, auth: bool, **kw):
        url = self.state.get("server_url").rstrip("/") + path
        headers = {"Authorization": f"Bearer {self.state.get('token')}", "X-Retix-Version": VERSION,
                   "X-Retix-Update-State": self.state.get("update_state") or "none"} if auth else {}
        try:
            r = self.http.request(method, url, headers=headers, timeout=8, **kw)
        except requests.RequestException as e:
            raise ServerUnreachable(str(e)) from e
        new_token = r.headers.get(TOKEN_HEADER)
        if auth and new_token and r.status_code < 400:
            self.state.set(token=new_token)   # сразу на диск: после перезапуска — уже новый
        hint = r.headers.get("X-Retix-Update")
        if hint and self.on_hint:
            self.on_hint(hint)
        if r.status_code >= 500:
            raise ServerUnreachable(f"HTTP {r.status_code}")
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except ValueError:
                detail = r.text
            raise ApiError(r.status_code, str(detail))
        return r.json()

    def register(self, company_login: str, password: str, device_name: str, public_key: str):
        return self._req("POST", "/api/register", auth=False, json={
            "company_login": company_login, "join_password": password, "device_name": device_name,
            "hostname": socket.gethostname(), "public_key": public_key, "client_version": VERSION})

    def me(self):
        return self._req("GET", "/api/me")

    def peers(self):
        return self._req("GET", "/api/peers")

    def heartbeat(self):
        return self._req("POST", "/api/heartbeat", json={"client_version": VERSION})

    def send_message(self, to: int, text: str):
        return self._req("POST", "/api/messages", json={"to": to, "text": text})

    def messages(self):
        return self._req("GET", "/api/messages")

    def logout(self):
        return self._req("POST", "/api/logout")

    def update_info(self):
        return self._req("GET", "/api/update")


# ====================================================================== проверка ответа сервера
# Конфигурация WireGuard, правила firewall и адреса для ping/mstsc/Radmin собираются из ответа сервера.
# Не верим ему вслепую: только сеть Retix Hub 10.66.0.0/16, ключи base64, без переводов строк.

VPN_NET = ipaddress.IPv4Network("10.66.0.0/16")
KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
ENDPOINT_RE = re.compile(r"^(?:[A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:]{2,39}\]):(\d{1,5})$")
PORTS_RE = re.compile(r"^\d{1,5}(,\d{1,5}){0,14}$")


def _ipv4(value) -> ipaddress.IPv4Address:
    ip = ipaddress.IPv4Address(str(value))
    if str(ip) != value:
        raise ValueError(f"адрес {value!r}")
    return ip


def _vpn_net(value) -> ipaddress.IPv4Network:
    net = ipaddress.IPv4Network(str(value).strip())
    if not net.subnet_of(VPN_NET):
        raise ValueError(f"сеть {value!r} вне {VPN_NET}")
    return net


def check_cfg(cfg: dict) -> None:
    """ValueError, если в конфигурации от сервера есть что-то кроме сети Retix Hub."""
    ip = _ipv4(cfg["ip"])
    subnet = _vpn_net(cfg["subnet"])
    if ip not in subnet or cfg["address"] != f"{ip}/32":
        raise ValueError("адрес ПК вне подсети компании")
    if _ipv4(cfg["server_ip"]) not in VPN_NET:
        raise ValueError("адрес сервера вне сети Retix Hub")
    for part in str(cfg["allowed_ips"]).split(","):
        _vpn_net(part)
    if not KEY_RE.match(str(cfg["server_public_key"])):
        raise ValueError("ключ сервера")
    m = ENDPOINT_RE.match(str(cfg["endpoint"]))
    if not m or not 0 < int(m.group(1)) < 65536:
        raise ValueError(f"endpoint {cfg['endpoint']!r}")
    for key in ("keepalive", "radmin_port"):
        if key in cfg and not (isinstance(cfg[key], int) and 0 <= cfg[key] < 65536):
            raise ValueError(key)
    if cfg.get("share_ports") and not PORTS_RE.match(str(cfg["share_ports"])):
        raise ValueError("порты")


def peer_ip_ok(ip, subnet: str) -> bool:
    """IP соседа — обычный IPv4 в подсети компании (его подставляем в ping, \\\\ip, mstsc, Radmin)."""
    try:
        return _ipv4(ip) in _vpn_net(subnet)
    except (ValueError, TypeError):
        return False


# ====================================================================== WireGuard

class Tunnel:
    @staticmethod
    def installed() -> bool:
        return WIREGUARD_EXE.exists()

    @staticmethod
    def build_conf(cfg: dict, private_key: str) -> str:
        return (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {cfg['address']}\n\n"
            "[Peer]\n"
            f"PublicKey = {cfg['server_public_key']}\n"
            f"Endpoint = {cfg['endpoint']}\n"
            f"AllowedIPs = {cfg['allowed_ips']}\n"     # только сеть компании -> интернет идёт мимо VPN
            f"PersistentKeepalive = {cfg['keepalive']}\n"
        )

    @staticmethod
    def service_state() -> str:
        """running / stopped / missing"""
        rc, out = run(["sc", "query", SERVICE], timeout=15)
        if rc == 1060 or "1060" in out:
            return "missing"
        return "running" if "RUNNING" in out else ("stopped" if rc == 0 else "missing")

    @classmethod
    def install(cls, conf_text: str) -> None:
        if cls.service_state() != "missing":
            cls.uninstall()
        CONF_FILE.write_text(conf_text, "utf-8")
        rc, out = run([str(WIREGUARD_EXE), "/installtunnelservice", str(CONF_FILE)])
        if rc != 0:
            raise RuntimeError(f"WireGuard: {out.strip()}")
        log.info("туннель установлен")

    @classmethod
    def uninstall(cls) -> None:
        run([str(WIREGUARD_EXE), "/uninstalltunnelservice", TUNNEL])
        for _ in range(20):  # служба удаляется асинхронно
            if cls.service_state() == "missing":
                break
            time.sleep(0.5)
        log.info("туннель удалён")

    @staticmethod
    def start() -> None:
        run(["sc", "start", SERVICE], timeout=15)

    @staticmethod
    def probe(ip: str) -> bool:
        """Живой ли туннель на самом деле: ping до сервера внутри VPN."""
        for _ in range(2):
            code, out = run(["ping", "-n", "1", "-w", "1500", ip], timeout=10)
            if code == 0 and "TTL=" in out.upper():
                return True
        return False

    @staticmethod
    def last_handshake() -> int:
        rc, out = run([str(WG_EXE), "show", TUNNEL, "latest-handshakes"], timeout=10)
        if rc != 0:
            return 0
        try:
            return max(int(line.split()[1]) for line in out.splitlines() if line.strip())
        except (ValueError, IndexError):
            return 0


def install_wireguard_if_needed() -> bool:
    """Если WireGuard не стоит — ставит MSI, лежащий рядом с exe (wireguard-amd64-*.msi)."""
    if Tunnel.installed():
        return True
    msi = sorted(app_dir().glob("wireguard*.msi"))
    if not msi:
        return False
    log.info("ставлю %s", msi[-1].name)
    run(["msiexec", "/i", str(msi[-1]), "/qn", "DO_NOT_LAUNCH=1"], timeout=300)
    return Tunnel.installed()


# ====================================================================== Windows: firewall, автозапуск

def ensure_firewall(subnet: str | None, ports: str = "445") -> None:
    """Входящие из подсети компании: общие папки (SMB) и ping. Интерфейс WireGuard Windows считает
    «общественной» сетью и без этих правил закрывает общие папки и ping даже на ПК, где доступ открыт."""
    for name in (FW_RULE, FW_RULE_PING):
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
    if subnet:
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_RULE}", "dir=in", "action=allow",
             "protocol=TCP", f"localport={ports}", f"remoteip={subnet}", "profile=any"])
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_RULE_PING}", "dir=in", "action=allow",
             "protocol=icmpv4:8,any", f"remoteip={subnet}", "profile=any"])
        log.info("firewall: общие папки (%s) и ping разрешены из %s", ports, subnet)


RADMIN_PORT = 4899


def lan_ports(cfg: dict) -> str:
    """Входящие TCP-порты из подсети компании: общие папки (из кабинета, обычно 445) + Radmin Server."""
    ports = [p for p in (cfg.get("share_ports") or "445").replace(" ", "").split(",") if p]
    radmin = str(cfg.get("radmin_port") or RADMIN_PORT)
    if radmin not in ports:
        ports.append(radmin)
    return ",".join(ports)


def find_radmin_viewer(saved: str = "") -> Path | None:
    """Radmin Viewer (Radmin.exe): сохранённый путь, стандартные папки, реестр App Paths."""
    candidates = [Path(saved)] if saved else []
    for env in ("ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"):
        base = os.environ.get(env)
        if base:
            candidates += [Path(base) / "Radmin Viewer 3" / "Radmin.exe", Path(base) / "Radmin Viewer" / "Radmin.exe"]
    for c in candidates:
        if c.is_file():
            return c
    if WINDOWS:
        try:
            import winreg
            for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(root, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Radmin.exe") as k:
                        p = Path(winreg.QueryValue(k, None).strip('"'))
                        if p.is_file():
                            return p
                except OSError:
                    pass
        except ImportError:
            pass
    return None


def radmin_args(exe: Path, ip: str, mode: str, port: int = RADMIN_PORT) -> list[str]:
    """Командная строка Radmin Viewer: full — полное управление, view — только просмотр, files — передача файлов."""
    flags = {"full": [], "view": ["/noinput"], "files": ["/file"]}[mode]
    return [str(exe), f"/connect:{ip}:{port}", *flags]


def port_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def smb_check(ip: str, timeout: float = 3.0) -> str | None:
    """Доступны ли общие папки (SMB, порт 445) на ПК. None — да, иначе понятная причина."""
    try:
        with socket.create_connection((ip, 445), timeout=timeout):
            return None
    except OSError:
        pass
    rc, out = run(["ping", "-n", "1", "-w", "1500", ip], timeout=10) if WINDOWS else (1, "")
    if rc == 0 and "TTL=" in out.upper():
        return ("Компьютер в сети (ping проходит), но порт общих папок 445 закрыт. Возможные причины:\n"
                "• на том ПК ещё старая версия Retix Hub — обновите до последней (она открывает 445 в firewall);\n"
                "• на том ПК выключен «Общий доступ к файлам и принтерам» или служба «Сервер» (LanmanServer).")
    return ("Компьютер не отвечает. Возможные причины:\n"
            "• он выключен или не подключён к Retix Hub;\n"
            "• на сервере Retix Hub не обновлены правила (обновите сервер: git pull && ./run.sh);\n"
            "• на том ПК старая версия Retix Hub — обновите до последней.")


def ensure_autostart() -> None:
    if not getattr(sys, "frozen", False):
        return
    run(["schtasks", "/Create", "/TN", APP_NAME, "/TR", f'"{sys.executable}" --minimized',
         "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"])


def remove_autostart() -> None:
    run(["schtasks", "/Delete", "/TN", APP_NAME, "/F"])


# ====================================================================== автообновление
# Как у касс Retix: суперадмин загружает установщик на сервер (/admin/updates) и публикует его.
# ПК в каждом запросе шлёт свою версию и состояние обновления (X-Retix-Version, X-Retix-Update-State),
# сервер в каждом ответе — до какой версии обновиться (X-Retix-Update). Изменилось — сразу
# GET /api/update; кроме того — раз в 10 минут. Версию, размер и SHA-256 клиент берёт ТОЛЬКО из
# манифеста, подписанного закрытым ключом сервера (Ed25519). Открытый ключ: зашитый в клиент
# (UPDATE_PUBLIC_KEYS или client_config.json → update_public_keys), а если его нет — ключ сервера,
# запомненный при первой связи по https (state.json → update_pubkey, доступ только администраторам).
# Дальше ключ не меняется: подписанное другим ключом клиент не ставит.

UPDATE_PUBLIC_KEYS: list[str] = []      # base64 открытых ключей подписи; обычно — в client_config.json
MANIFEST_APP = "Retix Hub"
MANIFEST_KIND = "retixhub-update"
MIN_CHECK_GAP = 10                      # сек — не чаще, даже если подсказка «мигает»
INSTALL_GRACE = 300                     # сек — столько установщику на работу, потом «не установилась»
VERSION_RE = re.compile(r"^\d{1,5}(\.\d{1,5}){1,3}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class UpdateError(Exception):
    """Понятный текст: что не так с обновлением."""


def vkey(version):
    """«1.0.6» -> (1, 0, 6, 0); не версия -> None."""
    v = str(version or "").strip()
    if not VERSION_RE.match(v):
        return None
    return tuple(([int(p) for p in v.split(".")] + [0, 0, 0])[:4])


def newer(a, b) -> bool:
    """Версия a новее b."""
    ka, kb = vkey(a), vkey(b)
    return ka is not None and (kb is None or ka > kb)


def update_public_keys() -> list[str]:
    keys = list(UPDATE_PUBLIC_KEYS)
    cfg = app_dir() / "client_config.json"
    try:
        extra = json.loads(cfg.read_text("utf-8")).get("update_public_keys") or []
        keys += [k for k in extra if isinstance(k, str)]
    except (OSError, ValueError, AttributeError):
        pass
    return [k.strip() for k in keys if KEY_RE.match(k.strip())]


def verify_manifest(info: dict, keys: list[str]) -> dict:
    """Ответ сервера (update) -> проверенный манифест {version, size, sha256, file}.
    UpdateError — подпись не сошлась или манифест чужой."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        body = base64.b64decode(str(info.get("manifest") or ""), validate=True)
        sig = base64.b64decode(str(info.get("signature") or ""), validate=True)
    except (ValueError, TypeError):
        raise UpdateError("манифест обновления повреждён")
    ok = False
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(sig, body)
            ok = True
            break
        except (InvalidSignature, ValueError):
            pass
    if not body or not ok:
        raise UpdateError("подпись обновления не сходится — установщик не от сервера Retix Hub")
    try:
        m = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise UpdateError("манифест обновления повреждён")
    if not isinstance(m, dict) or m.get("app") != MANIFEST_APP or m.get("kind") != MANIFEST_KIND:
        raise UpdateError("манифест не от обновления Retix Hub")
    size, sha, version = m.get("size"), str(m.get("sha256") or "").lower(), str(m.get("version") or "")
    if vkey(version) is None or not isinstance(size, int) or not 0 < size <= UPDATE_MAX_SIZE or not SHA_RE.match(sha):
        raise UpdateError("манифест обновления неполный")
    if info.get("version") and str(info["version"]) != version:
        raise UpdateError("версия в ответе сервера не совпадает с подписанной")
    return {"version": version, "size": size, "sha256": sha, "file": str(m.get("file") or "")}


def launch_installer(path: Path) -> None:
    """Тихая установка новой версии. Через «start», а не дочерним процессом: если установщику
    придётся закрыть RetixHub.exe силой, он не погибнет вместе с ним.
    /AUTOUPDATE=1 — после установки установщик сам запустит новый клиент (в трее)."""
    subprocess.Popen(["cmd", "/c", "start", "", str(path), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                      "/AUTOUPDATE=1"], creationflags=CREATE_NO_WINDOW)


class Updater(threading.Thread):
    """Фоновое обновление: сверка (подсказка сервера или раз в 10 минут), скачивание с докачкой в
    %ProgramData%\\RetixHub\\update, проверка подписи и SHA-256, тихая установка. VPN не рвётся:
    туннель держит служба WireGuard."""

    def __init__(self, state: State, api: "Api", on_update=None, launcher=None):
        super().__init__(daemon=True, name="updater")
        self.state, self.api = state, api
        self.on_update = on_update or (lambda ver: None)
        self.launcher = launcher or launch_installer
        self.wake = threading.Event()
        self.stop_event = threading.Event()
        self.last_hint: str | None = None
        self.last_check = 0.0
        self.warned_no_key = False
        self.http = requests.Session()
        self.http.headers["User-Agent"] = f"{APP_NAME}/{VERSION}"
        self.finish_pending()

    # --- из других потоков
    def note_hint(self, value: str):
        """X-Retix-Update из ответа на любой запрос. Изменился и есть что ставить — сверка сразу."""
        value = str(value or "").strip()[:32]
        if value == self.last_hint:
            return
        self.last_hint = value
        if value and value != "none":
            self.wake.set()

    # --- поток
    def run(self):
        if not getattr(sys, "frozen", False):
            log.info("автообновление выключено: запуск из исходников")
            return
        delay = UPDATE_FIRST
        while not self.stop_event.is_set():
            self.wake.wait(delay)
            self.wake.clear()
            if self.stop_event.is_set():
                return
            gap = time.time() - self.last_check
            if gap < MIN_CHECK_GAP:
                delay = MIN_CHECK_GAP - gap
                continue
            delay = UPDATE_EVERY
            try:
                if self.check():
                    return
            except Exception:  # noqa: BLE001
                log.exception("автообновление")

    def _set_state(self, value: str):
        if self.state.get("update_state") != value:
            self.state.set(update_state=value)   # уйдёт на сервер со следующим запросом

    def finish_pending(self):
        """После запуска: прошлое обновление встало или нет (видно суперадмину)."""
        attempt = self.state.get("update_attempt") or {}
        ver = attempt.get("version")
        if not ver:
            return
        if not newer(ver, VERSION):
            log.warning("Retix Hub обновлён до %s", VERSION)
            self.state.set(update_attempt={}, update_state="none")
            self._cleanup()
        elif time.time() - attempt.get("at", 0) > INSTALL_GRACE:
            log.warning("обновление до %s не установилось (работает %s)", ver, VERSION)
            self._set_state(f"failed:{ver}")

    def check(self) -> str | None:
        """Версия, которая начала устанавливаться, или None."""
        self.last_check = time.time()
        if self.state.get("auto_update") is False or not self.state.get("token"):
            return None
        base = (self.state.get("server_url") or "").rstrip("/")
        pins = self.state.get("update_pins") or {}
        pinned = pins.get(base) or ("" if pins else self.state.get("update_pubkey") or "")   # 1.0.6: один ключ
        keys = update_public_keys() or [k for k in [pinned] if KEY_RE.match(k)]
        u = urlparse(base)
        if u.scheme != "https" and u.hostname not in ("127.0.0.1", "localhost"):
            log.warning("автообновление только по https: %s", base)
            return None
        try:
            info = self.api.update_info()
        except (ApiError, ServerUnreachable):
            return None
        if not keys:   # первая связь: запомнить ключ сервера (по https, сертификат проверен)
            pk = str((info or {}).get("public_key") or "") if isinstance(info, dict) else ""
            if not KEY_RE.match(pk):
                if not self.warned_no_key:
                    log.warning("автообновление выключено: сервер не прислал ключ подписи")
                    self.warned_no_key = True
                return None
            self.state.set(update_pins={**pins, base: pk})
            keys = [pk]
            log.warning("ключ подписи обновлений запомнен: %s", pk)
        upd = info.get("update") if isinstance(info, dict) else None
        if not upd:
            self._set_state("none")
            self._cleanup()
            return None
        try:
            m = verify_manifest(upd, keys)
        except UpdateError as e:
            log.error("обновление отклонено: %s", e)
            self._set_state(f"error:{upd.get('version')}" if vkey(upd.get("version")) else "none")
            return None
        ver = m["version"]
        if not newer(ver, VERSION):
            self._set_state("none")
            return None
        attempt = self.state.get("update_attempt") or {}
        if attempt.get("version") == ver and time.time() - attempt.get("at", 0) < UPDATE_RETRY:
            return None   # эта версия уже ставилась и не встала — снова не раньше чем через час
        url = str(upd.get("url") or "")
        if not url.startswith("/api/update/file/"):
            log.error("обновление %s: неверная ссылка на файл", ver)
            return None
        self._set_state(f"downloading:{ver}")
        path = self._download(base + url, ver, m["sha256"], m["size"])
        if not path:
            self._set_state(f"error:{ver}")
            return None
        self._set_state(f"installing:{ver}")
        self.state.set(update_attempt={"version": ver, "at": int(time.time())})
        log.warning("обновление %s -> %s: запускаю установщик", VERSION, ver)
        self.launcher(path)
        self.on_update(ver)
        return ver

    def _download(self, url: str, ver: str, sha: str, size: int) -> Path | None:
        """Скачать (докачать после обрыва) и проверить. None — не вышло, файла нет."""
        UPDATE_DIR.mkdir(parents=True, exist_ok=True)
        final = UPDATE_DIR / f"RetixHub_Setup_{ver}.exe"
        part = UPDATE_DIR / f"RetixHub_Setup_{ver}.part"
        for f in UPDATE_DIR.iterdir():            # другие версии — уже не нужны
            if f not in (final, part):
                try:
                    f.unlink()
                except OSError:
                    pass
        if final.exists() and final.stat().st_size == size and self._sha(final) == sha:
            return final
        have = part.stat().st_size if part.exists() else 0
        if have > size:
            part.unlink()
            have = 0
        try:
            headers = {"Range": f"bytes={have}-"} if 0 < have < size else {}
            with self.http.get(url, stream=True, timeout=(10, 60), headers=headers) as r:
                if r.status_code == 416:
                    pass                                  # уже всё скачано
                else:
                    r.raise_for_status()
                    if r.status_code != 206:              # сервер начал сначала
                        have = 0
                    with open(part, "ab" if have else "wb") as f:
                        got = have
                        for chunk in r.iter_content(256 * 1024):
                            got += len(chunk)
                            if got > size:
                                raise UpdateError("файл больше заявленного")
                            f.write(chunk)
            if part.stat().st_size != size or self._sha(part) != sha:
                part.unlink()
                raise UpdateError("размер или SHA-256 не совпали с подписанными")
            part.replace(final)
            return final
        except (requests.RequestException, OSError, UpdateError) as e:
            log.warning("обновление %s не скачано: %s", ver, e)   # .part остаётся — докачаем
            return None

    @staticmethod
    def _sha(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _cleanup():
        """Установщики прошлых обновлений больше не нужны."""
        if UPDATE_DIR.exists():
            for f in UPDATE_DIR.iterdir():
                try:
                    f.unlink()
                except OSError:
                    pass


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True


# ====================================================================== логика подключения

class Status:
    NEED_LOGIN = "need_login"
    CONNECTING = "connecting"
    ONLINE = "online"
    SERVER_DOWN = "server_down"
    PENDING = "pending"
    BLOCKED = "blocked"
    ERROR = "error"
    OFF = "off"            # пользователь выключил кнопкой (туннель снят, вход сохранён)


class Worker(threading.Thread):
    """Фоновый цикл: держит туннель в рабочем состоянии и сообщает статус в GUI (только через очередь)."""

    def __init__(self, state: State, events: queue.Queue, tunnel=None):
        super().__init__(daemon=True, name="worker")
        self.state, self.events = state, events
        self.tunnel = tunnel or Tunnel          # в тестах подменяется
        self.api = Api(state)
        self.wake = threading.Event()
        self.stop_flag = False
        self.server_was_down = False
        self.last_install = 0.0
        self.reinstall_backoff = 60
        self.last_heartbeat = 0.0
        self.cfg: dict | None = None
        self.paused = False  # после «Выйти из сети»
        # шаг цикла и смена компании (вход, переключение, выход) не идут одновременно
        self.op_lock = threading.RLock()

    # --- связь с GUI
    def emit(self, kind: str, **data):
        self.events.put((kind, data))

    def status(self, status: str, text: str = ""):
        self.emit("status", status=status, text=text, cfg=self.cfg)

    # --- команды из GUI (вызываются в отдельном потоке)
    def login(self, server: str, company: str, password: str, device: str, remember: bool):
        """Вход в компанию. Другая компания, чем текущая, — добавляется: текущая уходит в сохранённые
        (Компания → переключиться), у новой — свой ключ WireGuard (для сервера это другой ПК).
        Не вышло — всё как было."""
        server, company = server.strip().rstrip("/"), company.strip()
        with self.op_lock:
            snap = self.state.snapshot()
            target = State.profile_key(server, company)
            if target != self.state.current_key() and self.state.get("company_login"):
                self.state.stash_current()
                if not self.state.activate(target):   # уже в списке — тот же ключ, тот же ПК на сервере
                    self.state.set(token="", private_key="", join_password="", company_name="", last_conf_hash="")
            self.state.set(server_url=server, company_login=company, device_name=device.strip())
            try:
                self._register(password)
            except (ApiError, ServerUnreachable) as e:
                self.state.restore(snap)
                return e.detail if isinstance(e, ApiError) else "Сервер недоступен. Проверьте адрес и интернет."
            self.state.set(join_password=password if remember else "", enabled=True, last_conf_hash="")
            self._reset_connection()
        self.wake.set()
        return None

    def switch_to(self, key: str) -> str | None:
        """Переключиться на сохранённую компанию: туннель и firewall пересоберутся под неё."""
        with self.op_lock:
            if key == self.state.current_key() and self.state.get("token"):
                return None
            snap = self.state.snapshot()
            self.state.stash_current()
            if not self.state.activate(key):
                self.state.restore(snap)
                return "Компания не найдена в списке"
            log.info("переключение на компанию %s", self.state.get("company_login"))
            self._reset_connection()
            self.emit("peers", peers=[])
            self.status(Status.CONNECTING, "Переключение на другую компанию…")
        self.wake.set()
        return None

    def forget_company(self, key: str) -> None:
        """Убрать сохранённую (не текущую) компанию; её вход отзывается на сервере."""
        with self.op_lock:
            if key == self.state.current_key():
                return
            p = self.state.forget(key)
        if p and p.get("token"):
            try:
                requests.post(str(p.get("server_url") or "").rstrip("/") + "/api/logout", timeout=8,
                              headers={"Authorization": f"Bearer {p['token']}", "User-Agent": f"{APP_NAME}/{VERSION}"})
            except requests.RequestException:
                pass   # не дошло — администратор компании удалит ПК в кабинете

    def _reset_connection(self):
        self.cfg = None
        self.paused = False
        self.server_was_down = False
        self.last_install = 0.0
        self.reinstall_backoff = 60
        self.last_heartbeat = 0.0

    def logout(self):
        with self.op_lock:
            self._logout()

    def _logout(self):
        self.paused = True
        if self.state.get("token"):
            try:
                self.api.logout()   # токен больше не действует, ПК снят с сервера WireGuard
            except (ApiError, ServerUnreachable):
                pass
        self.state.set(token="", join_password="", last_conf_hash="")
        try:
            self.tunnel.uninstall()
        finally:
            if self.state.get("fw_subnet"):
                ensure_firewall(None)
                self.state.set(fw_subnet="")
        self.cfg = None
        self.emit("peers", peers=[])
        self.status(Status.NEED_LOGIN)

    def set_enabled(self, enabled: bool):
        """Кнопка ON/OFF: OFF снимает туннель (и после перезагрузки остаётся выключенным), вход сохраняется."""
        self.state.set(enabled=enabled, last_conf_hash="")
        log.info("пользователь %s сеть", "включил" if enabled else "выключил")
        self.wake.set()

    def force_reconnect(self):
        self.state.set(last_conf_hash="")
        self.wake.set()

    def send_message(self, to: int, text: str) -> str | None:
        """Отправить сообщение ПК своей компании (из потока окна). None — отправлено, иначе текст ошибки."""
        try:
            self.api.send_message(to, text)
        except ApiError as e:
            return e.detail
        except ServerUnreachable:
            return "Сервер недоступен, сообщение не отправлено."
        return None

    # --- внутреннее
    def _register(self, password: str):
        # старый токен забываем до запроса: если ответ потеряется, он не уйдёт на сервер снова
        # (старый токен сервер считает копией входа и отключает ПК)
        self.state.set(token="")
        _, pub = self.state.keypair()
        res = self.api.register(self.state.get("company_login"), password,
                                self.state.get("device_name") or socket.gethostname(), pub)
        # новая регистрация = сервер заново добавил пира: старая сессия WireGuard недействительна,
        # переставляем туннель сразу, а не ждём, пока WireGuard сам заметит (15–180 с)
        self.state.set(token=res.pop("token"), last_conf_hash="")
        self.cfg = res
        log.info("зарегистрирован: %s %s", res["device_name"], res["ip"])

    def run(self):
        while not self.stop_flag:
            try:
                if not self.paused:
                    with self.op_lock:
                        self.step()
            except Exception as e:  # noqa: BLE001
                log.exception("ошибка цикла")
                self.status(Status.ERROR, str(e))
            self.wake.wait(CHECK_EVERY)
            self.wake.clear()

    def step(self):
        if not self.tunnel.installed() and not install_wireguard_if_needed():
            self.status(Status.ERROR, "WireGuard не установлен. Установите WireGuard for Windows.")
            return

        # 0. выключено кнопкой
        if self.state.get("enabled") is False:
            if self.tunnel.service_state() != "missing":
                self.tunnel.uninstall()
            self.emit("peers", peers=[])
            self.status(Status.OFF, "Отключено. Нажмите кнопку, чтобы подключиться.")
            return

        # 1. нет токена -> регистрация (если сохранён пароль) или окно входа
        if not self.state.get("token"):
            password = self.state.get("join_password")
            if not (password and self.state.get("company_login")):
                self.status(Status.NEED_LOGIN)
                return
            try:
                self._register(password)
            except ServerUnreachable:
                self.status(Status.SERVER_DOWN, "Сервер недоступен, ждём…")
                return
            except ApiError as e:
                text = e.detail
                if e.status == 401:
                    self.state.set(join_password="")  # пароль сменили — нужен ввод
                    text = "Пароль компании изменён администратором. Введите новый пароль."
                self.status(Status.NEED_LOGIN, text)
                return

        # 2. спрашиваем у сервера свою конфигурацию
        try:
            self.cfg = self.api.me()
        except ServerUnreachable:
            # туннель НЕ удаляем: как только сервер вернётся, WireGuard сам восстановит связь
            self.server_was_down = True
            self.status(Status.SERVER_DOWN, "Сервер недоступен. Как появится — подключимся.")
            return
        except ApiError as e:
            if e.status == 401:  # устройство удалено или токены сброшены -> регистрируемся заново
                log.info("токен недействителен: %s", e.detail)
                self.state.set(token="")
                self.wake.set()
                return
            if e.status == 403:
                if self.tunnel.service_state() != "missing":
                    self.tunnel.uninstall()
                self.status(Status.BLOCKED, e.detail)
                return
            raise

        try:
            check_cfg(self.cfg)
        except (ValueError, KeyError, TypeError) as e:
            log.error("сервер прислал неверную конфигурацию: %s", e)
            self.cfg = None
            self.status(Status.ERROR, "Сервер прислал неверную конфигурацию — туннель не изменён")
            return
        if self.cfg.get("company") and self.cfg["company"] != self.state.get("company_name"):
            self.state.set(company_name=str(self.cfg["company"])[:100])

        if self.cfg["status"] == "blocked":
            if self.tunnel.service_state() != "missing":
                self.tunnel.uninstall()
            self.status(Status.BLOCKED, "Устройство заблокировано администратором")
            return
        if self.cfg["status"] == "pending":
            self.status(Status.PENDING, "Ожидает одобрения администратора компании")
            return

        # 3. туннель: установлен, актуален, жив?
        priv, _ = self.state.keypair()
        conf = self.tunnel.build_conf(self.cfg, priv)
        conf_hash = hashlib.sha256(conf.encode()).hexdigest()
        svc = self.tunnel.service_state()
        now = time.time()
        hs = self.tunnel.last_handshake() if svc == "running" else 0
        hs_ok = bool(hs) and now - hs < HANDSHAKE_OK
        # «живой» = свежий handshake И реально проходит ping до сервера внутри VPN.
        # Одного handshake мало: после перезагрузки сервера он у клиента ещё «свежий», а сессии уже нет.
        alive = hs_ok and self.tunnel.probe(self.cfg["server_ip"])

        reason = None
        if svc == "missing":
            reason = "туннель не установлен"
        elif conf_hash != self.state.get("last_conf_hash"):
            reason = "конфигурация изменилась"
        elif self.server_was_down and not alive:
            reason = "сервер снова доступен"  # заодно заново резолвим Endpoint (IP сервера мог смениться)
        elif not alive and now - self.last_install > self.reinstall_backoff:
            reason = "нет связи с сервером"

        if reason:
            log.info("переустановка туннеля: %s", reason)
            self.status(Status.CONNECTING, f"Подключение… ({reason})")
            self.tunnel.install(conf)
            self.state.set(last_conf_hash=conf_hash)
            if reason == "нет связи с сервером":
                self.reinstall_backoff = min(self.reinstall_backoff * 2, 600)
            self.last_install = now
            self.server_was_down = False
            self.wake.set()  # быстро проверим ещё раз
            return
        if svc == "stopped":
            self.tunnel.start()

        self.server_was_down = False
        if alive:
            self.reinstall_backoff = 60

        # 4. firewall: общие папки и ping из подсети компании — на каждом ПК
        ports = lan_ports(self.cfg)
        want_fw = f"{self.cfg['subnet']}|{ports}"
        if want_fw != self.state.get("fw_subnet"):
            ensure_firewall(self.cfg["subnet"], ports)
            self.state.set(fw_subnet=want_fw)

        # 5. список компьютеров компании
        try:
            peers = self.api.peers()["peers"]
        except (ApiError, ServerUnreachable):
            peers = []
        peers = [p for p in peers if peer_ip_ok(p.get("ip"), self.cfg["subnet"])]
        self.emit("peers", peers=peers)

        # 6. новые сообщения от других ПК
        try:
            msgs = self.api.messages()["messages"]
            if msgs:
                log.info("сообщений: %d", len(msgs))
                self.emit("messages", messages=msgs)
        except (ApiError, ServerUnreachable):
            pass

        if now - self.last_heartbeat > HEARTBEAT_EVERY:
            try:
                self.api.heartbeat()
                self.last_heartbeat = now
            except (ApiError, ServerUnreachable):
                pass

        if not self.state.get("autostart_done"):
            ensure_autostart()
            self.state.set(autostart_done=True)

        if alive:
            self.status(Status.ONLINE, f"Подключено · {self.cfg['ip']}")
        else:
            self.status(Status.CONNECTING, "Ожидание ответа сервера WireGuard…")


# ====================================================================== GUI (в стиле Radmin VPN)
# Правило: к Tk обращается только главный поток. Фоновые потоки (Worker, трей, диалоги с net use)
# кладут события в очереди, главный поток забирает их в _poll. Вызов Tk из другого потока
# (в т.ч. after()) может «уронить» программу без следа в журнале.

C = {
    "bg": "#0d1117", "panel": "#131a23", "head": "#1a2330", "line": "#232e3d", "sel": "#1d4a74",
    "hover": "#1f2a38", "text": "#e3e9f1", "muted": "#7b889b", "name": "#4fc3f7",
    "on": "#1e8fe0", "off": "#3a4555", "green": "#22c55e", "orange": "#f59e0b", "red": "#ef4444",
    "entry": "#0a0e13",
}


def dark_menu(parent) -> "tk.Menu":
    """Выпадающее меню в цветах приложения."""
    return tk.Menu(parent, tearoff=0, bg=C["head"], fg=C["text"], activebackground=C["sel"],
                   activeforeground="white", disabledforeground=C["muted"], bd=0, relief="flat",
                   font=("Segoe UI", 9))


def dark_titlebar(win) -> None:
    """Тёмный заголовок окна Windows 10/11 (DWM). На других системах ничего не делает."""
    if not WINDOWS:
        return
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        on = ctypes.c_int(1)
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (новые и старые сборки Windows 10)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(on), ctypes.sizeof(on)) == 0:
                break
        r, g, b = (int(C["bg"][i:i + 2], 16) for i in (1, 3, 5))
        color = ctypes.c_int(r | (g << 8) | (b << 16))   # Windows 11: цвет заголовка = цвет окна
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(color), ctypes.sizeof(color))
    except Exception:  # noqa: BLE001
        log.debug("тёмный заголовок недоступен", exc_info=True)


def no_maximize_button(win) -> None:
    """Убрать кнопку «развернуть на весь экран» из заголовка окна Windows."""
    if not WINDOWS:
        return
    try:
        win.update_idletasks()
        u = ctypes.windll.user32
        hwnd = u.GetParent(win.winfo_id())
        style = u.GetWindowLongW(hwnd, -16)                       # GWL_STYLE
        u.SetWindowLongW(hwnd, -16, style & ~0x00010000)          # без WS_MAXIMIZEBOX
        u.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0020)  # NOSIZE|NOMOVE|NOZORDER|FRAMECHANGED
    except Exception:  # noqa: BLE001
        log.debug("кнопку «развернуть» не убрать", exc_info=True)


def render_power(on: bool, hover: bool = False, size: int = 76):
    """Кнопка ON/OFF со сглаживанием (рисуется через Pillow в 4 раза крупнее и уменьшается)."""
    from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageTk
    k = 4
    S = size * k
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    accent = (30, 143, 224) if on else (58, 69, 85)
    if hover:
        accent = tuple(min(255, c + 22) for c in accent)
    if on:  # мягкое свечение вокруг
        glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        ImageDraw.Draw(glow).ellipse((6 * k, 6 * k, S - 6 * k, S - 6 * k), fill=accent + (150,))
        img = Image.alpha_composite(img, glow.filter(ImageFilter.GaussianBlur(5 * k)))
    d = ImageDraw.Draw(img)
    pad = 7 * k
    d.ellipse((pad, pad, S - pad, S - pad), fill=(10, 14, 19, 255), outline=accent + (255,), width=3 * k)
    inner = pad + 6 * k
    top, bottom = tuple(min(255, c + 30) for c in accent), tuple(max(0, c - 25) for c in accent)
    grad = Image.new("RGBA", (S, S), (0, 0, 0, 0))                                        # градиент сверху вниз
    gd = ImageDraw.Draw(grad)
    for i in range(inner, S - inner):
        t = (i - inner) / max(1, S - 2 * inner)
        gd.line((inner, i, S - inner, i), fill=tuple(int(top[j] * (1 - t) + bottom[j] * t) for j in range(3)) + (255,))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).ellipse((inner, inner, S - inner, S - inner), fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)
    white = (255, 255, 255, 255) if on else (170, 182, 198, 255)
    c, r = S // 2, 13 * k
    cy = c - 5 * k
    d.arc((c - r, cy - r, c + r, cy + r), start=300, end=600, fill=white, width=3 * k)    # значок питания
    d.line((c, cy - r - 3 * k, c, cy + 1 * k), fill=white, width=3 * k)
    d.ellipse((c - 1.5 * k, cy - r - 4.5 * k, c + 1.5 * k, cy - r - 1.5 * k), fill=white)
    d.ellipse((c - 1.5 * k, cy - 0.5 * k, c + 1.5 * k, cy + 2.5 * k), fill=white)
    try:
        font = ImageFont.truetype("segoeuib.ttf", 10 * k)
    except OSError:
        try:
            font = ImageFont.truetype("DejaVuSans-Bold.ttf", 10 * k)
        except OSError:
            font = ImageFont.load_default()
    d.text((c, cy + r + 9 * k), "ON" if on else "OFF", fill=white, font=font, anchor="mm")
    return ImageTk.PhotoImage(img.resize((size, size), Image.LANCZOS))

# статус -> (текст плашки, цвет)
STATUS_VIEW = {
    Status.ONLINE: ("В сети", C["green"]),
    Status.CONNECTING: ("Подключение…", C["orange"]),
    Status.SERVER_DOWN: ("Сервер недоступен", C["red"]),
    Status.PENDING: ("Ждёт одобрения", C["orange"]),
    Status.BLOCKED: ("Заблокировано", C["red"]),
    Status.NEED_LOGIN: ("Не подключено", C["off"]),
    Status.ERROR: ("Ошибка", C["red"]),
    Status.OFF: ("Отключено", C["off"]),
}


def natural_key(text: str):
    """«2 касса» раньше «10 касса»."""
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", (text or "").lower())]


def make_signal_image(online: bool) -> "tk.PhotoImage":
    """Значок уровня сигнала, как в Radmin: 4 зелёные полоски или серый крестик."""
    w, h = 18, 14
    img = tk.PhotoImage(width=w, height=h)
    if online:
        for i in range(4):
            bh = 4 + i * 3
            x0 = 1 + i * 4
            img.put(C["green"], to=(x0, h - bh, x0 + 3, h))
    else:
        for i in range(7):
            img.put(C["muted"], to=(5 + i, 4 + i, 7 + i, 6 + i))
            img.put(C["muted"], to=(11 - i, 4 + i, 13 - i, 6 + i))
    return img


def setup_style(root: tk.Tk) -> None:
    st = ttk.Style(root)
    try:
        st.theme_use("clam")
    except tk.TclError:
        pass
    root.configure(bg=C["bg"])
    st.configure(".", background=C["bg"], foreground=C["text"], font=("Segoe UI", 9))
    st.configure("TFrame", background=C["bg"])
    st.configure("TLabel", background=C["bg"], foreground=C["text"])
    st.configure("Muted.TLabel", foreground=C["muted"])
    st.configure("Err.TLabel", foreground=C["red"])
    st.configure("TCheckbutton", background=C["bg"], foreground=C["text"])
    st.map("TCheckbutton", background=[("active", C["bg"])])
    st.configure("TEntry", fieldbackground=C["entry"], foreground=C["text"], insertcolor=C["text"],
                 bordercolor=C["line"], lightcolor=C["line"], darkcolor=C["line"])
    st.configure("TButton", background=C["on"], foreground="white", bordercolor=C["on"], focusthickness=0,
                 padding=(10, 5))
    st.map("TButton", background=[("disabled", C["off"]), ("active", "#3aaef0")])
    st.configure("Hub.Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["text"],
                 rowheight=24, borderwidth=0, font=("Segoe UI", 9))
    st.map("Hub.Treeview", background=[("selected", C["sel"])], foreground=[("selected", "white")])
    st.layout("Hub.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    st.configure("Hub.Vertical.TScrollbar", background=C["line"], troughcolor=C["panel"], bordercolor=C["panel"],
                 arrowcolor=C["muted"], lightcolor=C["line"], darkcolor=C["line"], gripcount=0, arrowsize=12)
    st.map("Hub.Vertical.TScrollbar", background=[("active", C["muted"])])


class LoginDialog(tk.Toplevel):
    def __init__(self, app: "App", error: str = "", add: bool = False):
        super().__init__(app)
        self.app = app
        self.title("Добавить компанию" if add else "Подключение к сети компании")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.transient(app)
        try:
            self.iconbitmap(str(resource_dir() / "app_icon.ico"))
        except Exception:  # noqa: BLE001
            pass
        st = app.state_
        frm = ttk.Frame(self, padding=16)
        frm.pack(fill="both")
        self.vars = {
            "server": tk.StringVar(value=st.get("server_url")),
            "company": tk.StringVar(value="" if add else st.get("company_login")),
            "password": tk.StringVar(),
            "device": tk.StringVar(value=st.get("device_name") or socket.gethostname()),
            "remember": tk.BooleanVar(value=True),
        }
        rows = [("Сервер", "server", ""), ("Логин компании", "company", ""),
                ("Пароль подключения", "password", "•"), ("Имя этого компьютера", "device", "")]
        for i, (label, key, show) in enumerate(rows):
            ttk.Label(frm, text=label).grid(row=i * 2, column=0, sticky="w", pady=(6 if i else 0, 2))
            e = ttk.Entry(frm, textvariable=self.vars[key], width=36, show=show)
            e.grid(row=i * 2 + 1, column=0, sticky="ew")
            if key == ("password" if self.vars["company"].get() else "company"):
                e.focus_set()
        ttk.Checkbutton(frm, text="Запомнить пароль (подключаться автоматически)",
                        variable=self.vars["remember"]).grid(row=8, column=0, sticky="w", pady=(10, 4))
        self.err = ttk.Label(frm, text=error, style="Err.TLabel", wraplength=300)
        self.err.grid(row=9, column=0, sticky="w")
        self.btn = ttk.Button(frm, text="Подключиться", command=self.submit)
        self.btn.grid(row=10, column=0, pady=(10, 0), sticky="ew")
        self.bind("<Return>", lambda _e: self.submit())
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.update_idletasks()   # по центру над главным окном
        x = app.winfo_rootx() + (app.winfo_width() - self.winfo_reqwidth()) // 2
        y = app.winfo_rooty() + 60
        self.geometry(f"+{max(0, x)}+{max(0, y)}")
        dark_titlebar(self)
        self.grab_set()

    def close(self):
        self.app.login_dialog = None
        self.destroy()

    def submit(self):
        v = {k: var.get() for k, var in self.vars.items()}
        if not all(str(v[k]).strip() for k in ("server", "company", "password", "device")):
            self.err.config(text="Заполните все поля")
            return
        self.btn.config(state="disabled", text="Подключение…")

        def work():
            err = self.app.worker.login(v["server"], v["company"], v["password"], v["device"], v["remember"])
            self.app.ui_q.put(("login_done", err))   # результат — главному потоку через очередь
        threading.Thread(target=work, daemon=True, name="login").start()

    def done(self, err):
        if err:
            self.err.config(text=err)
            self.btn.config(state="normal", text="Подключиться")
        else:
            self.close()


class MessageWindow(tk.Toplevel):
    """Переписка с одним компьютером: входящие показываются здесь, отсюда же — ответ."""

    def __init__(self, app: "App", peer: dict):
        super().__init__(app)
        self.app, self.peer = app, peer
        self.title(f"Сообщения — {peer['name']}")
        self.configure(bg=C["bg"])
        self.geometry("380x360")
        self.minsize(300, 240)
        try:
            self.iconbitmap(str(resource_dir() / "app_icon.ico"))
        except Exception:  # noqa: BLE001
            pass
        head = tk.Label(self, text=f"{peer['name']}   {peer.get('ip', '')}", bg=C["head"], fg=C["text"],
                        font=("Segoe UI", 10, "bold"), anchor="w", padx=10, pady=6)
        head.pack(fill="x")
        self.log = tk.Text(self, bg=C["panel"], fg=C["text"], relief="flat", wrap="word", height=10,
                           font=("Segoe UI", 10), padx=8, pady=6, state="disabled", cursor="arrow",
                           highlightthickness=0)
        self.log.tag_configure("me", foreground=C["name"], font=("Segoe UI", 9, "bold"))
        self.log.tag_configure("them", foreground=C["green"], font=("Segoe UI", 9, "bold"))
        self.log.tag_configure("err", foreground=C["red"])
        self.log.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        bottom = tk.Frame(self, bg=C["bg"])
        bottom.pack(fill="x", padx=8, pady=(0, 8))
        self.btn = ttk.Button(bottom, text="Отправить", command=self.send)
        self.btn.pack(side="right", padx=(6, 0), fill="y")
        self.entry = tk.Text(bottom, height=3, bg=C["entry"], fg=C["text"], insertbackground=C["text"],
                             relief="flat", wrap="word", font=("Segoe UI", 10), padx=6, pady=4,
                             highlightthickness=1, highlightbackground=C["line"], highlightcolor=C["on"])
        self.entry.pack(side="left", fill="both", expand=True)
        self.entry.bind("<Return>", self._enter)
        self.entry.focus_set()
        self.protocol("WM_DELETE_WINDOW", self.close)
        dark_titlebar(self)

    def _enter(self, event):
        if event.state & 0x1:  # Shift+Enter — новая строка
            return None
        self.send()
        return "break"

    def add(self, who: str, text: str, ts: float | None = None, tag: str = "them"):
        stamp = time.strftime("%H:%M", time.localtime(ts or time.time()))
        self.log.config(state="normal")
        self.log.insert("end", f"{who}  {stamp}\n", tag)
        self.log.insert("end", text.rstrip() + "\n\n", "err" if tag == "err" else ())
        self.log.config(state="disabled")
        self.log.see("end")

    def send(self):
        text = self.entry.get("1.0", "end").strip()
        if not text:
            return
        self.entry.delete("1.0", "end")
        self.add("Я", text, tag="me")
        peer_id = self.peer["id"]

        def work():
            err = self.app.worker.send_message(peer_id, text)
            if err:
                self.app.ui_q.put(("msg_error", (peer_id, err)))
        threading.Thread(target=work, daemon=True, name="message").start()

    def close(self):
        self.app.chats.pop(self.peer["id"], None)
        self.destroy()


def tray_image(color: str, size: int = 64):
    """Значок трея целиком в цвете статуса: как значок программы (узлы сети), только фон — цвет статуса."""
    from PIL import Image, ImageDraw
    k = 4
    S = size * k
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((2 * k, 2 * k, S - 2 * k, S - 2 * k), radius=14 * k, fill=color)
    c = S // 2
    nodes = [(17 * k, 17 * k), (S - 17 * k, 17 * k), (17 * k, S - 17 * k), (S - 17 * k, S - 17 * k)]
    for n in nodes:
        d.line([(c, c), n], fill="white", width=5 * k)
    for x, y in nodes:
        d.ellipse((x - 7 * k, y - 7 * k, x + 7 * k, y + 7 * k), fill="white")
    d.ellipse((c - 10 * k, c - 10 * k, c + 10 * k, c + 10 * k), fill="white")
    d.ellipse((c - 5 * k, c - 5 * k, c + 5 * k, c + 5 * k), fill=color)
    return img.resize((size, size), Image.LANCZOS)


class Tray:
    """Значок в области уведомлений (pystray, свой поток). Команды — в очередь главного потока."""

    def __init__(self, ui_q: queue.Queue):
        self.ui_q = ui_q
        self.icon = None
        self.images: dict[str, object] = {}
        try:
            import pystray
            from PIL import Image, ImageDraw
        except Exception:  # noqa: BLE001
            log.exception("трей недоступен")
            return
        for key, color in (("green", C["green"]), ("orange", C["orange"]), ("red", C["red"]), ("off", C["red"])):
            self.images[key] = tray_image(color)
        menu = pystray.Menu(
            pystray.MenuItem("Открыть Retix Hub", lambda: self.ui_q.put(("show", None)), default=True),
            pystray.MenuItem("Подключить / отключить", lambda: self.ui_q.put(("toggle", None))),
            pystray.MenuItem("Переподключить", lambda: self.ui_q.put(("reconnect", None))),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Выход (VPN продолжит работать)", lambda: self.ui_q.put(("quit", None))),
        )
        self.icon = pystray.Icon(APP_NAME, self.images["off"], APP_TITLE, menu)
        threading.Thread(target=self._run, daemon=True, name="tray").start()

    def _run(self):
        try:
            self.icon.run()
        except Exception:  # noqa: BLE001
            log.exception("трей остановился")
            self.icon = None

    @property
    def ok(self) -> bool:
        return self.icon is not None

    def update(self, color_key: str, title: str):
        if not self.icon:
            return
        try:
            self.icon.icon = self.images.get(color_key, self.images["off"])
            self.icon.title = title[:127]
        except Exception:  # noqa: BLE001
            log.exception("трей: обновление")

    def notify(self, title: str, text: str):
        if not self.icon:
            return
        try:
            self.icon.notify(text or " ", title)
        except Exception:  # noqa: BLE001
            log.debug("трей: уведомление не показано", exc_info=True)

    def stop(self):
        if self.icon:
            try:
                self.icon.stop()
            except Exception:  # noqa: BLE001
                pass


class App(tk.Tk):
    def __init__(self, state: State, minimized: bool = True, announce: bool = False):
        super().__init__()
        self.report_callback_exception = self._tk_error   # ошибки в обработчиках окна — в журнал
        self.state_ = state
        self.events: queue.Queue = queue.Queue()   # от Worker
        self.ui_q: queue.Queue = queue.Queue()     # от трея, диалогов, второго запуска программы
        self.worker = Worker(state, self.events)
        self.cfg = None
        self.peers: list[dict] = []
        self.login_dialog: LoginDialog | None = None
        self.last_status = None
        self.status_now = None
        self.collapsed = False
        self.chats: dict[int, MessageWindow] = {}

        self.title(APP_TITLE)
        try:
            self.iconbitmap(str(resource_dir() / "app_icon.ico"))
        except Exception:  # noqa: BLE001
            pass
        setup_style(self)
        self.geometry("360x620")
        self.minsize(320, 380)
        self.resizable(False, True)   # только по высоте; кнопки «развернуть» нет (см. no_maximize_button)
        self.img_on, self.img_off = make_signal_image(True), make_signal_image(False)
        self._build()
        self.tray = Tray(self.ui_q)
        # крестик — спрятать в трей (VPN работает дальше); без трея — свернуть
        self.protocol("WM_DELETE_WINDOW", self.hide)
        self.bind("<Unmap>", self._on_unmap)   # кнопка «свернуть» — тоже в трей, а не на панель задач
        if minimized:   # программа запускается в трей; окно — двойным щелчком по значку у часов
            self.after(100, self.hide)
        if announce:    # запустили ярлыком — подсказать, где программа (при автозапуске — молча)
            self.after(1500, lambda: self.tray.notify(
                APP_TITLE, "Retix Hub работает в трее (значок у часов). Двойной щелчок — открыть окно."))
        dark_titlebar(self)
        no_maximize_button(self)
        self.worker.start()
        self.updater = Updater(state, self.worker.api, on_update=lambda ver: self.ui_q.put(("update", ver)))
        self.worker.api.on_hint = self.updater.note_hint
        self.updater.start()
        self.after(200, self._poll)

    # --- журнал ошибок окна
    def _tk_error(self, exc, val, tb):
        log.error("ошибка в окне", exc_info=(exc, val, tb))

    # --- построение окна
    def _build(self):
        # своё меню (системное меню Windows нельзя перекрасить)
        bar = tk.Frame(self, bg=C["bg"])
        bar.pack(fill="x", padx=4, pady=(2, 0))
        m = dark_menu(self)
        m.add_command(label="Подключить / отключить", command=self.toggle)
        m.add_command(label="Переподключить", command=self.worker.force_reconnect)
        m.add_separator()
        m.add_command(label="Добавить компанию…", command=lambda: self.show_login(add=True))
        m.add_command(label="Выйти из сети компании", command=self.logout)
        m.add_separator()
        m.add_command(label="Открыть журнал", command=self.open_log)
        m.add_command(label="Папка журнала", command=lambda: self.open_path(log_dir()))
        m.add_separator()
        m.add_command(label="Выход (VPN продолжит работать)", command=self.quit_app)
        h = dark_menu(self)
        h.add_command(label="Как открыть доступ к папке…", command=self.help_share)
        h.add_command(label="О программе", command=self.about)
        self.company_menu = dark_menu(self)
        self.company_menu.configure(postcommand=self._fill_company_menu)   # список — при каждом открытии
        self._forget_menu = None
        for title, menu in (("Система", m), ("Компания", self.company_menu), ("Справка", h)):
            b = tk.Label(bar, text=title, bg=C["bg"], fg=C["text"], padx=8, pady=3, font=("Segoe UI", 9),
                         cursor="hand2")
            b.pack(side="left")
            b.bind("<Enter>", lambda _e, w=b: w.config(bg=C["hover"]))
            b.bind("<Leave>", lambda _e, w=b: w.config(bg=C["bg"]))
            b.bind("<Button-1>", lambda _e, w=b, mm=menu: mm.tk_popup(w.winfo_rootx(), w.winfo_rooty() + w.winfo_height()))

        # шапка: кнопка ON/OFF, имя ПК, IP, статус
        top = tk.Frame(self, bg=C["panel"], highlightthickness=1, highlightbackground=C["line"])
        top.pack(fill="x", padx=8, pady=(8, 6))
        self.power = tk.Canvas(top, width=76, height=76, bg=C["panel"], highlightthickness=0, cursor="hand2")
        self.power.pack(side="left", padx=8, pady=8)
        self.power.bind("<Button-1>", lambda _e: self.toggle())
        self.power_on, self.power_hover = False, False
        self.power.bind("<Enter>", lambda _e: self._hover_power(True))
        self.power.bind("<Leave>", lambda _e: self._hover_power(False))
        info = tk.Frame(top, bg=C["panel"])
        info.pack(side="left", fill="x", expand=True, pady=10)
        self.name_lbl = tk.Label(info, text=self.state_.get("device_name") or socket.gethostname(), bg=C["panel"],
                                 fg=C["name"], font=("Segoe UI", 12, "bold"), anchor="w")
        self.name_lbl.pack(fill="x")
        self.ip_lbl = tk.Label(info, text="—", bg=C["panel"], fg=C["text"], font=("Segoe UI", 11, "bold"),
                               anchor="w")
        self.ip_lbl.pack(fill="x")
        self.badge = tk.Label(info, text="Запуск…", bg=C["off"], fg="white", font=("Segoe UI", 9, "bold"),
                              padx=8, pady=2)
        self.badge.pack(anchor="w", pady=(4, 0))
        self._draw_power(False)

        # сеть компании: заголовок группы + список компьютеров
        box = tk.Frame(self, bg=C["panel"], highlightthickness=1, highlightbackground=C["line"])
        box.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.group = tk.Frame(box, bg=C["head"], cursor="hand2")
        self.group.pack(fill="x")
        self.group_lbl = tk.Label(self.group, text="▼  —", bg=C["head"], fg=C["text"],
                                  font=("Segoe UI", 10, "bold"), anchor="w", padx=8, pady=4)
        self.group_lbl.pack(side="left", fill="x", expand=True)
        self.count_lbl = tk.Label(self.group, text="", bg=C["head"], fg=C["muted"], padx=8)
        self.count_lbl.pack(side="right")
        for w in (self.group, self.group_lbl, self.count_lbl):
            w.bind("<Button-1>", lambda _e: self.toggle_group())

        self.list_frame = tk.Frame(box, bg=C["panel"])
        self.list_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(self.list_frame, columns=("ip",), show="tree", style="Hub.Treeview",
                                 selectmode="browse")
        self.tree.column("#0", width=200, stretch=True)
        self.tree.column("ip", width=92, stretch=False, anchor="e")
        self.tree.tag_configure("off", foreground=C["muted"])
        sb = ttk.Scrollbar(self.list_frame, orient="vertical", command=self.tree.yview,
                           style="Hub.Vertical.TScrollbar")

        def autohide(first, last):  # полоса прокрутки — только когда список не помещается
            if float(first) <= 0 and float(last) >= 1:
                sb.pack_forget()
            elif not sb.winfo_ismapped():
                sb.pack(side="right", fill="y", before=self.tree)
            sb.set(first, last)
        self.tree.configure(yscrollcommand=autohide)
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda _e: self.open_shares())
        self.tree.bind("<Return>", lambda _e: self.open_shares())
        self.tree.bind("<Button-3>", self.peer_menu)

        self.ctx = dark_menu(self)
        self.ctx.add_command(label="Сообщение", command=self.message)
        self.ctx.add_separator()
        self.ctx.add_command(label="Копировать IP-адрес", command=self.copy_ip)
        self.ctx.add_separator()
        self.ctx.add_command(label="Пинг", command=self.ping)
        self.ctx.add_command(label="Общие папки", command=self.open_shares)
        self.ctx.add_command(label="Подключить сетевой диск…", command=self.map_drive)
        self.ctx.add_separator()
        self.ctx.add_command(label="Полное управление", command=lambda: self.radmin("full"),
                             font=("Segoe UI", 9, "bold"))
        self.ctx.add_command(label="Только просмотр", command=lambda: self.radmin("view"))
        self.ctx.add_command(label="Передача файлов", command=lambda: self.radmin("files"))
        self.ctx.add_command(label="Удалённый рабочий стол (RDP)", command=self.remote_desktop)
        self.ctx.add_separator()
        self.ctx.add_command(label="Свойства", command=self.properties)

        self.msg_lbl = tk.Label(self, text="", bg=C["bg"], fg=C["muted"], anchor="w", justify="left",
                                wraplength=330, padx=10)
        self.msg_lbl.pack(fill="x", pady=(0, 6))
        self.bind("<Configure>", lambda e: self.msg_lbl.config(wraplength=max(200, e.width - 20))
                  if e.widget is self else None)

    def _hover_power(self, hover: bool):
        self.power_hover = hover
        self._draw_power(self.power_on)

    def _draw_power(self, on: bool):
        self.power_on = on
        cv = self.power
        cv.delete("all")
        try:
            self._power_img = render_power(on, self.power_hover)   # ссылку держим, иначе картинку удалит сборщик
            cv.create_image(38, 38, image=self._power_img)
            return
        except Exception:  # noqa: BLE001 — без Pillow рисуем попроще
            log.debug("кнопка через Pillow не нарисована", exc_info=True)
        color = C["on"] if on else C["off"]
        cv.create_oval(3, 3, 69, 69, fill="#dfe7f0", outline="")
        cv.create_oval(9, 9, 63, 63, fill=color, outline="")
        # значок питания
        cv.create_arc(22, 18, 50, 46, start=120, extent=300, style="arc", outline="white", width=3)
        cv.create_line(36, 14, 36, 31, fill="white", width=3, capstyle="round")
        cv.create_text(36, 54, text="ON" if on else "OFF", fill="white", font=("Segoe UI", 9, "bold"))

    # --- события
    def _poll(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "status":
                    self._on_status(**data)
                elif kind == "peers":
                    self._on_peers(data["peers"])
                elif kind == "messages":
                    self._on_messages(data["messages"])
        except queue.Empty:
            pass
        try:
            while True:
                kind, data = self.ui_q.get_nowait()
                self._on_ui(kind, data)
        except queue.Empty:
            pass
        self.after(250, self._poll)

    def _on_ui(self, kind, data):
        if kind == "show":
            self.show()
        elif kind == "toggle":
            self.toggle()
        elif kind == "reconnect":
            self.worker.force_reconnect()
        elif kind == "quit":
            self.quit_app()
        elif kind == "update":
            # установщик уже запущен: закрываемся, он поставит новую версию и запустит её
            self.tray.notify(APP_TITLE, f"Обновление до версии {data}…")
            self.after(800, self.quit_app)
        elif kind == "login_done":
            if self.login_dialog:
                self.login_dialog.done(data)
        elif kind == "info":
            messagebox.showinfo(APP_TITLE, data, parent=self)
        elif kind == "error":
            messagebox.showerror(APP_TITLE, data, parent=self)
        elif kind == "msg_error":
            peer_id, err = data
            if peer_id in self.chats:
                self.chats[peer_id].add("Не отправлено", err, tag="err")

    def _on_status(self, status, text, cfg):
        self.status_now = status
        if cfg:
            self.cfg = cfg
        label, color = STATUS_VIEW.get(status, ("—", C["off"]))
        self.badge.config(text=label, bg=color)
        enabled = self.state_.get("enabled") is not False and status not in (Status.NEED_LOGIN, Status.OFF)
        self._draw_power(enabled)
        c = self.cfg
        if c and status != Status.NEED_LOGIN:
            self.name_lbl.config(text=c.get("device_name") or socket.gethostname())
            self.ip_lbl.config(text=c.get("ip") or "—")
            hidden = c.get("show_peers") is False   # администратор скрыл список (сеть при этом та же)
            self.group_lbl.config(text=("▶  " if self.collapsed else "▼  ") + (c.get("company") or "—")
                                  + ("  · список скрыт администратором" if hidden else ""))
        elif status == Status.NEED_LOGIN:
            self.ip_lbl.config(text="—")
            self.group_lbl.config(text="▼  —")
        self.msg_lbl.config(text="" if status == Status.ONLINE else (text or ""))
        # значок в трее: зелёный — в сети, жёлтый — подключается, красный — VPN не работает (выключен, нет входа,
        # сервер недоступен, блок, ошибка)
        tray_color = {C["green"]: "green", C["orange"]: "orange"}.get(color, "red")
        ip = (c or {}).get("ip", "")
        self.tray.update(tray_color, f"{APP_TITLE} — {label}" + (f" · {ip}" if ip and status == Status.ONLINE else ""))
        if status == Status.NEED_LOGIN and self.last_status != Status.NEED_LOGIN and not self.login_dialog:
            self.show_login(text)
        if status in (Status.SERVER_DOWN, Status.BLOCKED):
            for i in self.tree.get_children():
                self.tree.item(i, image=self.img_off, tags=("off",))
        self.last_status = status

    def _on_peers(self, peers):
        self.peers = peers
        sel = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        others = [p for p in peers if not p.get("is_me")]
        others.sort(key=lambda p: (not p["online"], natural_key(p["name"])))
        for p in others:
            online = p["online"] and self.status_now not in (Status.SERVER_DOWN, Status.BLOCKED, Status.OFF)
            self.tree.insert("", "end", iid=str(p["id"]), text=" " + p["name"],
                             image=self.img_on if online else self.img_off,
                             values=(p["ip"],), tags=() if online else ("off",))
        if sel and self.tree.exists(sel[0]):
            self.tree.selection_set(sel[0])
        online = sum(1 for p in others if p["online"])
        self.count_lbl.config(text=f"{online} / {len(others)}" if others else "")

    # --- окно и трей
    def show(self):
        self.deiconify()
        self.lift()
        try:
            self.attributes("-topmost", True)
            self.after(200, lambda: self.attributes("-topmost", False))
            self.focus_force()
        except tk.TclError:
            pass

    def _on_unmap(self, event):
        if event.widget is self and self.tray.ok:
            self.after(10, lambda: self.state() == "iconic" and self.withdraw())

    def hide(self):
        if self.tray.ok:
            self.withdraw()
        else:
            self.iconify()

    def toggle_group(self):
        self.collapsed = not self.collapsed
        if self.collapsed:
            self.list_frame.pack_forget()
        else:
            self.list_frame.pack(fill="both", expand=True)
        txt = self.group_lbl.cget("text")[3:]
        self.group_lbl.config(text=("▶  " if self.collapsed else "▼  ") + txt)

    # --- действия
    def toggle(self):
        if self.status_now == Status.NEED_LOGIN:
            self.show_login()
            return
        enabled = self.state_.get("enabled") is not False
        self._draw_power(not enabled)
        self.badge.config(text="Отключение…" if enabled else "Подключение…", bg=C["orange"])
        threading.Thread(target=self.worker.set_enabled, args=(not enabled,), daemon=True, name="toggle").start()

    def show_login(self, error: str = "", add: bool = False):
        if self.login_dialog:
            self.login_dialog.lift()
            return
        self.show()
        self.login_dialog = LoginDialog(self, error, add=add)

    # --- несколько компаний: в сети — одна, остальные сохранены (вход и ключ)
    @staticmethod
    def _company_title(p: dict) -> str:
        return p.get("company_name") or p.get("company_login") or "—"

    def _fill_company_menu(self):
        m = self.company_menu
        m.delete(0, "end")
        if self._forget_menu is not None:
            self._forget_menu.destroy()
            self._forget_menu = None
        profiles = self.state_.profiles()
        for p in profiles:
            title = self._company_title(p)
            if p["active"]:
                m.add_command(label=f"●  {title}  (сейчас)", state="disabled")
            else:
                m.add_command(label=f"     {title}", command=lambda k=p["key"], t=title: self.switch_company(k, t))
        if profiles:
            m.add_separator()
        m.add_command(label="Добавить компанию…", command=lambda: self.show_login(add=True))
        others = [p for p in profiles if not p["active"]]
        if others:
            self._forget_menu = dark_menu(m)
            for p in others:
                title = self._company_title(p)
                self._forget_menu.add_command(label=title, command=lambda k=p["key"], t=title: self.forget_company(k, t))
            m.add_cascade(label="Убрать из списка", menu=self._forget_menu)

    def switch_company(self, key: str, title: str):
        if not messagebox.askyesno(APP_TITLE, f"Переключиться на «{title}»?\n\n"
                                              "Сеть текущей компании отключится — компьютер будет в сети выбранной. "
                                              "Вернуться можно так же, через меню «Компания».", parent=self):
            return
        for win in list(self.chats.values()):   # переписка — с ПК прежней компании
            win.close()

        def work():
            err = self.worker.switch_to(key)
            if err:
                self.ui_q.put(("error", err))
        threading.Thread(target=work, daemon=True, name="switch").start()

    def forget_company(self, key: str, title: str):
        if not messagebox.askyesno(APP_TITLE, f"Убрать «{title}» из списка?\n\n"
                                              "Вход этого ПК в эту компанию будет отозван. Чтобы вернуться, "
                                              "понадобится пароль подключения компании.", parent=self):
            return
        threading.Thread(target=lambda: self.worker.forget_company(key), daemon=True, name="forget").start()

    def selected_peer(self) -> dict | None:
        sel = self.tree.selection()
        if not sel:
            return None
        return next((p for p in self.peers if str(p["id"]) == sel[0]), None)

    def peer_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        try:
            self.ctx.tk_popup(event.x_root, event.y_root)
        finally:
            self.ctx.grab_release()

    def open_path(self, path):
        try:
            os.startfile(str(path))
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Не удалось открыть {path}\n{e}", parent=self)

    def open_log(self):
        path = log_dir() / "client.log"
        self.open_path(path if path.exists() else log_dir())

    def open_shares(self):
        p = self.selected_peer()
        if not p:
            return
        if not p["online"]:
            messagebox.showinfo(APP_TITLE, f"{p['name']} сейчас не в сети.", parent=self)
            return
        path = rf"\\{p['ip']}"

        def work():  # проверка и Проводник могут думать несколько секунд — не держим окно
            problem = smb_check(p["ip"])
            if problem:
                self.ui_q.put(("error", f"Общие папки {p['name']} ({path}) не открываются.\n\n{problem}"))
                return
            try:
                os.startfile(path)
            except OSError as e:
                # str(e) показывает путь как '\\\\10.66…' — берём только текст ошибки Windows
                self.ui_q.put(("error", f"Не удалось открыть {path}\n{e.strerror or e}\n\n"
                                        f"Проверьте, что на {p['name']} открыт общий доступ к папке "
                                        "(Справка → Как открыть доступ к папке)."))
        threading.Thread(target=work, daemon=True, name="open").start()

    def ping(self):
        p = self.selected_peer()
        if p and WINDOWS:
            # без cmd: имя ПК задаёт пользователь, в «cmd /k …» символы & | выполнились бы как команды
            subprocess.Popen(["ping", "-t", str(_ipv4(p["ip"]))], creationflags=subprocess.CREATE_NEW_CONSOLE)

    def _on_messages(self, msgs):
        for m in msgs:
            peer = next((p for p in self.peers if p["id"] == m["from_id"]), None) or \
                {"id": m["from_id"] or -m["id"], "name": m["from_name"], "ip": m["from_ip"]}
            win = self.open_chat(peer)
            win.add(peer["name"], m["text"], m["time"])
        if msgs:
            # окно сообщения — поверх всех, чтобы его увидели (даже если программа в трее)
            last = msgs[-1]
            win = self.chats.get(last["from_id"])
            if win:
                win.deiconify()
                win.lift()
                win.attributes("-topmost", True)
                win.after(1500, lambda w=win: w.winfo_exists() and w.attributes("-topmost", False))
                if WINDOWS:
                    win.bell()
            self.tray.notify(f"Сообщение от {last['from_name']}", last["text"][:200])

    def open_chat(self, peer: dict) -> "MessageWindow":
        win = self.chats.get(peer["id"])
        if not win or not win.winfo_exists():
            win = MessageWindow(self, peer)
            self.chats[peer["id"]] = win
        return win

    def message(self):
        p = self.selected_peer()
        if p:
            win = self.open_chat(p)
            win.deiconify()
            win.lift()
            win.entry.focus_set()

    def radmin(self, mode: str):
        """Radmin Viewer -> Radmin Server на выбранном ПК (порт 4899) через сеть Retix Hub."""
        p = self.selected_peer()
        if not p:
            return
        exe = find_radmin_viewer(self.state_.get("radmin_path") or "")
        if not exe:
            if not messagebox.askyesno(APP_TITLE, "Radmin Viewer не найден.\n\nУкажите файл Radmin.exe вручную?\n"
                                                  "(Скачать Radmin Viewer: https://www.radmin.ru/download/)",
                                       parent=self):
                return
            from tkinter import filedialog
            path = filedialog.askopenfilename(parent=self, title="Где Radmin.exe (Radmin Viewer)?",
                                              filetypes=[("Radmin Viewer", "Radmin.exe"), ("Программы", "*.exe")])
            if not path:
                return
            exe = Path(path)
            self.state_.set(radmin_path=str(exe))
        port = int((self.cfg or {}).get("radmin_port") or RADMIN_PORT)
        args = radmin_args(exe, p["ip"], mode, port)

        def work():  # проверка порта до 3 с — не держим окно
            if not port_open(p["ip"], port):
                self.ui_q.put(("error", f"Radmin Server на {p['name']} ({p['ip']}:{port}) не отвечает.\n\n"
                                        "• на том ПК не установлен или не запущен Radmin Server;\n"
                                        "• на том ПК старая версия Retix Hub (обновите — она открывает порт 4899);\n"
                                        "• сервер Retix Hub не обновлён (git pull && ./run.sh)."))
                return
            log.info("Radmin Viewer: %s", " ".join(args))
            try:
                subprocess.Popen(args, cwd=str(exe.parent))
            except OSError as e:
                self.ui_q.put(("error", f"Не удалось запустить Radmin Viewer\n{e.strerror or e}"))
        threading.Thread(target=work, daemon=True, name="radmin").start()

    def remote_desktop(self):
        """Удалённый рабочий стол Windows (RDP). На том ПК он должен быть включён (Windows Pro),
        а в кабинете компании открыт порт 3389 (или «любой трафик между ПК»)."""
        p = self.selected_peer()
        if not p:
            return
        if WINDOWS:
            subprocess.Popen(["mstsc", f"/v:{p['ip']}"])

    def properties(self):
        p = self.selected_peer()
        if not p:
            return
        hs = p.get("last_handshake") or 0
        seen = time.strftime("%d.%m.%Y %H:%M", time.localtime(hs)) if hs else "—"
        messagebox.showinfo(f"Свойства — {p['name']}", "\n".join([
            f"Имя:  {p['name']}",
            f"Компьютер:  {p.get('hostname') or '—'}",
            f"IP-адрес:  {p['ip']}",
            f"Статус:  {'в сети' if p['online'] else 'не в сети'}",
            f"Последняя связь:  {seen}",
            f"Версия Retix Hub:  {p.get('client_version') or '—'}",
            "",
            f"Общие папки:  \\\\{p['ip']}",
            f"Radmin:  {p['ip']}:{(self.cfg or {}).get('radmin_port') or RADMIN_PORT}",
        ]), parent=self)

    def copy_ip(self):
        p = self.selected_peer()
        if p:
            self.clipboard_clear()
            self.clipboard_append(p["ip"])

    def map_drive(self):
        p = self.selected_peer()
        if not p:
            return
        path = simpledialog.askstring(APP_TITLE, f"Общая папка на {p['name']}:\n(например \\\\{p['ip']}\\share)",
                                      initialvalue=rf"\\{p['ip']}" + "\\", parent=self)
        if not path or not re.match(r"^\\\\[^\\]+\\[^\\]+", path.strip()):
            return
        path = path.strip().rstrip("\\")
        letter = simpledialog.askstring(APP_TITLE, "Буква диска:", initialvalue="Z", parent=self)
        if not letter or not letter.strip()[:1].isalpha():
            return
        letter = letter.strip()[:1].upper() + ":"
        user = simpledialog.askstring(APP_TITLE, f"Логин для {path}\n(например {p['hostname'] or 'pc1'}\\user;"
                                                 " пусто — без логина):", parent=self) or ""
        pwd = simpledialog.askstring(APP_TITLE, "Пароль:", show="•", parent=self) if user else ""
        host = path.split("\\")[2]

        def work():
            if user:
                # cmdkey хранит пароль в диспетчере учётных данных — Проводник им тоже пользуется
                run(["cmdkey", f"/add:{host}", f"/user:{user}", f"/pass:{pwd}"])
            # чтобы диск из программы-админа был виден обычному Проводнику
            run(["reg", "add", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                 "/v", "EnableLinkedConnections", "/t", "REG_DWORD", "/d", "1", "/f"])
            run(["net", "use", letter, "/delete", "/y"])
            rc, out = run(["net", "use", letter, path, "/persistent:yes"])
            if rc == 0:
                self.ui_q.put(("info", f"Диск {letter} подключён к {path}.\nЕсли диск не виден в Проводнике — "
                                       "выйдите из Windows и зайдите снова (один раз)."))
            else:
                self.ui_q.put(("error", out.strip() or "Ошибка net use"))
        threading.Thread(target=work, daemon=True, name="net-use").start()

    def logout(self):
        if not messagebox.askyesno(APP_TITLE, "Отключить этот компьютер от сети компании?\n"
                                              "Для повторного входа понадобится пароль подключения.", parent=self):
            return
        threading.Thread(target=self.worker.logout, daemon=True, name="logout").start()

    def help_share(self):
        messagebox.showinfo(APP_TITLE, (
            "Компьютеры компании видят общие папки друг друга, как в локальной сети.\n\n"
            "Чтобы открыть папку другим:\n"
            "1. Правый щелчок по папке → Свойства → Доступ → Расширенная настройка.\n"
            "2. «Открыть общий доступ к этой папке» → Разрешения → выбрать, кому и что можно.\n\n"
            "Открыть папки соседа: двойной щелчок по нему в списке.\n"
            "Если Windows спрашивает логин — это пользователь и пароль Windows того компьютера."), parent=self)

    def about(self):
        messagebox.showinfo(APP_TITLE, f"{APP_TITLE} {VERSION}\n\nСервер: {self.state_.get('server_url')}\n"
                                       f"Журнал: {log_dir() / 'client.log'}", parent=self)

    def quit_app(self):
        log.info("выход из программы (VPN продолжает работать)")
        self.worker.stop_flag = True
        self.updater.stop_event.set()
        self.tray.stop()
        self.destroy()


# ====================================================================== main

def relaunch_as_admin():
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    exe = sys.executable
    if not getattr(sys, "frozen", False):
        params = f'"{os.path.abspath(__file__)}" {params}'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)


SHOW_EVENT = "Global\\RetixHubShowWindow"   # второй запуск программы просит первую показать окно


def _k32():
    from ctypes import wintypes as wt
    k = ctypes.windll.kernel32
    k.OpenEventW.restype = wt.HANDLE
    k.OpenEventW.argtypes = (wt.DWORD, wt.BOOL, wt.LPCWSTR)
    k.CreateEventW.restype = wt.HANDLE
    k.CreateEventW.argtypes = (ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR)
    k.SetEvent.argtypes = (wt.HANDLE,)
    k.CloseHandle.argtypes = (wt.HANDLE,)
    k.WaitForSingleObject.argtypes = (wt.HANDLE, wt.DWORD)
    k.WaitForSingleObject.restype = wt.DWORD
    return k


def signal_running_instance() -> bool:
    """Программа уже запущена? Тогда показать её окно и выйти (без лишнего окна UAC)."""
    if not WINDOWS:
        return False
    k = _k32()
    h = k.OpenEventW(0x0002 | 0x00100000, False, SHOW_EVENT)   # EVENT_MODIFY_STATE | SYNCHRONIZE
    if not h:
        return False
    k.SetEvent(h)
    k.CloseHandle(h)
    return True


def create_show_event():
    """Событие «показать окно»: открыть его может любой пользователь (программа работает как админ)."""
    from ctypes import wintypes as wt
    k = _k32()

    class SA(ctypes.Structure):
        _fields_ = [("nLength", wt.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wt.BOOL)]
    sd = ctypes.c_void_p()
    ok = ctypes.windll.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100002;;;AU)", 1, ctypes.byref(sd), None)
    sa = SA(ctypes.sizeof(SA), sd if ok else None, False)
    return k.CreateEventW(ctypes.byref(sa), False, False, SHOW_EVENT)


def watch_show_event(handle, ui_q: queue.Queue):
    k = _k32()

    def loop():
        while True:
            if k.WaitForSingleObject(handle, 1000) == 0:
                ui_q.put(("show", None))
    threading.Thread(target=loop, daemon=True, name="show-event").start()


_crash_file = None


def setup_logging() -> None:
    """Журнал в <папка программы>\\logs: client.log (обычный) и crash.log (аварийные падения)."""
    global _crash_file
    d = log_dir()
    handlers: list[logging.Handler] = []
    try:
        d.mkdir(parents=True, exist_ok=True)
        handlers.append(RotatingFileHandler(d / "client.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"))
        _crash_file = open(d / "crash.log", "a", encoding="utf-8")  # noqa: SIM115 — открыт всё время работы
        _crash_file.write(f"--- {time.strftime('%Y-%m-%d %H:%M:%S')} запуск {VERSION}, pid {os.getpid()}\n")
        _crash_file.flush()
        faulthandler.enable(_crash_file)   # падение интерпретатора/Tk — трассировка в crash.log
    except OSError:
        pass
    if sys.stderr:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.INFO, handlers=handlers, format="%(asctime)s %(levelname)s %(threadName)s %(message)s")

    sys.excepthook = lambda t, v, tb: log.critical("необработанная ошибка", exc_info=(t, v, tb))
    threading.excepthook = lambda a: log.critical(
        "ошибка в потоке %s", a.thread.name if a.thread else "?", exc_info=(a.exc_type, a.exc_value, a.exc_traceback))


def single_instance() -> bool:
    if not WINDOWS:
        return True
    ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\RetixHubClientMutex")
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


SELFTEST_FILE = "retixhub_selftest.txt"


def selftest() -> int:
    """retixhub.exe --selftest: проверка собранного exe (build.bat запускает её после сборки).
    Ничего не меняет в системе и прав администратора не просит. Отчёт — retixhub_selftest.txt рядом с exe."""
    import ssl
    lines, ok = [f"{APP_TITLE} {VERSION} self-test", f"python {sys.version.split()[0]}, frozen={getattr(sys, 'frozen', False)}"], True

    def check(name, fn):
        nonlocal ok
        try:
            lines.append(f"OK    {name}: {fn() or ''}".rstrip(": "))
        except Exception as e:  # noqa: BLE001
            ok = False
            lines.append(f"FAIL  {name}: {type(e).__name__}: {e}")

    def tk_check():
        root = tk.Tk()
        root.withdraw()
        setup_style(root)
        make_signal_image(True)
        version = root.tk.call("info", "patchlevel")
        root.destroy()
        return f"Tcl/Tk {version}"

    def crypto_check():
        key = X25519PrivateKey.generate()
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if len(pub) != 32:
            raise ValueError(f"длина ключа {len(pub)}")
        return "x25519"

    def ssl_check():
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
        return f"{ssl.OPENSSL_VERSION}, CA: {len(ctx.get_ca_certs())}"

    def tray_check():
        import PIL
        import pystray
        from PIL import Image
        Image.open(resource_dir() / "app_icon.ico").convert("RGBA")
        return f"pystray ({pystray.Icon.__module__}), Pillow {PIL.__version__}"

    def icon_check():
        path = resource_dir() / "app_icon.ico"
        if not path.exists():
            raise FileNotFoundError(path)
        return path.name

    check("Tcl/Tk", tk_check)
    check("cryptography", crypto_check)
    check("SSL", ssl_check)
    check("requests", lambda: requests.__version__)
    check("tray", tray_check)
    check("server_url", lambda: State._default_server())
    check("icon", icon_check)
    lines.append("RESULT: " + ("OK" if ok else "FAIL"))
    try:
        (app_dir() / SELFTEST_FILE).write_text("\n".join(lines) + "\n", "utf-8")
    except OSError:
        pass
    print("\n".join(lines))
    return 0 if ok else 1


def uninstall_cleanup() -> int:
    """retixhub.exe --uninstall: вызывает деинсталлятор. Снимает туннель, правила firewall и автозапуск.
    WireGuard и %ProgramData%\\RetixHub (ключ и вход) остаются — при повторной установке
    ПК вернётся в сеть сам."""
    for step in (Tunnel.uninstall, lambda: ensure_firewall(None), remove_autostart):
        try:
            step()
        except Exception:  # noqa: BLE001
            log.exception("uninstall")
    state = State()
    state.set(last_conf_hash="", fw_subnet="", autostart_done=False)
    return 0


def main():
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    uninstall = "--uninstall" in sys.argv
    # уже запущена — показать окно; до UAC, чтобы не спрашивать права зря
    if not uninstall and signal_running_instance():
        return
    if WINDOWS and not is_admin():
        relaunch_as_admin()
        return
    secure_data_dir()
    setup_logging()
    if uninstall:
        log.info("удаление программы: очистка")
        sys.exit(uninstall_cleanup())
    if not single_instance():
        signal_running_instance()
        return
    log.info("старт %s (%s)", VERSION, " ".join(sys.argv[1:]) or "без параметров")
    show_event = create_show_event() if WINDOWS else None
    # всегда в трей (окно — из трея); --show — открыть окно сразу. Нужен вход — окно входа покажется само.
    app = App(State(), minimized="--show" not in sys.argv, announce="--minimized" not in sys.argv)
    if show_event:
        watch_show_event(show_event, app.ui_q)
    try:
        app.mainloop()
    finally:
        log.info("окно закрыто")


if __name__ == "__main__":
    main()
