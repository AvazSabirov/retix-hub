"""
Retix Hub — клиент для Windows (окно, значок в трее).

* регистрируется на сервере по логину/паролю компании (ключ генерируется локально);
* ставит туннель через официальный WireGuard for Windows (служба WireGuardTunnel$retixhub);
* следит за сервером: если сервер пропал — ждёт, когда появится — переподключается;
* показывает компьютеры компании (online/offline), открывает их общие папки (\\\\10.66.x.y),
  подключает сетевой диск; файл hosts не трогает;
* открывает в firewall Windows общие папки (SMB) и ping из подсети компании.

Работает с правами администратора (перезапускает себя через UAC).
Журнал: <папка программы>\\logs\\client.log, аварийные падения — logs\\crash.log.
"""
import base64
import faulthandler
import ctypes
import hashlib
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

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

VERSION = "1.0.1"
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
FW_RULE = "RetixHub SMB"          # входящие общие папки (SMB) из подсети компании
FW_RULE_PING = "RetixHub Ping"    # входящий ping из подсети компании

CHECK_EVERY = 8          # сек — основной цикл
HANDSHAKE_OK = 180       # сек — handshake свежее этого = туннель жив
HEARTBEAT_EVERY = 60

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
    """Настройки клиента в %ProgramData%\\RetixHub\\state.json (доступ только админам/SYSTEM)."""

    FIELDS = {"server_url": "", "company_login": "", "device_name": "", "token": "",
              "private_key": "", "join_password": "", "last_conf_hash": "", "fw_subnet": "",
              "autostart_done": False, "enabled": True}

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

    def _req(self, method: str, path: str, auth: bool = True, **kw):
        url = self.state.get("server_url").rstrip("/") + path
        headers = {"Authorization": f"Bearer {self.state.get('token')}"} if auth else {}
        try:
            r = self.http.request(method, url, headers=headers, timeout=8, **kw)
        except requests.RequestException as e:
            raise ServerUnreachable(str(e)) from e
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


def ensure_autostart() -> None:
    if not getattr(sys, "frozen", False):
        return
    run(["schtasks", "/Create", "/TN", APP_NAME, "/TR", f'"{sys.executable}" --minimized',
         "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"])


def remove_autostart() -> None:
    run(["schtasks", "/Delete", "/TN", APP_NAME, "/F"])


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

    # --- связь с GUI
    def emit(self, kind: str, **data):
        self.events.put((kind, data))

    def status(self, status: str, text: str = ""):
        self.emit("status", status=status, text=text, cfg=self.cfg)

    # --- команды из GUI (вызываются в отдельном потоке)
    def login(self, server: str, company: str, password: str, device: str, remember: bool):
        self.state.set(server_url=server.strip().rstrip("/"), company_login=company.strip(),
                       device_name=device.strip())
        try:
            self._register(password)
        except ApiError as e:
            return e.detail
        except ServerUnreachable:
            return "Сервер недоступен. Проверьте адрес и интернет."
        self.state.set(join_password=password if remember else "", enabled=True)
        self.paused = False
        self.wake.set()
        return None

    def logout(self):
        self.paused = True
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
        ports = self.cfg.get("share_ports") or "445"
        want_fw = f"{self.cfg['subnet']}|{ports}"
        if want_fw != self.state.get("fw_subnet"):
            ensure_firewall(self.cfg["subnet"], ports)
            self.state.set(fw_subnet=want_fw)

        # 5. список компьютеров компании
        try:
            peers = self.api.peers()["peers"]
        except (ApiError, ServerUnreachable):
            peers = []
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


# ====================================================================== GUI
# Правило: к Tk обращается только главный поток. Фоновые потоки (Worker, трей, диалоги с net use)
# кладут события в очереди, главный поток забирает их в _poll. Вызов Tk из другого потока
# (в т.ч. after()) может «уронить» программу без следа в журнале.

C = {
    "bg": "#1b2431", "panel": "#232f3f", "head": "#2c3a4e", "line": "#334257", "sel": "#2f5d8a",
    "text": "#e6ebf2", "muted": "#8fa0b5", "name": "#5cc8f5",
    "on": "#2b9bd8", "off": "#5b6778", "green": "#22c55e", "orange": "#f59e0b", "red": "#ef4444",
    "entry": "#141b26",
}

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
    """Значок уровня сигнала: 4 зелёные полоски или серый крестик."""
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
    def __init__(self, app: "App", error: str = ""):
        super().__init__(app)
        self.app = app
        self.title("Подключение к сети компании")
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
            "company": tk.StringVar(value=st.get("company_login")),
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
        try:
            base = Image.open(resource_dir() / "app_icon.ico").convert("RGBA").resize((64, 64))
        except Exception:  # noqa: BLE001
            base = Image.new("RGBA", (64, 64), C["on"])
        for key, color in (("green", C["green"]), ("orange", C["orange"]), ("red", C["red"]), ("off", C["off"])):
            img = base.copy()
            d = ImageDraw.Draw(img)
            d.ellipse((38, 38, 63, 63), fill=color, outline="white", width=3)
            self.images[key] = img
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
    def __init__(self, state: State, minimized: bool):
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
        self.img_on, self.img_off = make_signal_image(True), make_signal_image(False)
        self._build()
        self.tray = Tray(self.ui_q)
        # крестик — спрятать в трей (VPN работает дальше); без трея — свернуть
        self.protocol("WM_DELETE_WINDOW", self.hide)
        if minimized:
            self.after(100, self.hide)
        self.worker.start()
        self.after(200, self._poll)

    # --- журнал ошибок окна
    def _tk_error(self, exc, val, tb):
        log.error("ошибка в окне", exc_info=(exc, val, tb))

    # --- построение окна
    def _build(self):
        menu = tk.Menu(self)
        m = tk.Menu(menu, tearoff=0)
        m.add_command(label="Подключить / отключить", command=self.toggle)
        m.add_command(label="Переподключить", command=self.worker.force_reconnect)
        m.add_separator()
        m.add_command(label="Войти в другую компанию…", command=self.show_login)
        m.add_command(label="Выйти из сети компании", command=self.logout)
        m.add_separator()
        m.add_command(label="Открыть журнал", command=self.open_log)
        m.add_command(label="Папка журнала", command=lambda: self.open_path(log_dir()))
        m.add_separator()
        m.add_command(label="Выход (VPN продолжит работать)", command=self.quit_app)
        menu.add_cascade(label="Система", menu=m)
        h = tk.Menu(menu, tearoff=0)
        h.add_command(label="Как открыть доступ к папке…", command=self.help_share)
        h.add_command(label="О программе", command=self.about)
        menu.add_cascade(label="Справка", menu=h)
        self.config(menu=menu)

        # шапка: кнопка ON/OFF, имя ПК, IP, статус
        top = tk.Frame(self, bg=C["panel"], highlightthickness=1, highlightbackground=C["line"])
        top.pack(fill="x", padx=8, pady=(8, 6))
        self.power = tk.Canvas(top, width=72, height=72, bg=C["panel"], highlightthickness=0, cursor="hand2")
        self.power.pack(side="left", padx=10, pady=10)
        self.power.bind("<Button-1>", lambda _e: self.toggle())
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

        self.ctx = tk.Menu(self, tearoff=0)
        self.ctx.add_command(label="Сообщение", command=self.message)
        self.ctx.add_separator()
        self.ctx.add_command(label="Копировать IP-адрес", command=self.copy_ip)
        self.ctx.add_separator()
        self.ctx.add_command(label="Пинг", command=self.ping)
        self.ctx.add_command(label="Общие папки", command=self.open_shares, font=("Segoe UI", 9, "bold"))
        self.ctx.add_command(label="Подключить сетевой диск…", command=self.map_drive)
        self.ctx.add_command(label="Удалённый рабочий стол", command=self.remote_desktop)
        self.ctx.add_separator()
        self.ctx.add_command(label="Свойства", command=self.properties)

        self.msg_lbl = tk.Label(self, text="", bg=C["bg"], fg=C["muted"], anchor="w", justify="left",
                                wraplength=330, padx=10)
        self.msg_lbl.pack(fill="x", pady=(0, 6))
        self.bind("<Configure>", lambda e: self.msg_lbl.config(wraplength=max(200, e.width - 20))
                  if e.widget is self else None)

    def _draw_power(self, on: bool):
        cv = self.power
        cv.delete("all")
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
            self.group_lbl.config(text=("▶  " if self.collapsed else "▼  ") + (c.get("company") or "—"))
        elif status == Status.NEED_LOGIN:
            self.ip_lbl.config(text="—")
            self.group_lbl.config(text="▼  —")
        self.msg_lbl.config(text="" if status == Status.ONLINE else (text or ""))
        tray_color = {C["green"]: "green", C["orange"]: "orange", C["red"]: "red"}.get(color, "off")
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

    def show_login(self, error: str = ""):
        if self.login_dialog:
            self.login_dialog.lift()
            return
        self.show()
        self.login_dialog = LoginDialog(self, error)

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

        def work():  # Проводник может думать несколько секунд — не держим окно
            try:
                os.startfile(path)
            except OSError as e:
                self.ui_q.put(("error", f"Не удалось открыть {path}\n{e}\n\nПроверьте, что на {p['name']} "
                                        "открыт общий доступ к папке (Справка → Как открыть доступ к папке)."))
        threading.Thread(target=work, daemon=True, name="open").start()

    def ping(self):
        p = self.selected_peer()
        if p and WINDOWS:
            subprocess.Popen(["cmd", "/k", f"title Ping {p['name']} & ping -t {p['ip']}"],
                             creationflags=subprocess.CREATE_NEW_CONSOLE)

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
    app = App(State(), minimized="--minimized" in sys.argv)
    if show_event:
        watch_show_event(show_event, app.ui_q)
    try:
        app.mainloop()
    finally:
        log.info("окно закрыто")


if __name__ == "__main__":
    main()
