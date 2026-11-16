"""
Retix Hub — клиент для Windows.

* регистрируется на сервере по логину/паролю компании (ключ генерируется локально);
* ставит туннель через официальный WireGuard for Windows (служба WireGuardTunnel$retixhub);
* следит за сервером: если сервер пропал — ждёт, когда появится — переподключается;
* показывает других пользователей компании, пишет их имена в hosts (\\\\pc1\\share работает по имени);
* открывает общую папку / подключает сетевой диск.

Запуск требует прав администратора (сборка PyInstaller с --uac-admin).
"""
import base64
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

VERSION = "1.0.0"
APP_NAME = "RetixHub"          # служебное имя: папки, задачи, мьютекс
APP_TITLE = "Retix Hub"        # то, что видит пользователь
TUNNEL = "retixhub"
DEFAULT_SERVER = "https://hub.retix.uz"  # можно переопределить client_config.json рядом с exe

WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if WINDOWS else 0

DATA_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / APP_NAME
STATE_FILE = DATA_DIR / "state.json"
CONF_FILE = DATA_DIR / f"{TUNNEL}.conf"
LOG_FILE = DATA_DIR / "client.log"

WG_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WireGuard"
WIREGUARD_EXE = WG_DIR / "wireguard.exe"
WG_EXE = WG_DIR / "wg.exe"
SERVICE = f"WireGuardTunnel${TUNNEL}"
HOSTS_FILE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
HOSTS_BEGIN, HOSTS_END = "# RetixHub BEGIN", "# RetixHub END"
FW_RULE = "RetixHub SMB"

CHECK_EVERY = 8          # сек — основной цикл
HANDSHAKE_OK = 180       # сек — handshake свежее этого = туннель жив
HEARTBEAT_EVERY = 60
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9-]{1,63}$")

log = logging.getLogger("retixhub")


def app_dir() -> Path:
    return Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent


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
              "autostart_done": False}

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
            tmp.replace(self.path)

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


# ====================================================================== Windows: hosts, firewall, автозапуск

def update_hosts(entries: dict[str, str], hosts_file: Path | None = None) -> bool:
    """entries: hostname -> ip. Пишет свой блок в hosts, только если что-то изменилось."""
    hosts_file = hosts_file or HOSTS_FILE
    try:
        text = hosts_file.read_text("utf-8", errors="ignore")
    except OSError:
        return False
    head = re.sub(rf"\r?\n?{re.escape(HOSTS_BEGIN)}.*?{re.escape(HOSTS_END)}\r?\n?", "\n", text, flags=re.S).rstrip()
    block = ""
    if entries:
        lines = [f"{ip}\t{name}" for name, ip in sorted(entries.items())]
        block = "\n".join([HOSTS_BEGIN, *lines, HOSTS_END])
    new = (head + "\n\n" + block + "\n") if block else (head + "\n")
    if new.replace("\r\n", "\n") == text.replace("\r\n", "\n"):
        return True
    try:
        hosts_file.write_text(new, "utf-8")
        run(["ipconfig", "/flushdns"], timeout=15)
        log.info("hosts обновлён: %s", entries)
        return True
    except OSError:
        log.exception("не удалось записать hosts")
        return False


def ensure_smb_firewall(subnet: str | None, ports: str = "445") -> None:
    """На ПК с общей папкой разрешаем SMB из подсети VPN (WG-интерфейс Windows считает «общественным»)."""
    run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE}"])
    if subnet:
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_RULE}", "dir=in", "action=allow",
             "protocol=TCP", f"localport={ports}", f"remoteip={subnet}", "profile=any"])
        log.info("firewall: SMB разрешён из %s", subnet)


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


class Worker(threading.Thread):
    """Фоновый цикл: держит туннель в рабочем состоянии и сообщает статус в GUI."""

    def __init__(self, state: State, events: queue.Queue, tunnel=None, hosts_file: Path | None = None):
        super().__init__(daemon=True, name="worker")
        self.state, self.events = state, events
        self.tunnel = tunnel or Tunnel          # в тестах подменяется
        self.hosts_file = hosts_file or HOSTS_FILE
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
        self.state.set(join_password=password if remember else "")
        self.paused = False
        self.wake.set()
        return None

    def logout(self):
        self.paused = True
        self.state.set(token="", join_password="", last_conf_hash="")
        try:
            self.tunnel.uninstall()
        finally:
            update_hosts({}, self.hosts_file)
            if self.state.get("fw_subnet"):
                ensure_smb_firewall(None)
                self.state.set(fw_subnet="")
        self.cfg = None
        self.status(Status.NEED_LOGIN)

    def force_reconnect(self):
        self.state.set(last_conf_hash="")
        self.wake.set()

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

        # 4. ПК с общей папкой — открываем SMB в firewall
        want_fw = self.cfg["subnet"] if self.cfg["is_share_host"] else ""
        if want_fw != self.state.get("fw_subnet"):
            ensure_smb_firewall(want_fw or None, self.cfg.get("share_ports") or "445")
            self.state.set(fw_subnet=want_fw)

        # 5. список пользователей + hosts
        try:
            peers = self.api.peers()["peers"]
        except (ApiError, ServerUnreachable):
            peers = []
        me_host = socket.gethostname().lower()
        hosts = {p["hostname"].lower(): p["ip"] for p in peers
                 if p["hostname"] and HOSTNAME_RE.match(p["hostname"]) and p["hostname"].lower() != me_host}
        update_hosts(hosts, self.hosts_file)
        self.emit("peers", peers=peers)

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

STATUS_VIEW = {
    Status.ONLINE: ("●  Подключено", "#16a34a"),
    Status.CONNECTING: ("●  Подключение…", "#d97706"),
    Status.SERVER_DOWN: ("●  Сервер недоступен", "#dc2626"),
    Status.PENDING: ("●  Ждёт одобрения", "#d97706"),
    Status.BLOCKED: ("●  Заблокировано", "#dc2626"),
    Status.NEED_LOGIN: ("●  Не подключено", "#6b7280"),
    Status.ERROR: ("●  Ошибка", "#dc2626"),
}


class LoginDialog(tk.Toplevel):
    def __init__(self, app: "App", error: str = ""):
        super().__init__(app)
        self.app = app
        self.title("Подключение к сети компании")
        self.resizable(False, False)
        self.transient(app)
        self.grab_set()
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
                ("Пароль компании", "password", "•"), ("Имя этого компьютера", "device", "")]
        for i, (label, key, show) in enumerate(rows):
            ttk.Label(frm, text=label).grid(row=i, column=0, sticky="w", pady=4)
            e = ttk.Entry(frm, textvariable=self.vars[key], width=34, show=show)
            e.grid(row=i, column=1, pady=4)
            if key == ("password" if self.vars["company"].get() else "company"):
                e.focus_set()
        ttk.Checkbutton(frm, text="Запомнить пароль (автоподключение после сбоев)",
                        variable=self.vars["remember"]).grid(row=4, column=0, columnspan=2, sticky="w", pady=6)
        self.err = ttk.Label(frm, text=error, foreground="#dc2626", wraplength=380)
        self.err.grid(row=5, column=0, columnspan=2, sticky="w")
        self.btn = ttk.Button(frm, text="Подключиться", command=self.submit)
        self.btn.grid(row=6, column=0, columnspan=2, pady=(10, 0), sticky="ew")
        self.bind("<Return>", lambda _e: self.submit())
        self.protocol("WM_DELETE_WINDOW", self.close)

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
            self.app.after(0, lambda: self.done(err))
        threading.Thread(target=work, daemon=True).start()

    def done(self, err):
        if err:
            self.err.config(text=err)
            self.btn.config(state="normal", text="Подключиться")
        else:
            self.app.login_dialog = None
            self.destroy()


class App(tk.Tk):
    def __init__(self, state: State, minimized: bool):
        super().__init__()
        self.state_ = state
        self.events: queue.Queue = queue.Queue()
        self.worker = Worker(state, self.events)
        self.cfg = None
        self.login_dialog: LoginDialog | None = None
        self.last_status = None

        self.title(f"{APP_TITLE} {VERSION}")
        try:
            self.iconbitmap(str(resource_dir() / "app_icon.ico"))
        except Exception:
            pass
        self.geometry("720x460")
        self.minsize(600, 360)
        self.protocol("WM_DELETE_WINDOW", self.iconify)  # крестик — свернуть, туннель работает дальше
        self._build()
        if minimized:
            self.iconify()
        self.worker.start()
        self.after(200, self._poll)

    def _build(self):
        top = ttk.Frame(self, padding=(14, 12))
        top.pack(fill="x")
        self.status_lbl = tk.Label(top, text="●  Запуск…", font=("Segoe UI", 13, "bold"), fg="#6b7280")
        self.status_lbl.pack(anchor="w")
        self.info_lbl = ttk.Label(top, text="", foreground="#6b7280")
        self.info_lbl.pack(anchor="w")

        btns = ttk.Frame(self, padding=(14, 0))
        btns.pack(fill="x")
        self.open_btn = ttk.Button(btns, text="📁  Открыть общую папку", command=self.open_share)
        self.open_btn.pack(side="left")
        ttk.Button(btns, text="Подключить диск…", command=self.map_drive).pack(side="left", padx=6)
        ttk.Button(btns, text="Переподключить", command=self.worker.force_reconnect).pack(side="left")
        ttk.Button(btns, text="Выйти из сети", command=self.logout).pack(side="right")

        cols = ("status", "name", "host", "ip", "share")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=12)
        for col, title, w in (("status", "Статус", 90), ("name", "Пользователь", 200), ("host", "Компьютер", 140),
                              ("ip", "IP", 110), ("share", "", 120)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("off", foreground="#9ca3af")
        self.tree.tag_configure("me", font=("Segoe UI", 9, "bold"))
        self.tree.pack(fill="both", expand=True, padx=14, pady=12)
        self.tree.bind("<Double-1>", self.open_peer)

        menu = tk.Menu(self)
        m = tk.Menu(menu, tearoff=0)
        m.add_command(label="Войти / сменить компанию…", command=self.show_login)
        m.add_command(label="Открыть журнал", command=lambda: os.startfile(LOG_FILE) if WINDOWS else None)
        m.add_separator()
        m.add_command(label="Закрыть программу (VPN продолжит работать)", command=self.quit_app)
        menu.add_cascade(label="Меню", menu=m)
        self.config(menu=menu)

    # --- события от Worker
    def _poll(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "status":
                    self._on_status(**data)
                elif kind == "peers":
                    self._on_peers(data["peers"])
        except queue.Empty:
            pass
        self.after(300, self._poll)

    def _on_status(self, status, text, cfg):
        self.cfg = cfg
        label, color = STATUS_VIEW.get(status, ("●", "#6b7280"))
        self.status_lbl.config(text=label, fg=color)
        info = text
        if cfg:
            info = f"{cfg['company']} · {cfg['device_name']} · {cfg['ip']}" + (f"   —   {text}" if text else "")
        self.info_lbl.config(text=info)
        self.open_btn.config(state="normal" if cfg and cfg.get("share") else "disabled")
        if status == Status.NEED_LOGIN and self.last_status != Status.NEED_LOGIN and not self.login_dialog:
            self.show_login(text)
        if status in (Status.SERVER_DOWN, Status.BLOCKED):
            for i in self.tree.get_children():
                self.tree.item(i, tags=("off",))
        self.last_status = status

    def _on_peers(self, peers):
        self.tree.delete(*self.tree.get_children())
        for p in sorted(peers, key=lambda p: (not p["is_share_host"], not p["online"], p["name"].lower())):
            tags = [] if p["online"] else ["off"]
            if p["is_me"]:
                tags.append("me")
            self.tree.insert("", "end", iid=str(p["id"]), tags=tags, values=(
                "🟢 online" if p["online"] else "⚪ offline",
                p["name"] + ("  (это я)" if p["is_me"] else ""),
                p["hostname"], p["ip"], "📁 общая папка" if p["is_share_host"] else ""))

    # --- действия
    def show_login(self, error: str = ""):
        if self.login_dialog:
            self.login_dialog.lift()
            return
        self.deiconify()
        self.login_dialog = LoginDialog(self, error)

    def share_path(self) -> str | None:
        share = (self.cfg or {}).get("share")
        if not share:
            return None
        host = share["hostname"] if share["hostname"] and HOSTNAME_RE.match(share["hostname"]) else share["ip"]
        return rf"\\{host}\{share['name']}"

    def open_share(self):
        path = self.share_path()
        if not path:
            messagebox.showinfo(APP_TITLE, "Администратор ещё не отметил компьютер с общей папкой.")
            return
        try:
            os.startfile(path)
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Не удалось открыть {path}\n{e}\n\n"
                                 "Проверьте, что компьютер с папкой онлайн.")

    def open_peer(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        ip = self.tree.item(sel[0], "values")[3]
        try:
            os.startfile(rf"\\{ip}")
        except OSError:
            pass

    def map_drive(self):
        path = self.share_path()
        if not path:
            messagebox.showinfo(APP_TITLE, "Компьютер с общей папкой не назначен.")
            return
        letter = simpledialog.askstring(APP_TITLE, "Буква диска:", initialvalue="Z", parent=self)
        if not letter:
            return
        letter = letter.strip().rstrip(":").upper()[:1] + ":"
        user = simpledialog.askstring(APP_TITLE, f"Логин для {path}\n(например pc1\\share_user, пусто — текущий):",
                                      parent=self) or ""
        pwd = simpledialog.askstring(APP_TITLE, "Пароль:", show="•", parent=self) if user else ""
        host = path.split("\\")[2]

        def work():
            if user:
                # cmdkey хранит пароль в диспетчере учётных данных пользователя — Проводник им тоже пользуется
                run(["cmdkey", f"/add:{host}", f"/user:{user}", f"/pass:{pwd}"])
            # чтобы диск из программы-админа был виден обычному Проводнику
            run(["reg", "add", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                 "/v", "EnableLinkedConnections", "/t", "REG_DWORD", "/d", "1", "/f"])
            run(["net", "use", letter, "/delete", "/y"])
            rc, out = run(["net", "use", letter, path, "/persistent:yes"])
            self.after(0, lambda: messagebox.showinfo(APP_TITLE, f"Диск {letter} подключён к {path}.\n"
                                                      "Если диск не виден в Проводнике — выйдите из Windows и зайдите снова (один раз).")
                       if rc == 0 else messagebox.showerror(APP_TITLE, out.strip() or "Ошибка net use"))
        threading.Thread(target=work, daemon=True).start()

    def logout(self):
        if not messagebox.askyesno(APP_TITLE, "Отключить этот компьютер от сети компании?"):
            return
        threading.Thread(target=self.worker.logout, daemon=True).start()
        self.tree.delete(*self.tree.get_children())

    def quit_app(self):
        self.worker.stop_flag = True
        self.destroy()


# ====================================================================== main

def relaunch_as_admin():
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    exe = sys.executable
    if not getattr(sys, "frozen", False):
        params = f'"{os.path.abspath(__file__)}" {params}'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)


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
        ttk.Label(root, text="test")
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

    def config_check():
        return State._default_server()

    def icon_check():
        path = resource_dir() / "app_icon.ico"
        if not path.exists():
            raise FileNotFoundError(path)
        return path.name

    check("Tcl/Tk", tk_check)
    check("cryptography", crypto_check)
    check("SSL", ssl_check)
    check("requests", lambda: requests.__version__)
    check("server_url", config_check)
    check("icon", icon_check)
    lines.append("RESULT: " + ("OK" if ok else "FAIL"))
    try:
        (app_dir() / SELFTEST_FILE).write_text("\n".join(lines) + "\n", "utf-8")
    except OSError:
        pass
    print("\n".join(lines))
    return 0 if ok else 1


def uninstall_cleanup() -> int:
    """retixhub.exe --uninstall: вызывает деинсталлятор. Снимает туннель, блок в hosts, правило firewall
    и автозапуск. WireGuard и %ProgramData%\\RetixHub (ключ и вход) остаются — при повторной установке
    ПК вернётся в сеть сам."""
    for step in (Tunnel.uninstall, lambda: update_hosts({}), lambda: ensure_smb_firewall(None), remove_autostart):
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
    if WINDOWS and not is_admin():
        relaunch_as_admin()
        return
    secure_data_dir()
    handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    logging.basicConfig(level=logging.INFO, handlers=[handler, logging.StreamHandler()],
                        format="%(asctime)s %(levelname)s %(message)s")
    if not single_instance():
        messagebox.showinfo(APP_TITLE, "Программа уже запущена (посмотрите на панели задач).")
        return
    if "--uninstall" in sys.argv:
        log.info("удаление программы: очистка")
        sys.exit(uninstall_cleanup())
    log.info("старт %s", VERSION)
    App(State(), minimized="--minimized" in sys.argv).mainloop()


if __name__ == "__main__":
    main()
