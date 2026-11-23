"""
Retix Hub — клиент для Windows (окно, значок в трее).

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
import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import ntpath
import os
import platform
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
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

VERSION = "1.0.29"
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
FW_RULE_DIRECT = "RetixHub Direct"  # входящие пакеты WireGuard от ПК своей локальной сети (прямой путь)

CHECK_EVERY = 8          # сек — основной цикл
HANDSHAKE_OK = 180       # сек — handshake свежее этого = туннель жив
HEARTBEAT_EVERY = 60

# Прямой путь по локальной сети (компания с «любым трафиком»): см. DirectPaths
DIRECT_KEEPALIVE = 10      # сек — keepalive соседу по локальной сети (в локалке трафик бесплатный)
DIRECT_PROBE_SECONDS = 20  # сек — столько ждём handshake по одному адресу соседа
DIRECT_RX_TIMEOUT = 35     # сек — от прямого соседа нет пакетов (и на ping нет ответа) — путь потерян
# WireGuard шлёт keepalive, только если 10 с ничего не отправлял И НЕ ПОЛУЧАЛ. Когда keepalive у обоих ПК,
# один всё время получает пакеты другого и сам молчит — по одним keepalive живой путь выглядел мёртвым
# (то у одного ПК, то у другого: «нет пакетов» через 35 с). Сосед молчит дольше этого — шлём ему ping
# через прямой путь: ответ — обычные данные, он приходит всегда, если путь работает в обе стороны.
DIRECT_NUDGE_AFTER = 12    # сек — по локальной сети
DIRECT_NUDGE_AFTER_WAN = 22  # сек — через интернет (keepalive там 20 с)
# Повторы — в начале общего окна по часам сервера, как через интернет: у обоих ПК одновременно. Раньше каждый
# ждал своё время от своего обрыва, проверка (20 с) попадала на паузу соседа — и так раз за разом.
DIRECT_RETRY_FAILED = 300  # сек — ни один адрес не ответил: снова в начале следующего окна
DIRECT_RETRY_LOST = 60     # сек — прямой путь пропал: снова в начале следующего окна
DIRECT_TICK = 1            # сек — пока идёт проверка пути, handshake смотрим чаще основного цикла
# Handshake и keepalive — ещё не всё: бывает, что они ходят, а данные напрямую не проходят (у соседа нет нашего
# адреса в AllowedIPs — его программа закрыта или зависла, — и WireGuard соседа выбрасывает наши пакеты; ответ
# ping приходит не тем путём). Keepalive соседа приходят, и такой путь выглядел живым вечно: ping и общие папки
# не работали, а с других ПК работали. Поэтому после включения прямого пути — ping соседу через него.
DIRECT_VERIFY_AFTER = 3    # сек после включения пути: сосед за это время тоже успевает его включить
DIRECT_VERIFY_RETRY = 5    # сек — повтор, если ping не ответил
DIRECT_VERIFY_TRIES = 2    # столько раз ping через прямой путь, прежде чем проверить его через сервер
LAN_CHECK_EVERY = 60       # сек — как часто перечитывать адреса своей локальной сети
DIRECT_CACHE_DAYS = 3      # сохранённые соседи действуют без сервера столько дней после его последнего ответа
DIRECT_CACHE_REFRESH = 3600  # сек — как часто переписывать неизменившийся список соседей на диск
# Прямой путь через интернет к ПК другого офиса (пробой NAT): дольше проверка, реже keepalive
DIRECT_KEEPALIVE_WAN = 20    # сек — держит открытой «дверь» в роутере (NAT забывает UDP через 30–60 с)
DIRECT_PROBE_WAN = 25        # сек — ждём handshake: соседу нужно успеть начать одновременно с нами
DIRECT_RX_TIMEOUT_WAN = 50   # сек — от соседа нет пакетов (2,5 keepalive) — путь потерян
DIRECT_SLOT_WAN_FAILED = 600  # сек — не получилось (роутер не умеет): снова в начале следующего окна
DIRECT_SLOT_WAN_LOST = 60     # сек — путь пропал: снова в начале следующего окна

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
              "fw_direct": 0, "direct_cache": {}, "autostart_done": False, "enabled": True, "auto_update": True, "update_attempt": {},
              "update_state": "none", "update_pubkey": "", "update_pins": {}, "profiles": {},
              # удалённое управление: какие настройки RustDesk применены, пароль, ещё не принятый сервером
              # (зашифрован DPAPI), и поставила ли RustDesk эта программа (тогда удаляет его вместе с собой)
              "remote_applied": "", "remote_pw_pending": "", "rustdesk_by_retix": False,
              # доступ к ЭТОМУ ПК, который выбрал его пользователь ('' — как разрешил администратор, ask, own, off)
              # и его собственный пароль для режима own (DPAPI; сервер его не знает)
              "remote_local": "", "remote_own_pw": "",
              # блокировка программы паролем этого компьютера (хэш PBKDF2; тот же пароль — «доступ по моему паролю»):
              # включена ли, через сколько минут без действий; показано ли окно «Настройки этого компьютера»
              "lock_hash": "", "lock_on": False, "lock_minutes": 10, "setup_done": False,
              # блокировка действует только на ПК, которому администратор разрешил управлять другими
              # (последний ответ сервера; помним, чтобы после запуска Windows без сервера решить сразу):
              "can_control": False, "lock_offered": False}
    PROFILE_FIELDS = ("server_url", "company_login", "company_name", "device_name", "token", "private_key",
                      "join_password", "direct_cache", "can_control")

    def __init__(self, path: Path | None = None):
        self.path = path or STATE_FILE
        self.data = dict(self.FIELDS)
        self.lock = threading.Lock()
        for path in (self.path, self.backup_path):   # основной файл испорчен (выключили питание) — запасная копия
            if not path.exists():
                continue
            try:
                loaded = json.loads(path.read_text("utf-8"))
                if not isinstance(loaded, dict):
                    raise ValueError("не объект")
                self.data.update(loaded)
                if path != self.path:
                    log.warning("state.json повреждён — взята запасная копия %s", path.name)
                break
            except Exception:
                log.exception("%s повреждён", path.name)
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

    @property
    def backup_path(self) -> Path:
        return self.path.with_name(self.path.name + ".bak")

    def get(self, key):
        with self.lock:
            v = self.data.get(key)
        return unprotect(v) if key in ("token", "private_key", "join_password") else v

    def set(self, **kw):
        with self.lock:
            old = {k: self.data[k] for k in kw if k in self.data}
            for k, v in kw.items():
                self.data[k] = protect(v) if k in ("token", "private_key", "join_password") else v
            try:
                self._write()
            except OSError:
                # на диск не легло — и в памяти остаётся прежнее: иначе после перезапуска программа взяла бы
                # с диска старый токен, а сервер счёл бы его копией входа на другом ПК
                for k in kw:
                    if k in old:
                        self.data[k] = old[k]
                    else:
                        self.data.pop(k, None)
                raise

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
        """Записать на диск (вызывать под self.lock). Сначала во временный файл с fsync, потом замена: выключение
        питания (кассы!) не оставит пустой или обрезанный state.json. Следом — та же запись в state.json.bak:
        если основной файл всё же испортится, программа возьмёт копию, а не начнёт с нуля (новый ключ, вход заново)."""
        text = json.dumps(self.data, ensure_ascii=False, indent=2)
        for target in (self.path, self.backup_path):
            tmp = target.with_name(target.name + ".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            for attempt in range(5):  # антивирус может на миг держать файл
                try:
                    tmp.replace(target)
                    break
                except PermissionError:
                    if attempt == 4:
                        if target == self.path:
                            raise
                        log.warning("запасная копия %s не записана", target.name)
                    else:
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

    def _req_locked(self, method: str, path: str, auth: bool, timeout: float = 8, headers: dict | None = None,
                    **kw):
        url = self.state.get("server_url").rstrip("/") + path
        headers = ({"Authorization": f"Bearer {self.state.get('token')}", "X-Retix-Version": VERSION,
                    "X-Retix-Update-State": self.state.get("update_state") or "none"} if auth else {}) \
            | (headers or {})
        try:
            r = self.http.request(method, url, headers=headers, timeout=timeout, **kw)
        except requests.RequestException as e:
            raise ServerUnreachable(str(e)) from e
        new_token = r.headers.get(TOKEN_HEADER)
        if auth and new_token and r.status_code < 400:
            try:
                self.state.set(token=new_token)   # сразу на диск: после перезапуска — уже новый
            except OSError as e:
                # не записался — остаёмся на прежнем токене (он действует, пока новый не использован);
                # сервер выдаст новый ещё раз через 30 с
                log.warning("новый токен не сохранён (%s) — остаюсь на прежнем", e)
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

    def register(self, company_login: str, password: str, device_name: str, public_key: str,
                 private_key: str = ""):
        body = {"company_login": company_login, "join_password": password, "device_name": device_name,
                "hostname": socket.gethostname(), "public_key": public_key, "client_version": VERSION}
        if private_key:
            body.update(self.key_proof(public_key, private_key))
        return self._req("POST", "/api/register", auth=False, json=body)

    def key_proof(self, public_key: str, private_key: str) -> dict:
        """Подтверждение, что этот ПК владеет закрытым ключом (сервер 1.0.26+): HMAC от X25519(свой ключ,
        ключ сервера) по времени сервера из /api/ping. Без него повторную регистрацию этого ПК мог бы сделать
        любой, кто знает пароль компании и открытый ключ ПК. Старый сервер ключа не отдаёт — {}."""
        try:
            info = self._req("GET", "/api/ping", auth=False)
            server_key, ts = str(info.get("server_public_key") or ""), int(info.get("time") or 0)
        except (ApiError, ServerUnreachable, AttributeError, TypeError, ValueError):
            return {}
        if not KEY_RE.match(server_key) or not ts:
            return {}
        return {"proof": key_proof(private_key, server_key, public_key, ts), "proof_ts": ts}

    def me(self):
        return self._req("GET", "/api/me")

    def peers(self):
        return self._req("GET", "/api/peers")

    def heartbeat(self, lan: list | None = None, wg_port: int = 0, direct: list | None = None,
                  radmin_server: bool | None = None, remote_ok: bool | None = None,
                  remote_local: str | None = None, nics: list | None = None, rustdesk_id: str = ""):
        # wan: этот клиент умеет прямой путь через интернет — сервер может свести его с ПК других офисов
        body = {"client_version": VERSION, "lan": list(lan or []), "wg_port": int(wg_port or 0),
                "direct": list(direct or []), "wan": True}
        if radmin_server is not None:
            body["radmin_server"] = bool(radmin_server)
        if remote_ok is not None:
            body["remote_ok"] = bool(remote_ok)
        if remote_local is not None:
            body["remote_local"] = remote_local
        if nics is not None:
            body["nics"] = list(nics)
        if rustdesk_id:
            body["rustdesk_id"] = rustdesk_id
        return self._req("POST", "/api/heartbeat", json=body)

    def wake(self, to: int):
        return self._req("POST", "/api/wake", json={"to": to})

    def upload_log(self, data: bytes):
        return self._req("POST", "/api/log", data=data, timeout=60, headers={"Content-Type": "application/gzip"})

    def remote_password(self, password: str):
        return self._req("POST", "/api/remote/password", json={"password": password})

    def remote_connect(self, to: int, kind: str = "control"):
        return self._req("POST", "/api/remote/connect", json={"to": to, "kind": kind})

    def send_message(self, to: int, text: str):
        return self._req("POST", "/api/messages", json={"to": to, "text": text})

    def messages(self):
        return self._req("GET", "/api/messages")

    def logout(self):
        return self._req("POST", "/api/logout")

    def rename(self, name: str):
        return self._req("POST", "/api/rename", json={"name": name})

    def update_info(self):
        return self._req("GET", "/api/update")


def key_proof(private_key: str, server_key: str, public_key: str, ts: int) -> str:
    shared = X25519PrivateKey.from_private_bytes(base64.b64decode(private_key)).exchange(
        X25519PublicKey.from_public_bytes(base64.b64decode(server_key)))
    return hmac.new(shared, f"retixhub-register|{public_key}|{int(ts)}".encode(), hashlib.sha256).hexdigest()


def normalize_server_url(server: str) -> str:
    """Адрес сервера из окна входа: без схемы — https://; http — только для этого же ПК (разработка).
    ValueError — адрес не https: пароль компании и токены пошли бы по сети открытым текстом."""
    server = (server or "").strip()
    if server and "://" not in server:
        server = "https://" + server
    server = server.rstrip("/")
    u = urlparse(server)
    if not u.hostname or (u.scheme != "https" and u.hostname not in ("127.0.0.1", "localhost")):
        raise ValueError("Адрес сервера должен начинаться с https://")
    return server


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


LAN_ENDPOINT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")


def lan_ip_ok(ip: ipaddress.IPv4Address) -> bool:
    """Адрес из локальной сети: частный, не 127.*, не 169.254.*, не сеть Retix Hub."""
    return (ip.is_private and not ip.is_loopback and not ip.is_link_local and not ip.is_multicast
            and not ip.is_unspecified and ip not in VPN_NET)


def lan_endpoint_ok(value) -> bool:
    m = LAN_ENDPOINT_RE.match(str(value))
    try:
        return bool(m) and lan_ip_ok(_ipv4(m.group(1))) and 0 < int(m.group(2)) < 65536
    except ValueError:
        return False


def wan_endpoint_ok(value) -> bool:
    """Внешний адрес соседа в интернете (как его видит сервер): публичный IPv4 и порт."""
    m = LAN_ENDPOINT_RE.match(str(value))
    try:
        return bool(m) and _ipv4(m.group(1)).is_global and 0 < int(m.group(2)) < 65536
    except ValueError:
        return False


def wan_neighbors(cfg: dict, own_key: str = "", skip=()) -> list[dict]:
    """ПК других офисов для прямого пути через интернет (direct_wan от сервера, клиент 1.0.12+). Проверки те
    же, что у соседей по локальной сети, но адрес — публичный. skip — ключи, уже известные как соседи по LAN."""
    if not cfg.get("direct_enabled"):
        return []
    out, seen = [], {own_key, str(cfg.get("server_public_key")), *skip}
    for n in cfg.get("direct_wan") or []:
        try:
            key, ip = str(n["public_key"]), str(n["ip"])
            if not KEY_RE.match(key) or key in seen:
                raise ValueError(f"ключ {key[:8]}…")
            if not peer_ip_ok(ip, cfg["subnet"]) or ip in (cfg["ip"], cfg["server_ip"]):
                raise ValueError(f"адрес {ip!r}")
            endpoints = [str(e) for e in n.get("endpoints") or [] if wan_endpoint_ok(e)][:2]
            if not endpoints:
                raise ValueError(f"нет внешнего адреса у {ip}")
            out.append({"id": int(n["id"]), "public_key": key, "ip": ip, "endpoints": endpoints, "wan": True})
            seen.add(key)
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            log.warning("сосед через интернет отклонён: %s", e)
    return out


def direct_neighbors(cfg: dict, own_key: str = "") -> list[dict]:
    """Соседи по локальной сети из ответа сервера — только то, что можно безопасно отдать WireGuard:
    ключ, IP соседа в подсети компании (не свой и не сервера) и его частные адреса в локальной сети."""
    if not cfg.get("direct_enabled"):
        return []
    out, seen = [], {own_key, str(cfg.get("server_public_key"))}
    for n in cfg.get("direct") or []:
        try:
            key, ip = str(n["public_key"]), str(n["ip"])
            if not KEY_RE.match(key) or key in seen:
                raise ValueError(f"ключ {key[:8]}…")
            if not peer_ip_ok(ip, cfg["subnet"]) or ip in (cfg["ip"], cfg["server_ip"]):
                raise ValueError(f"адрес {ip!r}")
            endpoints = [str(e) for e in n.get("endpoints") or [] if lan_endpoint_ok(e)][:4]
            if not endpoints:
                raise ValueError(f"нет адресов в локальной сети у {ip}")
            out.append({"id": int(n["id"]), "public_key": key, "ip": ip, "endpoints": endpoints})
            seen.add(key)
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            log.warning("сосед по локальной сети отклонён: %s", e)
    return out


def local_addresses() -> list[str] | None:
    """Свои IPv4 в локальных сетях: ["192.168.1.15/24", …] (без туннеля, 127.*, 169.254.*).
    None — адреса не прочитать (PowerShell не ответил вовремя): это не «локальной сети нет»."""
    if WINDOWS:
        ps = ("Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue | "
              "ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength }")
        code, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=20)
    else:
        code, out = run(["ip", "-4", "-o", "addr", "show"], timeout=10)
        out = "\n".join(w[i + 1] for w in (line.split() for line in out.splitlines())
                        for i, x in enumerate(w[:-1]) if x == "inet")
    if code != 0:
        return None
    found = []
    for line in out.split():
        try:
            iface = ipaddress.IPv4Interface(line.strip())
        except ValueError:
            continue
        if lan_ip_ok(iface.ip) and iface.network.prefixlen >= 8 and str(iface) not in found:
            found.append(str(iface))
    return found[:16]


# ---------------------------------------------------------------------- включение по сети (Wake-on-LAN)
# Пока в компании включено удалённое управление, ПК сообщает серверу свои сетевые карты: адрес в локальной сети
# и MAC. Когда администратор (или ПК с правом «управляет») включает выключенный ПК, сервер просит включённый ПК
# той же подсети разбудить его: этот ПК шлёт «волшебный пакет» (6 × FF и 16 × MAC) на широковещательный адрес
# своей подсети. Шлём только туда, куда сервер не может «направить» чужой трафик: на широковещательный адрес
# собственной локальной сети, проверенный по своим же адресам.

NICS_CHECK_EVERY = 300   # сек — как часто перечитывать свои сетевые карты (MAC меняется редко)
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2})([:-][0-9A-Fa-f]{2}){5}$")
WOL_PORTS = (9, 7)       # порты «волшебного пакета»: сетевой карте порт не важен, но иные роутеры смотрят на 9
WOL_REPEAT = 3


def clean_mac(value) -> str:
    raw = str(value or "").strip()
    if not MAC_RE.match(raw):
        return ""
    hexs = raw.replace(":", "").replace("-", "").upper()
    if hexs in ("000000000000", "FFFFFFFFFFFF") or int(hexs[:2], 16) & 1:
        return ""
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


def local_nics() -> list[dict] | None:
    """Свои сетевые карты в локальной сети: [{"addr": "192.168.1.15/24", "mac": "AA:BB:CC:DD:EE:FF"}, …].
    None — не прочитать (PowerShell не ответил вовремя)."""
    if WINDOWS:
        ps = ("$m=@{}; Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { $m[[int]$_.ifIndex]=$_.MacAddress }; "
              "Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue | "
              "ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength + ' ' + $m[[int]$_.InterfaceIndex] }")
        code, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=20)
    else:
        code, out = run(["ip", "-o", "-4", "addr", "show"], timeout=10)
        lines = []
        for line in out.splitlines():
            w = line.split()
            if len(w) > 3 and "inet" in w:
                try:
                    mac = Path(f"/sys/class/net/{w[1]}/address").read_text().strip()
                except OSError:
                    mac = ""
                lines.append(f"{w[w.index('inet') + 1]} {mac}")
        out = "\n".join(lines)
    if code != 0:
        return None
    found = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            iface = ipaddress.IPv4Interface(parts[0])
        except ValueError:
            continue
        mac = clean_mac(parts[1])
        item = {"addr": str(iface), "mac": mac}
        if mac and lan_ip_ok(iface.ip) and 8 <= iface.network.prefixlen <= 30 and item not in found:
            found.append(item)
    return found[:16]


def wake_job_ok(job, nics: list[dict] | None) -> bool:
    """Команда сервера «разбуди»: MAC одной карты и широковещательный адрес одной из СВОИХ локальных сетей."""
    if not isinstance(job, dict) or not clean_mac(job.get("mac")):
        return False
    for n in nics or []:
        try:
            if str(ipaddress.IPv4Interface(n["addr"]).network.broadcast_address) == str(job.get("broadcast")):
                return True
        except (ValueError, KeyError, TypeError):
            continue
    return False


def magic_packet(mac: str) -> bytes:
    return b"\xff" * 6 + bytes.fromhex(clean_mac(mac).replace(":", "")) * 16


def send_magic_packet(mac: str, broadcast: str) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for _ in range(WOL_REPEAT):
                for port in WOL_PORTS:
                    sock.sendto(magic_packet(mac), (broadcast, port))
        return True
    except OSError as e:
        log.warning("включение по сети: пакет на %s не отправлен: %s", broadcast, e)
        return False


# ---------------------------------------------------------------------- журнал для администратора
LOG_UPLOAD_MAX = 900_000     # байт gzip — столько принимает сервер (nginx по умолчанию — до 1 МБ)
LOG_TEXT_MAX = 6_000_000     # байт журнала берём с конца, не больше
LOG_RETRY = 60               # сек — не получилось отправить: снова не раньше


def _tail(path: Path, limit: int) -> bytes:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - limit))
            return f.read()
    except OSError:
        return b""


def log_files_text(limit: int = LOG_TEXT_MAX) -> bytes:
    """Конец журнала программы: client.log.3 … client.log (старые — первыми)."""
    d = log_dir()
    parts = [_tail(p, limit) for p in [d / f"client.log.{i}" for i in (3, 2, 1)] + [d / "client.log"] if p.exists()]
    return b"".join(parts)[-limit:]


def pack_log(header: str, body: bytes, limit: int = LOG_UPLOAD_MAX) -> bytes:
    """Заголовок + конец журнала, сжатые gzip и не больше limit: не влезает — берём меньше с конца."""
    head = header.encode("utf-8", "replace")
    while True:
        data = gzip.compress(head + body, 6)
        if len(data) <= limit or not body:
            return data
        body = body[len(body) // 2:]


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
    def check_reach(ip: str, done) -> None:
        """Отвечает ли ip на ping (через туннель) — в фоне: done(True/False) вызывается из другого потока."""
        def work():
            ok = False
            try:
                code, out = run(["ping", "-n", "2", "-w", "1000", ip], timeout=10)
                ok = code == 0 and "TTL=" in out.upper()
            finally:
                done(ok)
        threading.Thread(target=work, daemon=True, name="reach").start()

    @staticmethod
    def nudge(ip: str) -> None:
        """Один ping соседу через прямой путь — в фоне, не задерживая цикл (см. DIRECT_NUDGE_AFTER)."""
        threading.Thread(target=run, args=(["ping", "-n", "1", "-w", "1000", ip],), kwargs={"timeout": 5},
                         daemon=True, name="nudge").start()

    @staticmethod
    def last_handshake(key: str = "") -> int:
        """Последний handshake с пиром key (сервер). Без key — самый свежий из всех."""
        rc, out = run([str(WG_EXE), "show", TUNNEL, "latest-handshakes"], timeout=10)
        if rc != 0:
            return 0
        times = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                times[parts[0]] = int(parts[1])
        return times.get(key, 0) if key else max(times.values(), default=0)

    @staticmethod
    def dump() -> dict | None:
        """Живое состояние туннеля: порт и пиры (wg show dump). None — туннеля нет."""
        rc, out = run([str(WG_EXE), "show", TUNNEL, "dump"], timeout=10)
        return parse_wg_dump(out) if rc == 0 else None

    @staticmethod
    def set_peer(key: str, endpoint: str = "", allowed_ips: str | None = None, keepalive: int | None = None) -> bool:
        """Добавить/изменить пира на лету (wg set): без переустановки туннеля и без разрыва связи."""
        args = [str(WG_EXE), "set", TUNNEL, "peer", key]
        if endpoint:
            args += ["endpoint", endpoint]
        if allowed_ips is not None:
            args += ["allowed-ips", allowed_ips]
        if keepalive is not None:
            args += ["persistent-keepalive", str(keepalive)]
        rc, out = run(args, timeout=10)
        if rc != 0:
            log.warning("wg set: %s", out.strip())
        return rc == 0

    @staticmethod
    def remove_peer(key: str) -> None:
        run([str(WG_EXE), "set", TUNNEL, "peer", key, "remove"], timeout=10)

    @staticmethod
    def saved_conf() -> str:
        """Конфиг последнего туннеля (лежит в DATA_DIR — только SYSTEM и администраторы)."""
        try:
            return CONF_FILE.read_text("utf-8") if CONF_FILE.exists() else ""
        except OSError:
            return ""

    @staticmethod
    def set_listen_port(port: int) -> bool:
        rc, out = run([str(WG_EXE), "set", TUNNEL, "listen-port", str(port)], timeout=10)
        if rc != 0:
            log.warning("wg set listen-port: %s", out.strip())
        return rc == 0


def parse_wg_dump(out: str) -> dict:
    """wg show <tunnel> dump: первая строка — интерфейс (…, listen-port), дальше по строке на пира."""
    lines = [line for line in out.splitlines() if line.strip()]
    port, peers, own = 0, {}, ""
    if lines:
        head = lines[0].split("\t")
        port = int(head[2]) if len(head) >= 3 and head[2].isdigit() else 0
        own = head[1] if len(head) >= 2 else ""
    for line in lines[1:]:
        p = line.split("\t")
        if len(p) < 7:
            continue
        try:
            peers[p[0]] = {"endpoint": "" if p[2] == "(none)" else p[2],
                           "allowed_ips": "" if p[3] == "(none)" else p[3],
                           "handshake": int(p[4] or 0), "rx": int(p[5] or 0)}
        except ValueError:
            continue
    return {"listen_port": port, "peers": peers, "public_key": own}


class DirectPaths:
    """Прямой путь к ПК своей локальной сети — мимо сервера.

    Сервер сообщает соседей (ПК компании за тем же роутером) и их адреса в локальной сети. Сосед
    добавляется в WireGuard без AllowedIPs: трафик к нему по-прежнему идёт через сервер, а WireGuard
    тем временем делает handshake по локальному адресу. Прошёл — у соседа AllowedIPs = его IP/32: это
    точнее подсети компании у сервера, и пакеты к соседу идут напрямую (маршрут Windows не меняется —
    /32 и так внутри подсети туннеля). Handshake не прошёл ни по одному адресу, или от соседа перестали
    приходить пакеты, или сервер его больше не называет — сосед удаляется, трафик снова идёт через сервер.
    Пира сервера этот класс не трогает никогда.

    Сосед из другого офиса (wan) — то же самое, но адрес — внешний, с которого его видит сервер: оба ПК шлют
    handshake друг другу одновременно, и роутер каждого пропускает ответ на свой исходящий пакет (пробой NAT).
    Одновременность важна, поэтому повторные попытки — в начале общего окна по часам сервера (clock)."""

    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.server_key = ""
        self.wanted: dict[str, dict] = {}                  # ключ -> сосед от сервера
        self.probes: dict[str, dict] = {}                  # ключ -> {"started", "idx"}: идёт проверка
        self.rx: dict[str, tuple[int, float]] = {}         # ключ -> (принято байт, когда выросло)
        self.nudged: dict[str, float] = {}                 # ключ -> когда последний раз слали ping соседу
        self.backoff: dict[str, tuple[float, tuple]] = {}  # ключ -> (до какого времени не пробовать, адреса)
        self.active: dict[str, int] = {}                   # ключ -> id соседа: связь напрямую
        self.listen_port = 0
        self.own_port = 0                                  # порт, который задали сами (set_listen_port)
        self.port_done = False                             # порт туннеля уже приведён к сохранённому
        self.endpoints: dict[str, str] = {}                # ключ -> адрес, по которому сосед отвечает сейчас
        self.verify: dict[str, dict] = {}                  # ключ -> проверка пути ping-ом (DIRECT_VERIFY_*)
        self.noping: set[str] = set()                      # соседи, которые не отвечают на ping вообще
        self.clock = 0.0                                   # часы сервера минус свои: окна попыток через интернет

    def probing(self) -> bool:
        return bool(self.probes or self.verify)

    def active_ids(self) -> list[int]:
        return sorted(self.active.values())

    def wan_ids(self) -> set[int]:
        """С кем связь напрямую через интернет (остальные из active_ids — по локальной сети)."""
        return {i for k, i in self.active.items() if (self.wanted.get(k) or {}).get("wan")}

    def next_slot(self, now: float, period: int) -> float:
        """Начало следующего окна длиной period по часам сервера — у обоих ПК одно и то же."""
        server_now = now + self.clock
        return (server_now // period + 1) * period - self.clock

    def reset(self) -> None:
        """Туннель снят или переустановлен — прямых пиров в нём больше нет."""
        self.wanted.clear(); self.probes.clear(); self.rx.clear(); self.active.clear(); self.endpoints.clear()
        self.nudged.clear(); self.verify.clear()
        self.listen_port = self.own_port = 0
        self.port_done = False

    def sync(self, neighbors: list[dict], server_key: str) -> None:
        self.server_key = server_key
        self.wanted = {n["public_key"]: n for n in neighbors}
        self.poll()

    def poll(self) -> None:
        state = self.tunnel.dump()
        if state is None:
            return
        self.listen_port = state["listen_port"] or self.own_port
        # свои прямые пиры — без AllowedIPs или с одним /32; пир сервера (подсеть компании) не трогаем никогда,
        # даже если ключ сервера здесь неизвестен или устарел (сохранённые соседи без связи с сервером)
        live = {k: v for k, v in state["peers"].items()
                if k != self.server_key and ("," not in v["allowed_ips"])
                and (not v["allowed_ips"] or v["allowed_ips"].endswith("/32"))}
        protected = state["peers"].keys() - live.keys()     # пир сервера (по ключу или по его AllowedIPs)
        now = time.time()
        for key in live.keys() - self.wanted.keys():
            self._drop(key, f"сервер больше не называет соседом ПК id {self.active.get(key, '?')}")
        for key, n in self.wanted.items():
            if key in protected:
                log.warning("сосед %s с ключом пира сервера — пропускаем", n["ip"])
                continue
            self._check(key, n, live.get(key), now)

    def _check(self, key: str, n: dict, peer: dict | None, now: float) -> None:
        endpoints = tuple(n["endpoints"])
        wan = bool(n.get("wan"))
        where = "через интернет" if wan else "по локальной сети"
        until, failed = self.backoff.get(key, (0.0, ()))
        if now < until and (failed == endpoints or wan):
            if peer:
                self._drop(key, "ждём перед новой попыткой")
            return
        allowed = f"{n['ip']}/32"
        if peer is None:
            if key in self.active:   # сами не удаляли — значит, туннель перенастроил кто-то ещё (служба WireGuard)
                log.warning("прямой путь к %s: пир соседа пропал из туннеля", n["ip"])
            log.info("прямой путь к %s %s: проверяем %s", n["ip"], where, endpoints[0])
            self.active.pop(key, None)
            self.rx.pop(key, None)
            self.probes[key] = {"started": now, "idx": 0}
            self.tunnel.set_peer(key, endpoint=endpoints[0], keepalive=DIRECT_KEEPALIVE_WAN if wan else DIRECT_KEEPALIVE)
            return
        last = self.rx.get(key)
        if last is None or peer["rx"] != last[0]:
            self.rx[key] = last = (peer["rx"], now)
        if (self.verify.get(key) or {}).get("stage") == "server":
            self._verify_server(key, n, endpoints, wan, now)
            return
        if peer["allowed_ips"]:                               # уже напрямую
            if peer["allowed_ips"] != allowed:
                self.tunnel.set_peer(key, allowed_ips=allowed)
            quiet = now - last[1]
            if quiet > (DIRECT_RX_TIMEOUT_WAN if wan else DIRECT_RX_TIMEOUT):
                hs = int(now - peer["handshake"]) if peer["handshake"] else -1
                self._fail(key, endpoints, DIRECT_SLOT_WAN_LOST if wan else DIRECT_RETRY_LOST,
                           f"от {n['ip']} нет пакетов {int(now - last[1])} с (handshake {hs} с назад, "
                           f"адрес {peer['endpoint'] or '—'}) — снова через сервер", wan)
            else:
                self.active[key] = n["id"]
                if peer["endpoint"]:
                    self.endpoints[key] = peer["endpoint"]
                after = DIRECT_NUDGE_AFTER_WAN if wan else DIRECT_NUDGE_AFTER
                nudge = getattr(self.tunnel, "nudge", None)
                if nudge and quiet > after and now - self.nudged.get(key, 0) >= min(after, 6):
                    self.nudged[key] = now
                    nudge(n["ip"])
                self._verify_direct(key, n, now)
            return
        probe = self.probes.setdefault(key, {"started": now, "idx": 0})
        if peer["handshake"] and now - peer["handshake"] < HANDSHAKE_OK:
            self.tunnel.set_peer(key, allowed_ips=allowed)
            self.probes.pop(key, None)
            self.active[key] = n["id"]
            self.rx[key] = (peer["rx"], now)
            self.backoff.pop(key, None)
            if key not in self.noping and getattr(self.tunnel, "check_reach", None):
                self.verify[key] = {"stage": "direct", "at": now + DIRECT_VERIFY_AFTER, "tries": 0,
                                    "busy": False, "result": None}
            log.info("прямой путь к %s %s (%s)", n["ip"], where, peer["endpoint"] or endpoints[0])
        elif now - probe["started"] > (DIRECT_PROBE_WAN if wan else DIRECT_PROBE_SECONDS):
            probe["idx"] += 1
            if probe["idx"] >= len(endpoints):
                self._fail(key, endpoints, DIRECT_SLOT_WAN_FAILED if wan else DIRECT_RETRY_FAILED,
                           f"{n['ip']} не ответил {where}", wan)
            else:
                probe["started"] = now
                self.tunnel.set_peer(key, endpoint=endpoints[probe["idx"]])

    def _ping(self, key: str, ip: str, now: float) -> bool | None:
        """Ping соседу в фоне. None — ответа ещё нет (или рано), иначе ответил ли он."""
        v = self.verify[key]
        if v["busy"] or (v["result"] is None and now < v["at"]):
            return None
        if v["result"] is None:
            v["busy"] = True

            def done(ok, v=v):
                v["result"], v["busy"] = bool(ok), False
            self.tunnel.check_reach(ip, done)
            return None
        ok, v["result"] = v["result"], None
        return ok

    def _verify_direct(self, key: str, n: dict, now: float) -> None:
        """Путь включён: доходят ли до соседа данные (ping), а не только handshake и keepalive."""
        if key not in self.verify:
            return
        ok = self._ping(key, n["ip"], now)
        if ok is None:
            return
        v = self.verify[key]
        if ok:
            self.verify.pop(key, None)
            return
        v["tries"] += 1
        if v["tries"] < DIRECT_VERIFY_TRIES:
            v["at"] = now + DIRECT_VERIFY_RETRY
            return
        # напрямую ping не проходит — тот же ping через сервер: пир соседа остаётся (handshake идёт), но без
        # AllowedIPs, и пакеты к нему снова идут через сервер
        v.update(stage="server", at=now + 1)
        self.tunnel.set_peer(key, allowed_ips="")

    def _verify_server(self, key: str, n: dict, endpoints: tuple, wan: bool, now: float) -> None:
        ok = self._ping(key, n["ip"], now)
        if ok is None:
            return
        self.verify.pop(key, None)
        if ok:
            # через сервер отвечает, напрямую — нет: путь только выглядит рабочим
            self._fail(key, endpoints, DIRECT_SLOT_WAN_LOST if wan else DIRECT_RETRY_LOST,
                       f"{n['ip']} отвечает на ping через сервер, а напрямую — нет (handshake есть, данные "
                       f"не проходят) — снова через сервер", wan)
            return
        # не отвечает ни так, ни так — ping у соседа закрыт (антивирус); судить по нему нельзя, путь оставляем
        self.noping.add(key)
        self.tunnel.set_peer(key, allowed_ips=f"{n['ip']}/32")
        log.info("прямой путь к %s: на ping не отвечает ни напрямую, ни через сервер — путь оставляем", n["ip"])

    def _drop(self, key: str, why: str) -> None:
        if key in self.active:
            log.info("прямой путь закрыт: %s", why)
        self.tunnel.remove_peer(key)
        for d in (self.active, self.probes, self.rx, self.endpoints, self.nudged, self.verify):
            d.pop(key, None)

    def _fail(self, key: str, endpoints: tuple, delay: int, why: str, wan: bool = False) -> None:
        log.info("прямой путь: %s", why)
        self._drop(key, why)
        now = time.time()
        # в начале общего окна по часам сервера: сосед тоже не дождался и попробует в то же время
        self.backoff[key] = (self.next_slot(now, delay) if delay > 0 else now, endpoints)


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


def ensure_direct_firewall(port: int) -> None:
    """Входящие пакеты WireGuard из своей локальной сети на порт туннеля (прямой путь между ПК)."""
    run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE_DIRECT}"])
    if port:
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_RULE_DIRECT}", "dir=in", "action=allow",
             "protocol=UDP", f"localport={port}", "remoteip=localsubnet", "profile=any"])
        log.info("firewall: прямой путь — UDP %s из локальной сети", port)


RADMIN_PORT = 4899
RADMIN_SERVER_SERVICE = "RServer3"   # служба Radmin Server 3
RADMIN_CHECK_EVERY = 300             # сек — как часто проверять, стоит ли на этом ПК Radmin Server


def radmin_server_installed() -> bool:
    """Стоит ли на этом ПК Radmin Server: служба RServer3 или её файл. Об этом ПК сообщает серверу,
    и у других ПК компании меню управления к нему появляется, только если он есть."""
    if not WINDOWS:
        return False
    code, out = run(["sc", "query", RADMIN_SERVER_SERVICE], timeout=15)
    if code == 0 and "1060" not in out:
        return True
    windir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return any((windir / d / "rserver30" / "rserver3.exe").is_file() for d in ("SysWOW64", "System32"))


def radmin_menu_allowed(peer: dict | None, viewer: Path | None) -> bool:
    """Меню «Полное управление / Только просмотр / Передача файлов» — только если на том ПК есть
    Radmin Server (он сам сообщил серверу), а на этом — Radmin Viewer."""
    return bool(peer) and peer.get("radmin_server") is True and viewer is not None


def remote_menu_allowed(peer: dict | None, cfg: dict | None) -> bool:
    """Пункты RustDesk в меню: удалённое управление включено в компании, RustDesk готов на том ПК
    (он сам сообщил серверу) и стоит на этом."""
    remote = (cfg or {}).get("remote") if isinstance((cfg or {}).get("remote"), dict) else {}
    return bool(peer) and peer.get("remote") is True and not peer.get("is_me") and remote.get("mode") in REMOTE_MODES \
        and remote.get("can_control", True) is not False and rustdesk_exe() is not None


def remote_cloud_on(cfg: dict | None) -> bool:
    """Облако RustDesk включено в кабинете компании: только тогда у ПК есть ID RustDesk для подключения."""
    remote = (cfg or {}).get("remote") if isinstance((cfg or {}).get("remote"), dict) else {}
    return remote.get("cloud") is True


def rustdesk_id_missing_reason(peer: dict, cfg: dict | None) -> str:
    """Почему ID RustDesk того ПК неизвестен — одна конкретная причина, а не перечень возможных."""
    name = peer.get("name") or peer.get("ip") or "компьютер"
    if not remote_cloud_on(cfg):
        return (f"ID RustDesk не нужен: облако RustDesk выключено в кабинете компании (настройки сети, галочка "
                f"«Разрешить RustDesk через интернет»). В сети Retix Hub к {name} подключаются без ID: "
                f"«Удалённое управление» в меню компьютера.")
    ver = peer.get("client_version") or ""
    if not vkey(ver) or vkey(ver) < vkey("1.0.28"):
        return (f"ID RustDesk компьютера {name} неизвестен: на нём Retix Hub {ver or 'неизвестной версии'}, "
                f"а ID сообщает серверу только 1.0.28 и новее. Обновится сам — ID появится.")
    return (f"{name} ещё не сообщил свой ID RustDesk: RustDesk на нём не ответил программе Retix Hub. "
            f"Программа спрашивает ID раз в минуту, пока не узнает. Если долго нет — пришлите журнал того ПК "
            f"(кнопка «Журнал» в кабинете).")


def wake_menu_allowed(peer: dict | None) -> bool:
    """«Включить компьютер»: ПК выключен, сервер знает его MAC, а этому ПК разрешено управлять другими."""
    return bool(peer) and peer.get("wake") is True and not peer.get("online") and not peer.get("is_me")


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


# ====================================================================== удалённое управление (RustDesk)
# Официальный RustDesk без изменений: установщик Retix Hub кладёт его рядом с программой, клиент ставит его,
# когда в кабинете компании включено удалённое управление, и настраивает командной строкой RustDesk:
#  * прямой доступ по IP (порт REMOTE_PORT) — подключаются по адресу 10.66.N.x внутри сети Retix Hub;
#  * пускает только подсеть своей компании (whitelist), серверы RustDesk не используются: адрес сервера —
#    сервер Retix Hub внутри VPN, а firewall Windows не выпускает RustDesk никуда, кроме 10.66.0.0/16;
#  * «с согласием» — пользователь нажимает «Принять» (approve-mode click), «без согласия» — постоянный пароль
#    (approve-mode password). Пароль придумывает этот ПК и сообщает только серверу Retix Hub; сервер выдаёт
#    его тому ПК компании, которому разрешил подключиться, а после сеанса программа меняет пароль.
#  * «облако RustDesk» (галочка в кабинете, по умолчанию выключена): RustDesk ходит на обычные серверы RustDesk,
#    к ПК подключаются по ID из любого места, как в обычном RustDesk; ID программа сообщает серверу Retix Hub.
#    Прямой доступ по IP (порт REMOTE_PORT) и тогда — только из сети Retix Hub.

REMOTE_PORT = 21118
RUSTDESK_EXE = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RustDesk" / "rustdesk.exe"
FW_RULE_REMOTE = "RetixHub RustDesk"                     # входящие к RustDesk из подсети компании
FW_RULE_REMOTE_OUT = "RetixHub RustDesk only VPN (out)"  # RustDesk не выходит никуда, кроме сети Retix Hub
FW_RULE_REMOTE_IN = "RetixHub RustDesk only VPN (in)"    # …и никто, кроме сети Retix Hub, не подключается к нему
# всё, кроме 10.66.0.0/16 и 127.0.0.0/8 (IPv4), и все обычные IPv6 — для правил «блокировать» firewall
OUTSIDE_VPN = ("0.0.0.0-10.65.255.255,10.67.0.0-126.255.255.255,128.0.0.0-255.255.255.255,"
               "2000::/3,fc00::/7,fe80::/10")
RUSTDESK_SERVICE = "RustDesk"             # служба Windows, которую создаёт установщик RustDesk
RUSTDESK_PIPE = "RustDesk\\query"           # канал, через который rustdesk.exe --option/--password говорит со службой
RUSTDESK_START_WAIT = 30                  # сек — ждём, пока служба RustDesk поднимется и откроет канал
REMOTE_INSTALL_RETRY = 600   # сек — RustDesk не поставился: следующая попытка
REMOTE_SESSION_CHECK = 30    # сек — пока идёт сеанс, проверять его чаще незачем (пароль сменится после)
REMOTE_REAPPLY = 1800        # сек — настройки RustDesk повторяются (пользователь мог их поменять в окне RustDesk)
REMOTE_MODES = ("ask", "auto")
REMOTE_PW_RE = re.compile(r"^[A-Za-z0-9]{12,64}$")
OWN_PW_RE = re.compile(r"^[\x21-\x7e]{8,64}$")   # свой пароль пользователя: 8–64 латинских символа без пробелов
LOCK_PW_RE = re.compile(r"^\S{4,64}$")             # пароль только для блокировки программы: от 4 символов
LOCK_MINUTES = (1, 5, 10, 15, 30, 60)              # через сколько минут без действий программа блокируется
LOCK_DEFAULT_MINUTES = 10
LOCK_TRIES = 5          # неверных паролей подряд — и пауза
LOCK_PAUSE = 30         # сек, растёт с каждой следующей серией


def hash_lock_pw(password: str, salt: bytes | None = None, rounds: int = 200_000) -> str:
    """Пароль блокировки хранится только хэшем: из state.json его не прочитать."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return f"pbkdf2${rounds}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def check_lock_pw(password: str, stored: str) -> bool:
    try:
        kind, rounds, salt, digest = (stored or "").split("$")
        if kind != "pbkdf2":
            return False
        got = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), base64.b64decode(salt), int(rounds))
        return hmac.compare_digest(got, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False
REMOTE_LOCAL_CHOICES = {"": "Как разрешил администратор компании", "ask": "Только с моего согласия (нажать «Принять»)",
                        "own": "По моему паролю (его знаю только я)", "off": "Запретить управление этим компьютером"}


def remote_can_control(cfg: dict | None) -> bool:
    """Может ли этот ПК управлять другими: так решил администратор в кабинете (поле remote.can_control)."""
    remote = (cfg or {}).get("remote")
    return isinstance(remote, dict) and remote.get("can_control") is True


def combine_remote_mode(admin: str, local: str, own_password: bool) -> str:
    """Как можно управлять этим ПК: что разрешил администратор и что выбрал пользователь — только строже."""
    if admin not in REMOTE_MODES or local == "off":
        return "off"
    if local == "ask" or (local == "own" and not own_password):
        return "ask"
    return "own" if local == "own" else admin


def run_rd(args: list, timeout: int = 30) -> tuple[int, str]:
    """Команда rustdesk.exe. Не как run(): RustDesk запускает свои процессы (служба, значок у часов), и они
    наследуют каналы вывода — subprocess.run ждал бы их закрытия вечно, даже после таймаута (так в 1.0.16
    висел весь цикл программы, и сеть переставала обслуживаться). Здесь вывод — во временный файл,
    ждём только сам процесс и не дольше timeout."""
    import tempfile
    try:
        with tempfile.TemporaryFile() as out:
            p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                 creationflags=CREATE_NO_WINDOW)
            try:
                code = p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.kill()
                log.warning("RustDesk: %s не ответил за %d с", " ".join(map(str, args[1:2])), timeout)
                return -1, "timeout"
            out.seek(0)
            data = out.read()
    except OSError as e:
        return -1, str(e)
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return code, data.decode(enc)
        except UnicodeDecodeError:
            pass
    return code, data.decode("utf-8", "replace")


def rustdesk_exe() -> Path | None:
    return RUSTDESK_EXE if RUSTDESK_EXE.is_file() else None


def rustdesk_service_state() -> str:
    """Служба RustDesk: running, stopped или missing (её нет — RustDesk поставлен не до конца)."""
    if not WINDOWS:
        return "missing"
    code, out = run(["sc", "query", RUSTDESK_SERVICE], timeout=15)
    if code != 0 or "1060" in out:
        return "missing"
    return "running" if "RUNNING" in out else "stopped"


def rustdesk_ready() -> bool:
    """Служба RustDesk отвечает: открыт её канал. Без него rustdesk.exe --option молча пишет настройки только
    себе (текущему пользователю), а служба их не получает; --password падает с «os error 2»."""
    if not WINDOWS:
        return False
    try:
        return any(name.lower() == RUSTDESK_PIPE.lower() for name in os.listdir("\\\\.\\pipe\\"))
    except OSError:
        return False


def start_rustdesk() -> bool:
    """Запустить службу RustDesk, если она остановлена, и дождаться её канала."""
    if rustdesk_ready():
        return True
    if rustdesk_service_state() == "stopped":
        log.info("RustDesk: запускаю службу")
        run(["sc", "start", RUSTDESK_SERVICE], timeout=30)
    for _ in range(RUSTDESK_START_WAIT):
        if rustdesk_ready():
            return True
        time.sleep(1)
    return rustdesk_ready()


MSI_GUID_RE = re.compile(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}")


def rustdesk_msi_product() -> str | None:
    """RustDesk, поставленный MSI-пакетом (раньше, не Retix Hub): код продукта {…} для msiexec /x.
    Установщик RustDesk в виде exe поверх MSI не ставит: «Cannot install the EXE package over an existing MSI»."""
    if not WINDOWS:
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RustDesk") as k:
            values = {}
            for name in ("WindowsInstaller", "UninstallString", "QuietUninstallString"):
                try:
                    values[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    pass
    except OSError:
        return None
    if values.get("WindowsInstaller") != 1:
        return None
    m = MSI_GUID_RE.search(str(values.get("QuietUninstallString") or values.get("UninstallString") or ""))
    return m.group(0) if m else None


def remove_rustdesk_msi(product: str) -> bool:
    """Тихо удалить сломанный RustDesk из MSI (файлы есть, службы нет), чтобы поставить его заново."""
    log.warning("RustDesk: стоит MSI-пакет %s без службы — удаляю его, чтобы поставить заново", product)
    code, out = run_rd(["msiexec", "/x", product, "/qn", "/norestart"], timeout=600)
    if code not in (0, 1605, 3010):   # 1605 — уже не установлен, 3010 — нужна перезагрузка
        log.error("RustDesk: MSI не удалился (код %s) %s", code, " ".join(out.split())[:300])
        return False
    return True


STOP_SERVICE_RE = re.compile(r"^\s*stop-service\s*=", re.I)


def rustdesk_config_files() -> list[Path]:
    """Настройки RustDesk (RustDesk2.toml): этого пользователя (установщик берёт их, запущенный от него) и службы."""
    roots = [os.environ.get("APPDATA") or "",
             str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "ServiceProfiles" / "LocalService" / "AppData"
                 / "Roaming")]
    return [Path(r) / "RustDesk" / "config" / "RustDesk2.toml" for r in roots if r]


def clear_rustdesk_stop_service() -> bool:
    """Снять отметку stop-service из настроек RustDesk. С ней установщик RustDesk службу НЕ создаёт (так он
    понимает «служба остановлена пользователем»), а RustDesk ставит её себе сам — при удалении или неудачной
    установке. Осталась от прежнего RustDesk — каждая новая установка выходила без службы."""
    changed = False
    for path in rustdesk_config_files():
        try:
            lines = path.read_text("utf-8").splitlines(keepends=True)
        except OSError:
            continue
        keep = [ln for ln in lines if not STOP_SERVICE_RE.match(ln)]
        if len(keep) != len(lines):
            try:
                path.write_text("".join(keep), "utf-8")
                log.warning("RustDesk: снята отметка stop-service в %s — иначе служба не создаётся", path)
                changed = True
            except OSError as e:
                log.error("RustDesk: не удалось исправить %s: %s", path, e)
    return changed


def rustdesk_installer() -> Path | None:
    """Официальный установщик RustDesk, вложенный в установщик Retix Hub (rustdesk-<версия>-x86_64.exe)."""
    found = sorted(app_dir().glob("rustdesk-*.exe"), key=lambda p: vkey(p.name.split("-")[1]) or (0,))
    return found[-1] if found else None


def install_rustdesk() -> bool:
    """Тихая установка RustDesk (служба Windows: управление работает и на экране входа, и в окнах UAC)."""
    setup = rustdesk_installer()
    if not setup:
        log.warning("RustDesk: установщик rustdesk-*.exe рядом с программой не найден")
        return False
    log.info("ставлю %s", setup.name)
    clear_rustdesk_stop_service()
    code, out = run_rd([str(setup), "--silent-install"], timeout=900)   # в своём потоке: сеть не ждёт
    if out.strip():
        log.info("RustDesk --silent-install (код %s): %s", code, " ".join(out.split())[:500])
    for _ in range(30):
        if rustdesk_exe() and rustdesk_service_state() != "missing":
            return True
        time.sleep(1)
    log.error("RustDesk не установился: нет %s", "службы RustDesk" if rustdesk_exe() else "rustdesk.exe")
    return False


def rustdesk_servers(server_ip: str | None) -> dict[str, str]:
    """Серверы RustDesk: server_ip — вместо rs-ny.rustdesk.com сервер Retix Hub внутри VPN (порт закрыт,
    RustDesk никуда не ходит); None — обычное облако RustDesk (пустые значения — серверы RustDesk по умолчанию)."""
    if not server_ip:
        return {"custom-rendezvous-server": "", "relay-server": "", "api-server": ""}
    return {"custom-rendezvous-server": server_ip, "relay-server": server_ip, "api-server": f"http://{server_ip}"}


def rustdesk_options(mode: str, whitelist: str, server_ip: str, port: int = REMOTE_PORT,
                     cloud: bool = False) -> dict[str, str]:
    """Настройки RustDesk (rustdesk.exe --option ключ значение) для сети компании. whitelist — адреса через
    запятую: только ПК, которым администратор разрешил управлять (у старого сервера — подсеть компании).
    cloud — ещё и через облако RustDesk (по ID): тогда whitelist не ставится — подключения через сервер-посредник
    RustDesk приходят с его адреса, и whitelist не пустил бы никого. Прямой порт закрыт для интернета firewall."""
    if not whitelist and not cloud:
        raise ValueError("пустой whitelist у RustDesk пускает всех")
    if cloud and mode == "auto":
        # как в обычном RustDesk: одноразовый пароль из окна RustDesk или «Принять»; ПК компании из VPN
        # подключаются, как и раньше, по постоянному паролю от сервера Retix Hub
        approve, verification = "", "use-both-passwords"
    else:
        approve = "password" if mode in ("auto", "own") else "click"
        verification = "use-permanent-password"   # без одноразовых цифровых паролей в окне RustDesk
    return {
        "direct-server": "Y",                      # прямой доступ по IP
        "direct-access-port": str(port),
        "whitelist": "" if cloud else whitelist,
        "approve-mode": approve,
        "verification-method": verification,
        **rustdesk_servers(None if cloud else server_ip),
        "enable-lan-discovery": "N",
        "allow-auto-update": "N",                  # версию RustDesk обновляет установщик Retix Hub
        # тот, кто подключился, получает экран, мышь, клавиатуру, буфер и файлы — и не больше:
        "access-mode": "custom",                   # не «полный доступ» (он включил бы всё ниже)
        "enable-tunnel": "N",                      # без проброса портов через этот ПК в его локальную сеть
        "enable-terminal": "N",                    # без командной строки (в RustDesk она бывает от SYSTEM)
        "allow-remote-config-modification": "N",   # настройки RustDesk этого ПК удалённо не меняются
    }


def configure_rustdesk(exe: Path, options: dict[str, str]) -> bool:
    """Записать настройки через службу RustDesk. True — служба подтвердила главную (прямой доступ)."""
    for key, value in options.items():
        run_rd([str(exe), "--option", key, value])
    code, out = run_rd([str(exe), "--option", "direct-server"])
    got = out.strip().splitlines()[-1].strip() if out.strip() else ""
    if got != options["direct-server"]:
        log.warning("RustDesk: настройки не применились (служба не запущена?): %r", out.strip()[:200])
        return False
    return True


RUSTDESK_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,32}$")
RUSTDESK_ID_EVERY = 300   # сек — как часто перечитывать ID RustDesk этого ПК


def rustdesk_get_id(exe: Path) -> str:
    """ID RustDesk этого ПК (rustdesk.exe --get-id; спрашивает службу). '' — не узнали."""
    code, out = run_rd([str(exe), "--get-id"])
    lines = [x.strip() for x in out.strip().splitlines() if x.strip()]
    rid = lines[-1] if lines else ""
    return rid if RUSTDESK_ID_RE.match(rid) else ""


def configure_rustdesk_servers(exe: Path, server_ip: str | None) -> None:
    """Только серверы RustDesk: сервер Retix Hub в VPN (server_ip) или облако RustDesk (None)."""
    for key, value in rustdesk_servers(server_ip).items():
        run_rd([str(exe), "--option", key, value])


def set_rustdesk_password(exe: Path, password: str) -> bool:
    code, out = run_rd([str(exe), "--password", password])
    if "Done" in out:
        return True
    log.warning("RustDesk: пароль не установлен: %s", out.strip()[:200])
    return False


def new_remote_password() -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(alphabet[b % len(alphabet)] for b in os.urandom(20))


def rustdesk_session_active(port: int = REMOTE_PORT) -> bool:
    """Подключён ли сейчас кто-то к RustDesk этого ПК: установленное TCP-соединение на его порт (из сети Retix Hub)
    или окно подключения RustDesk (rustdesk.exe --cm) — оно открыто, пока идёт сеанс, и через облако RustDesk."""
    if not WINDOWS:
        return False
    ps = (f"$n = (Get-NetTCPConnection -LocalPort {int(port)} -State Established -ErrorAction SilentlyContinue "
          "| Measure-Object).Count; $n += (Get-CimInstance Win32_Process -Filter \"Name='rustdesk.exe'\" "
          "-ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*--cm*' } | Measure-Object).Count; $n")
    code, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=20)
    try:
        return code == 0 and int(out.strip().splitlines()[-1]) > 0
    except (ValueError, IndexError):
        return False


def ensure_remote_firewall(subnet: str | None, port: int = REMOTE_PORT, exe: Path | None = None,
                           cloud: bool = False) -> None:
    """Входящие к RustDesk — только с адресов subnet (ПК, которым разрешено управлять; через запятую). RustDesk вне сети Retix Hub — ни туда, ни оттуда
    («блокировать» в firewall Windows сильнее любого «разрешить», в том числе правил самого RustDesk).
    cloud — облако RustDesk: в интернет RustDesk ходит, закрыт для интернета только прямой порт."""
    run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE_REMOTE}"])
    if subnet:
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_RULE_REMOTE}", "dir=in", "action=allow",
             "protocol=TCP", f"localport={port}", f"remoteip={subnet}", "profile=any"])
    if exe and cloud:
        for name in (FW_RULE_REMOTE_OUT, FW_RULE_REMOTE_IN):
            run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_RULE_REMOTE_IN}", "dir=in",
             "action=block", f"program={exe}", "protocol=TCP", f"localport={port}", f"remoteip={OUTSIDE_VPN}",
             "profile=any"])
        log.info("firewall: RustDesk — и через облако RustDesk; прямой порт — только сеть Retix Hub (%s)", subnet)
    elif exe:
        for name, direction in ((FW_RULE_REMOTE_OUT, "out"), (FW_RULE_REMOTE_IN, "in")):
            run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
            run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={direction}",
                 "action=block", f"program={exe}", f"remoteip={OUTSIDE_VPN}", "profile=any"])
        log.info("firewall: RustDesk — только сеть Retix Hub, входящие из %s", subnet)


def remove_remote_firewall() -> None:
    for name in (FW_RULE_REMOTE, FW_RULE_REMOTE_OUT, FW_RULE_REMOTE_IN):
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])


def disable_remote() -> None:
    """Удалённое управление выключено (в кабинете, выход из сети): RustDesk больше не принимает подключения."""
    exe = rustdesk_exe()
    if exe:
        run_rd([str(exe), "--option", "direct-server", "N"])
    # входящих из сети компании больше нет; RustDesk — снова только в сети Retix Hub (и если было облако RustDesk)
    ensure_remote_firewall(None, REMOTE_PORT, exe)
    log.info("удалённое управление выключено")


def uninstall_remote(state: "State") -> None:
    """Удаление Retix Hub: RustDesk, поставленный этой программой, удаляется; чужой — только перестаёт
    принимать подключения. Правила firewall снимаются."""
    exe = rustdesk_exe()
    if exe and state.get("rustdesk_by_retix"):
        log.info("удаляю RustDesk")
        run_rd([str(exe), "--uninstall"], timeout=300)
    elif exe and state.get("remote_applied"):
        disable_remote()
    remove_remote_firewall()
    state.set(remote_applied="", remote_pw_pending="", rustdesk_by_retix=False)


def rustdesk_args(exe: Path, ip: str, port: int, kind: str, password: str = "") -> list[str]:
    """Командная строка RustDesk: control — управление, files — передача файлов."""
    target = ip if int(port) == REMOTE_PORT else f"{ip}:{int(port)}"
    args = [str(exe), "--file-transfer" if kind == "files" else "--connect", target]
    return args + (["--password", password] if password else [])


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


RESTART_AFTER = 240   # сек — страховка автообновления: программы нет столько после запуска установщика — запустить


def setup_log_path() -> Path:
    """Журнал последней установки или обновления (копирует установщик; его прикладывает «Журнал» администратора)."""
    return log_dir() / "setup.log"


def launch_installer(path: Path) -> None:
    """Тихая установка новой версии. Через «start», а не дочерним процессом: если установщику
    придётся закрыть RetixHub.exe силой, он не погибнет вместе с ним.
    /AUTOUPDATE=1 — после установки установщик сам запустит новый клиент (в трее). Свой журнал установщик
    кладёт в logs\\setup.log (RetixHub.iss)."""
    subprocess.Popen(["cmd", "/c", "start", "", str(path), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                      "/AUTOUPDATE=1"], creationflags=CREATE_NO_WINDOW)
    if getattr(sys, "frozen", False):
        restart_watchdog(Path(sys.executable))


def restart_watchdog(exe: Path, delay: int = RESTART_AFTER) -> None:
    """Страховка: установщик не запустил программу после обновления (или установка не удалась) — через
    несколько минут её запустит отдельный cmd, иначе ПК остаётся без программы до перезагрузки. Программа уже
    работает — ничего не делает (а лишний запуск с --minimized окно не открывает)."""
    name = ntpath.basename(str(exe))
    script = (f'ping -n {delay + 1} 127.0.0.1 >nul & tasklist /NH /FI "IMAGENAME eq {name}" | find /I "{name}" >nul'
              f' || start "" "{exe}" --minimized')
    subprocess.Popen(f'cmd /s /c "{script}"', creationflags=CREATE_NO_WINDOW)


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
            tail = _tail(setup_log_path(), 3_000).decode("utf-8", "replace").replace("\r", "").strip()
            if tail:
                log.warning("журнал установщика (конец):\n%s", tail)
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

def clean_device_name(name: str) -> str:
    """Имя ПК в сети компании: без управляющих символов, пробелы схлопнуты, до 64 символов (как на сервере)."""
    return " ".join("".join(ch for ch in (name or "") if ch.isprintable()).split())[:64]


class Status:
    NEED_LOGIN = "need_login"
    CONNECTING = "connecting"
    ONLINE = "online"
    SERVER_DOWN = "server_down"
    LAN_ONLY = "lan_only"  # сервер недоступен, но ПК офиса связаны напрямую (сохранённые соседи)
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
        self.direct = DirectPaths(self.tunnel)   # прямые пути к ПК своей локальной сети
        self.lan: list[str] = []                 # свои адреса в локальной сети (для соседей)
        self.lan_checked = 0.0
        self.reported = None                     # что последний раз сообщили серверу о локальной сети
        self.radmin_server: bool | None = None   # стоит ли здесь Radmin Server (None — ещё не проверяли)
        self.radmin_checked = 0.0
        self.remote_ok: bool | None = None       # RustDesk установлен и настроен (None — ещё не знаем)
        self.rustdesk_id = ""                    # ID RustDesk этого ПК (для облака RustDesk; сообщаем серверу)
        self.rustdesk_id_at = 0.0
        self.remote_install_at = 0.0
        self.remote_applied_at = 0.0
        self.remote_pw_force = False             # RustDesk только что настроен — нужен свой пароль
        self.remote_session_checked = 0.0        # когда последний раз смотрели, идёт ли сеанс RustDesk
        self.remote_job: threading.Thread | None = None   # установка и настройка RustDesk — в своём потоке
        self.remote_lock = threading.Lock()      # работа с RustDesk (фон и меню «Управление») — по одной
        self.last_peers: list[dict] = []         # список компьютеров с последнего ответа сервера
        self.nics: list[dict] | None = None      # свои сетевые карты для включения по сети (None — не сообщаем)
        self.nics_checked = 0.0
        self.log_sent_at = 0.0                   # когда последний раз отправляли журнал администратору
        self.last_status = ""                    # последний статус (для журнала администратору)
        # шаг цикла и смена компании (вход, переключение, выход) не идут одновременно
        self.op_lock = threading.RLock()

    # --- связь с GUI
    def emit(self, kind: str, **data):
        self.events.put((kind, data))

    def status(self, status: str, text: str = "", cfg: dict | None = None):
        self.last_status = f"{status}: {text}" if text else status
        self.emit("status", status=status, text=text, cfg=cfg or self.cfg)

    # --- команды из GUI (вызываются в отдельном потоке)
    def login(self, server: str, company: str, password: str, device: str, remember: bool):
        """Вход в компанию. Другая компания, чем текущая, — добавляется: текущая уходит в сохранённые
        (Компания → переключиться), у новой — свой ключ WireGuard (для сервера это другой ПК).
        Не вышло — всё как было."""
        try:
            server = normalize_server_url(server)
        except ValueError as e:
            return str(e)
        company = company.strip()
        with self.op_lock:
            snap = self.state.snapshot()
            target = State.profile_key(server, company)
            if target != self.state.current_key() and self.state.get("company_login"):
                self.state.stash_current()
                if not self.state.activate(target):   # уже в списке — тот же ключ, тот же ПК на сервере
                    self.state.set(token="", private_key="", join_password="", company_name="", last_conf_hash="",
                                   direct_cache={}, can_control=False)
            self.state.set(server_url=server, company_login=company, device_name=clean_device_name(device))
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
        self.direct.reset()
        self.lan, self.lan_checked, self.reported = [], 0.0, None
        self.last_peers = []

    def _uninstall(self):
        self.tunnel.uninstall()
        self.direct.reset()

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
        self.state.set(token="", join_password="", last_conf_hash="", direct_cache={}, can_control=False)
        try:
            self._uninstall()
        finally:
            if self.state.get("fw_subnet"):
                ensure_firewall(None)
                self.state.set(fw_subnet="")
            if self.state.get("fw_direct"):
                ensure_direct_firewall(0)
                self.state.set(fw_direct=0)
            if self.state.get("remote_applied"):
                disable_remote()
                self.state.set(remote_applied="", remote_pw_pending="")
                self.remote_ok = False
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

    def rename(self, name: str) -> str | None:
        """Сменить имя этого ПК в сети компании (из потока окна). None — готово, иначе текст ошибки."""
        name = clean_device_name(name)
        if not name:
            return "Введите имя компьютера."
        if not self.state.get("token"):
            # ещё не подключён — имя уйдёт на сервер при входе
            self.state.set(device_name=name)
            return None
        try:
            res = self.api.rename(name)
        except ApiError as e:
            if e.status in (404, 405):
                return "Сервер ещё не умеет менять имя из программы — попросите администратора компании."
            return e.detail
        except ServerUnreachable:
            return "Сервер недоступен, имя не изменено."
        name = clean_device_name(str((res or {}).get("device_name") or name)) or name
        log.info("имя компьютера: %s", name)
        self.state.set(device_name=name)
        if self.cfg:
            self.cfg = dict(self.cfg, device_name=name)
        self.wake.set()   # список компьютеров с новым именем — сразу
        return None

    def send_message(self, to: int, text: str) -> str | None:
        """Отправить сообщение ПК своей компании (из потока окна). None — отправлено, иначе текст ошибки."""
        try:
            self.api.send_message(to, text)
        except ApiError as e:
            return e.detail
        except ServerUnreachable:
            return "Сервер недоступен, сообщение не отправлено."
        return None

    def remote_connect(self, to: int, kind: str = "control") -> tuple[dict | None, str | None]:
        """Разрешение сервера подключиться к ПК через RustDesk (из потока окна): (ответ, None) или (None, ошибка)."""
        try:
            return self.api.remote_connect(to, kind), None
        except ApiError as e:
            if e.status in (404, 405) and "Компьютер" not in e.detail:
                return None, "Сервер Retix Hub ещё не умеет удалённое управление — его нужно обновить."
            return None, e.detail
        except ServerUnreachable:
            return None, "Сервер недоступен: без него подключение не разрешается."

    def wake_peer(self, to: int) -> tuple[str | None, str | None]:
        """Включить выключенный ПК компании по сети (из потока окна): (сообщение, None) или (None, ошибка)."""
        try:
            return str(self.api.wake(to).get("message") or "Команда включения отправлена"), None
        except ApiError as e:
            if e.status in (404, 405) and "Компьютер" not in e.detail:
                return None, "Сервер Retix Hub ещё не умеет включать компьютеры по сети — его нужно обновить."
            return None, e.detail
        except ServerUnreachable:
            return None, "Сервер недоступен: без него включить компьютер нельзя."

    # --- включение по сети: свои сетевые карты для сервера и команды «разбуди соседа»
    def _wol_step(self, now: float):
        if self.cfg.get("wol") is not True:
            self.nics = None   # удалённое управление выключено — MAC серверу не сообщаем
            return
        jobs = self.cfg.get("wake") if isinstance(self.cfg.get("wake"), list) else []
        every = NICS_CHECK_EVERY if self.nics is not None else 60
        if now - self.nics_checked > every or (jobs and not self.nics):
            found = local_nics()
            if found is not None:
                self.nics = found
            self.nics_checked = now
        for job in jobs:
            if not wake_job_ok(job, self.nics):
                log.warning("включение по сети: команда не для своей локальной сети — пропущена: %s", job)
                continue
            ok = send_magic_packet(job["mac"], str(job["broadcast"]))
            log.info("включение по сети: %s (%s) через %s — %s", str(job.get("name"))[:64], clean_mac(job["mac"]),
                     job["broadcast"], "пакет отправлен" if ok else "ошибка")

    # --- журнал программы по запросу администратора (кабинет → «Журнал»)
    def _log_header(self) -> str:
        cfg = self.cfg or {}
        nics = ", ".join(f"{n['addr']} {n['mac']}" for n in self.nics or []) or "—"
        lines = [f"Retix Hub {VERSION} — журнал программы для администратора компании",
                 f"Собран: {time.strftime('%Y-%m-%d %H:%M:%S %z')}",
                 f"Компьютер: {socket.gethostname()} · {platform.platform()}",
                 f"Компания: {self.state.get('company_name') or self.state.get('company_login') or '—'} · "
                 f"ПК: {self.state.get('device_name') or '—'} · IP: {cfg.get('ip') or '—'}",
                 f"Состояние: {self.last_status or '—'}",
                 f"Служба туннеля: {self.tunnel.service_state()}",
                 f"Локальная сеть: {', '.join(self.lan) or '—'} · прямые пути: {self.direct.active_ids() or '—'}",
                 f"Сетевые карты: {nics}"]
        if WINDOWS:
            _, out = run([str(WG_EXE), "show", TUNNEL], timeout=15)   # без закрытого ключа: wg его не показывает
            lines += ["", "--- wg show", out.strip()]
        try:
            lines += ["", "--- удалённое управление", self.rustdesk_status()]
        except Exception:  # noqa: BLE001
            log.exception("состояние RustDesk для журнала")
        crash = _tail(log_dir() / "crash.log", 64_000)
        if crash.strip():
            lines += ["", "--- crash.log (конец)", crash.decode("utf-8", "replace").rstrip()]
        setup = _tail(setup_log_path(), 16_000)
        if setup.strip():
            lines += ["", "--- журнал последней установки (setup.log, конец)",
                      setup.decode("utf-8", "replace").replace("\r", "").rstrip()]
        return "\n".join(lines + ["", "--- client.log", ""])

    def _log_step(self, now: float):
        if self.cfg.get("log_request") is not True or now - self.log_sent_at < LOG_RETRY:
            return
        self.log_sent_at = now
        try:
            data = pack_log(self._log_header(), log_files_text())
            self.api.upload_log(data)
            log.info("журнал отправлен администратору компании (%d КБ)", len(data) // 1024)
        except (ApiError, ServerUnreachable) as e:
            log.warning("журнал администратору не отправлен: %s", getattr(e, "detail", e))

    REMOTE_ASYNC = True   # в тестах — False: работа с RustDesk сразу, в том же потоке

    def _remote_step(self, now: float):
        """Удалённое управление (RustDesk). Установка и команды rustdesk.exe идут в отдельном потоке: основной
        цикл (туннель, прямые пути, список ПК) никогда их не ждёт, что бы ни случилось с RustDesk."""
        remote = self.cfg.get("remote") if isinstance(self.cfg.get("remote"), dict) else {}
        if remote.get("mode") not in REMOTE_MODES and remote.get("can_control") is not True \
                and not self.state.get("remote_applied"):
            self.remote_ok = False   # выключено, управлять другими нельзя, ничего не настроено — делать нечего
            return
        if not self.REMOTE_ASYNC:
            self._remote_work(now, self.cfg)
            return
        if self.remote_job and self.remote_job.is_alive():
            return                   # прошлая работа с RustDesk ещё идёт — не ждём её
        cfg = dict(self.cfg)
        self.remote_job = threading.Thread(target=self._remote_job, args=(now, cfg), daemon=True, name="rustdesk")
        self.remote_job.start()

    def _remote_job(self, now: float, cfg: dict):
        try:
            with self.remote_lock:
                self._remote_work(now, cfg)
        except Exception:  # noqa: BLE001
            log.exception("удалённое управление")

    def _remote_work(self, now: float, cfg: dict):
        remote = cfg.get("remote") if isinstance(cfg.get("remote"), dict) else {}
        admin = remote.get("mode") if remote.get("mode") in REMOTE_MODES else "off"
        own_pw = unprotect(self.state.get("remote_own_pw") or "")
        mode = combine_remote_mode(admin, self.state.get("remote_local") or "", bool(own_pw))
        can_ctrl = remote.get("can_control", admin != "off") is True   # старый сервер поля не шлёт
        cloud = remote.get("cloud") is True and admin != "off"   # и через облако RustDesk (галочка в кабинете)
        if isinstance(remote.get("allowed"), list):
            # пускаем только ПК, которым администратор разрешил управлять (и только адреса своей подсети)
            allowed = [ip for ip in remote["allowed"] if peer_ip_ok(ip, cfg["subnet"])][:254]
        else:
            allowed = [cfg["subnet"]] if admin != "off" else []   # сервер до 1.0.18: вся подсеть компании
        if not allowed and not cloud:
            mode = "off"   # управлять некому — RustDesk никого не пускает (пустой whitelist пустил бы всех)
        if mode == "off" and not can_ctrl:
            if self.state.get("remote_applied"):
                disable_remote()
                exe = rustdesk_exe()
                if exe and "cloud" in self.state.get("remote_applied"):   # было облако — серверы снова свои
                    configure_rustdesk_servers(exe, cfg["server_ip"])
                self.state.set(remote_applied="", remote_pw_pending="")
            self.remote_ok = False
            return
        port = remote.get("port") if isinstance(remote.get("port"), int) and 0 < remote["port"] < 65536 \
            else REMOTE_PORT
        exe = rustdesk_exe()
        # «установлен» — это и файлы, и служба: после оборванной установки (1.0.16) файлы есть, службы нет
        installed = bool(exe) and rustdesk_service_state() != "missing"
        if not installed and now - self.remote_install_at > REMOTE_INSTALL_RETRY:
            self.remote_install_at = now
            if exe:
                log.warning("RustDesk: rustdesk.exe есть, а службы нет — ставлю заново")
                product = rustdesk_msi_product()
                if product:
                    remove_rustdesk_msi(product)
            if install_rustdesk():
                self.state.set(rustdesk_by_retix=True, remote_applied="")
                installed = True
            exe = rustdesk_exe()
        if not exe or not installed:
            self.remote_ok = False
            return
        if not start_rustdesk():
            log.warning("RustDesk: служба не отвечает — настройки не применить, повторю позже")
            self.state.set(remote_applied="")
            self.remote_ok = False
            return
        self._rustdesk_id_step(exe, now)
        if mode == "off":
            # этот ПК только управляет другими: его RustDesk подключений не принимает (с облаком — и через
            # облако: whitelist 127.0.0.1 не пускает никого), а сам может подключаться и через облако по ID
            want = "off|cloud" if cloud else "off"
            if self.state.get("remote_applied") != want:
                disable_remote()
                ensure_remote_firewall(None, port, exe, cloud=cloud)
                if cloud:
                    run_rd([str(exe), "--option", "whitelist", "127.0.0.1"])
                if cloud or "cloud" in (self.state.get("remote_applied") or ""):
                    configure_rustdesk_servers(exe, None if cloud else cfg["server_ip"])
                self.state.set(remote_applied=want, remote_pw_pending="")
                log.info("удалённое управление: этим ПК управлять нельзя, он может управлять другими%s",
                         " (и через облако RustDesk)" if cloud else "")
            self.remote_ok = False
            return
        whitelist = ",".join(allowed)
        own_tag = hashlib.sha256(own_pw.encode()).hexdigest()[:12] if mode == "own" else ""
        want = f"{mode}|{whitelist}|{cfg['server_ip']}|{port}|{own_tag}" + ("|cloud" if cloud else "")
        if want != self.state.get("remote_applied") or now - self.remote_applied_at > REMOTE_REAPPLY:
            ensure_remote_firewall(whitelist, port, exe, cloud=cloud)
            ok = configure_rustdesk(exe, rustdesk_options(mode, whitelist, cfg["server_ip"], port, cloud=cloud))
            self.remote_applied_at = now
            if ok and mode == "own" and want != self.state.get("remote_applied"):
                ok = set_rustdesk_password(exe, own_pw)   # пароль пользователя — только в RustDesk, не на сервер
            if not ok:
                self.state.set(remote_applied="")
                self.remote_ok = False
                return
            if want != self.state.get("remote_applied"):
                log.info("удалённое управление: %s, пускаем %s%s, RustDesk настроен", mode, whitelist or "—",
                         ", и через облако RustDesk по ID" if cloud else "")
                # новые настройки (RustDesk поставлен заново, был свой пароль) — пароль для сервера тоже новый
                self.remote_pw_force = mode == "auto"
                self.state.set(remote_applied=want)
        self.remote_ok = True
        if mode == "auto":
            self._remote_password(exe, bool(remote.get("rotate")), port, now)

    def _rustdesk_id_step(self, exe: Path, now: float):
        """ID RustDesk этого ПК — серверу Retix Hub (в heartbeat): по нему подключаются через облако RustDesk."""
        if now - self.rustdesk_id_at < (RUSTDESK_ID_EVERY if self.rustdesk_id else 60):   # не узнали — через минуту
            return
        self.rustdesk_id_at = now
        rid = rustdesk_get_id(exe)
        if rid and rid != self.rustdesk_id:
            log.info("ID RustDesk этого ПК: %s", rid)
            self.rustdesk_id = rid
            self.wake.set()

    def rustdesk_status(self) -> str:
        """Текст для окна «Управление → Состояние RustDesk»."""
        exe = rustdesk_exe()
        service = rustdesk_service_state()
        remote = (self.cfg or {}).get("remote") if isinstance((self.cfg or {}).get("remote"), dict) else {}
        admin = remote.get("mode") if remote.get("mode") in REMOTE_MODES else "off"
        mode = combine_remote_mode(admin, self.state.get("remote_local") or "",
                                   bool(self.state.get("remote_own_pw")))
        titles = {"off": "нельзя", "ask": "только с согласием", "auto": "без согласия (пароль от сервера)",
                  "own": "по вашему паролю"}
        lines = [f"RustDesk:  {'установлен' if exe else 'не установлен'}",
                 "Служба RustDesk:  " + {"running": "работает", "stopped": "остановлена"}.get(service, "нет"),
                 f"Связь со службой:  {'есть' if rustdesk_ready() else 'нет'}",
                 f"Управлять этим ПК:  {titles[mode]}",
                 f"Этот ПК управляет другими:  {'да' if remote.get('can_control') is True else 'нет'}",
                 f"Облако RustDesk (по ID):  {'включено' if remote.get('cloud') is True else 'выключено'}",
                 f"ID RustDesk этого ПК:  {self.rustdesk_id or '—'}",
                 f"Готов к подключению:  {'да' if self.remote_ok else 'нет'}"]
        if self.state.get("rustdesk_by_retix"):
            lines.append("RustDesk поставлен программой Retix Hub (удалится вместе с ней)")
        return "\n".join(lines)

    def repair_rustdesk(self, reinstall: bool = False) -> tuple[bool, str]:
        """Меню «Управление»: поставить/запустить службу RustDesk или переставить RustDesk целиком.
        (True/False, текст для пользователя). Вызывается из потока окна, ждёт фоновую работу с RustDesk."""
        with self.remote_lock:
            exe = rustdesk_exe()
            service = rustdesk_service_state() if exe else "missing"
            if not reinstall and exe and service == "running" and start_rustdesk():
                ok, text = True, "RustDesk работает, служба запущена."
            elif not reinstall and exe and service == "stopped":
                ok = start_rustdesk()
                text = "Служба RustDesk запущена." if ok else "Служба RustDesk не запустилась — попробуйте «Переустановить RustDesk»."
            else:
                if not rustdesk_installer():
                    return False, ("Установщика RustDesk нет рядом с программой.\n"
                                   "Переустановите Retix Hub последней версией — RustDesk внутри неё.")
                product = rustdesk_msi_product()
                if product:
                    remove_rustdesk_msi(product)
                log.info("RustDesk: %s по команде пользователя", "переустановка" if reinstall else "установка службы")
                ok = install_rustdesk() and start_rustdesk()
                if ok:
                    self.state.set(rustdesk_by_retix=True)
                text = ("RustDesk установлен, служба работает." if ok else
                        "RustDesk не установился. Подробности — в журнале (Система → Открыть журнал).")
            exe = rustdesk_exe()
            if exe:   # что бы ни было в настройках RustDesk — в интернет и из интернета он не ходит
                ensure_remote_firewall(None, REMOTE_PORT, exe)
            self.state.set(remote_applied="", remote_pw_pending="")   # настроить заново в следующем шаге
            self.remote_applied_at = 0
            self.remote_install_at = 0
        self.wake.set()
        return ok, text

    def set_remote_access(self, local: str, password: str = "") -> str | None:
        """Пользователь выбрал, как можно управлять его ПК (из окна). None — сохранено, иначе текст ошибки."""
        if local not in REMOTE_LOCAL_CHOICES:
            return "Неизвестный режим"
        if local == "own":
            if password:
                if not OWN_PW_RE.match(password):
                    return "Пароль: от 8 до 64 латинских букв, цифр и знаков, без пробелов."
                # тот же пароль блокирует и саму программу: чужой человек за этим ПК без него ничего не сделает
                self.state.set(remote_own_pw=protect(password), lock_hash=hash_lock_pw(password), lock_on=True)
            elif not self.state.get("remote_own_pw"):
                return "Придумайте пароль."
        self.state.set(remote_local=local)
        self.remote_applied_at = 0   # RustDesk перенастроится в следующем шаге (или будет выключен)
        log.info("доступ к этому компьютеру: %s", REMOTE_LOCAL_CHOICES[local])
        self.reported = None    # сразу сообщить серверу
        self.wake.set()
        return None

    # --- блокировка программы паролем этого компьютера
    def can_control(self) -> bool:
        """Администратор разрешил этому ПК управлять другими (по последнему ответу сервера)."""
        return self.state.get("can_control") is True

    def lock_ready(self) -> bool:
        """Блокировать программу: включено, есть пароль и этот ПК может управлять другими. Компьютеры без
        права удалённого управления не блокируются, даже если блокировка включена в настройках."""
        return bool(self.state.get("lock_on") and self.state.get("lock_hash")) and self.can_control()

    def check_unlock(self, password: str) -> bool:
        return check_lock_pw(password, self.state.get("lock_hash") or "")

    def set_lock(self, on: bool, minutes: int, password: str = "") -> str | None:
        """Включить / выключить блокировку и задать её пароль. None — сохранено, иначе текст ошибки."""
        if minutes not in LOCK_MINUTES:
            return "Выберите, через сколько минут блокировать программу."
        if password:
            if not LOCK_PW_RE.match(password):
                return "Пароль: от 4 до 64 символов, без пробелов."
            self.state.set(lock_hash=hash_lock_pw(password))
        if on and not self.state.get("lock_hash"):
            return "Придумайте пароль — им программа будет разблокироваться."
        self.state.set(lock_on=bool(on), lock_minutes=minutes)
        log.info("блокировка программы: %s", f"через {minutes} мин без действий" if on else "выключена")
        return None

    def reset_lock(self, join_password: str) -> str | None:
        """Забыли пароль блокировки: подтвердить паролем подключения компании (его знает администратор) —
        блокировка снимается, пароль задаётся заново. Пароль не сохранён — проверяет сервер (повторный вход)."""
        if not join_password:
            return "Введите пароль подключения компании."
        saved = self.state.get("join_password") or ""
        if saved:
            if not hmac.compare_digest(saved.encode("utf-8"), join_password.encode("utf-8")):
                return "Неверный пароль подключения компании."
        else:
            if not (self.state.get("company_login") and self.state.get("token")):
                return "Этот компьютер не подключён к компании — пароль подключения проверить нечем."
            err = self.login(self.state.get("server_url"), self.state.get("company_login"), join_password,
                             self.state.get("device_name") or socket.gethostname(), remember=False)
            if err:
                return err
        self.state.set(lock_on=False, lock_hash="")
        log.warning("блокировка программы снята паролем подключения компании")
        return None

    def _remote_password(self, exe: Path, rotate: bool, port: int, now: float):
        """Свой пароль RustDesk: ставится в RustDesk и сообщается серверу. Сервер просит сменить (rotate) —
        после выдачи пароля другому ПК; пока идёт сеанс, пароль не меняем."""
        pending = unprotect(self.state.get("remote_pw_pending") or "")
        if not pending:
            if not (rotate or self.remote_pw_force):
                return
            if not self.remote_pw_force:
                if now - self.remote_session_checked < REMOTE_SESSION_CHECK:
                    return
                self.remote_session_checked = now
                if rustdesk_session_active(port):
                    return
            pending = new_remote_password()
            if not set_rustdesk_password(exe, pending):
                return
            self.remote_pw_force = False
            self.state.set(remote_pw_pending=protect(pending))
            log.info("удалённое управление: пароль RustDesk сменён")
        try:
            self.api.remote_password(pending)
            self.state.set(remote_pw_pending="")
        except (ApiError, ServerUnreachable) as e:
            log.warning("пароль RustDesk не передан серверу: %s", getattr(e, "detail", e))

    # --- внутреннее
    def _register(self, password: str):
        # старый токен забываем до запроса: если ответ потеряется, он не уйдёт на сервер снова
        # (старый токен сервер считает копией входа и отключает ПК)
        self.state.set(token="")
        priv, pub = self.state.keypair()
        res = self.api.register(self.state.get("company_login"), password,
                                self.state.get("device_name") or socket.gethostname(), pub, priv)
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
            self._wait(time.time() + CHECK_EVERY)
            self.wake.clear()

    def _wait(self, deadline: float):
        """Пауза до следующего шага. Пока проверяется прямой путь к соседу — раз в секунду смотрим
        handshake (только wg show, без запросов к серверу): обе стороны включают прямой путь почти
        одновременно, и соседу не приходится ждать до следующего шага."""
        while not self.stop_flag:
            left = deadline - time.time()
            if left <= 0:
                return
            fast = self.direct.probing() and not self.paused
            if self.wake.wait(min(left, DIRECT_TICK) if fast else left):
                return
            if fast:
                try:
                    with self.op_lock:
                        self.direct.poll()
                except Exception:  # noqa: BLE001
                    log.exception("прямой путь")

    def _direct_step(self, now: float):
        enabled = bool(self.cfg.get("direct_enabled"))
        if enabled and now - self.lan_checked > LAN_CHECK_EVERY:
            found = local_addresses()
            if found is None:
                # не прочитались (PowerShell не успел за 20 с при нагрузке): оставляем прежние. Иначе сервер
                # на минуту решал, что у ПК нет локальной сети, соседи закрывали прямой путь, а через 35 с
                # без пакетов его закрывал и этот ПК — путь «моргал» каждые несколько минут
                log.warning("адреса локальной сети не прочитаны — оставляем прежние")
                found = self.lan
            self.lan, self.lan_checked = found, now
        elif not enabled:
            self.lan = []
        _, pub = self.state.keypair()
        try:
            if isinstance(self.cfg.get("time"), int) and not isinstance(self.cfg.get("time"), bool):
                self.direct.clock = self.cfg["time"] - now
            lan = direct_neighbors(self.cfg, pub) if enabled else []
            wan = wan_neighbors(self.cfg, pub, skip={n["public_key"] for n in lan}) if enabled else []
            self.direct.sync(lan + wan, self.cfg["server_public_key"])
        except Exception:  # noqa: BLE001
            log.exception("прямой путь")
        if enabled and self.lan:
            self._ensure_port()
        want = self.direct.listen_port if enabled and self.lan else 0
        if want != (self.state.get("fw_direct") or 0):
            ensure_direct_firewall(want)
            self.state.set(fw_direct=want)

    # --- сохранённые соседи: прямой путь без сервера (нет интернета, перезагрузка без интернета)
    # После каждого ответа сервера в state.json (папка только для SYSTEM и администраторов) записываются
    # соседи, с которыми прямой путь уже работал и которых сервер называет сейчас, и порт своего туннеля.
    # Сервер недоступен — прямые пути поднимаются по этому списку (с той же проверкой handshake).
    # Сервер ответил — его список заменяет сохранённый: заблокированный/удалённый ПК исчезает сразу.

    def _direct_cache(self) -> dict:
        c = self.state.get("direct_cache")
        return c if isinstance(c, dict) else {}

    def _ensure_port(self):
        """Порт туннеля — тот же, что раньше: соседи знают его по сохранённому списку, даже если оба ПК
        перезагрузились без интернета. Нет сохранённого или он занят — свой случайный (если WireGuard не
        сообщил порт сам). Сервер узнает новый адрес ПК по первому же пакету (роуминг WireGuard)."""
        if self.direct.port_done:
            return
        saved = self._direct_cache().get("my_port")
        saved = saved if isinstance(saved, int) and 1024 <= saved < 65536 else 0
        if saved and self.direct.listen_port != saved and self.tunnel.set_listen_port(saved):
            self.direct.listen_port = self.direct.own_port = saved
        elif not self.direct.listen_port:
            port = 49152 + int.from_bytes(os.urandom(2), "big") % 16000
            if self.tunnel.set_listen_port(port):
                self.direct.listen_port = self.direct.own_port = port
        self.direct.port_done = bool(self.direct.listen_port)

    def _save_direct_cache(self, now: float):
        cfg = self.cfg or {}
        old = self._direct_cache()
        if not cfg.get("direct_enabled"):
            if old:
                self.state.set(direct_cache={})
            return
        _, pub = self.state.keypair()
        prev = {n.get("public_key"): n for n in old.get("neighbors") or [] if isinstance(n, dict)}
        names = {p.get("id"): p for p in self.last_peers}
        neighbors = []
        for n in direct_neighbors(cfg, pub):                 # только те, кого сервер называет сейчас
            key, before = n["public_key"], prev.get(n["public_key"]) or {}
            if key in self.direct.active:
                verified = now
                first = [e for e in [self.direct.endpoints.get(key, "")] if lan_endpoint_ok(e)]
            elif before:
                verified = before.get("verified_at") or 0
                first = [e for e in (before.get("endpoints") or [])[:1] if lan_endpoint_ok(e)]
            else:
                continue                                     # прямой путь с ним ещё не работал
            p = names.get(n["id"]) or before
            neighbors.append({"id": n["id"], "public_key": key, "ip": n["ip"],
                              "endpoints": list(dict.fromkeys(first + n["endpoints"]))[:4],
                              "verified_at": int(verified), "name": str(p.get("name") or "")[:64],
                              "hostname": str(p.get("hostname") or "")[:64]})
        new = {"cfg": {"device_id": cfg.get("device_id"), "device_name": str(cfg.get("device_name") or "")[:64],
                       "company": str(cfg.get("company") or "")[:100], "ip": cfg["ip"], "subnet": cfg["subnet"],
                       "server_ip": cfg["server_ip"], "server_public_key": cfg["server_public_key"],
                       "show_peers": cfg.get("show_peers") is not False, "direct_enabled": True},
               "my_port": self.direct.listen_port or old.get("my_port") or 0, "neighbors": neighbors}

        def same(a, b):   # без отметок времени: «сосед на связи» не повод писать на диск каждые 8 с
            strip = lambda c: dict(c, saved_at=0, neighbors=[dict(x, verified_at=0) for x in c.get("neighbors") or []])
            return strip(a) == strip(b)
        if not same(new, old) or now - (old.get("saved_at") or 0) > DIRECT_CACHE_REFRESH:
            self.state.set(direct_cache=dict(new, saved_at=int(now)))

    def _offline_direct(self, now: float) -> bool:
        """Сервер недоступен: прямые пути по сохранённым соседям. True — хотя бы с одним ПК связь напрямую."""
        cache = self._direct_cache()
        cfg = cache.get("cfg") if isinstance(cache.get("cfg"), dict) else {}
        ttl = DIRECT_CACHE_DAYS * 86400
        fresh = now - (cache.get("saved_at") or 0) < ttl
        try:
            if not (fresh and cfg.get("direct_enabled") and KEY_RE.match(str(cfg.get("server_public_key")))
                    and peer_ip_ok(cfg.get("ip"), cfg.get("subnet"))):
                raise ValueError("нет сохранённых соседей")
            if not self._offline_tunnel():
                return False
            _, pub = self.state.keypair()
            saved = [n for n in cache.get("neighbors") or []
                     if isinstance(n, dict) and now - (n.get("verified_at") or 0) < ttl]
            neighbors = direct_neighbors(dict(cfg, direct=saved), pub)
            server_key = cfg["server_public_key"]
            # прямые пути через интернет, которые уже работают, остаются: интернет может быть, а сервера нет.
            # Пропадёт и интернет — от соседа не будет пакетов, и путь закроется сам.
            have = {n["public_key"] for n in neighbors}
            neighbors += [n for k, n in self.direct.wanted.items()
                          if n.get("wan") and k in self.direct.active and k not in have and server_key == self.direct.server_key]
        except (ValueError, TypeError, KeyError):
            if not self.direct.wanted:
                return False
            neighbors, server_key = [], self.direct.server_key   # срок вышел — прямые пути закрываем
        try:
            self.direct.sync(neighbors, server_key)
            if neighbors:
                self._ensure_port()
        except Exception:  # noqa: BLE001
            log.exception("прямой путь без сервера")
        return bool(self.direct.active_ids())

    def _offline_tunnel(self) -> bool:
        """Без сервера: туннель этого ПК и этой компании работает. Служба остановлена — запускаем; туннель
        снят (кнопка OFF, потом ON) — ставим из последнего конфига, если он этой компании (её ключ)."""
        priv, pub = self.state.keypair()
        svc = self.tunnel.service_state()
        if svc == "missing":
            conf = self.tunnel.saved_conf()
            if not conf or f"PrivateKey = {priv}\n" not in conf:
                return False
            log.info("сервер недоступен — туннель из последнего конфига, для локальной сети")
            self.tunnel.install(conf)
            self.direct.reset()
            self.state.set(last_conf_hash=hashlib.sha256(conf.encode()).hexdigest())
            self.last_install = time.time()
        elif svc == "stopped":
            self.tunnel.start()
        state = self.tunnel.dump()
        # туннель другой компании (переключились без сервера) — её соседей в него не добавляем
        return bool(state) and state.get("public_key") == pub

    def _offline_view(self) -> dict:
        """Что показать в окне без ответа сервера (после перезагрузки без интернета)."""
        cfg = self._direct_cache().get("cfg") or {}
        return {"device_name": cfg.get("device_name") or self.state.get("device_name"), "ip": cfg.get("ip"),
                "company": cfg.get("company") or self.state.get("company_name"),
                "show_peers": cfg.get("show_peers", True)}

    def _offline_peers(self) -> list[dict]:
        """Список компьютеров без сервера: в сети — те, с кем связь напрямую."""
        cache = self._direct_cache()
        cfg = cache.get("cfg") or {}
        base = self.last_peers or [
            {"id": n.get("id"), "name": n.get("name") or n.get("ip"), "hostname": n.get("hostname") or "",
             "ip": n.get("ip"), "is_me": False, "is_share_host": False}
            for n in cache.get("neighbors") or [] if isinstance(n, dict) and peer_ip_ok(n.get("ip"), cfg.get("subnet"))]
        if cfg.get("show_peers") is False:
            base = [p for p in base if p.get("is_me")]
        direct, wan = set(self.direct.active_ids()), self.direct.wan_ids()
        return [dict(p, online=bool(p.get("is_me")) or p.get("id") in direct, direct=p.get("id") in direct,
                     direct_wan=p.get("id") in wan) for p in base]

    def step(self):
        if not self.tunnel.installed() and not install_wireguard_if_needed():
            self.status(Status.ERROR, "WireGuard не установлен. Установите WireGuard for Windows.")
            return

        # 0. выключено кнопкой
        if self.state.get("enabled") is False:
            if self.tunnel.service_state() != "missing":
                self._uninstall()
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
            if self._offline_direct(time.time()):
                n = len(self.direct.active_ids())
                self.status(Status.LAN_ONLY, f"Нет связи с сервером — компьютеры офиса доступны напрямую ({n})",
                            cfg=self.cfg or self._offline_view())
                self.emit("peers", peers=self._offline_peers())
            else:
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
                    self._uninstall()
                self.state.set(direct_cache={})
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
        ctrl = remote_can_control(self.cfg)
        if ctrl != (self.state.get("can_control") is True):
            self.state.set(can_control=ctrl)
            log.info("право управлять другими ПК: %s", "есть — программа блокируется паролем" if ctrl
                     else "нет — программа не блокируется")
        # имя могли сменить в кабинете — запоминаем, иначе повторный вход вернул бы старое
        name = clean_device_name(str(self.cfg.get("device_name") or ""))
        if name and name != self.state.get("device_name"):
            self.state.set(device_name=name)
        # администратор запросил журнал — отправляем сразу, даже если ПК ждёт одобрения или заблокирован
        try:
            self._log_step(time.time())
        except Exception:  # noqa: BLE001
            log.exception("журнал для администратора")

        if self.cfg["status"] == "blocked":
            if self.tunnel.service_state() != "missing":
                self._uninstall()
            self.state.set(direct_cache={})
            self.status(Status.BLOCKED, "Устройство заблокировано администратором")
            return
        if self.cfg["status"] == "pending":
            # ПК снова ждёт одобрения (например, вход скопирован на другой ПК): прямых путей у него быть не должно
            self.state.set(direct_cache={})
            try:
                self.direct.sync([], self.cfg["server_public_key"])
            except Exception:  # noqa: BLE001
                log.exception("прямой путь")
            self.status(Status.PENDING, "Ожидает одобрения администратора компании")
            return

        # включение по сети: команды «разбуди соседа» приходят в этом ответе один раз — до всего, что может
        # закончить шаг раньше (переустановка туннеля)
        try:
            self._wol_step(time.time())
        except Exception:  # noqa: BLE001
            log.exception("включение по сети")

        # 3. туннель: установлен, актуален, жив?
        priv, _ = self.state.keypair()
        conf = self.tunnel.build_conf(self.cfg, priv)
        conf_hash = hashlib.sha256(conf.encode()).hexdigest()
        svc = self.tunnel.service_state()
        now = time.time()
        hs = self.tunnel.last_handshake(self.cfg["server_public_key"]) if svc == "running" else 0
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
            self.direct.reset()    # новый туннель — без прямых пиров, проверим их заново
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

        # 5. удалённое управление (RustDesk) — по режиму из кабинета компании
        try:
            self._remote_step(now)
        except Exception:  # noqa: BLE001
            log.exception("удалённое управление")

        # 6. прямые пути к ПК своей локальной сети (компания с «любым трафиком между ПК»)
        self._direct_step(now)

        # 7. список компьютеров компании
        try:
            peers = self.api.peers()["peers"]
        except (ApiError, ServerUnreachable):
            peers = []
        direct, wan = set(self.direct.active_ids()), self.direct.wan_ids()
        peers = [dict(p, direct=p.get("id") in direct, direct_wan=p.get("id") in wan)
                 for p in peers if peer_ip_ok(p.get("ip"), self.cfg["subnet"])]
        self.emit("peers", peers=peers)
        if peers:
            self.last_peers = peers
        self._save_direct_cache(now)

        # 8. новые сообщения от других ПК
        try:
            msgs = self.api.messages()["messages"]
            if msgs:
                log.info("сообщений: %d", len(msgs))
                self.emit("messages", messages=msgs)
        except (ApiError, ServerUnreachable):
            pass

        # адреса локальной сети, порт туннеля и прямые пути изменились — сообщаем серверу сразу
        if now - self.radmin_checked > RADMIN_CHECK_EVERY:
            try:
                self.radmin_server = radmin_server_installed()
            except Exception:  # noqa: BLE001
                log.exception("проверка Radmin Server")
            self.radmin_checked = now
        port = self.direct.listen_port if self.lan else 0
        local = self.state.get("remote_local") or ""
        nics = None if self.nics is None else tuple((n["addr"], n["mac"]) for n in self.nics)
        report = (tuple(self.lan), port, tuple(self.direct.active_ids()), self.radmin_server, self.remote_ok, local,
                  nics, self.rustdesk_id)
        if now - self.last_heartbeat > HEARTBEAT_EVERY or report != self.reported:
            try:
                self.api.heartbeat(self.lan, port, self.direct.active_ids(), self.radmin_server, self.remote_ok,
                                   local, self.nics, self.rustdesk_id)
                self.last_heartbeat, self.reported = now, report
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
    "bg": "#0d1117", "panel": "#131a23", "head": "#1a2330", "line": "#232e3d", "sel": "#17462f",
    "hover": "#1f2a38", "text": "#e3e9f1", "muted": "#7b889b", "name": "#5fd38d",
    # фирменный тёмно-зелёный Retix Hub (как фон значка): кнопка ON, кнопки окон, рамки
    "on": "#1e854f", "on_hover": "#25a062",
    "off": "#3a4555", "green": "#22c55e", "orange": "#f59e0b", "red": "#ef4444",
    "entry": "#0a0e13",
    # выпадающие меню — светлее окна, чтобы сразу отличались от списка под ними; разделитель — чуть светлее меню
    "menu": "#212c3b", "menu_line": "#323f51",
}


def work_area(win) -> tuple[int, int, int, int]:
    """Рабочая область основного монитора без панели задач: (left, top, right, bottom)."""
    if WINDOWS:
        try:
            r = wintypes.RECT()
            if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(r), 0):   # SPI_GETWORKAREA
                return r.left, r.top, r.right, r.bottom
        except Exception:  # noqa: BLE001
            pass
    return 0, 0, win.winfo_screenwidth(), win.winfo_screenheight() - 48


def monitor_area(win, x: int, y: int) -> tuple[int, int, int, int]:
    """Рабочая область монитора, на котором точка (x, y): меню не должно уезжать на соседний монитор."""
    if WINDOWS:
        try:
            class MONITORINFO(ctypes.Structure):
                _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT), ("rcWork", wintypes.RECT),
                            ("dwFlags", wintypes.DWORD)]
            u = ctypes.windll.user32
            u.MonitorFromPoint.restype = ctypes.c_void_p
            u.MonitorFromPoint.argtypes = [wintypes.POINT, wintypes.DWORD]
            u.GetMonitorInfoW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MONITORINFO)]
            mon = u.MonitorFromPoint(wintypes.POINT(x, y), 2)   # MONITOR_DEFAULTTONEAREST
            info = MONITORINFO()
            info.cbSize = ctypes.sizeof(info)
            if mon and u.GetMonitorInfoW(mon, ctypes.byref(info)):
                r = info.rcWork
                return r.left, r.top, r.right, r.bottom
        except Exception:  # noqa: BLE001
            log.debug("монитор у точки не определён", exc_info=True)
    return work_area(win)


def round_corners(win, radius: int = 8) -> None:
    """Скруглить углы окна без рамки (меню). Windows 11 — средствами DWM (сглаженно, без светлой рамки),
    Windows 10 / 8.1 — областью окна."""
    if not WINDOWS:
        return
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
    except Exception:  # noqa: BLE001
        return
    try:
        pref = ctypes.c_int(2)   # DWMWA_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND
        if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(pref), ctypes.sizeof(pref)) == 0:
            none = ctypes.c_uint(0xFFFFFFFE)   # DWMWA_BORDER_COLOR = DWMWA_COLOR_NONE: без рамки по краю
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 34, ctypes.byref(none), ctypes.sizeof(none))
            return
    except Exception:  # noqa: BLE001 — Windows 10 и 8.1: DWM углы не скругляет
        pass
    try:
        w, h = win.winfo_width(), win.winfo_height()
        rgn = ctypes.windll.gdi32.CreateRoundRectRgn(0, 0, w + 1, h + 1, 2 * radius, 2 * radius)
        ctypes.windll.user32.SetWindowRgn(hwnd, rgn, True)   # область теперь принадлежит окну
    except Exception:  # noqa: BLE001
        log.debug("углы меню не скруглены", exc_info=True)


def unbind_all_func(widget, seq: str, funcid: str) -> None:
    """Снять одну свою привязку bind_all(..., add="+"), не трогая остальные (unbind_all сняла бы все)."""
    try:
        script = widget.tk.call("bind", "all", seq)
        keep = "\n".join(line for line in str(script).split("\n") if funcid not in line)
        widget.tk.call("bind", "all", seq, keep)
        widget.deletecommand(funcid)
    except tk.TclError:
        pass


class HubMenu:
    """Выпадающее меню программы вместо tk.Menu: у меню Windows по краю белая рамка, её не перекрасить.
    Своё — оттенка светлее окна, без рамки, со скруглёнными углами. Вызовы — как у tk.Menu."""

    FONT = ("Segoe UI", 9)
    PAD = 5
    MIN_WIDTH = 190
    KEYS = ("<Escape>", "<Up>", "<Down>", "<Left>", "<Right>", "<Return>")
    open_menu: "HubMenu | None" = None   # открытое меню верхнего уровня — одно на программу

    def __init__(self, parent, postcommand=None):
        self.parent = parent.parent if isinstance(parent, HubMenu) else parent
        self.items: list[dict] = []
        self.postcommand = postcommand
        self.win: tk.Toplevel | None = None
        self.rows: list[tuple[tuple, dict]] = []   # (виджеты строки, пункт)
        self.active = -1
        self.sub: HubMenu | None = None            # открытое подменю
        self.sub_index = -1
        self.owner: HubMenu | None = None          # у подменю — меню, из которого оно открыто
        self._watch_job = None
        self._binds: list[tuple[str, str]] = []   # глобальные привязки открытого меню: (событие, id)

    # --- как у tk.Menu
    def configure(self, **kw):
        if "postcommand" in kw:
            self.postcommand = kw["postcommand"]

    config = configure

    def add_command(self, label: str, command=None, font=None, **_):
        self.items.append({"kind": "command", "label": label, "command": command, "font": font})

    def add_radiobutton(self, label: str, variable=None, value=None, command=None, **_):
        self.items.append({"kind": "radio", "label": label, "command": command, "variable": variable,
                           "value": value})

    def add_cascade(self, label: str, menu: "HubMenu", **_):
        self.items.append({"kind": "cascade", "label": label, "menu": menu})

    def add_separator(self):
        self.items.append({"kind": "sep"})

    def delete(self, *_):
        self.items = []

    def destroy(self):
        self.unpost()

    def grab_release(self):
        pass

    def tk_popup(self, x: int, y: int):
        self.post(x, y)

    @property
    def posted(self) -> bool:
        return self.win is not None

    # --- показ
    def post(self, x: int, y: int, owner: "HubMenu | None" = None):
        if owner is None and HubMenu.open_menu is not None:
            HubMenu.open_menu.unpost()
        self.unpost()
        if self.postcommand:
            self.postcommand()
        self.owner, self.active = owner, -1
        win = tk.Toplevel(self.parent, bg=C["menu"])
        win.withdraw()
        win.overrideredirect(True)
        try:
            win.attributes("-topmost", True)
        except tk.TclError:
            pass
        self.win = win
        self._root_pos = (self.parent.winfo_rootx(), self.parent.winfo_rooty())
        body = tk.Frame(win, bg=C["menu"], pady=self.PAD)
        body.pack(fill="both", expand=True)
        self.rows = []
        for item in self.items:
            if item["kind"] == "sep":
                tk.Frame(body, bg=C["menu_line"], height=1).pack(fill="x", padx=10, pady=4)
                continue
            row = tk.Frame(body, bg=C["menu"])
            row.pack(fill="x", padx=self.PAD)
            checked = item["kind"] == "radio" and item["variable"] is not None \
                and item["variable"].get() == item["value"]
            mark = tk.Label(row, text="●" if checked else "", width=2, bg=C["menu"], fg=C["green"],
                            font=("Segoe UI", 7))
            mark.pack(side="left")
            label = tk.Label(row, text=item["label"], bg=C["menu"], fg=C["text"], font=item.get("font") or self.FONT,
                             anchor="w", pady=4)
            label.pack(side="left", fill="x", expand=True)
            arrow = tk.Label(row, text="›" if item["kind"] == "cascade" else "", width=2, bg=C["menu"],
                             fg=C["muted"], font=self.FONT)
            arrow.pack(side="right")
            i = len(self.rows)
            for w in (row, mark, label, arrow):
                w.bind("<Enter>", lambda _e, n=i: self._hover(n))
                w.bind("<Button-1>", lambda _e, n=i: self._invoke(n))
            self.rows.append(((row, mark, label, arrow), item))
        win.bind("<Leave>", lambda _e: self._leave())
        win.update_idletasks()
        w, h = max(win.winfo_reqwidth(), self.MIN_WIDTH), win.winfo_reqheight()
        left, top, right, bottom = monitor_area(self.parent, x, y)
        if x + w > right:   # не помещается справа: подменю — слева от меню, остальное — сдвинуть
            x = owner.win.winfo_rootx() - w + 2 if owner and owner.win else right - w
        if y + h > bottom:
            y = y - h if owner is None and y - h >= top else bottom - h
        x, y = max(left, x), max(top, y)
        win.geometry(f"{w}x{h}+{x}+{y}")
        win.deiconify()
        win.lift()
        round_corners(win)
        if owner is None:
            HubMenu.open_menu = self
            self.parent.after_idle(self._grab_global)   # после текущего щелчка — иначе он сразу закроет меню
            self._watch_job = self.parent.after(200, self._watch)

    def unpost(self):
        if self.sub:
            self.sub.unpost()
        self.sub, self.sub_index = None, -1
        if self.win is not None:
            try:
                self.win.destroy()
            except tk.TclError:
                pass
        self.win, self.rows, self.active = None, [], -1
        if self.owner is None and HubMenu.open_menu is self:
            HubMenu.open_menu = None
            if self._watch_job:
                self.parent.after_cancel(self._watch_job)
                self._watch_job = None
            for seq, funcid in self._binds:
                unbind_all_func(self.parent, seq, funcid)
            self._binds = []

    def _windows(self) -> list:
        out, m = [], self
        while m is not None and m.win is not None:
            out.append(m.win)
            m = m.sub
        return out

    def _grab_global(self):
        """Щелчок в окне программы мимо меню — закрыть меню; стрелки, Enter и Esc — управление меню."""
        if HubMenu.open_menu is not self or self.win is None:
            return
        self._binds = [("<ButtonPress>", self.parent.bind_all("<ButtonPress>", self._outside_click, add="+"))]
        for seq in self.KEYS:
            self._binds.append((seq, self.parent.bind_all(seq, self._key, add="+")))

    def _outside_click(self, event):
        try:
            top = event.widget.winfo_toplevel()
        except (AttributeError, KeyError, tk.TclError):
            top = None
        if top not in self._windows():
            self.unpost()

    def _watch(self):
        """Щёлкнули в другой программе или на рабочем столе — меню закрывается, как обычное меню Windows."""
        self._watch_job = None
        if self.win is None:
            return
        try:   # окно спрятали в трей или передвинули за заголовок — меню больше не у своего места
            if not self.parent.winfo_viewable() or \
                    (self.parent.winfo_rootx(), self.parent.winfo_rooty()) != self._root_pos:
                self.unpost()
                return
        except tk.TclError:
            return
        if WINDOWS:
            try:   # активно окно другой программы (или рабочий стол)
                u = ctypes.windll.user32
                u.GetForegroundWindow.restype = ctypes.c_void_p
                fg = u.GetForegroundWindow()
                pid = wintypes.DWORD()
                if fg:
                    u.GetWindowThreadProcessId(ctypes.c_void_p(fg), ctypes.byref(pid))
                    if pid.value and pid.value != os.getpid():
                        self.unpost()
                        return
            except Exception:  # noqa: BLE001
                log.debug("активное окно не определено", exc_info=True)
        self._watch_job = self.parent.after(200, self._watch)

    # --- пункты
    def _paint(self, i: int, on: bool):
        if not 0 <= i < len(self.rows):
            return
        widgets, item = self.rows[i]
        for w in widgets:
            w.configure(bg=C["sel"] if on else C["menu"])
        widgets[2].configure(fg="white" if on else C["text"])

    def _hover(self, i: int):
        if i != self.active:
            self._paint(self.active, False)
            self.active = i
            self._paint(i, True)
        if self.sub and self.sub_index != i:
            self.sub.unpost()
            self.sub, self.sub_index = None, -1
        if self.rows[i][1]["kind"] == "cascade" and not self.sub:
            self._open_sub(i)

    def _leave(self):
        if self.win is None or self.sub:
            return
        x, y = self.win.winfo_pointerxy()
        try:
            under = self.win.winfo_containing(x, y)
            inside = under is not None and under.winfo_toplevel() is self.win
        except (KeyError, tk.TclError):
            inside = False
        if not inside:
            self._paint(self.active, False)
            self.active = -1

    def _open_sub(self, i: int):
        row = self.rows[i][0][0]
        menu = self.rows[i][1]["menu"]
        menu.post(self.win.winfo_rootx() + self.win.winfo_width() - 2, row.winfo_rooty() - self.PAD, owner=self)
        self.sub, self.sub_index = menu, i

    def _invoke(self, i: int):
        if not 0 <= i < len(self.rows):
            return
        item = self.rows[i][1]
        if item["kind"] == "cascade":
            if not self.sub:
                self._open_sub(i)
            return
        root = self
        while root.owner is not None:
            root = root.owner
        root.unpost()
        if item["kind"] == "radio" and item["variable"] is not None:
            item["variable"].set(item["value"])
        if item["command"]:
            self.parent.after_idle(item["command"])

    def _move(self, step: int):
        if not self.rows:
            return
        i = self.active if self.active >= 0 else (-1 if step > 0 else len(self.rows))
        self._hover((i + step) % len(self.rows))

    def _key(self, event):
        m = self
        while m.sub is not None and m.sub.win is not None:
            m = m.sub
        key = event.keysym
        if key == "Escape" or (key == "Left" and m.owner is None):
            if m.owner is not None:
                m.owner.sub.unpost()
                m.owner.sub, m.owner.sub_index = None, -1
            else:
                m.unpost()
        elif key == "Left":
            m.owner.sub.unpost()
            m.owner.sub, m.owner.sub_index = None, -1
        elif key in ("Down", "Up"):
            m._move(1 if key == "Down" else -1)
        elif key == "Right" and m.active >= 0 and m.rows[m.active][1]["kind"] == "cascade":
            m._invoke(m.active)
            if m.sub:
                m.sub._move(1)
        elif key == "Return" and m.active >= 0:
            m._invoke(m.active)
        return "break"


def dark_menu(parent) -> HubMenu:
    """Выпадающее меню в цветах приложения."""
    return HubMenu(parent)


_CORNERS: dict = {}   # скруглённые углы панелей (Pillow, со сглаживанием): (радиус, цвет, фон) → картинки


def corner_images(r: int, fill: str, bg: str) -> dict:
    key = (r, fill, bg)
    if key not in _CORNERS:
        from PIL import Image, ImageDraw, ImageTk
        k = 4
        big = Image.new("RGB", (2 * r * k, 2 * r * k), bg)
        ImageDraw.Draw(big).ellipse((0, 0, 2 * r * k - 1, 2 * r * k - 1), fill=fill)
        img = big.resize((2 * r, 2 * r), Image.LANCZOS)
        boxes = {"nw": (0, 0, r, r), "ne": (r, 0, 2 * r, r), "sw": (0, r, r, 2 * r), "se": (r, r, 2 * r, 2 * r)}
        _CORNERS[key] = {name: ImageTk.PhotoImage(img.crop(box)) for name, box in boxes.items()}
    return _CORNERS[key]


def round_rect(cv: "tk.Canvas", x0: int, y0: int, x1: int, y1: int, r: int, fill: str, bg: str, tag: str) -> None:
    """Прямоугольник со скруглёнными углами на холсте (под остальным содержимым холста)."""
    cv.delete(tag)
    r = max(0, min(r, (x1 - x0) // 2, (y1 - y0) // 2))
    cv.create_rectangle(x0 + r, y0, x1 - r, y1, fill=fill, outline="", tags=tag)
    cv.create_rectangle(x0, y0 + r, x1, y1 - r, fill=fill, outline="", tags=tag)
    if r:
        try:
            imgs = corner_images(r, fill, bg)
            for name, x, y in (("nw", x0, y0), ("ne", x1, y0), ("sw", x0, y1), ("se", x1, y1)):
                cv.create_image(x, y, image=imgs[name], anchor=name, tags=tag)
        except Exception:  # noqa: BLE001 — без Pillow: углы кругами, без сглаживания
            for x, y in ((x0, y0), (x1 - 2 * r, y0), (x0, y1 - 2 * r), (x1 - 2 * r, y1 - 2 * r)):
                cv.create_oval(x, y, x + 2 * r, y + 2 * r, fill=fill, outline="", tags=tag)
    cv.tag_lower(tag)


class RoundPanel(tk.Frame):
    """Панель окна со скруглёнными углами и без рамки: содержимое — в self.body, фон со скруглёнными углами
    рисуется на холсте под ним. Размер — как у обычной рамки: по содержимому (stretch — тянется по месту)."""

    def __init__(self, master, radius: int = 10, pad: int = 5, stretch: bool = False,
                 fill: str = C["panel"], bg: str = C["bg"]):
        super().__init__(master, bg=bg)
        self.radius, self.pad, self.stretch, self.fill, self.bg_ = radius, pad, stretch, fill, bg
        # холст — под содержимым и на размер не влияет (place); размер панели задаёт self.body
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0, width=1, height=1)
        self.canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.body = tk.Frame(self, bg=fill)
        self.body.pack(fill="both", expand=True, padx=pad, pady=pad)
        self.bind("<Configure>", self._layout)

    def fit(self):
        """Совместимость: высота и так по содержимому."""

    def _layout(self, e):
        if e.widget is self:
            round_rect(self.canvas, 0, 0, e.width, e.height, self.radius, self.fill, self.bg_, "panel")


class Pill(tk.Canvas):
    """Плашка статуса со скруглёнными краями."""

    FONT = ("Segoe UI", 8, "bold")

    def __init__(self, master, bg: str):
        super().__init__(master, bg=bg, highlightthickness=0, bd=0, height=20, width=10)
        self.bg_ = bg

    def show(self, text: str, color: str):
        import tkinter.font as tkfont
        w, h = tkfont.Font(font=self.FONT).measure(text) + 18, 20
        self.configure(width=w, height=h)
        self.delete("all")
        round_rect(self, 0, 0, w, h, h // 2, color, self.bg_, "pill")
        self.create_text(w // 2, h // 2, text=text, fill="white", font=self.FONT)


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
    accent = tuple(int(C["on"][i:i + 2], 16) for i in (1, 3, 5)) if on else (58, 69, 85)
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
    Status.LAN_ONLY: ("Только локальная сеть", C["orange"]),
    Status.PENDING: ("Ждёт одобрения", C["orange"]),
    Status.BLOCKED: ("Заблокировано", C["red"]),
    Status.NEED_LOGIN: ("Не подключено", C["off"]),
    Status.ERROR: ("Ошибка", C["red"]),
    Status.OFF: ("Отключено", C["off"]),
}


def sort_peers(peers) -> list[dict]:
    """Список компьютеров — по имени (Касса 2 раньше Касса 10). ПК, который выключился, остаётся на своём
    месте: список не прыгает, и нужный компьютер легко найти."""
    return sorted(peers, key=lambda p: natural_key(p["name"]))


NO_ROLE = "Без роли"


def group_peers(peers) -> list[tuple[str, list[dict]]]:
    """Список компьютеров по группам — ролям из кабинета («Склад», «Администраторы» …), по порядку ролей
    в кабинете; ПК без роли — последней группой. Ролей нет ни у одного ПК — одна группа без заголовка ('')."""
    peers = sort_peers(peers)
    if not any(p.get("role") for p in peers):
        return [("", peers)] if peers else []
    groups: dict[str, list[dict]] = {}
    for p in peers:
        groups.setdefault(p.get("role") or NO_ROLE, []).append(p)

    def order(name):
        if name == NO_ROLE and not any(p.get("role") for p in groups[name]):
            return (1, 0, "")
        return (0, min(int(p.get("role_pos") or 0) for p in groups[name]), name.lower())
    return [(name, groups[name]) for name in sorted(groups, key=order)]


def natural_key(text: str):
    """«2 касса» раньше «10 касса»."""
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", (text or "").lower())]


# как связан ПК из списка: значок вместо подписи «⇄ LAN / ⇄ WAN» рядом с IP.
# Через сервер — зелёная R с логотипа Retix Hub
LINK_COLORS = {"server": C["green"], "lan": "#2dd4bf", "wan": "#60a5fa", "off": C["muted"]}
LINK_HINTS = {"server": "В сети · связь через сервер Retix Hub", "lan": "В сети · напрямую по локальной сети",
              "wan": "В сети · напрямую через интернет", "off": "Не в сети"}


def peer_link(p: dict, online: bool) -> str:
    """Значок ПК в списке: server / lan / wan / off."""
    if not online:
        return "off"
    if p.get("direct"):
        return "wan" if p.get("direct_wan") else "lan"
    return "server"


def logo_letter(color: str, size: int = 16):
    """Буква R из значка Retix Hub (app_icon.ico) цветом color, без фона, по размеру значка."""
    from PIL import Image, ImageChops
    icon = Image.open(resource_dir() / "app_icon.ico")
    icon.size = max(icon.info.get("sizes") or [icon.size])
    r, g, b, a = icon.convert("RGBA").split()
    # белая буква на зелёном фоне: светлое (min(r,g,b) > 90) — буква, остальное прозрачно
    light = ImageChops.darker(ImageChops.darker(r, g), b).point(lambda v: max(0, min(255, (v - 90) * 255 // 150)))
    mask = ImageChops.multiply(light, a)
    box = mask.getbbox()
    if not box:
        raise ValueError("в значке нет буквы")
    x0, y0, x1, y1 = box
    side = max(x1 - x0, y1 - y0)
    cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
    crop = (cx - side // 2, cy - side // 2, cx - side // 2 + side, cy - side // 2 + side)
    out = Image.new("RGBA", mask.size, color)
    out.putalpha(mask)
    # высота — как у остальных значков списка (13 из 16 точек, поля по краям), а не во весь квадрат
    inner = max(1, round(size * 13 / 16))
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    canvas.alpha_composite(out.crop(crop).resize((inner, inner), Image.LANCZOS),
                           ((size - inner + 1) // 2, (size - inner + 1) // 2))
    return canvas


def render_link_icon(kind: str, size: int = 16):
    """Значок связи (Pillow, рисуется в 8 раз крупнее и уменьшается — со сглаживанием):
    server — зелёная R как на логотипе, lan — гнездо сетевого кабеля, wan — глобус, off — крестик."""
    from PIL import Image, ImageDraw
    if kind == "server":
        try:
            return logo_letter(LINK_COLORS["server"], size)
        except Exception:  # noqa: BLE001 — нет значка программы: полоски сигнала
            log.debug("буква R из app_icon.ico не собрана", exc_info=True)
    S = size * 8
    u = S / 16                         # 1 точка значка 16×16
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    col = tuple(int(LINK_COLORS[kind][i:i + 2], 16) for i in (1, 3, 5)) + (255,)
    w, thin = max(1, round(1.5 * u)), max(1, round(1.2 * u))
    if kind == "server":
        for i in range(4):
            x0, h = (1.5 + i * 3.5) * u, (4 + i * 3) * u
            d.rounded_rectangle((x0, 14.5 * u - h, x0 + 2.5 * u, 14.5 * u), radius=0.6 * u, fill=col)
    elif kind == "lan":
        d.rounded_rectangle((1 * u, 1.5 * u, 15 * u, 14.5 * u), radius=2.2 * u, outline=col, width=w)
        d.polygon([(4 * u, 4.5 * u), (12 * u, 4.5 * u), (12 * u, 10 * u), (10.5 * u, 10 * u), (10.5 * u, 12 * u),
                   (5.5 * u, 12 * u), (5.5 * u, 10 * u), (4 * u, 10 * u)], fill=col)
        for i in range(4):             # контакты
            x = (5.5 + i * 1.65) * u
            d.rectangle((x, 4.5 * u, x + 0.7 * u, 7 * u), fill=(0, 0, 0, 0))
    elif kind == "wan":
        c, r = 8 * u, 6.6 * u
        d.ellipse((c - r, c - r, c + r, c + r), outline=col, width=w)
        d.ellipse((c - 2.6 * u, c - r, c + 2.6 * u, c + r), outline=col, width=thin)
        d.line((c - r, c, c + r, c), fill=col, width=thin)
        for dy in (-1, 1):             # параллели
            d.arc((c - 5.6 * u, c + dy * 3.2 * u - 3 * u, c + 5.6 * u, c + dy * 3.2 * u + 3 * u),
                  start=200 if dy < 0 else 20, end=340 if dy < 0 else 160, fill=col, width=thin)
    else:
        d.line((4 * u, 4 * u, 12 * u, 12 * u), fill=col, width=round(1.8 * u))
        d.line((12 * u, 4 * u, 4 * u, 12 * u), fill=col, width=round(1.8 * u))
    return img.resize((size, size), Image.LANCZOS)


def make_link_images() -> dict:
    """Значки связи для списка компьютеров. Без Pillow — попроще, по точкам."""
    try:
        from PIL import ImageTk
        return {k: ImageTk.PhotoImage(render_link_icon(k)) for k in LINK_COLORS}
    except Exception:  # noqa: BLE001
        log.debug("значки через Pillow не нарисованы", exc_info=True)
    w = h = 16
    imgs = {k: tk.PhotoImage(width=w, height=h) for k in LINK_COLORS}
    for i in range(4):
        bh = 4 + i * 3
        imgs["server"].put(LINK_COLORS["server"], to=(1 + i * 4, h - 1 - bh, 4 + i * 4, h - 1))
    lan = imgs["lan"]
    for x0, y0, x1, y1 in ((1, 1, 15, 3), (1, 13, 15, 15), (1, 1, 3, 15), (13, 1, 15, 15), (4, 7, 12, 10), (6, 10, 10, 12)):
        lan.put(LINK_COLORS["lan"], to=(x0, y0, x1, y1))
    for x in (4, 6, 8, 10):
        lan.put(LINK_COLORS["lan"], to=(x, 5, x + 1, 7))
    wan = imgs["wan"]
    for y in range(16):                # круг, меридиан и экватор
        for x in range(16):
            r = ((x - 7.5) ** 2 + (y - 7.5) ** 2) ** 0.5
            if 5.6 <= r <= 7.1 or (y in (7, 8) and r < 7) or (abs((x - 7.5) / 2.6) ** 2 + ((y - 7.5) / 6.6) ** 2 - 1) ** 2 < 0.06:
                wan.put(LINK_COLORS["wan"], to=(x, y, x + 1, y + 1))
    for i in range(7):
        imgs["off"].put(LINK_COLORS["off"], to=(4 + i, 4 + i, 6 + i, 6 + i))
        imgs["off"].put(LINK_COLORS["off"], to=(10 - i, 4 + i, 12 - i, 6 + i))
    return imgs


class Tooltip:
    """Подсказка у курсора (для значков в списке компьютеров)."""

    def __init__(self, root):
        self.root, self.win, self.text = root, None, ""

    def show(self, text: str, x: int, y: int):
        if self.win and text == self.text:
            return
        self.hide()
        self.text = text
        self.win = tk.Toplevel(self.root)
        self.win.wm_overrideredirect(True)
        self.win.attributes("-topmost", True)
        tk.Label(self.win, text=text, bg=C["head"], fg=C["text"], font=("Segoe UI", 8), padx=6, pady=2,
                 highlightthickness=1, highlightbackground=C["line"]).pack()
        self.win.geometry(f"+{x + 14}+{y + 16}")

    def hide(self):
        if self.win:
            self.win.destroy()
        self.win, self.text = None, ""


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
    st.configure("TRadiobutton", background=C["bg"], foreground=C["text"], indicatorbackground=C["entry"])
    st.map("TRadiobutton", background=[("active", C["bg"])], indicatorbackground=[("selected", C["on"])])
    st.configure("TEntry", fieldbackground=C["entry"], foreground=C["text"], insertcolor=C["text"],
                 bordercolor=C["line"], lightcolor=C["line"], darkcolor=C["line"])
    st.map("TEntry", bordercolor=[("focus", C["on"])], lightcolor=[("focus", C["on"])])   # рамка в фокусе — зелёная
    st.configure("TButton", background=C["on"], foreground="white", bordercolor=C["on"], focusthickness=0,
                 padding=(10, 5))
    st.map("TButton", background=[("disabled", C["off"]), ("active", C["on_hover"])])
    st.configure("Hub.Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["text"],
                 rowheight=20, borderwidth=0, font=("Segoe UI", 8))
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
            "server": tk.StringVar(value=st.get("server_url") or State._default_server()),   # не показывается
            "company": tk.StringVar(value="" if add else st.get("company_login")),
            "password": tk.StringVar(),
            "device": tk.StringVar(value=st.get("device_name") or socket.gethostname()),
            "remember": tk.BooleanVar(value=True),
        }
        # адрес сервера зашит в программу (client_config.json) — его не спрашиваем
        rows = [("Логин компании", "company", ""), ("Пароль подключения", "password", "•"),
                ("Имя этого компьютера", "device", "")]
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
        self.update_idletasks()   # по центру над главным окном (оно — в правом нижнем углу)
        ax, ay, aw, _ = app.frame_box()
        x = ax + (aw - self.winfo_reqwidth()) // 2
        y = ay + 60
        self.geometry(f"+{max(0, x)}+{max(0, y)}")
        dark_titlebar(self)
        self.grab_set()

    def close(self):
        self.app.login_dialog = None
        self.destroy()

    def submit(self):
        v = {k: var.get() for k, var in self.vars.items()}
        if not all(str(v[k]).strip() for k in ("company", "password", "device")):
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


class RenameDialog(tk.Toplevel):
    """Сменить имя этого компьютера в сети компании (его видят другие ПК и кабинет компании)."""

    def __init__(self, app: "App"):
        super().__init__(app)
        self.app = app
        self.title("Имя компьютера")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.transient(app)
        try:
            self.iconbitmap(str(resource_dir() / "app_icon.ico"))
        except Exception:  # noqa: BLE001
            pass
        frm = ttk.Frame(self, padding=16)
        frm.pack(fill="both")
        current = (app.cfg or {}).get("device_name") or app.state_.get("device_name") or socket.gethostname()
        ttk.Label(frm, text="Имя этого компьютера в сети компании").grid(row=0, column=0, sticky="w", pady=(0, 2))
        ttk.Label(frm, text="Так его видят другие компьютеры и кабинет компании.", style="Muted.TLabel")\
            .grid(row=1, column=0, sticky="w", pady=(0, 6))
        self.var = tk.StringVar(value=current)
        self.entry = ttk.Entry(frm, textvariable=self.var, width=36)
        self.entry.grid(row=2, column=0, sticky="ew")
        self.entry.focus_set()
        self.entry.select_range(0, "end")
        self.err = ttk.Label(frm, text="", style="Err.TLabel", wraplength=280)
        self.err.grid(row=3, column=0, sticky="w", pady=(4, 0))
        self.btn = ttk.Button(frm, text="Сохранить", command=self.submit)
        self.btn.grid(row=4, column=0, pady=(8, 0), sticky="ew")
        self.bind("<Return>", lambda _e: self.submit())
        self.bind("<Escape>", lambda _e: self.close())
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.update_idletasks()   # по центру над главным окном
        ax, ay, aw, _ = app.frame_box()
        self.geometry(f"+{max(0, ax + (aw - self.winfo_reqwidth()) // 2)}+{max(0, ay + 60)}")
        dark_titlebar(self)
        self.grab_set()

    def close(self):
        self.app.rename_dialog = None
        self.destroy()

    def submit(self):
        name = clean_device_name(self.var.get())
        if not name:
            self.err.config(text="Введите имя компьютера")
            return
        self.btn.config(state="disabled", text="Сохранение…")

        def work():
            self.app.ui_q.put(("rename_done", (name, self.app.worker.rename(name))))
        threading.Thread(target=work, daemon=True, name="rename").start()

    def done(self, err):
        if err:
            self.err.config(text=err)
            self.btn.config(state="normal", text="Сохранить")
        else:
            self.close()


class Dropdown(tk.Label):
    """Выбор из списка в цветах программы (выпадает своё меню HubMenu, а не белый список ttk.Combobox)."""

    def __init__(self, master, options: dict, value, command=None):
        super().__init__(master, bg=C["entry"], fg=C["text"], font=("Segoe UI", 9), anchor="w", padx=8, pady=3,
                         cursor="hand2", highlightthickness=1, highlightbackground=C["line"])
        self.options, self.value, self.command = options, value, command
        self.menu = HubMenu(master)
        for key, title in options.items():
            self.menu.add_command(label=title, command=lambda k=key: self.set(k))
        self.bind("<Button-1>", lambda _e: self.menu.unpost() if self.menu.posted else
                  self.menu.tk_popup(self.winfo_rootx(), self.winfo_rooty() + self.winfo_height() + 2))
        self.set(value, quiet=True)

    def set(self, value, quiet: bool = False):
        self.value = value
        self.configure(text=f"{self.options.get(value, value)}   ▾")
        if self.command and not quiet:
            self.command()

    def enable(self, on: bool):
        self.configure(fg=C["text"] if on else C["muted"], cursor="hand2" if on else "arrow")
        self.bind("<Button-1>", (lambda _e: self.menu.unpost() if self.menu.posted else
                                 self.menu.tk_popup(self.winfo_rootx(), self.winfo_rooty() + self.winfo_height() + 2))
                  if on else (lambda _e: "break"))


class SettingsDialog(tk.Toplevel):
    """Настройки этого компьютера — то, что касается только его: имя в сети компании, как им можно управлять
    (RustDesk; только строже, чем разрешил администратор), пароль этого компьютера и блокировка программы.
    Пароль один: им разблокируется программа, и по нему подключаются, если выбран доступ «по моему паролю».
    При первом запуске окно открывается само."""

    def __init__(self, app: "App", first: bool = False, offer_lock: bool = False):
        super().__init__(app)
        self.app, self.first = app, first
        st = app.state_
        can_ctrl = app.worker.can_control()
        if can_ctrl:   # блокировку этому ПК уже предложили — второй раз окно само не откроется
            st.set(lock_offered=True)
        self.title("Настройка этого компьютера" if first else "Настройки этого компьютера")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.transient(app)
        try:
            self.iconbitmap(str(resource_dir() / "app_icon.ico"))
        except Exception:  # noqa: BLE001
            pass
        frm = ttk.Frame(self, padding=16)
        frm.pack(fill="both")
        row = 0

        def put(widget, pady=(0, 0), sticky="w"):
            nonlocal row
            widget.grid(row=row, column=0, sticky=sticky, pady=pady)
            row += 1
            return widget

        def head(text):
            put(tk.Label(frm, text=text, bg=C["bg"], fg=C["name"], font=("Segoe UI", 10, "bold")),
                pady=(12 if row else 0, 4))

        def muted(text):
            put(ttk.Label(frm, text=text, style="Muted.TLabel", wraplength=340, justify="left"), pady=(0, 4))

        if first:
            muted("Эти настройки касаются только этого компьютера. Их можно изменить позже: "
                  "«Система → Настройки этого компьютера…».")
        if offer_lock:
            muted("Администратор компании разрешил этому компьютеру управлять другими ПК. Включите блокировку "
                  "программы паролем, чтобы этим не воспользовался чужой человек за этим компьютером.")
        # имя
        head("Имя компьютера")
        self.name0 = (app.cfg or {}).get("device_name") or st.get("device_name") or socket.gethostname()
        self.name = tk.StringVar(value=self.name0)
        put(ttk.Entry(frm, textvariable=self.name, width=40), sticky="ew")
        muted("Так его видят другие компьютеры и кабинет компании.")
        # доступ
        head("Доступ к этому компьютеру")
        remote = (app.cfg or {}).get("remote") if isinstance((app.cfg or {}).get("remote"), dict) else {}
        admin = remote.get("mode") if remote.get("mode") in REMOTE_MODES else "off"
        muted({"off": "Сейчас администратор компании не разрешил управлять этим компьютером — к нему никто "
                      "не подключится, что бы вы ни выбрали.",
               "ask": "Администратор компании разрешил управление этим компьютером только с вашего согласия.",
               "auto": "Администратор компании разрешил подключаться к этому компьютеру без вашего согласия "
                       "(по одноразовому паролю от сервера Retix Hub)."}[admin])
        self.local = tk.StringVar(value=st.get("remote_local") or "")
        for key, title in REMOTE_LOCAL_CHOICES.items():
            put(ttk.Radiobutton(frm, text=title, value=key, variable=self.local, command=self._toggle), pady=1)
        # пароль
        head("Пароль этого компьютера")
        self.has_lock = bool(st.get("lock_hash"))
        self.has_own = bool(st.get("remote_own_pw"))
        muted("Им разблокируется программа Retix Hub, и по нему подключаются к этому компьютеру, если выбран "
              "доступ «по моему паролю». Сервер Retix Hub его не знает."
              + (" Пусто — оставить прежний." if self.has_lock or self.has_own else ""))
        self.pw1, self.pw2, self.pw0 = tk.StringVar(), tk.StringVar(), tk.StringVar()
        put(ttk.Label(frm, text="Новый пароль", style="Muted.TLabel"))
        self.e1 = put(ttk.Entry(frm, textvariable=self.pw1, show="•", width=40), sticky="ew")
        put(ttk.Label(frm, text="Повторите пароль", style="Muted.TLabel"), pady=(4, 0))
        put(ttk.Entry(frm, textvariable=self.pw2, show="•", width=40), sticky="ew")
        # блокировка
        head("Блокировка программы")
        # по умолчанию блокируются только ПК с правом управлять другими (администраторы)
        self.lock_on = tk.BooleanVar(value=bool(st.get("lock_on")) if st.get("setup_done") and not offer_lock
                                     else can_ctrl)
        put(ttk.Checkbutton(frm, text="Блокировать программу паролем этого компьютера", variable=self.lock_on,
                            command=self._toggle))
        line = ttk.Frame(frm)
        put(line, pady=(4, 0))
        ttk.Label(line, text="через", style="Muted.TLabel").pack(side="left")
        minutes = st.get("lock_minutes") if st.get("lock_minutes") in LOCK_MINUTES else LOCK_DEFAULT_MINUTES
        self.minutes = Dropdown(line, {m: f"{m} мин" for m in LOCK_MINUTES}, minutes)
        self.minutes.pack(side="left", padx=6)
        ttk.Label(line, text="без действий в программе и после запуска Windows", style="Muted.TLabel")\
            .pack(side="left")
        muted("Заблокированную программу нельзя открыть, отключить или закрыть, не зная пароля: так чужой "
              "человек за этим компьютером не воспользуется сетью компании. Сеть при этом работает.")
        if not can_ctrl:
            muted("Этому компьютеру не разрешено управлять другими ПК — программа на нём не блокируется. "
                  "Блокировка заработает, когда администратор компании даст такое право.")
        if self.has_lock:   # менять пароль и снимать блокировку — только зная прежний
            put(ttk.Label(frm, text="Текущий пароль (чтобы сменить пароль или выключить блокировку)",
                          style="Muted.TLabel"), pady=(6, 0))
            put(ttk.Entry(frm, textvariable=self.pw0, show="•", width=40), sticky="ew")
        self.err = put(ttk.Label(frm, text="", style="Err.TLabel", wraplength=340), pady=(6, 0))
        self.btn = put(ttk.Button(frm, text="Сохранить", command=self.submit), pady=(8, 0), sticky="ew")
        self._toggle()
        self.bind("<Return>", lambda _e: self.submit())
        self.bind("<Escape>", lambda _e: self.close())
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.update_idletasks()
        ax, ay, aw, ah = app.frame_box()
        y = max(0, min(ay + 20, ay + ah - self.winfo_reqheight()))
        self.geometry(f"+{max(0, ax + (aw - self.winfo_reqwidth()) // 2)}+{y}")
        dark_titlebar(self)
        self.grab_set()

    def _toggle(self):
        self.minutes.enable(self.lock_on.get())

    def close(self):
        if self.first:   # закрыли без сохранения — больше не навязываемся (есть пункт в меню «Система»)
            self.app.state_.set(setup_done=True)
        self.app.settings_dialog = None
        self.destroy()

    def submit(self):
        name = clean_device_name(self.name.get())
        local, pw1, pw2, pw0 = self.local.get(), self.pw1.get(), self.pw2.get(), self.pw0.get()
        lock_on, minutes = self.lock_on.get(), self.minutes.value
        if not name:
            return self.err.config(text="Введите имя компьютера.")
        if pw1 != pw2:
            return self.err.config(text="Пароли не совпадают.")
        if local == "own" and not (pw1 or self.has_own):
            return self.err.config(text="Для доступа «по моему паролю» придумайте пароль.")
        if local == "own" and pw1 and not OWN_PW_RE.match(pw1):
            return self.err.config(text="Для доступа по паролю: от 8 до 64 латинских букв, цифр и знаков, "
                                        "без пробелов.")
        if lock_on and not (pw1 or self.has_lock or (local == "own" and self.has_own)):
            return self.err.config(text="Придумайте пароль — им программа будет разблокироваться. "
                                        "Или снимите галочку «Блокировать программу».")
        if pw1 and not LOCK_PW_RE.match(pw1):
            return self.err.config(text="Пароль: от 4 до 64 символов, без пробелов.")
        if self.has_lock and (pw1 or not lock_on) and not self.app.worker.check_unlock(pw0):
            return self.err.config(text="Неверный текущий пароль." if pw0 else "Введите текущий пароль.")
        self.btn.config(state="disabled", text="Сохранение…")
        worker = self.app.worker

        def work():
            err = None
            if name != self.name0:
                err = worker.rename(name)
                if not err:
                    self.app.ui_q.put(("rename_done", (name, None)))
            if not err:   # пароль «по моему паролю» — он же пароль блокировки (set_remote_access)
                err = worker.set_remote_access(local, pw1 if local == "own" else "")
            if not err and lock_on and not pw1 and local == "own" and not self.has_lock:
                # блокировку включили, а пароль уже есть только у доступа «по моему паролю» — он и блокирует
                worker.state.set(lock_hash=hash_lock_pw(unprotect(worker.state.get("remote_own_pw") or "")))
            if not err:
                err = worker.set_lock(lock_on, minutes, pw1)
            if not err:
                worker.state.set(setup_done=True)
            self.app.ui_q.put(("settings_done", err))
        threading.Thread(target=work, daemon=True, name="settings").start()

    def done(self, err):
        if err:
            self.err.config(text=err)
            self.btn.config(state="normal", text="Сохранить")
        else:
            self.first = False
            self.close()


class MessageWindow(tk.Toplevel):
    """Переписка с одним компьютером: входящие показываются здесь, отсюда же — ответ."""

    def __init__(self, app: "App", peer: dict):
        super().__init__(app)
        self.app, self.peer = app, peer
        self.title(f"Сообщения — {peer['name']}")
        self.configure(bg=C["bg"])
        left, top, right, bottom = work_area(app)   # по центру экрана (рабочей области без панели задач)
        self.geometry(f"380x360+{max(left, (left + right - 380) // 2)}+{max(top, (top + bottom - 360) // 2 - 16)}")
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


def tray_image(color: str, size: int = 64, original: bool = False):
    """Значок трея: «в сети» — сам значок Retix Hub (original), иначе — тот же значок с фоном цвета статуса."""
    from PIL import Image
    try:
        icon = Image.open(resource_dir() / "app_icon.ico")
        icon.size = max(icon.info.get("sizes") or [icon.size])
        src = icon.convert("RGBA").resize((size, size), Image.LANCZOS)
        if original:
            return src
        cr, cg, cb = (int(color[i:i + 2], 16) for i in (1, 3, 5))
        out = Image.new("RGBA", src.size)
        px, opx = src.load(), out.load()
        for yy in range(src.size[1]):
            for xx in range(src.size[0]):
                r, g, b, a = px[xx, yy]
                t = max(0.0, min(1.0, (min(r, g, b) - 90) / 150))   # белая буква — белая, фон — цвет
                opx[xx, yy] = (int(cr + (255 - cr) * t), int(cg + (255 - cg) * t), int(cb + (255 - cb) * t), a)
        return out
    except Exception:  # noqa: BLE001 — нет значка: рисуем узлы сети
        log.debug("значок трея из app_icon.ico не собран", exc_info=True)
    from PIL import ImageDraw
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
            self.images[key] = tray_image(color, original=key == "green")
        menu = pystray.Menu(
            pystray.MenuItem("Открыть Retix Hub", lambda: self.ui_q.put(("show", None)), default=True),
            pystray.MenuItem("Подключить / отключить", lambda: self.ui_q.put(("toggle", None))),
            pystray.MenuItem("Переподключить", lambda: self.ui_q.put(("reconnect", None))),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Выход (VPN продолжит работать)", lambda: self.ui_q.put(("ask_quit", None))),
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
    def __init__(self, state: State, minimized: bool = True):
        super().__init__()
        self.withdraw()   # до сборки — невидимо: иначе окно на миг появляется в левом верхнем углу
        self._size = (360, 620)
        self._pos: tuple[int, int] | None = None
        self.net_up: bool | None = None      # для уведомлений «сеть пропала / подключено»
        self._lost_job = None
        self.report_callback_exception = self._tk_error   # ошибки в обработчиках окна — в журнал
        self.state_ = state
        self.events: queue.Queue = queue.Queue()   # от Worker
        self.ui_q: queue.Queue = queue.Queue()     # от трея, диалогов, второго запуска программы
        self.worker = Worker(state, self.events)
        self.cfg = None
        self.peers: list[dict] = []
        self.login_dialog: LoginDialog | None = None
        self.rename_dialog: RenameDialog | None = None
        self.settings_dialog: SettingsDialog | None = None
        # блокировка программы паролем этого компьютера: через N минут без действий и после запуска
        self.locked = False
        self.last_activity = time.monotonic()
        self._lock_pending = None            # действие из трея, которое выполнить после разблокировки
        self._lock_fails, self._lock_until = 0, 0.0
        self._lock_chats: list = []          # окна переписки, спрятанные на время блокировки
        self.last_status = None
        self.status_now = None
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
        self.link_img = make_link_images()   # значки связи в списке: через сервер / LAN / интернет / не в сети
        self._build()
        self.tray = Tray(self.ui_q)
        # крестик — спрятать в трей (VPN работает дальше); без трея — свернуть
        self.protocol("WM_DELETE_WINDOW", self.hide)
        self.bind("<Unmap>", self._on_unmap)   # кнопка «свернуть» — тоже в трей, а не на панель задач
        if not minimized:   # иначе — сразу в трее; окно — двойным щелчком по значку у часов
            self.after(0, self.show)
        elif not self.tray.ok:   # трея нет — хотя бы на панели задач, иначе программу не открыть
            self.after(0, lambda: (self.place_corner(), self.iconify()))
        dark_titlebar(self)
        no_maximize_button(self)
        for seq in ("<Motion>", "<KeyPress>", "<ButtonPress>"):   # любое действие в окнах программы
            self.bind_all(seq, self._activity, add="+")
        if self.worker.lock_ready():   # после запуска Windows — сразу заблокирована
            self.lock()
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
        m.add_command(label="Настройки этого компьютера…", command=self.settings)
        m.add_command(label="Имя компьютера…", command=self.rename)
        m.add_command(label="Заблокировать программу", command=self.lock_now)
        m.add_command(label="Добавить компанию…", command=lambda: self.show_login(add=True))
        m.add_command(label="Выйти из сети компании", command=self.logout)
        m.add_separator()
        m.add_command(label="Открыть журнал", command=self.open_log)
        m.add_command(label="Папка журнала", command=lambda: self.open_path(log_dir()))
        m.add_separator()
        m.add_command(label="Выход (VPN продолжит работать)", command=self.ask_quit)
        r = dark_menu(self)
        r.add_command(label="Доступ к этому компьютеру…", command=self.access)
        r.add_separator()
        r.add_command(label="Состояние RustDesk", command=self.rustdesk_status)
        r.add_command(label="Установить / запустить службу RustDesk", command=lambda: self.rustdesk_repair(False))
        r.add_command(label="Переустановить RustDesk", command=lambda: self.rustdesk_repair(True))
        h = dark_menu(self)
        h.add_command(label="Как открыть доступ к папке…", command=self.help_share)
        h.add_command(label="О программе", command=self.about)
        self.company_menu = dark_menu(self)
        self.company_menu.configure(postcommand=self._fill_company_menu)   # список — при каждом открытии
        self._company_var = tk.StringVar(self, "")
        self._forget_menu = None
        for title, menu in (("Система", m), ("Компания", self.company_menu), ("Управление", r), ("Справка", h)):
            b = tk.Label(bar, text=title, bg=C["bg"], fg=C["text"], padx=8, pady=3, font=("Segoe UI", 9),
                         cursor="hand2")
            b.pack(side="left")
            b.bind("<Enter>", lambda _e, w=b: w.config(bg=C["hover"]))
            b.bind("<Leave>", lambda _e, w=b: w.config(bg=C["bg"]))
            b.bind("<Button-1>", lambda _e, w=b, mm=menu: mm.unpost() if mm.posted else
                   mm.tk_popup(w.winfo_rootx(), w.winfo_rooty() + w.winfo_height() + 2))

        # шапка: кнопка ON/OFF, имя ПК, IP, компания; панели — со скруглёнными углами, без рамки
        self.top_frame = RoundPanel(self)
        self.top_frame.pack(fill="x", padx=8, pady=(8, 6))
        top = self.top_frame.body
        self.power = tk.Canvas(top, width=76, height=76, bg=C["panel"], highlightthickness=0, cursor="hand2")
        self.power.pack(side="left", padx=(6, 8), pady=4)
        self.power.bind("<Button-1>", lambda _e: self.toggle())
        self.power_on, self.power_hover = False, False
        self.power.bind("<Enter>", lambda _e: self._hover_power(True))
        self.power.bind("<Leave>", lambda _e: self._hover_power(False))
        info = tk.Frame(top, bg=C["panel"])
        info.pack(side="left", fill="x", expand=True, pady=6)
        self.name_lbl = tk.Label(info, text=self.state_.get("device_name") or socket.gethostname(), bg=C["panel"],
                                 fg=C["name"], font=("Segoe UI", 12, "bold"), anchor="w", cursor="hand2")
        self.name_lbl.pack(fill="x")
        self.name_lbl.bind("<Double-1>", lambda _e: self.rename())   # двойной щелчок по имени — сменить
        self.ip_lbl = tk.Label(info, text="—", bg=C["panel"], fg=C["text"], font=("Segoe UI", 11, "bold"),
                               anchor="w")
        self.ip_lbl.pack(fill="x")
        # третья строка: компания и сколько ПК в сети; плашка статуса — только когда не «в сети»
        line = tk.Frame(info, bg=C["panel"])
        line.pack(fill="x", pady=(4, 0))
        self.badge = Pill(line, bg=C["panel"])
        self.badge_text = ""
        self.company_lbl = tk.Label(line, text="", bg=C["panel"], fg=C["muted"], font=("Segoe UI", 9), anchor="w",
                                    justify="left", wraplength=230)
        self.company_lbl.pack(side="left", fill="x", expand=True)
        self._set_badge("Запуск…", C["off"])
        self._draw_power(False)

        # компьютеры компании: группы по ролям из кабинета (Склад, Администраторы …), каждую можно свернуть
        self.list_box = RoundPanel(self, stretch=True)
        self.list_box.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.compact = False   # список другим ПК скрыт администратором — окно только с шапкой
        self.collapsed_groups = set(self.state_.get("collapsed_groups") or [])
        self.group_rows: dict[str, str] = {}
        self.list_frame = tk.Frame(self.list_box.body, bg=C["panel"])
        self.list_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(self.list_frame, columns=("ip",), show="tree", style="Hub.Treeview",
                                 selectmode="browse")
        self.tree.column("#0", width=200, stretch=True)
        self.tree.column("ip", width=84, stretch=False, anchor="e")
        self.tree.tag_configure("off", foreground=C["muted"])
        self.tree.tag_configure("group", foreground=C["name"], font=("Segoe UI", 9, "bold"))
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
        self.tree.bind("<Double-1>", lambda e: self._tree_click(e) or self.open_shares())
        self.tree.bind("<Return>", lambda _e: None if HubMenu.open_menu else self.open_shares())   # Enter — пункт меню
        self.tree.bind("<Button-3>", self.peer_menu)
        self.tree.bind("<Button-1>", self._tree_click)
        self.tip = Tooltip(self)
        self.tree.bind("<Motion>", self._tree_hover)
        self.tree.bind("<Leave>", lambda _e: self.tip.hide())

        # меню правой кнопки: с пунктами Radmin Viewer — только если у того ПК есть Radmin Server, а здесь Viewer;
        # с пунктами RustDesk — если удалённое управление включено в кабинете и готово на обоих ПК
        # «Копировать ID RustDesk» — только с облаком RustDesk: без него ID не нужен и его нет
        self.ctx_menus = {(radmin, remote, wake, cloud): self._build_peer_menu(radmin, remote, wake, cloud)
                          for radmin in (True, False) for remote in (True, False) for wake in (True, False)
                          for cloud in (True, False)}
        self.ctx = self.ctx_menus[(False, False, False, False)]

        self.msg_lbl = tk.Label(self, text="", bg=C["bg"], fg=C["muted"], anchor="w", justify="left",
                                wraplength=330, padx=10)
        self.msg_lbl.pack(fill="x", pady=(0, 6))
        self.bind("<Configure>", lambda e: self.msg_lbl.config(wraplength=max(200, e.width - 20))
                  if e.widget is self else None)
        self._build_lock()

    def _set_badge(self, text: str, color: str = ""):
        """Плашка статуса под IP. «В сети» не показываем: это и так видно по зелёной кнопке ON."""
        self.badge_text = text
        if not text:
            self.badge.pack_forget()
            return
        self.badge.show(text, color)
        if not self.badge.winfo_manager():
            self.badge.pack(side="left", padx=(0, 8), before=self.company_lbl)

    def _company_line(self):
        """Компания и сколько её компьютеров в сети: «Zoo Planeta · 5 / 8»."""
        c = self.cfg or {}
        if self.status_now == Status.NEED_LOGIN or not c:
            self.company_lbl.config(text="")
            return
        text = c.get("company") or ""
        if c.get("show_peers") is False:
            text += "  · список скрыт администратором"
        else:
            others = [p for p in self.peers if not p.get("is_me")]
            if others:
                online = sum(1 for p in others if self._peer_online(p))
                text += f"  · {online} / {len(others)}"
        self.company_lbl.config(text=text)
        if self.locked:
            self._lock_info()

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
        if not self.locked and self.worker.lock_ready():
            minutes = self.state_.get("lock_minutes") if self.state_.get("lock_minutes") in LOCK_MINUTES \
                else LOCK_DEFAULT_MINUTES
            if time.monotonic() - self.last_activity >= minutes * 60:
                log.info("программа заблокирована: %d мин без действий", minutes)
                self.lock()
        self.after(250, self._poll)

    LOCKED_ACTIONS = {"toggle": "подключить или отключить сеть", "reconnect": "переподключить сеть",
                      "ask_quit": "закрыть программу"}

    def _on_ui(self, kind, data):
        if self.locked and kind in self.LOCKED_ACTIONS:   # из трея — только после пароля
            self._lock_pending = kind
            self.show()
            self.lock_hint.config(text=f"Чтобы {self.LOCKED_ACTIONS[kind]}, введите пароль этого компьютера.")
            return
        if kind == "show":
            self.show()
        elif kind == "toggle":
            self.toggle()
        elif kind == "reconnect":
            self.worker.force_reconnect()
        elif kind == "quit":
            self.quit_app()
        elif kind == "ask_quit":
            self.ask_quit()
        elif kind == "update":
            # установщик уже запущен: закрываемся, он поставит новую версию и запустит её
            self.tray.notify(APP_TITLE, f"Обновление до версии {data}…")
            self.after(800, self.quit_app)
        elif kind == "rename_done":
            name, err = data
            if not err:
                self.name_lbl.config(text=name)
                if self.cfg:
                    self.cfg = dict(self.cfg, device_name=name)
            if self.rename_dialog:
                self.rename_dialog.done(err)
        elif kind == "login_done":
            if self.login_dialog:
                self.login_dialog.done(data)
            if not data and not self.state_.get("setup_done"):   # первый вход — настройки этого компьютера
                self.after(300, lambda: self.settings(first=True))
        elif kind == "settings_done":
            if self.settings_dialog:
                self.settings_dialog.done(data)
        elif kind == "lock_reset":
            self._lock_reset_done(data)
        elif kind == "info":
            messagebox.showinfo(APP_TITLE, data, parent=self)
        elif kind == "error":
            messagebox.showerror(APP_TITLE, data, parent=self)
        elif kind == "msg_error":
            peer_id, err = data
            if peer_id in self.chats:
                self.chats[peer_id].add("Не отправлено", err, tag="err")

    LOST_AFTER_MS = 20000   # короткие переподключения (смена настроек, переустановка туннеля) — без уведомления

    def _net_notify(self, status):
        """Уведомление в трее: «Подключено к сети …» и «Сеть … недоступна» — только при смене состояния."""
        company = (self.cfg or {}).get("company") or self.state_.get("company_name") or self.state_.get("company_login")
        if status == Status.ONLINE:
            if self._lost_job:
                self.after_cancel(self._lost_job)
                self._lost_job = None
            if self.net_up is not True or company != getattr(self, "_net_company", company):   # или сменили компанию
                self.tray.notify("Подключено к сети", f"«{company}» · {(self.cfg or {}).get('ip', '')}".rstrip(" ·"))
            self.net_up = True
            self._net_company = company
            return
        if status in (Status.OFF, Status.NEED_LOGIN):   # выключили сами / вышли — это не «пропала»
            if self._lost_job:
                self.after_cancel(self._lost_job)
                self._lost_job = None
            self.net_up = False
            return
        if self.net_up and not self._lost_job:
            def lost():
                self._lost_job = None
                if self.status_now != Status.ONLINE and self.net_up:
                    self.net_up = False
                    if self.status_now == Status.LAN_ONLY:
                        self.tray.notify("Нет связи с сервером",
                                         f"Компьютеры офиса в сети «{company}» доступны напрямую.")
                    else:
                        self.tray.notify("Сеть недоступна", f"Нет связи с сетью «{company}». Переподключаемся…")
            self._lost_job = self.after(0 if status == Status.BLOCKED else self.LOST_AFTER_MS, lost)

    def _on_status(self, status, text, cfg):
        self.status_now = status
        if cfg:
            self.cfg = cfg
        label, color = STATUS_VIEW.get(status, ("—", C["off"]))
        self._set_badge("" if status == Status.ONLINE else label, color)
        enabled = self.state_.get("enabled") is not False and status not in (Status.NEED_LOGIN, Status.OFF)
        self._draw_power(enabled)
        c = self.cfg
        if c and status != Status.NEED_LOGIN:
            self.name_lbl.config(text=c.get("device_name") or socket.gethostname())
            self.ip_lbl.config(text=c.get("ip") or "—")
            hidden = c.get("show_peers") is False   # администратор скрыл список (сеть при этом та же)
            self.set_compact(hidden)
        elif status == Status.NEED_LOGIN:
            self.ip_lbl.config(text="—")
            self.set_compact(False)
        self._company_line()
        self.msg_lbl.config(text="" if status == Status.ONLINE else (text or ""))
        if self.compact and not self.locked:
            self._fit_compact()
        # значок в трее: зелёный — в сети, жёлтый — подключается, красный — VPN не работает (выключен, нет входа,
        # сервер недоступен, блок, ошибка)
        self._net_notify(status)
        tray_color = {C["green"]: "green", C["orange"]: "orange"}.get(color, "red")
        ip = (c or {}).get("ip", "")
        self.tray.update(tray_color, f"{APP_TITLE} — {label}" + (f" · {ip}" if ip and status == Status.ONLINE else ""))
        if status == Status.NEED_LOGIN and self.last_status != Status.NEED_LOGIN and not self.login_dialog \
                and not self.locked:
            self.show_login(text)
        if status in (Status.SERVER_DOWN, Status.BLOCKED) or (self.last_status in (Status.SERVER_DOWN, Status.BLOCKED)
                                                              and status != self.last_status):
            self._render_peers()
        self.last_status = status
        self._lock_rights()

    def _lock_rights(self):
        """Право управлять другими ПК забрали — программа больше не блокируется (снять блокировку сразу).
        Дали, а блокировка не настроена, — один раз предложить её в настройках."""
        if self.locked:
            if not self.worker.lock_ready():
                log.info("блокировка снята: у этого ПК нет права управлять другими")
                self.unlock()
            return
        if self.worker.can_control() and not self.worker.lock_ready() and not self.state_.get("lock_offered") \
                and self.state_.get("setup_done") and not self.login_dialog and not self.settings_dialog:
            self.state_.set(lock_offered=True)
            self.after(300, lambda: self.settings(offer_lock=True))

    def _fit_compact(self):
        """Окно по содержимому: пустую строку сообщения не показываем, длинную — целиком."""
        if self.msg_lbl.cget("text"):
            self.msg_lbl.pack(fill="x", pady=(0, 6))
        else:
            self.msg_lbl.pack_forget()
        self.update_idletasks()
        self.top_frame.fit()
        self.update_idletasks()
        self._size = (max(self.winfo_width(), 320), self.winfo_reqheight())
        self.geometry(f"{self._size[0]}x{self._size[1]}")
        if self.state() == "normal":
            self.place_corner()

    def _peer_online(self, p: dict) -> bool:
        return bool(p.get("online")) and self.status_now not in (Status.SERVER_DOWN, Status.BLOCKED, Status.OFF)

    def _on_peers(self, peers):
        self.peers = peers
        self._render_peers()
        self._company_line()

    def _render_peers(self):
        """Список: заголовок группы (роль, сколько в сети) и её компьютеры; свёрнутая группа — только заголовок."""
        sel = self.tree.selection()
        top = self.tree.yview()[0]
        self.tree.delete(*self.tree.get_children())
        groups = group_peers(p for p in self.peers if not p.get("is_me"))
        self.group_rows = {}   # строка заголовка → имя группы (имя роли может быть любым — в id строки его нет)
        for i, (name, group) in enumerate(groups):
            if name:
                closed = name in self.collapsed_groups
                online = sum(1 for p in group if self._peer_online(p))
                self.group_rows[f"g:{i}"] = name
                self.tree.insert("", "end", iid=f"g:{i}", text=("▶  " if closed else "▼  ") + name,
                                 values=(f"{online} / {len(group)}",), tags=("group",))
                if closed:
                    continue
            for p in group:
                online = self._peer_online(p)
                self.tree.insert("", "end", iid=str(p["id"]), text=" " + p["name"],
                                 image=self.link_img[peer_link(p, online)], values=(p["ip"],),
                                 tags=() if online else ("off",))
        if sel and self.tree.exists(sel[0]):
            self.tree.selection_set(sel[0])
        self.tree.yview_moveto(top)

    def _tree_click(self, event):
        """Щелчок по заголовку группы — свернуть / развернуть её."""
        row = self.tree.identify_row(event.y)
        if row in self.group_rows:
            self.toggle_role_group(self.group_rows[row])
            return "break"
        return None

    def toggle_role_group(self, name: str):
        self.collapsed_groups ^= {name}
        self.state_.set(collapsed_groups=sorted(self.collapsed_groups))   # запомнить до следующего запуска
        self._render_peers()

    def _tree_hover(self, event):
        """Подсказка над значком: как связан ПК (через сервер, по локальной сети, через интернет)."""
        row = self.tree.identify_row(event.y)
        box = self.tree.bbox(row, "#0") if row else None
        p = next((x for x in self.peers if str(x.get("id")) == row), None) if box else None
        if not p or event.x > box[0] + 40:   # только над значком (он после отступа строки)
            self.tip.hide()
            return
        online = "off" not in self.tree.item(row, "tags")
        self.tip.show(LINK_HINTS[peer_link(p, online)], event.x_root, event.y_root)

    # --- окно и трей
    def show(self):
        self.place_corner()
        self.deiconify()
        self.after(30, self.place_corner)   # рамка окна известна только после показа
        self.lift()
        try:
            self.attributes("-topmost", True)
            self.after(200, lambda: self.attributes("-topmost", False))
            self.focus_force()
        except tk.TclError:
            pass
        if self.locked:
            self.after(60, self.lock_entry.focus_force)
        elif not self.state_.get("setup_done") and self.state_.get("token") and not self.login_dialog:
            self.after(300, lambda: self.settings(first=True))   # обновились с прежней версии — один раз

    # --- блокировка программы
    def _activity(self, _event=None):
        if not self.locked:
            self.last_activity = time.monotonic()

    def _build_lock(self):
        """Экран блокировки — поверх всего окна (меню, список, кнопка ON/OFF под ним недоступны)."""
        f = tk.Frame(self, bg=C["bg"])
        panel = RoundPanel(f)
        panel.pack(expand=True, fill="x", padx=8)
        b = panel.body
        try:
            from PIL import ImageTk
            self._lock_logo = ImageTk.PhotoImage(tray_image(C["green"], 56, original=True))
            tk.Label(b, image=self._lock_logo, bg=C["panel"]).pack(pady=(14, 6))
        except Exception:  # noqa: BLE001
            log.debug("значок на экране блокировки не нарисован", exc_info=True)
        tk.Label(b, text="Программа заблокирована", bg=C["panel"], fg=C["text"],
                 font=("Segoe UI", 12, "bold")).pack()
        # и под блокировкой видно, работает ли сеть: статус, имя и IP этого ПК, компания
        self.lock_status = Pill(b, bg=C["panel"])
        self.lock_status.pack(pady=(8, 2))
        self.lock_net = tk.Label(b, text="", bg=C["panel"], fg=C["text"], font=("Segoe UI", 10, "bold"))
        self.lock_net.pack(pady=(2, 0))
        self.lock_company = tk.Label(b, text="", bg=C["panel"], fg=C["muted"], font=("Segoe UI", 9),
                                     wraplength=280, justify="center")
        self.lock_company.pack(pady=(0, 0))
        self.lock_hint = tk.Label(b, text="", bg=C["panel"], fg=C["muted"], font=("Segoe UI", 9), wraplength=280,
                                  justify="center")
        self.lock_hint.pack(pady=(10, 4), padx=12)
        self.lock_var = tk.StringVar()
        self.lock_entry = ttk.Entry(b, textvariable=self.lock_var, show="•", width=30, justify="center")
        self.lock_entry.pack(padx=24, fill="x")
        self.lock_entry.bind("<Return>", lambda _e: self._lock_submit())
        self.lock_err = tk.Label(b, text="", bg=C["panel"], fg=C["red"], font=("Segoe UI", 9), wraplength=280)
        self.lock_err.pack(pady=(4, 0))
        self.lock_btn = ttk.Button(b, text="Разблокировать", command=self._lock_submit)
        self.lock_btn.pack(padx=24, fill="x", pady=(2, 6))
        self.lock_forgot = tk.Label(b, text="Забыли пароль?", bg=C["panel"], fg=C["muted"], cursor="hand2",
                                    font=("Segoe UI", 8, "underline"))
        self.lock_forgot.pack(pady=(0, 12))
        self.lock_forgot.bind("<Button-1>", lambda _e: self._lock_mode(not self._lock_reset))
        self._lock_reset = False
        self.lock_frame = f

    def _lock_mode(self, reset: bool):
        """Обычный вход паролем этого компьютера или сброс забытого пароля паролем подключения компании."""
        self._lock_reset = reset
        self.lock_var.set("")
        self.lock_err.config(text="")
        if reset:
            self.lock_hint.config(text="Введите пароль подключения компании (его знает администратор компании). "
                                       "Блокировка снимется, новый пароль можно будет задать в настройках.")
            self.lock_btn.config(text="Снять блокировку")
            self.lock_forgot.config(text="Вспомнил пароль")
        else:
            self.lock_hint.config(text="Введите пароль этого компьютера.")
            self.lock_btn.config(text="Разблокировать")
            self.lock_forgot.config(text="Забыли пароль?")
        self.lock_entry.focus_set()

    def _lock_info(self):
        """Строки экрана блокировки: статус подключения, имя и IP этого ПК, компания — как в шапке окна."""
        c = self.cfg or {}
        label, color = STATUS_VIEW.get(self.status_now, ("Запуск…", C["off"]))
        self.lock_status.show(label, color)
        ip = c.get("ip") if self.status_now != Status.NEED_LOGIN else ""
        self.lock_net.config(text=" · ".join(x for x in (c.get("device_name") or self.state_.get("device_name"),
                                                        ip) if x))
        self.lock_company.config(text=self.company_lbl.cget("text") or self.state_.get("company_name") or "")

    def lock_now(self):
        if not self.worker.can_control():
            messagebox.showinfo(APP_TITLE, "Программа блокируется только на компьютерах, которым администратор "
                                           "компании разрешил управлять другими ПК.", parent=self)
            return
        if not self.worker.lock_ready():
            messagebox.showinfo(APP_TITLE, "Сначала задайте пароль этого компьютера и включите блокировку.",
                                parent=self)
            self.settings()
            return
        self.lock()

    def lock(self):
        if self.locked:
            return
        self.locked = True
        if HubMenu.open_menu:
            HubMenu.open_menu.unpost()
        self.tip.hide()
        for dlg in (self.rename_dialog, self.settings_dialog):
            if dlg is not None and dlg.winfo_exists():
                dlg.close()
        self._lock_chats = []
        for win in list(self.chats.values()):   # переписку чужой человек не увидит
            if win.winfo_exists() and win.state() != "withdrawn":
                win.withdraw()
                self._lock_chats.append(win)
        self.tree.configure(takefocus=0)
        self._lock_info()
        self._lock_pending = None
        self._lock_mode(False)
        self.lock_frame.place(x=0, y=0, relwidth=1, relheight=1)
        self.lock_frame.lift()
        if self.compact:   # окно без списка низкое — экрану блокировки нужно место
            self.geometry(f"{self._size[0]}x{max(self._size[1], 390)}")
            if self.state() == "normal":
                self.place_corner()

    def unlock(self):
        self.locked = False
        self.last_activity = time.monotonic()
        self._lock_fails = 0
        self.lock_frame.place_forget()
        self.lock_var.set("")
        self.tree.configure(takefocus=1)
        for win in self._lock_chats:
            if win.winfo_exists():
                win.deiconify()
        self._lock_chats = []
        if self.compact:
            self._fit_compact()
        pending, self._lock_pending = self._lock_pending, None
        if pending:
            self.after(50, lambda: self._on_ui(pending, None))

    def _lock_submit(self):
        now = time.monotonic()
        if now < self._lock_until:
            self.lock_err.config(text=f"Слишком много попыток. Подождите {int(self._lock_until - now) + 1} с.")
            return
        password = self.lock_var.get()
        if self._lock_reset:
            self.lock_btn.config(state="disabled")
            threading.Thread(target=lambda: self.ui_q.put(("lock_reset", self.worker.reset_lock(password))),
                             daemon=True, name="lock-reset").start()
            return
        if self.worker.check_unlock(password):
            log.info("программа разблокирована")
            self.unlock()
            return
        self._lock_failed("Неверный пароль.")

    def _lock_failed(self, text: str):
        self._lock_fails += 1
        self.lock_var.set("")
        if self._lock_fails % LOCK_TRIES == 0:
            self._lock_until = time.monotonic() + LOCK_PAUSE * (self._lock_fails // LOCK_TRIES)
            text += f" Слишком много попыток — подождите {int(self._lock_until - time.monotonic())} с."
            log.warning("блокировка: %d неверных паролей подряд", self._lock_fails)
        self.lock_err.config(text=text)

    def _lock_reset_done(self, err):
        self.lock_btn.config(state="normal")
        if err:
            self._lock_failed(err)
            return
        self.unlock()
        self.after(200, self.settings)   # задать новый пароль

    def settings(self, first: bool = False, offer_lock: bool = False):
        if self.locked:
            return
        if self.settings_dialog and self.settings_dialog.winfo_exists():
            self.settings_dialog.lift()
            return
        if first and self.state_.get("setup_done"):
            return
        self.show()
        self.settings_dialog = SettingsDialog(self, first=first, offer_lock=offer_lock)

    def place_corner(self):
        """Окно — в правый нижний угол рабочей области (над панелью задач), как у программ из трея."""
        try:
            self.update_idletasks()
            mapped = self.winfo_ismapped() and self.winfo_width() > 1
            w, h = (self.winfo_width(), self.winfo_height()) if mapped else self._size
            self._size = (w, h)
            # рамка окна Windows: заголовок и края (пока окно не показано — обычные размеры)
            border = (max(self.winfo_rootx() - self.winfo_x(), 0) if mapped else 0) or 8
            title = (max(self.winfo_rooty() - self.winfo_y(), 0) if mapped else 0) or 31
            left, top, right, bottom = work_area(self)
            x = max(left, right - w - 2 * border - 4)
            y = max(top, bottom - h - title - border - 4)
            self._pos = (x, y)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except tk.TclError:
            pass

    def frame_box(self) -> tuple[int, int, int, int]:
        """Где главное окно (x, y, ширина, высота) — даже если оно ещё не показано."""
        if self._pos is None:
            self.place_corner()
        x, y = self._pos or (0, 0)
        return x, y, self._size[0], self._size[1]

    def set_compact(self, compact: bool):
        """Нет доступа к списку ПК — окно ниже: только шапка (кнопка, имя, IP, статус) и строка сообщений."""
        if compact == self.compact:
            return
        self.compact = compact
        width = self.winfo_width() if self.winfo_width() > 1 else 360
        if compact:
            self.list_box.pack_forget()
            self.resizable(False, False)
            self.minsize(320, 1)
            self.update_idletasks()
            self._size = (width, self.winfo_reqheight())
            self.geometry(f"{width}x{self._size[1]}")
        else:
            self.list_box.pack(fill="both", expand=True, padx=8, pady=(0, 4), after=self.top_frame)
            self.msg_lbl.pack(fill="x", pady=(0, 6))
            self.minsize(320, 380)
            self.resizable(False, True)
            self._size = (width, 620)
            self.geometry(f"{width}x620")
        if self.locked and compact:   # экрану блокировки нужно место
            self.geometry(f"{width}x{max(self._size[1], 330)}")
        if self.state() == "normal":
            self.place_corner()

    def _on_unmap(self, event):
        if event.widget is self and self.tray.ok:
            self.after(10, lambda: self.state() == "iconic" and self.withdraw())

    def hide(self):
        if self.tray.ok:
            self.withdraw()
        else:
            self.iconify()

    # --- действия
    def toggle(self):
        if self.status_now == Status.NEED_LOGIN:
            self.show_login()
            return
        enabled = self.state_.get("enabled") is not False
        self._draw_power(not enabled)
        self._set_badge("Отключение…" if enabled else "Подключение…", C["orange"])
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
        current = next((p["key"] for p in profiles if p["active"]), "")
        self._company_var.set(current)
        for p in profiles:
            title = self._company_title(p)
            m.add_radiobutton(label=title, variable=self._company_var, value=p["key"], selectcolor=C["green"],
                              command=(lambda: None) if p["active"] else
                              (lambda k=p["key"], t=title, cur=current: self.switch_company(k, t, cur)))
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

    def switch_company(self, key: str, title: str, current: str = ""):
        if not messagebox.askyesno(APP_TITLE, f"Переключиться на «{title}»?\n\n"
                                              "Сеть текущей компании отключится — компьютер будет в сети выбранной. "
                                              "Вернуться можно так же, через меню «Компания».", parent=self):
            self._company_var.set(current)   # отказались — отметка остаётся на текущей
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

    def _build_peer_menu(self, radmin: bool, remote: bool = False, wake: bool = False, cloud: bool = False):
        m = dark_menu(self)
        if wake:
            m.add_command(label="Включить компьютер", command=self.wake_peer, font=("Segoe UI", 9, "bold"))
            m.add_separator()
        m.add_command(label="Сообщение", command=self.message)
        m.add_separator()
        m.add_command(label="Копировать IP-адрес", command=self.copy_ip)
        m.add_separator()
        m.add_command(label="Пинг", command=self.ping)
        m.add_command(label="Общие папки", command=self.open_shares)
        m.add_command(label="Подключить сетевой диск…", command=self.map_drive)
        m.add_separator()
        if remote:
            m.add_command(label="Удалённое управление", command=lambda: self.remote("control"),
                          font=("Segoe UI", 9, "bold"))
            m.add_command(label="Передача файлов (RustDesk)", command=lambda: self.remote("files"))
            if cloud:
                m.add_command(label="Копировать ID RustDesk", command=self.copy_rustdesk_id)
        if radmin:
            m.add_command(label="Полное управление", command=lambda: self.radmin("full"),
                          font=("Segoe UI", 9, "bold"))
            m.add_command(label="Только просмотр", command=lambda: self.radmin("view"))
            m.add_command(label="Передача файлов", command=lambda: self.radmin("files"))
        m.add_command(label="Удалённый рабочий стол (RDP)", command=self.remote_desktop)
        m.add_separator()
        m.add_command(label="Свойства", command=self.properties)
        return m

    def peer_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row or row.startswith("g:"):   # заголовок группы — без меню
            return
        self.tree.selection_set(row)
        viewer = find_radmin_viewer(self.state_.get("radmin_path") or "")
        peer = self.selected_peer()
        self.ctx = self.ctx_menus[(radmin_menu_allowed(peer, viewer), remote_menu_allowed(peer, self.cfg),
                                   wake_menu_allowed(peer), remote_cloud_on(self.cfg))]
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
            if self.locked:   # покажем после разблокировки; текст чужому человеку не виден
                win.withdraw()
                if win not in self._lock_chats:
                    self._lock_chats.append(win)
        if msgs and self.locked:
            self.tray.notify(f"Сообщение от {msgs[-1]['from_name']}", "Разблокируйте Retix Hub, чтобы прочитать.")
        elif msgs:
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

    def remote(self, kind: str):
        """RustDesk -> RustDesk выбранного ПК (прямой доступ по IP в сети Retix Hub) с разрешения сервера."""
        p = self.selected_peer()
        if not p:
            return
        if not p["online"]:
            messagebox.showinfo(APP_TITLE, f"{p['name']} сейчас не в сети.", parent=self)
            return
        exe = rustdesk_exe()
        if not exe:
            messagebox.showinfo(APP_TITLE, "RustDesk на этом компьютере ещё ставится — попробуйте через пару минут.",
                                parent=self)
            return
        subnet = (self.cfg or {}).get("subnet") or ""

        def work():   # запрос к серверу и проверка порта — несколько секунд, окно не держим
            res, err = self.worker.remote_connect(p["id"], kind)
            if err:
                self.ui_q.put(("error", f"Удалённое управление {p['name']}:\n{err}"))
                return
            ip, port, password = res.get("ip"), res.get("port"), str(res.get("password") or "")
            if not peer_ip_ok(ip, subnet) or not isinstance(port, int) or not 0 < port < 65536 \
                    or not REMOTE_PW_RE.match(password or "x" * 12):
                self.ui_q.put(("error", "Сервер прислал неверный адрес для подключения."))
                return
            if not port_open(ip, port):
                self.ui_q.put(("error", f"RustDesk на {p['name']} ({ip}:{port}) не отвечает.\n\n"
                                        "• на том ПК ещё ставится RustDesk или он выключен;\n"
                                        "• на том ПК старая версия Retix Hub — обновите до последней;\n"
                                        "• сервер Retix Hub не обновлён (git pull && ./run.sh)."))
                return
            log.info("RustDesk: %s %s:%s (%s)", kind, ip, port, res.get("mode"))
            try:
                subprocess.Popen(rustdesk_args(exe, ip, port, kind, password), cwd=str(exe.parent))
            except OSError as e:
                self.ui_q.put(("error", f"Не удалось запустить RustDesk\n{e.strerror or e}"))
                return
            if res.get("mode") == "ask":
                self.ui_q.put(("info", f"Запрос отправлен на {p['name']}.\n"
                                       "Подключение начнётся, когда пользователь того ПК нажмёт «Принять»."))
            elif res.get("mode") == "own":
                self.ui_q.put(("info", f"Пользователь {p['name']} защитил компьютер своим паролем.\n"
                                       "Введите в окне RustDesk пароль, который он вам сообщил."))
        threading.Thread(target=work, daemon=True, name="remote").start()

    def wake_peer(self):
        """Включить выбранный выключенный ПК по сети: команду отправит включённый ПК из его локальной сети."""
        p = self.selected_peer()
        if not p:
            return

        def work():
            msg, err = self.worker.wake_peer(p["id"])
            self.ui_q.put(("error", f"Включить {p['name']}:\n{err}") if err else ("info", msg))
        threading.Thread(target=work, daemon=True, name="wake").start()

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
            f"Связь:  {('напрямую через интернет' if p.get('direct_wan') else 'напрямую по локальной сети') if p.get('direct') else 'через сервер Retix Hub'}",
            f"Последняя связь:  {seen}",
            f"Версия Retix Hub:  {p.get('client_version') or '—'}",
            "",
            f"Общие папки:  \\\\{p['ip']}",
            *([f"Radmin:  {p['ip']}:{(self.cfg or {}).get('radmin_port') or RADMIN_PORT}"]
              if p.get("radmin_server") else []),
            *([f"RustDesk:  {p['ip']}:{((self.cfg or {}).get('remote') or {}).get('port') or REMOTE_PORT}"]
              if p.get("remote") else []),
            *([f"ID RustDesk (облако):  {p['rustdesk_id']}"] if p.get("rustdesk_id") else []),
        ]), parent=self)

    def copy_rustdesk_id(self):
        """ID RustDesk того ПК — подключиться через облако RustDesk из любого места (если включено в кабинете)."""
        p = self.selected_peer()
        if not p:
            return
        rid = str(p.get("rustdesk_id") or "")
        if not RUSTDESK_ID_RE.match(rid):
            messagebox.showinfo(APP_TITLE, rustdesk_id_missing_reason(p, self.cfg), parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(rid)

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

    def rustdesk_status(self):
        def work():
            self.ui_q.put(("info", self.worker.rustdesk_status()))
        threading.Thread(target=work, daemon=True, name="rd-status").start()

    def rustdesk_repair(self, reinstall: bool):
        what = "Переустановить RustDesk" if reinstall else "Установить / запустить службу RustDesk"
        if reinstall and not messagebox.askyesno(APP_TITLE, "Переустановить RustDesk?\n\nОн будет удалён и поставлен "
                                                            "заново (около минуты), идущий сеанс управления прервётся.",
                                                 parent=self):
            return
        self.tray.notify(APP_TITLE, f"{what}…")

        def work():
            ok, text = self.worker.repair_rustdesk(reinstall)
            self.ui_q.put(("info" if ok else "error", text))
        threading.Thread(target=work, daemon=True, name="rd-repair").start()

    def access(self):
        self.settings()

    def rename(self):
        if self.rename_dialog and self.rename_dialog.winfo_exists():
            self.rename_dialog.lift()
            return
        self.show()
        self.rename_dialog = RenameDialog(self)

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

    def ask_quit(self):
        if messagebox.askyesno(APP_TITLE, "Закрыть программу Retix Hub?\n\nVPN продолжит работать — его держит "
                                          "служба WireGuard. Отключить сеть — кнопка OFF.", parent=self):
            self.quit_app()

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


def signal_running_instance(show: bool = True) -> bool:
    """Программа уже запущена? Тогда показать её окно (show) и выйти (без лишнего окна UAC)."""
    if not WINDOWS:
        return False
    k = _k32()
    h = k.OpenEventW(0x0002 | 0x00100000, False, SHOW_EVENT)   # EVENT_MODIFY_STATE | SYNCHRONIZE
    if not h:
        return False
    if show:
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
        make_link_images()
        version = root.tk.call("info", "patchlevel")
        root.destroy()
        return f"Tcl/Tk {version}"

    def crypto_check():
        key = X25519PrivateKey.generate()
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if len(pub) != 32:
            raise ValueError(f"длина ключа {len(pub)}")
        import cryptography
        return f"x25519, cryptography {cryptography.__version__}"

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
    state = State()
    for step in (Tunnel.uninstall, lambda: ensure_firewall(None), lambda: ensure_direct_firewall(0),
                 remove_autostart, lambda: uninstall_remote(state)):
        try:
            step()
        except Exception:  # noqa: BLE001
            log.exception("uninstall")
    state.set(last_conf_hash="", fw_subnet="", fw_direct=0, autostart_done=False)
    return 0


def main():
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    uninstall = "--uninstall" in sys.argv
    # уже запущена — показать окно; до UAC, чтобы не спрашивать права зря. С --minimized (автозапуск,
    # перезапуск после обновления) — окно не открывать
    show = "--minimized" not in sys.argv
    if not uninstall and signal_running_instance(show):
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
        signal_running_instance(show)
        return
    log.info("старт %s (%s)", VERSION, " ".join(sys.argv[1:]) or "без параметров")
    show_event = create_show_event() if WINDOWS else None
    # всегда в трей (окно — из трея); --show — открыть окно сразу. Нужен вход — окно входа покажется само.
    app = App(State(), minimized="--show" not in sys.argv)
    if show_event:
        watch_show_event(show_event, app.ui_q)
    try:
        app.mainloop()
    finally:
        log.info("окно закрыто")


if __name__ == "__main__":
    main()
