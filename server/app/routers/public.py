"""Публичная часть hub.retix.uz: главная страница, скачивание клиента, справка по API."""
import glob
import hashlib
import os
import re
import threading

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, RedirectResponse

from ..config import APP_NAME, APP_VERSION, DOWNLOADS_DIR, PUBLIC_URL
from ..web import templates

router = APIRouter(include_in_schema=False)

CLIENT_FILE = "RetixHub.exe"              # старый вариант: один exe
SETUP_PATTERN = "RetixHub_Setup_*.exe"     # установщик из client/build.bat — отдаётся самый новый
WIREGUARD_URL = "https://download.wireguard.com/windows-client/wireguard-installer.exe"


SETUP_RE = re.compile(r"^RetixHub_Setup_(\d+(?:\.\d+){1,3})\.exe$")


def _version_key(path: str):
    ver = os.path.basename(path)[len("RetixHub_Setup_"):-len(".exe")]
    return [int(p) if p.isdigit() else 0 for p in ver.split(".")], os.path.getmtime(path)


def client_file() -> str | None:
    """Что отдавать по «Скачать»: самый новый RetixHub_Setup_<версия>.exe, иначе RetixHub.exe."""
    setups = [p for p in glob.glob(os.path.join(DOWNLOADS_DIR, SETUP_PATTERN)) if os.path.isfile(p)]
    if setups:
        return max(setups, key=_version_key)
    path = os.path.join(DOWNLOADS_DIR, CLIENT_FILE)
    return path if os.path.isfile(path) else None


def client_available() -> bool:
    return client_file() is not None


_sha_cache: dict[tuple, str] = {}
_sha_lock = threading.Lock()


def file_sha256(path: str) -> str:
    """sha256 установщика; считается один раз на файл (путь, размер, время изменения)."""
    st = os.stat(path)
    key = (path, st.st_size, st.st_mtime_ns)
    with _sha_lock:
        if key not in _sha_cache:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            _sha_cache.clear()
            _sha_cache[key] = h.hexdigest()
        return _sha_cache[key]


@router.get("/")
def landing(request: Request, msg: str = "", err: int = 0):
    return templates.TemplateResponse(request, "landing.html", {
        "title": APP_NAME, "version": APP_VERSION, "public_url": PUBLIC_URL,
        "client_available": client_available(),
        "client_name": os.path.basename(client_file() or CLIENT_FILE), "wireguard_url": WIREGUARD_URL,
        "msg": msg, "err": err})


@router.get("/download/client")
def download_client():
    path = client_file()
    if not path:
        return RedirectResponse("/?msg=Клиент+ещё+не+выложен.+Обратитесь+к+администратору.&err=1#download",
                                status_code=303)
    return FileResponse(path, filename=os.path.basename(path), media_type="application/octet-stream")


@router.get("/api/client/version")
def client_version():
    """Автообновление клиента: самая новая версия установщика в downloads/ и его sha256.
    Клиент проверяет раз в 10 минут, скачивает /download/client и сверяет sha256."""
    path = client_file()
    m = SETUP_RE.match(os.path.basename(path)) if path else None
    if not m:
        return {"version": None}
    return {"version": m.group(1), "file": os.path.basename(path), "size": os.path.getsize(path),
            "sha256": file_sha256(path), "url": "/download/client"}


@router.get("/download/wireguard")
def download_wireguard():
    return RedirectResponse(WIREGUARD_URL, status_code=302)


@router.get("/api")
def api_info():
    """Короткая справка: какие запросы принимает hub.retix.uz."""
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "base_url": f"{PUBLIC_URL}/api",
        "endpoints": {
            "GET /api/ping": "проверка доступности сервера",
            "POST /api/register": "регистрация ПК по логину и паролю компании",
            "GET /api/me": "конфигурация WireGuard этого ПК (Bearer-токен)",
            "GET /api/peers": "пользователи сети своей компании (Bearer-токен)",
            "POST /api/heartbeat": "отметка клиента (Bearer-токен)",
            "POST /api/logout": "выход ПК из сети компании (Bearer-токен)",
            "GET /api/client/version": "последняя версия клиента и sha256 установщика (автообновление)",
        },
    }
