"""Публичная часть hub.retix.uz: главная страница, скачивание клиента, справка по API."""
import glob
import os

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, RedirectResponse

from .. import db, updates
from ..config import APP_NAME, APP_VERSION, DOWNLOADS_DIR, PUBLIC_URL
from ..web import templates

router = APIRouter(include_in_schema=False)

CLIENT_FILE = "RetixHub.exe"              # старый вариант: один exe
SETUP_PATTERN = "RetixHub_Setup_*.exe"     # установщик из client/build.bat — отдаётся самый новый
WIREGUARD_URL = "https://download.wireguard.com/windows-client/wireguard-installer.exe"


def _version_key(path: str):
    ver = os.path.basename(path)[len("RetixHub_Setup_"):-len(".exe")]
    return [int(p) if p.isdigit() else 0 for p in ver.split(".")], os.path.getmtime(path)


def _site_release():
    conn = db.connect()
    try:
        return updates.site_release(conn)
    finally:
        conn.close()


def client_file() -> str | None:
    """Что отдавать по «Скачать»: версия, опубликованная в суперадмине для всех компаний;
    если таких нет — самый новый RetixHub_Setup_<версия>.exe из downloads/, иначе RetixHub.exe."""
    rel = _site_release()
    if rel is not None:
        return os.path.join(updates.updates_dir(), rel["stored_name"])
    setups = [p for p in glob.glob(os.path.join(DOWNLOADS_DIR, SETUP_PATTERN)) if os.path.isfile(p)]
    if setups:
        return max(setups, key=_version_key)
    path = os.path.join(DOWNLOADS_DIR, CLIENT_FILE)
    return path if os.path.isfile(path) else None


def client_available() -> bool:
    return client_file() is not None


@router.get("/")
def landing(request: Request, msg: str = "", err: int = 0):
    return templates.TemplateResponse(request, "landing.html", {
        "title": APP_NAME, "version": APP_VERSION, "public_url": PUBLIC_URL,
        "client_available": client_available(),
        "client_name": _client_name(), "wireguard_url": WIREGUARD_URL,
        "msg": msg, "err": err})


def _client_name() -> str:
    rel = _site_release()
    return rel["file_name"] if rel is not None else os.path.basename(client_file() or CLIENT_FILE)


@router.get("/download/client")
def download_client():
    rel = _site_release()
    if rel is not None:
        conn = db.connect()
        try:
            conn.execute("UPDATE app_releases SET site_downloads=site_downloads+1 WHERE id=?", (rel["id"],))
            conn.commit()
        finally:
            conn.close()
        return FileResponse(os.path.join(updates.updates_dir(), rel["stored_name"]), filename=rel["file_name"],
                            media_type="application/octet-stream")
    path = client_file()
    if not path:
        return RedirectResponse("/?msg=Клиент+ещё+не+выложен.+Обратитесь+к+администратору.&err=1#download",
                                status_code=303)
    return FileResponse(path, filename=os.path.basename(path), media_type="application/octet-stream")


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
            "GET /api/update": "обновление клиента: версия и подписанный манифест (Bearer-токен)",
        },
    }
