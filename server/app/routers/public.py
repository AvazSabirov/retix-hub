"""Публичная часть hub.retix.uz: главная страница, скачивание клиента, справка по API."""
import os

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, RedirectResponse

from ..config import APP_NAME, APP_VERSION, DOWNLOADS_DIR, PUBLIC_URL
from ..web import templates

router = APIRouter(include_in_schema=False)

CLIENT_FILE = "RetixHub.exe"
WIREGUARD_URL = "https://download.wireguard.com/windows-client/wireguard-installer.exe"


def client_available() -> bool:
    return os.path.isfile(os.path.join(DOWNLOADS_DIR, CLIENT_FILE))


@router.get("/")
def landing(request: Request, msg: str = "", err: int = 0):
    return templates.TemplateResponse(request, "landing.html", {
        "title": APP_NAME, "version": APP_VERSION, "public_url": PUBLIC_URL,
        "client_available": client_available(), "wireguard_url": WIREGUARD_URL,
        "msg": msg, "err": err})


@router.get("/download/client")
def download_client():
    path = os.path.join(DOWNLOADS_DIR, CLIENT_FILE)
    if not os.path.isfile(path):
        return RedirectResponse("/?msg=Клиент+ещё+не+выложен.+Обратитесь+к+администратору.&err=1#download",
                                status_code=303)
    return FileResponse(path, filename=CLIENT_FILE, media_type="application/octet-stream")


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
        },
    }
