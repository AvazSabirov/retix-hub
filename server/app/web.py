"""Общее для HTML-кабинетов: шаблоны, редиректы с сообщениями."""
import hmac
import os
import secrets
import time
from urllib.parse import urlencode

from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .config import APP_VERSION
from .updates import dt_text

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


def _ago(ts: int) -> str:
    if not ts:
        return "никогда"
    s = int(time.time() - ts)
    if s < 60:
        return f"{s} сек назад"
    if s < 3600:
        return f"{s // 60} мин назад"
    if s < 86400:
        return f"{s // 3600} ч назад"
    return f"{s // 86400} дн назад"


templates.env.filters["ago"] = _ago
templates.env.globals["server_version"] = APP_VERSION   # в шапке суперадмина: какой сервер сейчас работает


def redirect(url: str, msg: str = "", err: bool = False) -> RedirectResponse:
    if msg:
        url += ("&" if "?" in url else "?") + urlencode({"msg": msg, **({"err": 1} if err else {})})
    return RedirectResponse(url, status_code=303)


def csrf_token(request) -> str:
    """Токен формы для сессии (страница «Обновления»): чужой сайт его не знает."""
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(24)
        request.session["csrf"] = token
    return token


def csrf_ok(request, token) -> bool:
    expected = request.session.get("csrf") or ""
    return bool(expected) and hmac.compare_digest(expected, str(token or ""))


templates.env.filters["dt"] = lambda s: dt_text(s) if s else "—"


class LoginRequired(HTTPException):
    def __init__(self, url: str):
        super().__init__(status_code=303, headers={"Location": url})
