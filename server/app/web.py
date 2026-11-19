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
templates.env.filters["ts"] = lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—"
templates.env.globals["server_version"] = APP_VERSION   # в шапке суперадмина: какой сервер сейчас работает


def redirect(url: str, msg: str = "", err: bool = False) -> RedirectResponse:
    if msg:
        url, hash_, fragment = url.partition("#")   # сообщение — до «#раздела», иначе браузер его не пошлёт
        url += ("&" if "?" in url else "?") + urlencode({"msg": msg, **({"err": 1} if err else {})}) + hash_ + fragment
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
    return bool(expected) and hmac.compare_digest(expected.encode(), str(token or "").encode())


templates.env.filters["dt"] = lambda s: dt_text(s) if s else "—"


class LoginRequired(HTTPException):
    def __init__(self, url: str):
        super().__init__(status_code=303, headers={"Location": url})


# ---------- защита страниц: чужие формы (CSRF) и заголовки ----------

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
PROTECTED_PREFIXES = ("/admin", "/cabinet")
SECURITY_HEADERS = [
    (b"x-frame-options", b"DENY"),                    # страницы кабинетов не открыть в чужой рамке
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"content-security-policy",
     b"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
     b"frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'"),
]


def _same_origin(value: str, host: str) -> bool:
    from urllib.parse import urlsplit
    try:
        u = urlsplit(value)
    except ValueError:
        return False
    return u.scheme in ("http", "https") and bool(u.netloc) and u.netloc.lower() == host.lower()


class SecurityMiddleware:
    """POST в кабинеты и суперадмин — только со страниц этого же сайта (Origin/Referer = Host). Cookie сессии уже
    SameSite=Strict, но «тот же сайт» для браузера — весь *.retix.uz: XSS на любом поддомене смог бы отправлять
    формы. Нет ни Origin, ни Referer (старый браузер, скрипт) — пропускаем, как раньше.
    Каждому ответу — заголовки безопасности; HSTS — когда сайт работает по https (COOKIE_SECURE)."""

    def __init__(self, app, hsts: bool = False):
        self.app = app
        self.headers = SECURITY_HEADERS + ([(b"strict-transport-security", b"max-age=31536000")] if hsts else [])

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        if scope["method"] in UNSAFE_METHODS and scope["path"].startswith(PROTECTED_PREFIXES):
            host = headers.get("host", "")
            source = headers.get("origin") or headers.get("referer")
            if source is not None and not _same_origin(source, host):
                body = "Запрос отклонён: форма отправлена не со страницы Retix Hub".encode()
                await send({"type": "http.response.start", "status": 403,
                            "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                                        (b"content-length", str(len(body)).encode()), *self.headers]})
                await send({"type": "http.response.body", "body": body})
                return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                have = {k.lower() for k, _ in message.get("headers") or []}
                message = dict(message, headers=[*message.get("headers", []),
                                                 *((k, v) for k, v in self.headers if k not in have)])
            await send(message)

        await self.app(scope, receive, send_with_headers)
