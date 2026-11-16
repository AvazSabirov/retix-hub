"""Общее для HTML-кабинетов: шаблоны, редиректы с сообщениями."""
import os
import time
from urllib.parse import urlencode

from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

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


def redirect(url: str, msg: str = "", err: bool = False) -> RedirectResponse:
    if msg:
        url += ("&" if "?" in url else "?") + urlencode({"msg": msg, **({"err": 1} if err else {})})
    return RedirectResponse(url, status_code=303)


class LoginRequired(HTTPException):
    def __init__(self, url: str):
        super().__init__(status_code=303, headers={"Location": url})
