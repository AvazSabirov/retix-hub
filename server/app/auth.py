import hashlib
import secrets
import threading
import time

import bcrypt
from fastapi import HTTPException, Request


def hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()


def check_pw(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:72], hashed.encode())
    except Exception:
        return False


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def new_token() -> tuple[str, str]:
    """(токен клиенту, хеш в базу)"""
    token = secrets.token_urlsafe(32)
    return token, sha256(token)


def client_ip(request: Request) -> str:
    host = request.client.host if request.client else ""
    if host in ("127.0.0.1", "::1"):  # пришло через nginx
        real = request.headers.get("x-real-ip")
        if real:
            return real.strip()
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return host


class RateLimiter:
    """Неудачные попытки входа: не больше `limit` за `window` секунд с IP."""

    def __init__(self, limit: int = 10, window: int = 600):
        self.limit, self.window = limit, window
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.time()
        with self._lock:
            hits = [t for t in self._fails.get(key, []) if now - t < self.window]
            self._fails[key] = hits
            if len(hits) >= self.limit:
                raise HTTPException(429, "Слишком много попыток, попробуйте позже")

    def fail(self, key: str) -> None:
        with self._lock:
            self._fails.setdefault(key, []).append(time.time())

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)


limiter = RateLimiter()
