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
    """Неудачные попытки: не больше `limit` за `window` секунд на ключ. Пустые ключи не хранятся,
    устаревшие вычищаются — память не растёт с каждым новым IP."""

    def __init__(self, limit: int = 10, window: int = 600, max_keys: int = 50_000):
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _hits(self, key: str, now: float) -> list[float]:
        hits = [t for t in self._fails.get(key, ()) if now - t < self.window]
        if hits:
            self._fails[key] = hits
        else:
            self._fails.pop(key, None)
        return hits

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._hits(key, time.time())) >= self.limit

    def check(self, key: str) -> None:
        if self.blocked(key):
            raise HTTPException(429, "Слишком много попыток, попробуйте позже")

    def fail(self, key: str) -> None:
        now = time.time()
        with self._lock:
            if len(self._fails) >= self.max_keys:
                for k in [k for k, v in self._fails.items() if not v or now - v[-1] >= self.window]:
                    del self._fails[k]
                if len(self._fails) >= self.max_keys:   # всё свежее (перебор с множества IP) — самые старые
                    for k in sorted(self._fails, key=lambda k: self._fails[k][-1])[:self.max_keys // 10]:
                        del self._fails[k]
            self._fails.setdefault(key, []).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._fails.clear()


# Попытки входа (регистрация ПК, кабинет компании, суперадмин) считаются раздельно:
#  * по паре «логин + IP» — успешный вход сбрасывает только её, а не неудачи по чужим логинам
#    (раньше успешная регистрация своего ПК обнуляла и перебор пароля суперадмина с того же IP);
#  * по IP для каждого вида входа отдельно — перебор разных логинов; не сбрасывается успехом.
#    ПК офиса со старым паролем компании не мешают администратору войти в кабинет с того же IP;
#  * у суперадмина ещё общий счётчик неудач со всех IP.
limiter = RateLimiter(limit=10, window=600)            # «вид входа + логин + IP»
# «вид входа + IP»: у регистрации больше — за одним NAT офиса может быть сотня ПК со старым паролем компании
ip_limiters = {"register": RateLimiter(limit=100, window=600), "cabinet": RateLimiter(limit=30, window=600),
               "admin": RateLimiter(limit=20, window=600)}
admin_limiter = RateLimiter(limit=100, window=3600)    # суперадмин, все IP вместе


def _login_keys(kind: str, login: str, ip: str) -> list[tuple[RateLimiter, str]]:
    keys = [(limiter, f"{kind}|{(login or '').strip().lower()[:64]}|{ip}"), (ip_limiters[kind], ip)]
    if kind == "admin":
        keys.append((admin_limiter, "admin"))
    return keys


def login_check(kind: str, login: str, ip: str) -> None:
    for lim, key in _login_keys(kind, login, ip):
        lim.check(key)


def login_failed(kind: str, login: str, ip: str) -> None:
    for lim, key in _login_keys(kind, login, ip):
        lim.fail(key)


def login_ok(kind: str, login: str, ip: str) -> None:
    limiter.reset(_login_keys(kind, login, ip)[0][1])


def reset_limiters() -> None:
    """Для тестов."""
    for lim in (limiter, admin_limiter, *ip_limiters.values()):
        lim.clear()
