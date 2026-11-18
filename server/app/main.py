import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from . import db, monitor, services, telegram, wg
from .config import (APP_NAME, APP_VERSION, API_HOST, API_PORT, COOKIE_SECURE, DRY_RUN, LOG_LEVEL, SECRET_KEY,
                     SUPERADMIN_PASSWORD)
from .routers import admin, api_client, cabinet, public, updates

# минимальный журнал: ошибки и предупреждения; строка о запуске — всегда (логгер retixhub на INFO)
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("retixhub")
log.setLevel(logging.INFO)  # этот логгер пишет только строку о запуске и предупреждения


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    if not SUPERADMIN_PASSWORD:
        log.warning("SUPERADMIN_PASSWORD не задан — вход в /admin отключён")
    if DRY_RUN:
        log.warning("WG_DRY_RUN=1: wg и iptables не изменяются")
    wg.setup_interface()
    services.reconcile()
    stop = monitor.start()
    tg_stop = telegram.start()   # TELEGRAM_BOT_TOKEN не задан — бота нет
    log.info("Retix Hub %s запущен, server pubkey %s, журнал: %s", APP_VERSION, wg.server_public_key(), LOG_LEVEL)
    yield
    stop.set()
    if tg_stop:
        tg_stop.set()


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, session_cookie="retix_session",
                   same_site="strict", https_only=COOKIE_SECURE, max_age=12 * 3600)
app.include_router(api_client.router)
app.include_router(cabinet.router)
app.include_router(admin.router)
app.include_router(updates.router)
app.include_router(public.router)


if __name__ == "__main__":
    # access_log выключен: каждый запрос касс (раз в 8 с) засорял бы журнал; ошибки uvicorn остаются
    uvicorn.run(app, host=API_HOST, port=API_PORT, proxy_headers=False, access_log=LOG_LEVEL == "DEBUG",
                log_level=LOG_LEVEL.lower())
