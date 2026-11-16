import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from . import db, monitor, services, wg
from .config import (APP_NAME, APP_VERSION, API_HOST, API_PORT, COOKIE_SECURE, DRY_RUN, SECRET_KEY,
                     SUPERADMIN_PASSWORD)
from .routers import admin, api_client, cabinet, public

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("retixhub")


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
    log.info("Retix Hub запущен, server pubkey %s", wg.server_public_key())
    yield
    stop.set()


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, session_cookie="retix_session",
                   same_site="strict", https_only=COOKIE_SECURE, max_age=12 * 3600)
app.include_router(api_client.router)
app.include_router(cabinet.router)
app.include_router(admin.router)
app.include_router(public.router)


if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT, proxy_headers=False)
