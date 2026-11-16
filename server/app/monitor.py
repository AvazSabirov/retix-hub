"""Фоновый поток: online-статус из `wg show dump` и периодическая сверка с базой."""
import logging
import os
import threading
import time

from . import db, services, wg

log = logging.getLogger("monitor")

DUMP_EVERY = int(os.getenv("MONITOR_EVERY", "10"))  # сек
RECONCILE_EVERY = 300  # сек — лечит ручные изменения wg / iptables


def update_handshakes(conn, peers: list[dict]) -> int:
    """Записывает в базу время последнего handshake и endpoint каждого пира."""
    if not peers:
        return 0
    conn.executemany(
        "UPDATE devices SET last_handshake=?, endpoint=? WHERE public_key=?",
        [(p["latest_handshake"], p["endpoint"], p["public_key"]) for p in peers])
    conn.commit()
    return len(peers)


def _loop(stop: threading.Event) -> None:
    last_reconcile = time.time()
    while not stop.wait(DUMP_EVERY):
        conn = db.connect()
        try:
            update_handshakes(conn, wg.dump())
            if time.time() - last_reconcile > RECONCILE_EVERY:
                services.reconcile(conn)
                last_reconcile = time.time()
        except Exception:
            log.exception("monitor error")
        finally:
            conn.close()


def start() -> threading.Event:
    stop = threading.Event()
    threading.Thread(target=_loop, args=(stop,), daemon=True, name="wg-monitor").start()
    return stop
