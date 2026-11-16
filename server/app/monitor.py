"""Фоновый поток: online-статус из `wg show dump` и периодическая сверка с базой."""
import logging
import os
import threading
import time

from . import db, services, wg

log = logging.getLogger("monitor")

DUMP_EVERY = int(os.getenv("MONITOR_EVERY", "10"))  # сек
RECONCILE_EVERY = 300  # сек — лечит ручные изменения wg / iptables


def update_handshakes(conn, peers: list[dict], now: int | None = None) -> int:
    """Записывает в базу время последнего handshake, endpoint и принятый трафик каждого пира.
    Счётчик rx изменился — от ПК пришли пакеты (keepalive каждые 25 с), last_rx_at = сейчас."""
    if not peers:
        return 0
    now = int(time.time()) if now is None else now
    conn.executemany(
        "UPDATE devices SET last_handshake=?, endpoint=?, "
        "last_rx_at=CASE WHEN ?>0 AND ?<>rx_bytes THEN ? ELSE last_rx_at END, rx_bytes=? "
        "WHERE public_key=?",
        [(p["latest_handshake"], p["endpoint"], p["rx"], p["rx"], now, p["rx"], p["public_key"])
         for p in peers])
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
