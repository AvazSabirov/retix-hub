"""Фоновый поток: online-статус из `wg show dump` и периодическая сверка с базой."""
import logging
import os
import threading
import time

from . import db, services, wg

log = logging.getLogger("monitor")

DUMP_EVERY = int(os.getenv("MONITOR_EVERY", "10"))  # сек
RECONCILE_EVERY = 300  # сек — лечит ручные изменения wg / iptables
CLEANUP_EVERY = 86400  # сек — чистка старых записей журнала
AUDIT_KEEP_DAYS = int(os.getenv("AUDIT_KEEP_DAYS", "365"))


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


def ensure_interface(conn) -> bool:
    """wg0 пропал (перезапуск сети на хосте, ip link del) — создать заново и вернуть пиры и правила из базы.
    Раньше сервер ждал перезапуска контейнера, а все ПК были без связи. True — интерфейс пересоздан."""
    if wg.DRY_RUN or wg.interface_exists():
        return False
    log.warning("интерфейс %s пропал — создаю заново", wg.WG_IF)
    wg.setup_interface()
    services.reconcile(conn)
    return True


def cleanup(conn, now: float | None = None) -> int:
    """Журнал действий хранится AUDIT_KEEP_DAYS дней (0 — всегда). Возвращает, сколько записей удалено."""
    if AUDIT_KEEP_DAYS <= 0:
        return 0
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime((now or time.time()) - AUDIT_KEEP_DAYS * 86400))
    with db.write_lock:
        n = conn.execute("DELETE FROM audit_log WHERE created_at<?", (cutoff,)).rowcount
        conn.commit()
    return n


def _loop(stop: threading.Event) -> None:
    last_reconcile, last_cleanup = time.time(), 0.0
    while not stop.wait(DUMP_EVERY):
        conn = db.connect()
        try:
            if ensure_interface(conn):
                last_reconcile = time.time()
            update_handshakes(conn, wg.dump())
            if time.time() - last_reconcile > RECONCILE_EVERY:
                services.reconcile(conn)
                last_reconcile = time.time()
            if time.time() - last_cleanup > CLEANUP_EVERY:
                cleanup(conn)
                last_cleanup = time.time()
        except Exception:
            log.exception("monitor error")
        finally:
            conn.close()


def start() -> threading.Event:
    stop = threading.Event()
    threading.Thread(target=_loop, args=(stop,), daemon=True, name="wg-monitor").start()
    return stop
