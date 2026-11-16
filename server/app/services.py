"""Бизнес-логика, общая для API клиента, кабинета компании и суперадмина."""
import logging
import re
import sqlite3
import time

from . import db, wg
from .config import (NET_PREFIX, ONLINE_SECONDS, RADMIN_PORT, SERVER_IP,
                     WG_ENDPOINT, WG_KEEPALIVE)

log = logging.getLogger("services")

LOGIN_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
HOSTNAME_RE = re.compile(r"[^A-Za-z0-9-]")
PORTS_RE = re.compile(r"^\d{1,5}(,\d{1,5}){0,14}$")
SHARE_RE = re.compile(r"^[^\\/:*?\"<>|]{1,80}$")


# ---------- адресация ----------

def subnet(company) -> str:
    return f"{NET_PREFIX}.{company['subnet_index']}.0/24"


def allocate_subnet(conn: sqlite3.Connection) -> int | None:
    used = {r[0] for r in conn.execute("SELECT subnet_index FROM companies")}
    return next((i for i in range(1, 255) if i not in used), None)


def allocate_ip(conn: sqlite3.Connection, company) -> str | None:
    used = {r[0] for r in conn.execute("SELECT ip FROM devices WHERE company_id=?", (company["id"],))}
    n = company["subnet_index"]
    return next((f"{NET_PREFIX}.{n}.{h}" for h in range(2, 255)
                 if f"{NET_PREFIX}.{n}.{h}" not in used), None)


# ---------- утилиты ----------

def clean_hostname(name: str) -> str:
    return HOSTNAME_RE.sub("", name or "")[:63]


def clean_ports(ports: str) -> str | None:
    ports = (ports or "").replace(" ", "")
    if not PORTS_RE.match(ports) or any(not 0 < int(p) < 65536 for p in ports.split(",")):
        return None
    return ports


def is_online(dev) -> bool:
    return bool(dev["last_handshake"]) and time.time() - dev["last_handshake"] < ONLINE_SECONDS


def device_status(dev) -> str:
    if dev["is_blocked"]:
        return "blocked"
    if not dev["is_approved"]:
        return "pending"
    return "active"


def audit(conn, company_id, action: str, details: str = "") -> None:
    conn.execute("INSERT INTO audit_log(company_id, action, details) VALUES (?,?,?)",
                 (company_id, action, details[:500]))


def list_devices(conn, company_id: int) -> list[dict]:
    rows = conn.execute("SELECT * FROM devices WHERE company_id=? ORDER BY is_share_host DESC, name",
                        (company_id,)).fetchall()
    return [dict(r, online=is_online(r), status=device_status(r)) for r in rows]


def share_host(conn, company_id: int):
    return conn.execute(
        "SELECT * FROM devices WHERE company_id=? AND is_share_host=1 AND is_blocked=0 "
        "AND is_approved=1 ORDER BY id LIMIT 1", (company_id,)).fetchone()


def client_config(conn, dev, company) -> dict:
    """Всё, что нужно клиенту, чтобы собрать .conf WireGuard."""
    share = share_host(conn, company["id"])
    return {
        "device_id": dev["id"],
        "device_name": dev["name"],
        "company": company["name"] or company["login"],
        "status": device_status(dev),
        "address": f"{dev['ip']}/32",
        "ip": dev["ip"],
        "subnet": subnet(company),
        "server_ip": SERVER_IP,
        "server_public_key": wg.server_public_key(),
        "endpoint": WG_ENDPOINT,
        "allowed_ips": f"{subnet(company)}, {SERVER_IP}/32",
        "keepalive": WG_KEEPALIVE,
        "is_share_host": bool(dev["is_share_host"]),
        "share_ports": company["share_ports"],
        "radmin_port": RADMIN_PORT,
        "share": {
            "ip": share["ip"],
            "hostname": share["hostname"],
            "name": company["share_name"],
        } if share else None,
    }


# ---------- синхронизация сети с базой ----------

def build_forward_rules(conn) -> list[str]:
    rules = []
    for c in conn.execute("SELECT * FROM companies WHERE is_active=1 ORDER BY id"):
        sub = subnet(c)
        if c["full_lan"]:
            rules.append(f"-A RETIX_FWD -s {sub} -d {sub} -j ACCEPT")
            continue
        # по умолчанию между всеми ПК компании: ping и общие папки Windows (SMB).
        # Что именно открыто, решает сам пользователь ПК: какие папки он расшарил.
        rules.append(f"-A RETIX_FWD -s {sub} -d {sub} -p icmp -j ACCEPT")
        ports = clean_ports(c["share_ports"]) or "445"
        rules.append(f"-A RETIX_FWD -s {sub} -d {sub} -p tcp -m multiport --dports {ports} -j ACCEPT")
        # Radmin Viewer -> Radmin Server на кассах
        rules.append(f"-A RETIX_FWD -s {sub} -d {sub} -p tcp --dport {RADMIN_PORT} -j ACCEPT")
    return rules


def reconcile(conn=None) -> bool:
    """Приводит wg0 и iptables в соответствие с базой. База — источник правды."""
    own = conn is None
    conn = conn or db.connect()
    try:
        with db.write_lock:
            rows = conn.execute(
                "SELECT d.public_key, d.ip FROM devices d JOIN companies c ON c.id=d.company_id "
                "WHERE c.is_active=1 AND d.is_blocked=0 AND d.is_approved=1").fetchall()
            wg.sync_peers({r["public_key"]: r["ip"] for r in rows})
            wg.apply_firewall(build_forward_rules(conn))
        return True
    except Exception:
        log.exception("reconcile failed")
        return False
    finally:
        if own:
            conn.close()


# ---------- действия над устройствами (кабинет и админка) ----------

def device_action(conn, company_id: int, device_id: int, action: str, value: str = "") -> str:
    """Возвращает сообщение для пользователя. company_id ограничивает доступ."""
    dev = conn.execute("SELECT * FROM devices WHERE id=? AND company_id=?",
                       (device_id, company_id)).fetchone()
    if not dev:
        raise LookupError("Устройство не найдено")

    with db.write_lock:
        if action == "approve":
            conn.execute("UPDATE devices SET is_approved=1 WHERE id=?", (device_id,))
            msg = "Устройство одобрено"
        elif action == "block":
            conn.execute("UPDATE devices SET is_blocked=1 WHERE id=?", (device_id,))
            msg = "Устройство заблокировано"
        elif action == "unblock":
            conn.execute("UPDATE devices SET is_blocked=0 WHERE id=?", (device_id,))
            msg = "Устройство разблокировано"
        elif action == "delete":
            conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
            msg = "Устройство удалено"
        elif action == "share":
            conn.execute("UPDATE devices SET is_share_host=0 WHERE company_id=?", (company_id,))
            conn.execute("UPDATE devices SET is_share_host=1 WHERE id=?", (device_id,))
            msg = f"{dev['name']} — теперь компьютер с общей папкой"
        elif action == "unshare":
            conn.execute("UPDATE devices SET is_share_host=0 WHERE id=?", (device_id,))
            msg = "Отметка общей папки снята"
        elif action == "rename":
            name = (value or "").strip()[:64]
            if not name:
                raise ValueError("Пустое имя")
            conn.execute("UPDATE devices SET name=? WHERE id=?", (name, device_id))
            msg = "Переименовано"
        else:
            raise ValueError("Неизвестное действие")
        audit(conn, company_id, f"device_{action}", f"{dev['name']} {dev['ip']} {value}".strip())
        conn.commit()
        reconcile(conn)
    return msg
