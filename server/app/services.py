"""Бизнес-логика, общая для API клиента, кабинета компании и суперадмина."""
import ipaddress
import json
import logging
import re
import sqlite3
import time

from . import db, wg
from .config import (NET_PREFIX, OFFLINE_AFTER_SECONDS, ONLINE_SECONDS, RADMIN_PORT, SERVER_IP,
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


def clean_device_name(name: str) -> str:
    """Имя ПК в сети компании: без управляющих символов, пробелы схлопнуты, до 64 символов."""
    return " ".join("".join(ch for ch in (name or "") if ch.isprintable()).split())[:64]


def clean_ports(ports: str) -> str | None:
    ports = (ports or "").replace(" ", "")
    if not PORTS_RE.match(ports) or any(not 0 < int(p) < 65536 for p in ports.split(",")):
        return None
    return ports


def is_online(dev) -> bool:
    """В сети = сессия WireGuard жива (handshake) И от ПК недавно приходил трафик.
    По одному handshake выключенный ПК ещё до 3 минут выглядел бы «в сети»."""
    now = time.time()
    return (bool(dev["last_handshake"]) and now - dev["last_handshake"] < ONLINE_SECONDS
            and now - dev["last_rx_at"] < OFFLINE_AFTER_SECONDS)


# Для прямого пути — терпимее, чем для отметки «в сети»: один потерянный keepalive (25 с) плюс интервал опроса
# wg (10 с) уже давали паузу больше OFFLINE_AFTER_SECONDS, сервер на один ответ переставал называть соседа,
# и работающий прямой путь закрывался у обоих ПК.
DIRECT_RX_GRACE = 120   # сек


def online_for_direct(dev) -> bool:
    now = time.time()
    return (bool(dev["last_handshake"]) and now - dev["last_handshake"] < ONLINE_SECONDS
            and now - dev["last_rx_at"] < max(OFFLINE_AFTER_SECONDS, DIRECT_RX_GRACE))


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
    names = {r["id"]: r["name"] for r in rows}
    full_lan = bool((conn.execute("SELECT full_lan FROM companies WHERE id=?", (company_id,)).fetchone()
                     or {"full_lan": 0})["full_lan"])
    out = []
    for r in rows:
        online = is_online(r)
        direct = [names[i] for i in _json_ints(r["direct_ids"]) if i in names] \
            if full_lan and online and time.time() - r["lan_at"] < LAN_FRESH_SECONDS else []
        out.append(dict(r, online=online, status=device_status(r), direct_peers=direct))
    return out


def share_host(conn, company_id: int):
    return conn.execute(
        "SELECT * FROM devices WHERE company_id=? AND is_share_host=1 AND is_blocked=0 "
        "AND is_approved=1 ORDER BY id LIMIT 1", (company_id,)).fetchone()


# ---------- прямой путь по локальной сети ----------
# Компания с «любым трафиком между ПК» (full_lan): ПК одной локальной сети шлют друг другу пакеты
# WireGuard напрямую, а не через сервер. Сервер только сводит соседей: каждый ПК сообщает адреса своей
# локальной сети и UDP-порт WireGuard (heartbeat), а в /api/me получает список соседей. Сам путь клиент
# проверяет: сосед становится «прямым», только когда с ним прошёл handshake, иначе трафик идёт через сервер.
# Правила ping/папки/Radmin на сервере прямой трафик обошёл бы — поэтому только при full_lan.

LAN_FRESH_SECONDS = 300   # адреса локальной сети старше — не верим (ПК их шлёт раз в минуту)
LAN_MAX_ADDRS = 16
VPN_NET = ipaddress.IPv4Network(f"{NET_PREFIX}.0.0/16")


def _json_ints(value) -> list[int]:
    try:
        data = json.loads(value or "[]")
        return [int(x) for x in data if isinstance(x, int)] if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def clean_lan(addrs) -> list[str]:
    """Только частные IPv4 локальной сети вида 192.168.1.15/24: без 127.*, 169.254.*, 10.66.* и интернета."""
    out = []
    for a in addrs or []:
        try:
            iface = ipaddress.IPv4Interface(str(a).strip())
        except ValueError:
            continue
        ip = iface.ip
        net = iface.network
        if (not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
                or ip in VPN_NET or net.prefixlen < 8
                or (net.prefixlen < 31 and ip in (net.network_address, net.broadcast_address))):
            continue
        if str(iface) not in out:
            out.append(str(iface))
    return out[:LAN_MAX_ADDRS]


def _lan(dev) -> list[ipaddress.IPv4Interface]:
    try:
        return [ipaddress.IPv4Interface(a) for a in clean_lan(json.loads(dev["lan_addrs"] or "[]"))]
    except (ValueError, TypeError):
        return []


def _public_ip(endpoint: str) -> str:
    """'203.0.113.5:51234' -> '203.0.113.5' (откуда сервер видит пакеты WireGuard этого ПК)."""
    host = (endpoint or "").rsplit(":", 1)[0].strip("[]")
    return host if ":" in endpoint else ""


def _lan_ready(dev, now: float) -> bool:
    return bool(dev["wg_port"]) and now - dev["lan_at"] < LAN_FRESH_SECONDS


ENDPOINT_V4_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")


def _internet_endpoint(endpoint: str) -> str:
    """'203.0.113.5:51234' — внешний IPv4 и порт, с которых сервер видит пакеты ПК; иначе ''."""
    m = ENDPOINT_V4_RE.match(endpoint or "")
    try:
        ok = bool(m) and ipaddress.IPv4Address(m.group(1)).is_global and 0 < int(m.group(2)) < 65536
    except ValueError:
        ok = False
    return endpoint if ok else ""


def _wan_ready(dev, now: float) -> bool:
    return bool(dev["wan_ok"]) and now - dev["lan_at"] < LAN_FRESH_SECONDS


def direct_neighbors(conn, dev, company) -> list[dict]:
    """Соседи по локальной сети, с которыми ПК может связываться напрямую.
    Соседи — ПК той же компании, которые выходят в интернет с того же внешнего IP (один офис за одним
    роутером) или, если NAT нет вовсе, стоят в одной подсети. Адреса соседа: сначала из общей подсети."""
    now = time.time()
    if not company["full_lan"] or device_status(dev) != "active" or not dev["token_hash"] \
            or not _lan_ready(dev, now):
        return []
    mine = _lan(dev)
    my_ips = {m.ip for m in mine}
    my_pub = _public_ip(dev["endpoint"])
    if not mine or not my_pub:
        return []
    result = []
    rows = conn.execute("SELECT * FROM devices WHERE company_id=? AND id<>? AND is_blocked=0 AND is_approved=1 "
                        "AND token_hash IS NOT NULL ORDER BY id", (company["id"], dev["id"])).fetchall()
    for o in rows:
        if not online_for_direct(o) or not _lan_ready(o, now):
            continue
        theirs = [t for t in _lan(o) if t.ip not in my_ips]
        their_pub = _public_ip(o["endpoint"])
        shared = [t for t in theirs if any(t.ip in m.network for m in mine)]
        if their_pub and their_pub == my_pub:          # один офис за одним роутером
            candidates = shared + [t for t in theirs if t not in shared]
        elif my_pub in {str(i) for i in my_ips} and their_pub in {str(t.ip) for t in _lan(o)}:
            candidates = shared                         # без NAT: ПК и сервер в одной сети
        else:
            continue
        if candidates:
            result.append({"id": o["id"], "public_key": o["public_key"], "ip": o["ip"],
                           "endpoints": [f"{t.ip}:{o['wg_port']}" for t in candidates[:4]]})
    return result


# ---------- прямой путь через интернет ----------
# ПК компании с «любым трафиком» в разных офисах тоже пробуют связаться напрямую (пробой NAT). Сервер видит,
# с какого внешнего адреса и порта приходят пакеты WireGuard каждого ПК: это и есть «дверь» в его роутере,
# открытая для сокета туннеля. Сервер отдаёт эти адреса обоим ПК, они одновременно шлют друг другу handshake,
# и каждый роутер пропускает ответ на свой же исходящий пакет. Не все роутеры так умеют (симметричный NAT,
# часть мобильных операторов) — тогда handshake не проходит и трафик, как раньше, идёт через сервер.

def wan_neighbors(conn, dev, company) -> list[dict]:
    """ПК той же компании за ДРУГИМ внешним IP, с которыми можно попробовать прямой путь через интернет.
    Оба ПК должны уметь это (клиент 1.0.12+, wan в heartbeat) — иначе пробовать бессмысленно."""
    now = time.time()
    if not company["full_lan"] or device_status(dev) != "active" or not dev["token_hash"] \
            or not _wan_ready(dev, now):
        return []
    mine = _internet_endpoint(dev["endpoint"])
    if not mine:
        return []
    result = []
    rows = conn.execute("SELECT * FROM devices WHERE company_id=? AND id<>? AND is_blocked=0 AND is_approved=1 "
                        "AND token_hash IS NOT NULL ORDER BY id", (company["id"], dev["id"])).fetchall()
    for o in rows:
        theirs = _internet_endpoint(o["endpoint"])
        if not theirs or _public_ip(theirs) == _public_ip(mine) or not online_for_direct(o) \
                or not _wan_ready(o, now):
            continue                                    # тот же внешний IP — это один офис (direct_neighbors)
        result.append({"id": o["id"], "public_key": o["public_key"], "ip": o["ip"], "endpoints": [theirs]})
    return result


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
        "show_peers": bool(dev["show_peers"]),
        "share_ports": company["share_ports"],
        "radmin_port": RADMIN_PORT,
        "share": {
            "ip": share["ip"],
            "hostname": share["hostname"],
            "name": company["share_name"],
        } if share else None,
        # прямой путь по локальной сети: включён ли в компании и с кем можно попробовать
        "direct_enabled": bool(company["full_lan"]),
        "direct": direct_neighbors(conn, dev, company),
        "direct_wan": wan_neighbors(conn, dev, company),   # ПК других офисов: прямой путь через интернет
        "time": int(time.time()),   # часы сервера: ПК пробуют прямой путь через интернет одновременно
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


SPEED_MAX = 10000  # Мбит/с


def clean_speed(value) -> int | None:
    """Скорость в Мбит/с: 0 — без ограничения. Пусто — 0. Не число или вне 0…10000 — None."""
    value = str(value if value is not None else "").strip()
    if not value:
        return 0
    if not value.isdigit() or int(value) > SPEED_MAX:
        return None
    return int(value)


def build_shaping(conn) -> list[dict]:
    """Ограничения скорости через сервер: компании и ПК, которые сейчас в wg0."""
    out = []
    for c in conn.execute("SELECT id, subnet_index, speed_limit FROM companies WHERE is_active=1 "
                          "ORDER BY subnet_index").fetchall():
        devices = sorted((int(r["ip"].rsplit(".", 1)[1]), int(r["speed_limit"])) for r in conn.execute(
            "SELECT ip, speed_limit FROM devices WHERE company_id=? AND speed_limit>0 AND is_blocked=0 "
            "AND is_approved=1 AND token_hash IS NOT NULL", (c["id"],)))
        if c["speed_limit"] > 0 or devices:
            out.append({"subnet": c["subnet_index"], "mbit": int(c["speed_limit"]), "devices": devices})
    return out


def reconcile(conn=None) -> bool:
    """Приводит wg0 и iptables в соответствие с базой. База — источник правды."""
    own = conn is None
    conn = conn or db.connect()
    try:
        with db.write_lock:
            rows = conn.execute(
                "SELECT d.public_key, d.ip FROM devices d JOIN companies c ON c.id=d.company_id "
                "WHERE c.is_active=1 AND d.is_blocked=0 AND d.is_approved=1 "
                "AND d.token_hash IS NOT NULL").fetchall()  # токен отозван (выход, «отключить все») — вне сети
            wg.sync_peers({r["public_key"]: r["ip"] for r in rows})
            wg.apply_firewall(build_forward_rules(conn))
            wg.apply_shaping(build_shaping(conn))
        return True
    except Exception:
        log.exception("reconcile failed")
        return False
    finally:
        if own:
            conn.close()


# ---------- токены устройств ----------

def retire_token(conn, device_id: int, token_hash: str | None, now: int) -> None:
    """Токен больше не действует; если он придёт снова — это копия с другого ПК."""
    if token_hash:
        conn.execute("INSERT OR REPLACE INTO token_history(token_hash, device_id, revoked_at) VALUES (?,?,?)",
                     (token_hash, device_id, now))
    conn.execute("DELETE FROM token_history WHERE revoked_at<?", (now - 30 * 86400,))


def revoke_tokens(conn, where: str, args: tuple) -> None:
    """Сбросить токены устройств (без commit): клиенты должны войти заново, из WireGuard они уходят."""
    conn.execute(f"UPDATE devices SET token_hash=NULL, token_next_hash=NULL, token_next_at=0 WHERE {where}", args)


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
        elif action in ("peers_on", "peers_off"):
            # только то, что видно в программе: сеть (ping, папки, Radmin) не меняется
            conn.execute("UPDATE devices SET show_peers=? WHERE id=?", (1 if action == "peers_on" else 0, device_id))
            msg = (f"{dev['name']} видит другие компьютеры в программе" if action == "peers_on" else
                   f"{dev['name']} больше не видит другие компьютеры в программе (сеть не изменилась)")
        elif action == "speed":
            mbit = clean_speed(value)
            if mbit is None:
                raise ValueError(f"Скорость — целое число Мбит/с от 0 до {SPEED_MAX} (0 — без ограничения)")
            conn.execute("UPDATE devices SET speed_limit=? WHERE id=?", (mbit, device_id))
            msg = f"{dev['name']}: скорость через сервер " + (f"до {mbit} Мбит/с" if mbit else "без ограничения")
        elif action == "rename":
            name = clean_device_name(value)
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
