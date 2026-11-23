"""Бизнес-логика, общая для API клиента, кабинета компании и суперадмина."""
import base64
import calendar
import hashlib
import ipaddress
import json
import logging
import re
import sqlite3
import time

from . import db, wg
from .config import (NET_PREFIX, OFFLINE_AFTER_SECONDS, ONLINE_SECONDS, RADMIN_PORT, REMOTE_PORT, SECRET_KEY,
                     SERVER_IP, WG_ENDPOINT, WG_KEEPALIVE)

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


# «В сети» — это туннель WireGuard: его держит служба Windows, и он живёт без программы Retix Hub (её закрыли,
# она зависла или не запустилась после обновления). Программа шлёт heartbeat раз в минуту (last_seen). Туннель
# есть, а heartbeat давно нет — значит, программа не работает: прямые пути, удалённое управление и обновления
# на этом ПК не обслуживаются, и подключиться к нему может не получиться, хотя он «в сети».
APP_SILENT_SECONDS = 300


def _utc_ts(text) -> float:
    """'2026-11-23 08:35:42' (CURRENT_TIMESTAMP SQLite, UTC) -> секунды; не разобрали -> 0."""
    try:
        return float(calendar.timegm(time.strptime(str(text or "")[:19], "%Y-%m-%d %H:%M:%S")))
    except ValueError:
        return 0.0


def app_alive(dev) -> bool:
    """Программа Retix Hub на ПК недавно отзывалась (heartbeat)."""
    return time.time() - _utc_ts(dev["last_seen"]) < APP_SILENT_SECONDS


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
    company = conn.execute("SELECT * FROM companies WHERE id=?", (company_id,)).fetchone()
    full_lan = bool(company and company["full_lan"])
    roles = {r["id"]: (i, r["name"]) for i, r in enumerate(list_roles(conn, company_id))}
    out = []
    for r in rows:
        online = is_online(r)
        direct = [names[i] for i in _json_ints(r["direct_ids"]) if i in names] \
            if full_lan and online and time.time() - r["lan_at"] < LAN_FRESH_SECONDS else []
        pos, role = roles.get(r["role_id"], (len(roles), ""))
        out.append(dict(r, online=online, app_ok=not online or app_alive(r), status=device_status(r), direct_peers=direct,
                        remote_effective=effective_remote_mode(r, company) if company else "off",
                        wol_ready=bool(_nics(r)), role_id=r["role_id"] if role else 0, role=role, role_pos=pos))
    return out


# ---------- роли (группы) компьютеров ----------
# Роли создаёт администратор компании в кабинете («Склад», «Администраторы» …) и назначает ПК — при одобрении
# или в списке компьютеров. В программе список ПК разбит на группы по ролям. На сеть роль не влияет.

ROLE_NAME_MAX = 40
ROLES_MAX = 30


def clean_role_name(value) -> str:
    return " ".join("".join(ch for ch in str(value or "") if ch.isprintable()).split())[:ROLE_NAME_MAX]


def list_roles(conn, company_id: int) -> list[dict]:
    """Роли компании по порядку групп, с числом ПК в каждой."""
    rows = conn.execute("SELECT r.*, (SELECT COUNT(*) FROM devices d WHERE d.role_id=r.id AND d.company_id=r.company_id)"
                        " AS devices FROM roles r WHERE r.company_id=? ORDER BY r.position, r.id",
                        (company_id,)).fetchall()
    return [dict(r) for r in rows]


def role_id_value(conn, company_id: int, value) -> int:
    """id роли из формы: '' или 0 — без роли; чужая или несуществующая роль — ошибка."""
    value = str(value or "").strip()
    if value in ("", "0"):
        return 0
    if not value.isdigit() or not conn.execute("SELECT 1 FROM roles WHERE id=? AND company_id=?",
                                               (int(value), company_id)).fetchone():
        raise ValueError("Роль не найдена")
    return int(value)


def role_action(conn, company_id: int, action: str, role_id: int = 0, value: str = "", actor: str = "") -> str:
    """Роли компании: add (value — имя), rename, delete, up, down. Возвращает сообщение для пользователя."""
    with db.write_lock:
        roles = list_roles(conn, company_id)
        if action == "add":
            name = clean_role_name(value)
            if not name:
                raise ValueError("Введите название роли")
            if len(roles) >= ROLES_MAX:
                raise ValueError(f"Не больше {ROLES_MAX} ролей")
            if any(r["name"].lower() == name.lower() for r in roles):
                raise ValueError(f"Роль «{name}» уже есть")
            conn.execute("INSERT INTO roles(company_id, name, position) VALUES (?,?,?)",
                         (company_id, name, max([r["position"] for r in roles] or [0]) + 1))
            msg = f"Роль «{name}» создана"
        else:
            role = next((r for r in roles if r["id"] == role_id), None)
            if not role:
                raise LookupError("Роль не найдена")
            name = role["name"]
            if action == "rename":
                new = clean_role_name(value)
                if not new:
                    raise ValueError("Введите название роли")
                if any(r["name"].lower() == new.lower() and r["id"] != role_id for r in roles):
                    raise ValueError(f"Роль «{new}» уже есть")
                conn.execute("UPDATE roles SET name=? WHERE id=?", (new, role_id))
                msg, value = f"Роль «{name}» теперь «{new}»", new
            elif action == "delete":
                conn.execute("UPDATE devices SET role_id=0 WHERE role_id=? AND company_id=?", (role_id, company_id))
                conn.execute("DELETE FROM roles WHERE id=?", (role_id,))
                msg = f"Роль «{name}» удалена, её компьютеры — без роли"
            elif action in ("up", "down"):
                i = roles.index(role)
                j = i - 1 if action == "up" else i + 1
                if not 0 <= j < len(roles):
                    return f"Роль «{name}» уже {'первая' if action == 'up' else 'последняя'}"
                roles[i], roles[j] = roles[j], roles[i]
                for pos, r in enumerate(roles, 1):   # порядок 1..N без пропусков
                    conn.execute("UPDATE roles SET position=? WHERE id=?", (pos, r["id"]))
                msg = f"Роль «{name}» — {'выше' if action == 'up' else 'ниже'}"
            else:
                raise ValueError("Неизвестное действие")
        audit(conn, company_id, f"role_{action}", f"{name} {value if action == 'rename' else ''}".strip()
              + (f" ({actor})" if actor else ""))
        conn.commit()
    return msg


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


# ---------- удалённое управление (RustDesk) ----------
# На каждом ПК стоит официальный RustDesk без изменений. Клиент Retix Hub настраивает его: прямой доступ по IP
# (порт REMOTE_PORT) только из подсети компании, серверы RustDesk не используются. Кто к кому подключился —
# решает и записывает в журнал этот сервер (/api/remote/connect).
#   ask  — пароля нет, пользователь ПК сам нажимает «Принять» (approve-mode click);
#   auto — без участия пользователя, по паролю (approve-mode password). Пароль придумывает сам ПК и сообщает
#          серверу (/api/remote/password), сервер отдаёт его только тому, кому разрешил подключиться.
#          Выданный пароль одноразовый: после сеанса ПК меняет его сам (rotate в /api/me).

REMOTE_MODES = {"off": "выключено", "ask": "с согласием пользователя", "auto": "без согласия (по паролю)"}
# Права по ПК (кабинет): кто может управлять другими (remote_control, по умолчанию — никто) и можно ли управлять
# этим ПК (remote_access — только строже режима компании). Пользователь ПК в программе может сделать ещё
# строже (remote_local): только с его согласием, только по его собственному паролю (его сервер не знает), запретить.
REMOTE_ACCESS = {"company": "как в компании", "ask": "только с согласием", "off": "выключено"}
REMOTE_LOCAL = {"": "как разрешил администратор", "ask": "только с моего согласия", "own": "по моему паролю",
                "off": "запрещено пользователем"}
EFFECTIVE_TITLES = {"off": "нельзя", "ask": "с согласием", "auto": "без согласия", "own": "по паролю пользователя"}
REMOTE_ROTATE_AFTER = 120   # сек после выдачи пароля: подключиться успевают, дальше ПК меняет пароль (без сеанса)
REMOTE_PW_RE = re.compile(r"^[A-Za-z0-9]{12,64}$")
RUSTDESK_ID_RE = r"^[A-Za-z0-9_-]{6,32}$"   # ID RustDesk (обычно 9–10 цифр; бывает и свой, из букв)


def remote_cloud(company) -> bool:
    """RustDesk работает и через облако RustDesk: к ПК подключаются по ID из любого места, не только из VPN.
    Включает администратор компании (по умолчанию выключено), только вместе с удалённым управлением."""
    return remote_mode(company) != "off" and bool(company["remote_cloud"])


def clean_remote_mode(value) -> str | None:
    value = str(value or "").strip()
    return value if value in REMOTE_MODES else None


def _fernet():
    from cryptography.fernet import Fernet
    key = hashlib.sha256(("retixhub-remote:" + SECRET_KEY).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def seal(text: str) -> str:
    """Пароль RustDesk в базе — зашифрованным (ключ из SECRET_KEY): копия базы без ключа его не раскрывает."""
    return _fernet().encrypt(text.encode()).decode() if text else ""


def unseal(value: str) -> str:
    """'' — пароля нет или его не расшифровать (сменился SECRET_KEY): ПК придумает новый."""
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode()).decode()
    except Exception:  # noqa: BLE001
        return ""


def remote_mode(company) -> str:
    return clean_remote_mode(company["remote_mode"]) or "off"


def admin_remote_mode(dev, company) -> str:
    """Режим управления ЭТИМ ПК, который разрешил администратор: режим компании, для ПК — только строже."""
    mode = remote_mode(company)
    access = dev["remote_access"] if dev["remote_access"] in REMOTE_ACCESS else "company"
    if mode == "off" or access == "off":
        return "off"
    return "ask" if access == "ask" else mode


def effective_remote_mode(dev, company) -> str:
    """Как на самом деле можно управлять ПК: решение администратора и выбор пользователя ПК (только строже)."""
    admin = admin_remote_mode(dev, company)
    local = dev["remote_local"] if dev["remote_local"] in REMOTE_LOCAL else ""
    if admin == "off" or local == "off":
        return "off"
    return local or admin


def can_control(dev, company) -> bool:
    return bool(dev["remote_control"]) and remote_mode(company) != "off" and device_status(dev) == "active"


REMOTE_PW_GIVE_LIMIT = 10   # выдач пароля RustDesk (кабинет, Telegram) на компанию в час


def give_remote_password(conn, company, dev, actor: str) -> dict:
    """Пароль RustDesk ПК для подключения через облако RustDesk по ID (кабинет, Telegram): только ПК «без
    согласия» и только с включённым облаком. Выдача — как подключение: в журнале, после сеанса ПК сменит
    пароль сам (rotate). ValueError — почему не выдали."""
    name = dev["name"]
    if not remote_cloud(company):
        raise ValueError("Облако RustDesk выключено: «Настройки сети» → «Разрешить RustDesk через интернет»")
    if device_status(dev) != "active":
        raise ValueError(f"{name} не подключён к сети компании (ждёт одобрения или заблокирован)")
    mode = effective_remote_mode(dev, company)
    if mode != "auto":
        raise ValueError(f"Пароль выдаётся только для ПК, которыми можно управлять без согласия. {name}: "
                         + {"off": "управлять нельзя", "ask": "только с согласием пользователя (он нажмёт «Принять»)",
                            "own": "по паролю пользователя (его знает только он)"}.get(mode, mode))
    if not dev["rustdesk_id"]:
        raise ValueError(f"ID RustDesk у {name} ещё неизвестен: нужна Retix Hub 1.0.28 или новее, и RustDesk "
                         "должен быть готов")
    password = unseal(dev["remote_pw"])
    if not password:
        raise ValueError(f"{name} ещё готовит удалённое управление, попробуйте через минуту")
    given = conn.execute("SELECT COUNT(*) FROM audit_log WHERE company_id=? AND action='remote_password' "
                         "AND created_at > datetime('now', '-1 hour')", (company["id"],)).fetchone()[0]
    if given >= REMOTE_PW_GIVE_LIMIT:
        raise ValueError(f"Слишком много выдач пароля RustDesk за час (не больше {REMOTE_PW_GIVE_LIMIT}). "
                         "Подождите.")
    with db.write_lock:   # пароль выдан — после сеанса ПК сменит его сам
        conn.execute("UPDATE devices SET remote_used_at=? WHERE id=?", (int(time.time()), dev["id"]))
        audit(conn, company["id"], "remote_password",
              f"пароль RustDesk выдан ({actor}) → {name} {dev['ip']}, ID {dev['rustdesk_id']}")
        conn.commit()
    return {"name": name, "ip": dev["ip"], "rustdesk_id": dev["rustdesk_id"], "password": password}


def remote_controllers(conn, company, exclude_id: int = 0) -> list[str]:
    """IP компьютеров компании, которым администратор разрешил управлять другими ПК: только их пускает RustDesk."""
    if remote_mode(company) == "off":
        return []
    rows = conn.execute("SELECT ip FROM devices WHERE company_id=? AND remote_control=1 AND is_blocked=0 "
                        "AND is_approved=1 AND token_hash IS NOT NULL AND id<>? ORDER BY id",
                        (company["id"], exclude_id)).fetchall()
    return [r["ip"] for r in rows]


def remote_config(conn, dev, company) -> dict:
    """Что клиент делает с RustDesk. mode — что разрешил администратор (выбор пользователя ПК клиент
    добавляет сам), allowed — с каких адресов пускать, rotate — пора сменить пароль, can_control —
    может ли этот ПК управлять другими."""
    mode = admin_remote_mode(dev, company)
    used = dev["remote_used_at"]
    rotate = effective_remote_mode(dev, company) == "auto" and (
        not unseal(dev["remote_pw"]) or bool(used) and time.time() - used >= REMOTE_ROTATE_AFTER)
    return {"mode": mode, "port": REMOTE_PORT, "rotate": rotate, "can_control": can_control(dev, company),
            "cloud": remote_cloud(company),
            "allowed": remote_controllers(conn, company, dev["id"]) if mode != "off" else []}


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
        "remote": remote_config(conn, dev, company),   # удалённое управление (RustDesk), клиент 1.0.16+
        "log_request": bool(dev["log_requested_at"]),  # администратор ждёт журнал программы (клиент 1.0.21+)
        # сообщать ли сетевые карты (MAC) для включения по сети: только пока включено удалённое управление
        "wol": wol_enabled(company) and device_status(dev) == "active",
    }


# ---------- включение по сети (Wake-on-LAN) ----------
# Выключенный ПК не может сам выйти на связь. Его будит «волшебный пакет» в его локальной сети: шлёт его
# включённый ПК той же компании из той же подсети. Каждый ПК (клиент 1.0.21+, удалённое управление в компании
# включено) сообщает в heartbeat свои сетевые карты: адрес в локальной сети и MAC. Сервер помнит последние
# известные карты выключенного ПК, находит включённый ПК в той же подсети и в /api/me отдаёт ему MAC
# и широковещательный адрес подсети. Включить ПК может администратор (кабинет, суперадмин) и ПК с правом
# «управляет» — только пока в компании включено удалённое управление.

MAC_RE = re.compile(r"^([0-9A-F]{2})([:-]?[0-9A-F]{2}){5}$")
NICS_MAX = 16
WOL_HELPER_FRESH = 900    # сек: сетевые карты помощника сообщены не раньше — он и сейчас в той сети
WOL_DELIVER_TTL = 120     # сек: команда не забрана за это время (помощник выключился) — не отдаём
WOL_REPEAT = 15           # сек: чаще одну и ту же команду не создаём (двойное нажатие)
WOL_HELPERS = 2           # через сколько ПК слать пакет (на случай, если один как раз выключается)


def clean_mac(value) -> str:
    """'aa-bb-cc-dd-ee-ff' -> 'AA:BB:CC:DD:EE:FF'; '' — не MAC одной сетевой карты (пустой, групповой, FF…)."""
    raw = str(value or "").strip().upper()
    if not MAC_RE.match(raw):
        return ""
    hexs = raw.replace(":", "").replace("-", "")
    if hexs in ("000000000000", "FFFFFFFFFFFF") or int(hexs[:2], 16) & 1:
        return ""
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


def clean_nics(nics) -> list[dict]:
    """Сетевые карты ПК: адрес в частной локальной сети (как clean_lan) и MAC."""
    out = []
    for n in nics or []:
        if not isinstance(n, dict):
            continue
        addr, mac = clean_lan([n.get("addr")]), clean_mac(n.get("mac"))
        if addr and mac and ipaddress.IPv4Interface(addr[0]).network.prefixlen <= 30:
            item = {"addr": addr[0], "mac": mac}
            if item not in out:
                out.append(item)
    return out[:NICS_MAX]


def _nics(dev) -> list[dict]:
    try:
        return clean_nics(json.loads(dev["nics"] or "[]"))
    except (ValueError, TypeError, KeyError, IndexError):
        return []


def wol_enabled(company) -> bool:
    return remote_mode(company) != "off"


def wake_helpers(conn, target, company, limit: int = WOL_HELPERS) -> list[tuple]:
    """[(ПК-помощник, [(широковещательный адрес, MAC), …]), …]: включённые ПК компании в одной подсети
    с выключенным. Сначала — за тем же внешним IP (тот же офис: у двух офисов может быть одна 192.168.1.0/24)."""
    now = time.time()
    targets = [(ipaddress.IPv4Interface(n["addr"]).network, n["mac"]) for n in _nics(target)]
    target_pub = _public_ip(target["endpoint"])
    found = []
    for o in conn.execute("SELECT * FROM devices WHERE company_id=? AND id<>? AND is_blocked=0 AND is_approved=1 "
                          "AND token_hash IS NOT NULL ORDER BY id", (company["id"], target["id"])).fetchall():
        if not is_online(o) or now - o["nics_at"] > WOL_HELPER_FRESH:
            continue
        own = {ipaddress.IPv4Interface(n["addr"]).network for n in _nics(o)}
        jobs = []
        for net, mac in targets:
            job = (str(net.broadcast_address), mac)
            if net in own and job not in jobs:
                jobs.append(job)
        if jobs:
            same_office = bool(target_pub) and _public_ip(o["endpoint"]) == target_pub
            found.append((0 if same_office else 1, o["id"], o, jobs))
    found.sort(key=lambda x: (x[0], x[1]))
    return [(o, jobs) for _, _, o, jobs in found[:limit]]


def wake_device(conn, company, target_id: int, actor: str = "") -> str:
    """Команда включить выключенный ПК. Сообщение для пользователя; ValueError/LookupError — почему нельзя."""
    target = conn.execute("SELECT * FROM devices WHERE id=? AND company_id=?", (target_id, company["id"])).fetchone()
    if not target:
        raise LookupError("Устройство не найдено")
    if not wol_enabled(company):
        raise ValueError("Включение по сети доступно, когда в компании включено удалённое управление")
    if device_status(target) != "active":
        raise ValueError(f"{target['name']} не одобрен или заблокирован")
    if is_online(target):
        raise ValueError(f"{target['name']} уже в сети")
    if not _nics(target):
        raise ValueError(f"MAC-адрес {target['name']} ещё неизвестен: компьютер должен хотя бы раз выйти на связь "
                         "с Retix Hub 1.0.21 или новее, пока в компании включено удалённое управление")
    helpers = wake_helpers(conn, target, company)
    if not helpers:
        raise ValueError(f"Некому включить {target['name']}: в его локальной сети сейчас нет включённого "
                         "компьютера компании с Retix Hub 1.0.21 или новее")
    now = int(time.time())
    with db.write_lock:
        if conn.execute("SELECT 1 FROM wake_requests WHERE target_id=? AND created_at>?",
                        (target["id"], now - WOL_REPEAT)).fetchone():
            raise ValueError(f"Команда включения {target['name']} уже отправлена, подождите немного")
        conn.execute("DELETE FROM wake_requests WHERE created_at<?", (now - 86400,))
        for helper, jobs in helpers:
            conn.executemany("INSERT INTO wake_requests(company_id, target_id, helper_id, mac, broadcast, created_at) "
                             "VALUES (?,?,?,?,?,?)",
                             [(company["id"], target["id"], helper["id"], mac, bcast, now) for bcast, mac in jobs])
        names = ", ".join(h["name"] for h, _ in helpers)
        audit(conn, company["id"], "device_wake",
              f"{target['name']} {target['ip']} через {names}" + (f" ({actor})" if actor else ""))
        conn.commit()
    return (f"Команда включения {target['name']} отправлена через {names}. Компьютер включится за минуту, "
            "если в его BIOS и сетевой карте разрешено пробуждение по сети (Wake-on-LAN)")


def take_wake_jobs(conn, dev) -> list[dict]:
    """Команды «разбудить» для этого ПК-помощника (каждая отдаётся один раз)."""
    if device_status(dev) != "active":
        return []
    now = int(time.time())
    rows = conn.execute("SELECT w.id, w.mac, w.broadcast, w.target_id, d.name FROM wake_requests w "
                        "JOIN devices d ON d.id=w.target_id WHERE w.helper_id=? AND w.delivered_at=0 "
                        "AND w.created_at>? ORDER BY w.id LIMIT 32", (dev["id"], now - WOL_DELIVER_TTL)).fetchall()
    if not rows:
        return []
    conn.executemany("UPDATE wake_requests SET delivered_at=? WHERE id=?", [(now, r["id"]) for r in rows])
    conn.commit()
    return [{"id": r["target_id"], "name": r["name"], "mac": r["mac"], "broadcast": r["broadcast"]} for r in rows]


# ---------- журнал программы с ПК ----------
# Администратор нажимает «Журнал» у ПК — сервер ставит отметку, ПК видит её в следующем /api/me (через секунды)
# и присылает свой журнал (/api/log, gzip). Без запроса ПК журнал не шлёт и сервер его не примет.

LOG_UPLOAD_MAX = 900_000       # байт gzip: nginx по умолчанию пропускает тело до 1 МБ
LOG_TEXT_MAX = 16_000_000      # байт после распаковки — больше не распаковываем (защита от «zip-бомбы»)
LOG_KEEP = 5                   # журналов на ПК хранится


def request_log(conn, dev, actor: str = "") -> str:
    with db.write_lock:
        conn.execute("UPDATE devices SET log_requested_at=? WHERE id=?", (int(time.time()), dev["id"]))
        audit(conn, dev["company_id"], "log_request", f"{dev['name']} {dev['ip']}" + (f" ({actor})" if actor else ""))
        conn.commit()
    return (f"Журнал {dev['name']} запрошен: программа пришлёт его при следующей связи с сервером (обычно за "
            "несколько секунд, если ПК в сети). Нужна Retix Hub 1.0.21 или новее")


def save_log(conn, dev, data: bytes, size: int) -> None:
    with db.write_lock:
        conn.execute("INSERT INTO device_logs(company_id, device_id, created_at, size, data) VALUES (?,?,?,?,?)",
                     (dev["company_id"], dev["id"], int(time.time()), size, data))
        conn.execute("DELETE FROM device_logs WHERE device_id=? AND id NOT IN "
                     "(SELECT id FROM device_logs WHERE device_id=? ORDER BY id DESC LIMIT ?)",
                     (dev["id"], dev["id"], LOG_KEEP))
        conn.execute("UPDATE devices SET log_requested_at=0 WHERE id=?", (dev["id"],))
        audit(conn, dev["company_id"], "log_received", f"{dev['name']} {dev['ip']}: {size // 1024} КБ")
        conn.commit()


def company_logs(conn, company_id: int) -> list:
    return conn.execute("SELECT l.id, l.created_at, l.size, d.name, d.ip FROM device_logs l "
                        "JOIN devices d ON d.id=l.device_id WHERE l.company_id=? ORDER BY l.id DESC LIMIT 30",
                        (company_id,)).fetchall()


def log_file(conn, company_id: int, log_id: int):
    """(имя файла, текст) журнала своей компании или None."""
    import gzip
    row = conn.execute("SELECT l.*, d.hostname FROM device_logs l JOIN devices d ON d.id=l.device_id "
                       "WHERE l.id=? AND l.company_id=?", (log_id, company_id)).fetchone()
    if not row:
        return None
    stamp = time.strftime("%Y%m%d-%H%M", time.localtime(row["created_at"]))
    host = clean_hostname(row["hostname"]) or f"pc{row['device_id']}"
    return f"retixhub-{host}-{stamp}.txt", gzip.decompress(row["data"])


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
        for ip in remote_controllers(conn, c):   # RustDesk -> RustDesk: только с ПК, которым разрешено управлять
            rules.append(f"-A RETIX_FWD -s {ip}/32 -d {sub} -p tcp --dport {REMOTE_PORT} -j ACCEPT")
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

def device_action(conn, company_id: int, device_id: int, action: str, value: str = "", actor: str = "") -> str:
    """Возвращает сообщение для пользователя. company_id ограничивает доступ. actor — кто (для журнала)."""
    dev = conn.execute("SELECT * FROM devices WHERE id=? AND company_id=?",
                       (device_id, company_id)).fetchone()
    if not dev:
        raise LookupError("Устройство не найдено")
    if action == "log_request":
        return request_log(conn, dev, actor)
    if action == "wake":
        company = conn.execute("SELECT * FROM companies WHERE id=?", (company_id,)).fetchone()
        return wake_device(conn, company, device_id, actor)

    with db.write_lock:
        if action == "approve":
            role_id = role_id_value(conn, company_id, value) if value else dev["role_id"]
            conn.execute("UPDATE devices SET is_approved=1, role_id=? WHERE id=?", (role_id, device_id))
            role = conn.execute("SELECT name FROM roles WHERE id=?", (role_id,)).fetchone()
            msg = "Устройство одобрено" + (f", роль «{role['name']}»" if role else "")
            value = role["name"] if role else ""
        elif action == "role":
            role_id = role_id_value(conn, company_id, value)
            conn.execute("UPDATE devices SET role_id=? WHERE id=?", (role_id, device_id))
            role = conn.execute("SELECT name FROM roles WHERE id=?", (role_id,)).fetchone()
            msg = f"{dev['name']}: " + (f"роль «{role['name']}»" if role else "без роли")
            value = role["name"] if role else "без роли"
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
        elif action in ("control_on", "control_off"):
            conn.execute("UPDATE devices SET remote_control=? WHERE id=?", (1 if action == "control_on" else 0, device_id))
            msg = (f"{dev['name']} может управлять другими компьютерами" if action == "control_on" else
                   f"{dev['name']} больше не может управлять другими компьютерами")
        elif action == "remote_access":
            if value not in REMOTE_ACCESS:
                raise ValueError("Неизвестный режим управления компьютером")
            conn.execute("UPDATE devices SET remote_access=? WHERE id=?", (value, device_id))
            msg = f"Управление {dev['name']}: {REMOTE_ACCESS[value]}"
        elif action == "rename":
            name = clean_device_name(value)
            if not name:
                raise ValueError("Пустое имя")
            conn.execute("UPDATE devices SET name=? WHERE id=?", (name, device_id))
            msg = "Переименовано"
        else:
            raise ValueError("Неизвестное действие")
        audit(conn, company_id, f"device_{action}",
              f"{dev['name']} {dev['ip']} {value}".strip() + (f" ({actor})" if actor else ""))
        conn.commit()
        reconcile(conn)
    return msg
