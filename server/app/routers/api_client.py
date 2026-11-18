"""API для Windows-клиента."""
import json
import time
import zlib

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import db, services, telegram, updates, wg
from ..auth import RateLimiter, check_pw, client_ip, limiter, new_token, sha256
from ..config import REMOTE_PORT, TOKEN_ROTATE_SECONDS

# Новый токен сервер отдаёт в этом заголовке. Клиент переходит на него сразу; старый действует,
# пока клиент не пришёл с новым. После этого старый токен — только у копии: она отключает ПК.
TOKEN_HEADER = "X-Retix-Token"
NEXT_TOKEN_RETRY = 30  # сек: клиент не забрал выданный токен (ответ потерялся) — выдать заново

router = APIRouter(prefix="/api", tags=["client"])


class RegisterIn(BaseModel):
    company_login: str = Field(min_length=1, max_length=64)
    join_password: str = Field(min_length=1, max_length=128)
    device_name: str = Field(min_length=1, max_length=64)
    hostname: str = Field(default="", max_length=64)
    public_key: str = Field(min_length=44, max_length=44)
    client_version: str = Field(default="", max_length=32)


class RenameIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class MessageIn(BaseModel):
    to: int
    text: str = Field(min_length=1, max_length=2000)


MESSAGES_PER_MINUTE = 30
MESSAGES_KEEP_DAYS = 7


class NicIn(BaseModel):
    addr: str = Field(default="", max_length=43)   # 192.168.1.15/24
    mac: str = Field(default="", max_length=17)


class HeartbeatIn(BaseModel):
    client_version: str = Field(default="", max_length=32)
    # прямой путь по локальной сети (клиенты 1.0.11+): адреса ПК в локальной сети, порт WireGuard
    # и с какими ПК связь сейчас идёт напрямую. Старые клиенты эти поля не шлют.
    lan: list[str] | None = Field(default=None, max_length=services.LAN_MAX_ADDRS)
    wg_port: int = Field(default=0, ge=0, le=65535)
    direct: list[int] = Field(default_factory=list, max_length=254)
    # клиент 1.0.12+: умеет прямой путь через интернет к ПК других офисов (пробой NAT)
    wan: bool = False
    # клиент 1.0.12+: стоит ли на ПК Radmin Server. Нет поля (старый клиент) — прежнее значение
    radmin_server: bool | None = None
    # клиент 1.0.16+: RustDesk на ПК установлен и настроен (удалённое управление). Нет поля — прежнее значение
    remote_ok: bool | None = None
    # клиент 1.0.18+: как пользователь ПК разрешил управлять своим компьютером ('' — как администратор)
    remote_local: str | None = Field(default=None, pattern="^(|ask|own|off)$")
    # клиент 1.0.21+: сетевые карты (адрес в локальной сети и MAC) — для включения по сети. Нет поля — прежние
    nics: list[NicIn] | None = Field(default=None, max_length=services.NICS_MAX)


class WakeIn(BaseModel):
    to: int


class RemotePasswordIn(BaseModel):
    password: str = Field(min_length=12, max_length=64)


class RemoteConnectIn(BaseModel):
    to: int
    kind: str = Field(default="control", pattern="^(control|files)$")


# не больше стольких запросов на подключение с одного ПК в минуту
remote_limiter = RateLimiter(limit=20, window=60)


def _token_reused(conn, device_id: int, now: int) -> None:
    """Пришёл старый токен: им пользуются два компьютера. Отключаем ПК до одобрения администратором."""
    with db.write_lock:
        dev = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not dev:
            return
        was_active = services.device_status(dev) == "active"
        services.revoke_tokens(conn, "id=?", (device_id,))
        conn.execute("UPDATE devices SET is_approved=0 WHERE id=?", (device_id,))
        services.audit(conn, dev["company_id"], "token_reuse",
                       f"{dev['name']} {dev['ip']}: токен использован на двух ПК, ждёт одобрения")
        conn.commit()
        services.reconcile(conn)
    if was_active:   # копия стучится снова и снова — в группу только первый раз
        telegram.notify_pending(conn, device_id, "token_reuse")


def current_device(request: Request, response: Response, conn=Depends(db.get_db)):
    """Устройство по Bearer-токену. Один токен — один компьютер: токен регулярно меняется,
    а старый, пришедший снова, отключает устройство (см. TOKEN_HEADER)."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer ") or not auth[7:].strip():
        raise HTTPException(401, "Нет токена")
    token_hash = sha256(auth[7:].strip())
    now = int(time.time())
    dev = conn.execute("SELECT * FROM devices WHERE token_hash=?", (token_hash,)).fetchone()
    if not dev:
        dev = conn.execute("SELECT * FROM devices WHERE token_next_hash=?", (token_hash,)).fetchone()
        if dev:  # клиент перешёл на новый токен — прежний больше не действует
            with db.write_lock:
                services.retire_token(conn, dev["id"], dev["token_hash"], now)
                conn.execute("UPDATE devices SET token_hash=?, token_next_hash=NULL, token_next_at=0, "
                             "token_set_at=? WHERE id=?", (token_hash, now, dev["id"]))
                conn.commit()
            dev = conn.execute("SELECT * FROM devices WHERE id=?", (dev["id"],)).fetchone()
    if not dev:
        old = conn.execute("SELECT device_id FROM token_history WHERE token_hash=?", (token_hash,)).fetchone()
        if old:
            _token_reused(conn, old["device_id"], now)
            raise HTTPException(401, "Этот вход уже используется на другом компьютере. "
                                     "ПК отключён и ждёт одобрения администратора компании")
        raise HTTPException(401, "Устройство не найдено, нужна повторная регистрация")
    company = conn.execute("SELECT * FROM companies WHERE id=?", (dev["company_id"],)).fetchone()
    if not company["is_active"]:
        raise HTTPException(403, "Компания отключена")
    updates.note_device(conn, dev, request, response)   # версия ПК, состояние обновления, подсказка
    if dev["token_hash"] == token_hash and now - dev["token_set_at"] >= TOKEN_ROTATE_SECONDS \
            and (not dev["token_next_hash"] or now - dev["token_next_at"] >= NEXT_TOKEN_RETRY):
        token, next_hash = new_token()
        conn.execute("UPDATE devices SET token_next_hash=?, token_next_at=? WHERE id=?", (next_hash, now, dev["id"]))
        conn.commit()
        response.headers[TOKEN_HEADER] = token
    return conn, dev, company


@router.get("/ping")
def ping():
    return {"ok": True, "time": int(time.time())}


@router.post("/register")
def register(data: RegisterIn, request: Request, conn=Depends(db.get_db)):
    ip = client_ip(request)
    limiter.check(ip)

    if not wg.valid_pubkey(data.public_key):
        raise HTTPException(400, "Неверный публичный ключ")

    company = conn.execute("SELECT * FROM companies WHERE login=?", (data.company_login.strip(),)).fetchone()
    if not company or not check_pw(data.join_password, company["join_pass_hash"]):
        limiter.fail(ip)
        raise HTTPException(401, "Неверный логин или пароль компании")
    if not company["is_active"]:
        raise HTTPException(403, "Компания отключена")
    limiter.reset(ip)

    name = services.clean_device_name(data.device_name)
    if not name:
        raise HTTPException(400, "Пустое имя компьютера")
    hostname = services.clean_hostname(data.hostname)
    token, token_hash = new_token()

    with db.write_lock:
        existing = conn.execute("SELECT * FROM devices WHERE public_key=?", (data.public_key,)).fetchone()
        if existing and existing["company_id"] != company["id"]:
            raise HTTPException(409, "Этот ключ уже зарегистрирован в другой компании")

        now = int(time.time())
        if existing:  # повторная регистрация того же ПК — новый токен, тот же IP
            # прежний токен перестаёт действовать; если он придёт снова — вход скопирован на другой ПК
            services.retire_token(conn, existing["id"], existing["token_hash"], now)
            conn.execute("UPDATE devices SET token_hash=?, token_next_hash=NULL, token_next_at=0, token_set_at=?, "
                         "name=?, hostname=?, client_version=? WHERE id=?",
                         (token_hash, now, name, hostname, data.client_version, existing["id"]))
            dev_id = existing["id"]
            services.audit(conn, company["id"], "device_reregister", f"{name} {existing['ip']}")
        else:
            count = conn.execute("SELECT COUNT(*) FROM devices WHERE company_id=?", (company["id"],)).fetchone()[0]
            if count >= company["max_devices"]:
                raise HTTPException(403, f"Достигнут лимит устройств ({company['max_devices']})")
            new_ip = services.allocate_ip(conn, company)
            if not new_ip:
                raise HTTPException(403, "Нет свободных адресов в подсети")
            cur = conn.execute(
                "INSERT INTO devices(company_id, name, hostname, public_key, ip, token_hash, token_set_at, "
                "is_approved, client_version) VALUES (?,?,?,?,?,?,?,?,?)",
                (company["id"], name, hostname, data.public_key, new_ip, token_hash, now,
                 0 if company["require_approval"] else 1, data.client_version))
            dev_id = cur.lastrowid
            services.audit(conn, company["id"], "device_register", f"{name} {new_ip} from {ip}")
        conn.commit()
        services.reconcile(conn)
    if not existing:
        telegram.notify_pending(conn, dev_id, "new", ip)   # ждёт одобрения — запрос в группу компании

    dev = conn.execute("SELECT * FROM devices WHERE id=?", (dev_id,)).fetchone()
    return {"token": token, **services.client_config(conn, dev, company)}


@router.get("/me")
def me(ctx=Depends(current_device)):
    conn, dev, company = ctx
    cfg = services.client_config(conn, dev, company)
    cfg["wake"] = services.take_wake_jobs(conn, dev)   # разбудить выключенные ПК своей локальной сети
    return cfg


@router.get("/peers")
def peers(ctx=Depends(current_device)):
    conn, dev, company = ctx
    if services.device_status(dev) != "active":
        raise HTTPException(403, "Устройство не активно")
    hidden = not dev["show_peers"]   # нет доступа — в программе только сам ПК (сеть при этом та же)
    me_controls = services.can_control(dev, company)   # меню RustDesk — только у ПК, которому разрешено управлять
    result = []
    for d in services.list_devices(conn, company["id"]):
        if d["status"] != "active" or (hidden and d["id"] != dev["id"]):
            continue
        result.append({
            "id": d["id"],
            "name": d["name"],
            "hostname": d["hostname"],
            "ip": d["ip"],
            "online": d["online"],
            "last_handshake": d["last_handshake"],
            "client_version": d["client_version"],
            "is_share_host": bool(d["is_share_host"]),
            "radmin_server": bool(d["radmin_server"]),
            # к нему можно подключиться через RustDesk (и этому ПК разрешено управлять)
            "remote": me_controls and bool(d["remote_ok"]) and d["remote_effective"] != "off",
            "remote_mode": d["remote_effective"] if me_controls else "off",
            # выключен, но его можно включить по сети (этому ПК разрешено управлять)
            "wake": me_controls and not d["online"] and d["wol_ready"] and d["id"] != dev["id"],
            "is_me": d["id"] == dev["id"],
        })
    return {"company": company["name"] or company["login"], "peers": result, "peers_hidden": hidden}


def _require_active(dev):
    if services.device_status(dev) != "active":
        raise HTTPException(403, "Устройство не активно")


@router.post("/messages")
def send_message(data: MessageIn, ctx=Depends(current_device)):
    """Сообщение другому ПК своей компании. Доставляется, когда получатель спросит /api/messages."""
    conn, dev, company = ctx
    _require_active(dev)
    if not dev["show_peers"]:
        raise HTTPException(403, "Администратор компании не дал этому компьютеру доступ к другим компьютерам")
    text = data.text.strip()
    if not text:
        raise HTTPException(400, "Пустое сообщение")
    target = conn.execute("SELECT * FROM devices WHERE id=? AND company_id=?", (data.to, company["id"])).fetchone()
    if not target or services.device_status(target) != "active":
        raise HTTPException(404, "Получатель не найден")
    now = int(time.time())
    sent = conn.execute("SELECT COUNT(*) FROM messages WHERE from_device_id=? AND created_at>?",
                        (dev["id"], now - 60)).fetchone()[0]
    if sent >= MESSAGES_PER_MINUTE:
        raise HTTPException(429, "Слишком много сообщений, подождите минуту")
    conn.execute("INSERT INTO messages(company_id, from_device_id, to_device_id, text, created_at) VALUES (?,?,?,?,?)",
                 (company["id"], dev["id"], target["id"], text, now))
    conn.execute("DELETE FROM messages WHERE created_at<?", (now - MESSAGES_KEEP_DAYS * 86400,))
    conn.commit()
    return {"ok": True}


@router.get("/messages")
def get_messages(ctx=Depends(current_device)):
    """Новые сообщения этому ПК; каждое отдаётся один раз."""
    conn, dev, _ = ctx
    _require_active(dev)
    rows = conn.execute(
        "SELECT m.id, m.from_device_id, m.text, m.created_at, d.name AS from_name, d.ip AS from_ip "
        "FROM messages m LEFT JOIN devices d ON d.id=m.from_device_id "
        "WHERE m.to_device_id=? AND m.delivered=0 ORDER BY m.id LIMIT 50", (dev["id"],)).fetchall()
    if rows:
        conn.executemany("UPDATE messages SET delivered=1 WHERE id=?", [(r["id"],) for r in rows])
        conn.commit()
    return {"messages": [{"id": r["id"], "from_id": r["from_device_id"], "from_name": r["from_name"] or "—",
                          "from_ip": r["from_ip"] or "", "text": r["text"], "time": r["created_at"]} for r in rows]}


@router.post("/rename")
def rename(data: RenameIn, ctx=Depends(current_device)):
    """Пользователь ПК меняет имя своего компьютера в сети компании (клиент 1.0.13+)."""
    conn, dev, company = ctx
    if dev["is_blocked"]:
        raise HTTPException(403, "Устройство заблокировано администратором")
    name = services.clean_device_name(data.name)
    if not name:
        raise HTTPException(400, "Пустое имя")
    if name != dev["name"]:
        with db.write_lock:
            conn.execute("UPDATE devices SET name=? WHERE id=?", (name, dev["id"]))
            services.audit(conn, company["id"], "device_rename_self", f"{dev['name']} → {name} {dev['ip']}")
            conn.commit()
    return {"ok": True, "device_name": name}


@router.post("/logout")
def logout(ctx=Depends(current_device)):
    """«Выйти из сети» в клиенте: токен больше не действует, ПК снимается с wg0."""
    conn, dev, company = ctx
    with db.write_lock:
        services.revoke_tokens(conn, "id=?", (dev["id"],))
        services.audit(conn, company["id"], "device_logout", f"{dev['name']} {dev['ip']}")
        conn.commit()
        services.reconcile(conn)
    return {"ok": True}


@router.post("/heartbeat")
def heartbeat(data: HeartbeatIn, ctx=Depends(current_device)):
    conn, dev, _ = ctx
    conn.execute("UPDATE devices SET last_seen=CURRENT_TIMESTAMP, client_version=? WHERE id=?",
                 (data.client_version, dev["id"]))
    if data.lan is not None:
        conn.execute("UPDATE devices SET lan_addrs=?, wg_port=?, lan_at=?, direct_ids=?, wan_ok=? WHERE id=?",
                     (json.dumps(services.clean_lan(data.lan)), data.wg_port, int(time.time()),
                      json.dumps(sorted(set(data.direct))), 1 if data.wan else 0, dev["id"]))
    if data.radmin_server is not None:
        conn.execute("UPDATE devices SET radmin_server=? WHERE id=?", (1 if data.radmin_server else 0, dev["id"]))
    if data.remote_ok is not None:
        conn.execute("UPDATE devices SET remote_ok=? WHERE id=?", (1 if data.remote_ok else 0, dev["id"]))
    if data.nics is not None:
        nics = services.clean_nics([n.model_dump() for n in data.nics])
        if nics:   # пусто (карты не прочитались) — оставляем последние известные: по ним ПК и будят
            conn.execute("UPDATE devices SET nics=?, nics_at=? WHERE id=?",
                         (json.dumps(nics), int(time.time()), dev["id"]))
    if data.remote_local is not None and data.remote_local != dev["remote_local"]:
        conn.execute("UPDATE devices SET remote_local=? WHERE id=?", (data.remote_local, dev["id"]))
        if data.remote_local:   # не «как администратор» — пароль сервера больше не действует
            conn.execute("UPDATE devices SET remote_pw='', remote_used_at=0 WHERE id=?", (dev["id"],))
        services.audit(conn, dev["company_id"], "remote_local",
                       f"{dev['name']} {dev['ip']}: {services.REMOTE_LOCAL[data.remote_local]}")
    conn.commit()
    return {"ok": True}


# ---------- удалённое управление (RustDesk) ----------

@router.post("/remote/password")
def remote_password(data: RemotePasswordIn, ctx=Depends(current_device)):
    """ПК поставил новый пароль своему RustDesk и сообщает его: сервер выдаст его только тому ПК своей компании,
    которому разрешит подключиться (/api/remote/connect). Прежний пароль больше не действует."""
    conn, dev, company = ctx
    _require_active(dev)
    if not services.REMOTE_PW_RE.match(data.password):
        raise HTTPException(400, "Пароль: 12–64 латинских букв и цифр")
    conn.execute("UPDATE devices SET remote_pw=?, remote_used_at=0 WHERE id=?", (services.seal(data.password), dev["id"]))
    conn.commit()
    return {"ok": True}


@router.post("/remote/connect")
def remote_connect(data: RemoteConnectIn, ctx=Depends(current_device)):
    """Разрешение подключиться к ПК своей компании через RustDesk: адрес и, если управление без согласия,
    пароль. Каждое подключение — в журнале компании."""
    conn, dev, company = ctx
    _require_active(dev)
    mode = services.remote_mode(company)
    if mode == "off":
        raise HTTPException(403, "Удалённое управление выключено в кабинете компании")
    if not dev["show_peers"]:
        raise HTTPException(403, "Администратор компании не дал этому компьютеру доступ к другим компьютерам")
    if not services.can_control(dev, company):
        raise HTTPException(403, "Администратор компании не разрешил этому компьютеру управлять другими "
                                 "(кабинет → список компьютеров → «Управляет»)")
    remote_limiter.check(str(dev["id"]))   # до поиска ПК: перебором номеров ничего не узнать
    remote_limiter.fail(str(dev["id"]))
    target = conn.execute("SELECT * FROM devices WHERE id=? AND company_id=?", (data.to, company["id"])).fetchone()
    if not target or target["id"] == dev["id"] or services.device_status(target) != "active":
        raise HTTPException(404, "Компьютер не найден")
    mode = services.effective_remote_mode(target, company)
    if mode == "off":
        raise HTTPException(403, f"Управлять компьютером {target['name']} нельзя: "
                                 + ("так решил его пользователь" if target["remote_local"] == "off"
                                    else "выключено администратором"))
    if not target["remote_ok"]:
        raise HTTPException(409, f"На {target['name']} удалённое управление ещё не готово: нужна Retix Hub 1.0.16 "
                                 "или новее, и программа должна успеть поставить RustDesk (несколько минут)")
    if not services.is_online(target):
        raise HTTPException(409, f"{target['name']} сейчас не в сети")
    password = ""
    if mode == "auto":
        password = services.unseal(target["remote_pw"])
        if not password:
            raise HTTPException(409, f"{target['name']} ещё готовит удалённое управление, попробуйте через минуту")
    with db.write_lock:
        if mode == "auto":   # пароль выдан — после сеанса ПК сменит его сам
            conn.execute("UPDATE devices SET remote_used_at=? WHERE id=?", (int(time.time()), target["id"]))
        services.audit(conn, company["id"], "remote_connect",
                       f"{dev['name']} {dev['ip']} → {target['name']} {target['ip']}"
                       f"{' (файлы)' if data.kind == 'files' else ''}")
        conn.commit()
    return {"ip": target["ip"], "port": REMOTE_PORT, "mode": mode, "password": password, "name": target["name"]}


@router.post("/wake")
def wake(data: WakeIn, ctx=Depends(current_device)):
    """Включить выключенный ПК своей компании по сети (Wake-on-LAN): может ПК с правом «управляет»."""
    conn, dev, company = ctx
    _require_active(dev)
    if not dev["show_peers"]:
        raise HTTPException(403, "Администратор компании не дал этому компьютеру доступ к другим компьютерам")
    if not services.can_control(dev, company):
        raise HTTPException(403, "Включать компьютеры по сети могут только ПК, которым администратор разрешил "
                                 "управлять другими, пока в компании включено удалённое управление")
    if data.to == dev["id"]:
        raise HTTPException(404, "Компьютер не найден")
    remote_limiter.check(str(dev["id"]))
    remote_limiter.fail(str(dev["id"]))
    try:
        msg = services.wake_device(conn, company, data.to, f"{dev['name']} {dev['ip']}")
    except LookupError:
        raise HTTPException(404, "Компьютер не найден") from None
    except ValueError as e:
        raise HTTPException(409, str(e)) from None
    return {"ok": True, "message": msg}


# ---------- журнал программы по запросу администратора ----------

@router.post("/log")
async def upload_log(request: Request, ctx=Depends(current_device)):
    """ПК присылает свой журнал (gzip), когда администратор его запросил (log_request в /api/me)."""
    conn, dev, _ = ctx
    if not dev["log_requested_at"]:
        raise HTTPException(409, "Журнал не запрашивали")
    if int(request.headers.get("content-length") or 0) > services.LOG_UPLOAD_MAX:
        raise HTTPException(413, "Журнал слишком большой")
    body = await request.body()
    if not body or len(body) > services.LOG_UPLOAD_MAX:
        raise HTTPException(413 if body else 400, "Журнал слишком большой" if body else "Пустой журнал")
    unzip = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        text = unzip.decompress(body, services.LOG_TEXT_MAX)
    except zlib.error:
        raise HTTPException(400, "Журнал не в формате gzip") from None
    if unzip.unconsumed_tail:
        raise HTTPException(413, "Журнал слишком большой")
    if not unzip.eof:
        raise HTTPException(400, "Журнал передан не полностью")
    services.save_log(conn, dev, body, len(text))
    return {"ok": True}
