"""API для Windows-клиента."""
import json
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import db, services, updates, wg
from ..auth import check_pw, client_ip, limiter, new_token, sha256
from ..config import TOKEN_ROTATE_SECONDS

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


def _token_reused(conn, device_id: int, now: int) -> None:
    """Пришёл старый токен: им пользуются два компьютера. Отключаем ПК до одобрения администратором."""
    with db.write_lock:
        dev = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not dev:
            return
        services.revoke_tokens(conn, "id=?", (device_id,))
        conn.execute("UPDATE devices SET is_approved=0 WHERE id=?", (device_id,))
        services.audit(conn, dev["company_id"], "token_reuse",
                       f"{dev['name']} {dev['ip']}: токен использован на двух ПК, ждёт одобрения")
        conn.commit()
        services.reconcile(conn)


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

    dev = conn.execute("SELECT * FROM devices WHERE id=?", (dev_id,)).fetchone()
    return {"token": token, **services.client_config(conn, dev, company)}


@router.get("/me")
def me(ctx=Depends(current_device)):
    conn, dev, company = ctx
    return services.client_config(conn, dev, company)


@router.get("/peers")
def peers(ctx=Depends(current_device)):
    conn, dev, company = ctx
    if services.device_status(dev) != "active":
        raise HTTPException(403, "Устройство не активно")
    hidden = not dev["show_peers"]   # нет доступа — в программе только сам ПК (сеть при этом та же)
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
    conn.commit()
    return {"ok": True}
