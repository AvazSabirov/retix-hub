"""API для Windows-клиента."""
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import db, services, wg
from ..auth import check_pw, client_ip, limiter, new_token, sha256

router = APIRouter(prefix="/api", tags=["client"])


class RegisterIn(BaseModel):
    company_login: str = Field(min_length=1, max_length=64)
    join_password: str = Field(min_length=1, max_length=128)
    device_name: str = Field(min_length=1, max_length=64)
    hostname: str = Field(default="", max_length=64)
    public_key: str = Field(min_length=44, max_length=44)
    client_version: str = Field(default="", max_length=32)


class HeartbeatIn(BaseModel):
    client_version: str = Field(default="", max_length=32)


def current_device(request: Request, conn=Depends(db.get_db)):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Нет токена")
    dev = conn.execute("SELECT * FROM devices WHERE token_hash=?", (sha256(auth[7:].strip()),)).fetchone()
    if not dev:
        raise HTTPException(401, "Устройство не найдено, нужна повторная регистрация")
    company = conn.execute("SELECT * FROM companies WHERE id=?", (dev["company_id"],)).fetchone()
    if not company["is_active"]:
        raise HTTPException(403, "Компания отключена")
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

    name = data.device_name.strip()[:64]
    hostname = services.clean_hostname(data.hostname)
    token, token_hash = new_token()

    with db.write_lock:
        existing = conn.execute("SELECT * FROM devices WHERE public_key=?", (data.public_key,)).fetchone()
        if existing and existing["company_id"] != company["id"]:
            raise HTTPException(409, "Этот ключ уже зарегистрирован в другой компании")

        if existing:  # повторная регистрация того же ПК — новый токен, тот же IP
            conn.execute("UPDATE devices SET token_hash=?, name=?, hostname=?, client_version=? WHERE id=?",
                         (token_hash, name, hostname, data.client_version, existing["id"]))
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
                "INSERT INTO devices(company_id, name, hostname, public_key, ip, token_hash, is_approved, client_version) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (company["id"], name, hostname, data.public_key, new_ip, token_hash,
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
    result = []
    for d in services.list_devices(conn, company["id"]):
        if d["status"] != "active":
            continue
        result.append({
            "id": d["id"],
            "name": d["name"],
            "hostname": d["hostname"],
            "ip": d["ip"],
            "online": d["online"],
            "last_handshake": d["last_handshake"],
            "is_share_host": bool(d["is_share_host"]),
            "is_me": d["id"] == dev["id"],
        })
    return {"company": company["name"] or company["login"], "peers": result}


@router.post("/heartbeat")
def heartbeat(data: HeartbeatIn, ctx=Depends(current_device)):
    conn, dev, _ = ctx
    conn.execute("UPDATE devices SET last_seen=CURRENT_TIMESTAMP, client_version=? WHERE id=?",
                 (data.client_version, dev["id"]))
    conn.commit()
    return {"ok": True}
