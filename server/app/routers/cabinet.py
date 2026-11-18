"""Кабинет компании. Компания берётся ТОЛЬКО из сессии — чужие данные недоступны."""
from fastapi import APIRouter, Depends, Form, Request

from .. import db, services
from ..auth import check_pw, client_ip, hash_pw, limiter
from ..web import LoginRequired, redirect, templates

router = APIRouter(prefix="/cabinet", include_in_schema=False)


def current_company(request: Request, conn=Depends(db.get_db)):
    cid = request.session.get("company_id") if request.session.get("role") == "company" else None
    company = conn.execute("SELECT * FROM companies WHERE id=?", (cid,)).fetchone() if cid else None
    if not company or not company["is_active"]:
        request.session.clear()
        raise LoginRequired("/cabinet/login")
    return conn, company


@router.get("/login")
def login_page(request: Request, msg: str = "", err: int = 0):
    return templates.TemplateResponse(request, "login.html", {
        "title": "Кабинет компании", "action": "/cabinet/login",
        "login_label": "Логин компании", "msg": msg, "err": err})


@router.post("/login")
def login(request: Request, login: str = Form(...), password: str = Form(...), conn=Depends(db.get_db)):
    ip = client_ip(request)
    limiter.check(ip)
    c = conn.execute("SELECT * FROM companies WHERE login=?", (login.strip(),)).fetchone()
    if not c or not check_pw(password, c["cabinet_pass_hash"]):
        limiter.fail(ip)
        return redirect("/cabinet/login", "Неверный логин или пароль", err=True)
    if not c["is_active"]:
        return redirect("/cabinet/login", "Компания отключена", err=True)
    limiter.reset(ip)
    request.session.clear()
    request.session.update({"role": "company", "company_id": c["id"]})
    return redirect("/cabinet")


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/cabinet/login")


@router.get("")
def index(request: Request, ctx=Depends(current_company), msg: str = "", err: int = 0):
    conn, company = ctx
    devices = services.list_devices(conn, company["id"])
    remote_log = conn.execute("SELECT * FROM audit_log WHERE company_id=? AND action='remote_connect' "
                              "ORDER BY id DESC LIMIT 30", (company["id"],)).fetchall()
    return templates.TemplateResponse(request, "cabinet.html", {
        "title": company["name"] or company["login"], "company": company,
        "subnet": services.subnet(company), "devices": devices,
        "remote_modes": services.REMOTE_MODES, "remote_access": services.REMOTE_ACCESS,
        "remote_mode": services.remote_mode(company), "remote_log": remote_log,
        "online": sum(d["online"] for d in devices),
        "action_prefix": "/cabinet/devices/", "logout_url": "/cabinet/logout",
        "msg": msg, "err": err})


@router.post("/devices/{device_id}/{action}")
def device_action(device_id: int, action: str, value: str = Form(""), ctx=Depends(current_company)):
    conn, company = ctx
    try:
        msg = services.device_action(conn, company["id"], device_id, action, value)
    except (LookupError, ValueError) as e:
        return redirect("/cabinet", str(e), err=True)
    return redirect("/cabinet", msg)


@router.post("/settings")
def settings(require_approval: str = Form(""), full_lan: str = Form(""),
             share_name: str = Form("share"), share_ports: str = Form("445"),
             remote_mode: str | None = Form(None), ctx=Depends(current_company)):
    conn, company = ctx
    remote = services.remote_mode(company) if remote_mode is None else services.clean_remote_mode(remote_mode)
    if remote is None:
        return redirect("/cabinet", "Неизвестный режим удалённого управления", err=True)
    ports = services.clean_ports(share_ports)
    if not ports:
        return redirect("/cabinet", "Порты: числа через запятую, например 445", err=True)
    share_name = share_name.strip()
    if not services.SHARE_RE.match(share_name):
        return redirect("/cabinet", "Недопустимое имя общей папки", err=True)
    with db.write_lock:
        conn.execute("UPDATE companies SET require_approval=?, full_lan=?, share_name=?, share_ports=?, remote_mode=? "
                     "WHERE id=?", (1 if require_approval else 0, 1 if full_lan else 0, share_name, ports, remote,
                                    company["id"]))
        services.audit(conn, company["id"], "settings", f"approval={bool(require_approval)} full_lan={bool(full_lan)} "
                                                        f"ports={ports} remote={remote}")
        conn.commit()
        services.reconcile(conn)
    return redirect("/cabinet", "Настройки сохранены")


@router.post("/join-password")
def join_password(new_password: str = Form(...), kick_all: str = Form(""), ctx=Depends(current_company)):
    conn, company = ctx
    if len(new_password) < 6:
        return redirect("/cabinet", "Пароль минимум 6 символов", err=True)
    with db.write_lock:
        conn.execute("UPDATE companies SET join_pass_hash=? WHERE id=?", (hash_pw(new_password), company["id"]))
        if kick_all:
            # токены сброшены и пиры сняты с wg0 — ПК отключены от сети, пока не войдут с новым паролем
            services.revoke_tokens(conn, "company_id=?", (company["id"],))
        services.audit(conn, company["id"], "join_password", "kick_all" if kick_all else "")
        conn.commit()
        if kick_all:
            services.reconcile(conn)
    return redirect("/cabinet", "Пароль подключения изменён" + (", все устройства должны войти заново" if kick_all else ""))


@router.post("/cabinet-password")
def cabinet_password(old_password: str = Form(...), new_password: str = Form(...), ctx=Depends(current_company)):
    conn, company = ctx
    if not check_pw(old_password, company["cabinet_pass_hash"]):
        return redirect("/cabinet", "Текущий пароль неверный", err=True)
    if len(new_password) < 6:
        return redirect("/cabinet", "Пароль минимум 6 символов", err=True)
    conn.execute("UPDATE companies SET cabinet_pass_hash=? WHERE id=?", (hash_pw(new_password), company["id"]))
    services.audit(conn, company["id"], "cabinet_password")
    conn.commit()
    return redirect("/cabinet", "Пароль кабинета изменён")
