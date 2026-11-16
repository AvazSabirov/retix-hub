"""Кабинет суперадмина: все компании."""
import hmac
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request

from .. import db, services
from ..auth import client_ip, hash_pw, limiter
from ..config import SUPERADMIN_LOGIN, SUPERADMIN_PASSWORD
from ..web import LoginRequired, redirect, templates

router = APIRouter(prefix="/admin", include_in_schema=False)


def require_admin(request: Request, conn=Depends(db.get_db)):
    if request.session.get("role") != "admin" or not SUPERADMIN_PASSWORD:
        raise LoginRequired("/admin/login")
    return conn


def get_company(conn, company_id: int):
    c = conn.execute("SELECT * FROM companies WHERE id=?", (company_id,)).fetchone()
    if not c:
        raise LoginRequired("/admin?" + urlencode({"msg": "Компания не найдена", "err": 1}))
    return c


@router.get("/login")
def login_page(request: Request, msg: str = "", err: int = 0):
    return templates.TemplateResponse(request, "login.html", {
        "title": "Суперадмин", "action": "/admin/login", "login_label": "Логин",
        "msg": msg, "err": err})


@router.post("/login")
def login(request: Request, login: str = Form(...), password: str = Form(...)):
    ip = client_ip(request)
    limiter.check(ip)
    good = bool(SUPERADMIN_PASSWORD) \
        and hmac.compare_digest(login.encode(), SUPERADMIN_LOGIN.encode()) \
        and hmac.compare_digest(password.encode(), SUPERADMIN_PASSWORD.encode())
    if not good:
        limiter.fail(ip)
        return redirect("/admin/login", "Неверный логин или пароль", err=True)
    limiter.reset(ip)
    request.session.clear()
    request.session["role"] = "admin"
    return redirect("/admin")


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/admin/login")


@router.get("")
def index(request: Request, conn=Depends(require_admin), msg: str = "", err: int = 0):
    companies = []
    for c in conn.execute("SELECT * FROM companies ORDER BY login"):
        devs = services.list_devices(conn, c["id"])
        companies.append({**dict(c), "subnet": services.subnet(c), "total": len(devs),
                          "online": sum(d["online"] for d in devs),
                          "pending": sum(d["status"] == "pending" for d in devs)})
    return templates.TemplateResponse(request, "admin.html", {
        "title": "Компании", "companies": companies, "logout_url": "/admin/logout",
        "msg": msg, "err": err})


@router.post("/companies")
def create_company(login: str = Form(...), name: str = Form(""), cabinet_password: str = Form(...),
                   join_password: str = Form(...), max_devices: int = Form(20),
                   approval_form: str = Form(""), require_approval: str = Form(""), conn=Depends(require_admin)):
    login = login.strip()
    # галочка «ПК ждут одобрения» есть в форме (approval_form) — берём её; без формы — одобрение включено
    approval = (1 if require_approval else 0) if approval_form else 1
    if not services.LOGIN_RE.match(login):
        return redirect("/admin", "Логин: 3–32 символа, латиница, цифры, _ . -", err=True)
    if len(cabinet_password) < 6 or len(join_password) < 6:
        return redirect("/admin", "Пароли минимум 6 символов", err=True)
    with db.write_lock:
        if conn.execute("SELECT 1 FROM companies WHERE login=?", (login,)).fetchone():
            return redirect("/admin", "Такой логин уже есть", err=True)
        idx = services.allocate_subnet(conn)
        if idx is None:
            return redirect("/admin", "Свободных подсетей нет", err=True)
        cur = conn.execute(
            "INSERT INTO companies(login, name, cabinet_pass_hash, join_pass_hash, subnet_index, max_devices, "
            "require_approval) VALUES (?,?,?,?,?,?,?)",
            (login, name.strip()[:100], hash_pw(cabinet_password), hash_pw(join_password), idx,
             max(1, min(max_devices, 253)), approval))
        services.audit(conn, cur.lastrowid, "company_create", f"{login} approval={bool(approval)}")
        conn.commit()
        services.reconcile(conn)
    return redirect("/admin", f"Компания {login} создана, подсеть 10.66.{idx}.0/24")


@router.get("/companies/{company_id}")
def company_page(request: Request, company_id: int, conn=Depends(require_admin), msg: str = "", err: int = 0):
    c = get_company(conn, company_id)
    devices = services.list_devices(conn, c["id"])
    log = conn.execute("SELECT * FROM audit_log WHERE company_id=? ORDER BY id DESC LIMIT 30", (c["id"],)).fetchall()
    return templates.TemplateResponse(request, "admin_company.html", {
        "title": c["login"], "company": c, "subnet": services.subnet(c), "devices": devices,
        "online": sum(d["online"] for d in devices), "log": log,
        "action_prefix": f"/admin/companies/{c['id']}/devices/", "logout_url": "/admin/logout",
        "msg": msg, "err": err})


@router.post("/companies/{company_id}/update")
def update_company(company_id: int, name: str = Form(""), max_devices: int = Form(20),
                   is_active: str = Form(""), require_approval: str = Form(""), conn=Depends(require_admin)):
    c = get_company(conn, company_id)
    with db.write_lock:
        conn.execute("UPDATE companies SET name=?, max_devices=?, is_active=?, require_approval=? WHERE id=?",
                     (name.strip()[:100], max(1, min(max_devices, 253)), 1 if is_active else 0,
                      1 if require_approval else 0, c["id"]))
        services.audit(conn, c["id"], "company_update",
                       f"active={bool(is_active)} max={max_devices} approval={bool(require_approval)}")
        conn.commit()
        services.reconcile(conn)
    return redirect(f"/admin/companies/{c['id']}", "Сохранено")


@router.post("/companies/{company_id}/passwords")
def set_passwords(company_id: int, cabinet_password: str = Form(""), join_password: str = Form(""),
                  conn=Depends(require_admin)):
    c = get_company(conn, company_id)
    changed = []
    for field, value, label in (("cabinet_pass_hash", cabinet_password, "кабинета"),
                                ("join_pass_hash", join_password, "подключения")):
        if value:
            if len(value) < 6:
                return redirect(f"/admin/companies/{c['id']}", "Пароль минимум 6 символов", err=True)
            conn.execute(f"UPDATE companies SET {field}=? WHERE id=?", (hash_pw(value), c["id"]))
            changed.append(label)
    if not changed:
        return redirect(f"/admin/companies/{c['id']}", "Ничего не изменено", err=True)
    services.audit(conn, c["id"], "admin_passwords", ", ".join(changed))
    conn.commit()
    return redirect(f"/admin/companies/{c['id']}", "Изменён пароль " + " и ".join(changed))


@router.post("/companies/{company_id}/delete")
def delete_company(company_id: int, confirm: str = Form(""), conn=Depends(require_admin)):
    c = get_company(conn, company_id)
    if confirm != c["login"]:
        return redirect(f"/admin/companies/{c['id']}", "Для удаления введите логин компании", err=True)
    with db.write_lock:
        conn.execute("DELETE FROM companies WHERE id=?", (c["id"],))
        services.audit(conn, None, "company_delete", c["login"])
        conn.commit()
        services.reconcile(conn)
    return redirect("/admin", f"Компания {c['login']} удалена")


@router.post("/companies/{company_id}/devices/{device_id}/{action}")
def device_action(company_id: int, device_id: int, action: str, value: str = Form(""),
                  conn=Depends(require_admin)):
    c = get_company(conn, company_id)
    url = f"/admin/companies/{c['id']}"
    try:
        return redirect(url, services.device_action(conn, c["id"], device_id, action, value))
    except (LookupError, ValueError) as e:
        return redirect(url, str(e), err=True)
