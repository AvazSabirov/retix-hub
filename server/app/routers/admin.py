"""Кабинет суперадмина: все компании."""
import hashlib
import hmac
import threading
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request

from .. import db, services, telegram
from ..auth import check_pw, client_ip, hash_pw, login_check, login_failed, login_ok
from ..config import SECRET_KEY, SUPERADMIN_LOGIN, SUPERADMIN_PASSWORD
from ..web import LoginRequired, csrf_ok, csrf_token, redirect, templates
from .cabinet import log_response, role_redirect, tg_view

router = APIRouter(prefix="/admin", include_in_schema=False)


_admin_hash = ""
_admin_hash_lock = threading.Lock()


def _superadmin_hash() -> str:
    """bcrypt пароля суперадмина (считается один раз): каждая попытка входа стоит как bcrypt, а не как
    сравнение строк — перебор в тысячи раз медленнее."""
    global _admin_hash
    with _admin_hash_lock:
        if not _admin_hash and SUPERADMIN_PASSWORD:
            _admin_hash = hash_pw(SUPERADMIN_PASSWORD)
        return _admin_hash


def superadmin_ok(login: str, password: str) -> bool:
    if not SUPERADMIN_PASSWORD:
        return False
    same_login = hmac.compare_digest(login.encode(), SUPERADMIN_LOGIN.encode())
    good_pw = check_pw(password, _superadmin_hash())     # всегда, чтобы по времени не было видно, верен ли логин
    # bcrypt видит только первые 72 байта — точное совпадение проверяем отдельно
    return same_login and good_pw and hmac.compare_digest(password.encode(), SUPERADMIN_PASSWORD.encode())


def admin_session_mark() -> str:
    """Отметка в сессии суперадмина: сменили логин или пароль в .env — прежние сессии больше не действуют."""
    return hashlib.sha256(f"admin|{SUPERADMIN_LOGIN}|{SUPERADMIN_PASSWORD}|{SECRET_KEY}".encode()).hexdigest()[:24]


def is_admin_session(request: Request) -> bool:
    return (bool(SUPERADMIN_PASSWORD) and request.session.get("role") == "admin"
            and hmac.compare_digest(str(request.session.get("pv") or ""), admin_session_mark()))


def require_admin(request: Request, conn=Depends(db.get_db)):
    if not is_admin_session(request):
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
    login_check("admin", login, ip)
    if not superadmin_ok(login, password):
        login_failed("admin", login, ip)
        return redirect("/admin/login", "Неверный логин или пароль", err=True)
    login_ok("admin", login, ip)
    request.session.clear()
    request.session.update({"role": "admin", "pv": admin_session_mark()})
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
        "title": "Компании", "companies": companies, "logout_url": "/admin/logout", "admin_nav": "companies",
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
        "roles": services.list_roles(conn, c["id"]), "role_prefix": f"/admin/companies/{c['id']}/roles/",
        "remote_modes": services.REMOTE_MODES, "remote_access": services.REMOTE_ACCESS,
        "remote_mode": services.remote_mode(c),
        "online": sum(d["online"] for d in devices), "log": log,
        "logs": services.company_logs(conn, c["id"]), "log_prefix": f"/admin/companies/{c['id']}/logs/",
        "tg": tg_view(c), "tg_prefix": f"/admin/companies/{c['id']}/telegram/",
        "action_prefix": f"/admin/companies/{c['id']}/devices/", "logout_url": "/admin/logout", "admin_nav": "companies",
        "msg": msg, "err": err})


@router.post("/companies/{company_id}/update")
def update_company(company_id: int, name: str = Form(""), max_devices: int = Form(20),
                   is_active: str = Form(""), require_approval: str = Form(""), speed_limit: str | None = Form(None),
                   remote_mode: str | None = Form(None), conn=Depends(require_admin)):
    c = get_company(conn, company_id)
    remote = services.remote_mode(c) if remote_mode is None else services.clean_remote_mode(remote_mode)
    if remote is None:
        return redirect(f"/admin/companies/{c['id']}", "Неизвестный режим удалённого управления", err=True)
    speed = c["speed_limit"] if speed_limit is None else services.clean_speed(speed_limit)
    if speed is None:
        return redirect(f"/admin/companies/{c['id']}",
                        f"Скорость — целое число Мбит/с от 0 до {services.SPEED_MAX} (0 — без ограничения)", err=True)
    with db.write_lock:
        conn.execute("UPDATE companies SET name=?, max_devices=?, is_active=?, require_approval=?, speed_limit=?, "
                     "remote_mode=? WHERE id=?", (name.strip()[:100], max(1, min(max_devices, 253)),
                                                  1 if is_active else 0, 1 if require_approval else 0, speed, remote,
                                                  c["id"]))
        services.audit(conn, c["id"], "company_update",
                       f"active={bool(is_active)} max={max_devices} approval={bool(require_approval)} speed={speed} "
                       f"remote={remote}")
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


@router.post("/companies/{company_id}/roles/add")
def role_add(company_id: int, value: str = Form(""), conn=Depends(require_admin)):
    c = get_company(conn, company_id)
    return role_redirect(f"/admin/companies/{c['id']}", conn, c["id"], "add", 0, value, "суперадмин")


@router.post("/companies/{company_id}/roles/{role_id}/{action}")
def role_change(company_id: int, role_id: int, action: str, value: str = Form(""), conn=Depends(require_admin)):
    c = get_company(conn, company_id)
    return role_redirect(f"/admin/companies/{c['id']}", conn, c["id"], action, role_id, value, "суперадмин")


@router.post("/companies/{company_id}/devices/{device_id}/{action}")
def device_action(company_id: int, device_id: int, action: str, value: str = Form(""),
                  conn=Depends(require_admin)):
    c = get_company(conn, company_id)
    url = f"/admin/companies/{c['id']}"
    try:
        return redirect(url, services.device_action(conn, c["id"], device_id, action, value, actor="суперадмин"))
    except (LookupError, ValueError) as e:
        return redirect(url, str(e), err=True)


@router.get("/companies/{company_id}/logs/{log_id}")
def download_log(company_id: int, log_id: int, conn=Depends(require_admin)):
    c = get_company(conn, company_id)
    return log_response(conn, c["id"], log_id) or redirect(f"/admin/companies/{c['id']}", "Журнал не найден", err=True)


@router.post("/companies/{company_id}/telegram/unlink")
def telegram_unlink(company_id: int, conn=Depends(require_admin)):
    c = get_company(conn, company_id)
    telegram.unlink(conn, c, "суперадмин")
    return redirect(f"/admin/companies/{c['id']}", "Группа Telegram отключена")


# ---------- настройки сервера ----------

@router.get("/settings")
def settings_page(request: Request, conn=Depends(require_admin), msg: str = "", err: int = 0):
    token, source = telegram.saved_token(conn)
    linked = conn.execute("SELECT login, name, tg_chat_title FROM companies WHERE tg_chat_id<>'' ORDER BY login").fetchall()
    return templates.TemplateResponse(request, "admin_settings.html", {
        "title": "Настройки", "csrf": csrf_token(request), "logout_url": "/admin/logout", "admin_nav": "settings",
        "tg_source": source, "tg_running": telegram.enabled(), "tg_bot": telegram.bot_username,
        "tg_error": telegram.last_error, "tg_masked": (token.split(":", 1)[0] + ":•••••" + token[-4:]) if token else "",
        "tg_linked": linked, "msg": msg, "err": err})


@router.post("/settings/telegram")
def settings_telegram(request: Request, csrf: str = Form(""), token: str = Form(""), conn=Depends(require_admin)):
    if not csrf_ok(request, csrf):
        return redirect("/admin/settings", "Форма устарела, обновите страницу", err=True)
    try:
        username, unlinked = telegram.set_token(conn, token)
    except ValueError as e:
        return redirect("/admin/settings", str(e), err=True)
    return redirect("/admin/settings", f"Бот @{username} подключён" + (
        f". Это другой бот: группы компаний ({unlinked}) отключены, их нужно подключить заново в кабинетах"
        if unlinked else ""))


@router.post("/settings/telegram/delete")
def settings_telegram_delete(request: Request, csrf: str = Form(""), conn=Depends(require_admin)):
    if not csrf_ok(request, csrf):
        return redirect("/admin/settings", "Форма устарела, обновите страницу", err=True)
    left = telegram.delete_token(conn)
    return redirect("/admin/settings", "Токен удалён" + (": работает токен из .env (TELEGRAM_BOT_TOKEN)" if left
                                                         else ", Telegram-бот выключен"))
