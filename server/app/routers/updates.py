"""Обновления клиента: страница суперадмина /admin/updates и API для ПК (логика — app/updates.py)."""
import os
import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, Response, StreamingResponse
from starlette.datastructures import UploadFile

from .. import db, services, updates
from ..config import TZ
from ..web import csrf_ok, csrf_token, redirect, templates
from .admin import require_admin
from .api_client import current_device

router = APIRouter(include_in_schema=False)


# ---------------------------------------------------------------------------
# ПК
# ---------------------------------------------------------------------------
@router.get("/api/update")
def device_update(request: Request, ctx=Depends(current_device)):
    """Что ставить этому ПК: {"current", "update": null | {...}}."""
    conn, dev, _ = ctx
    if services.device_status(dev) != "active":
        raise HTTPException(403, "Устройство не активно")
    version = request.headers.get("x-retix-version", "").strip() or dev["client_version"]
    rel = updates.pick(conn, dev["company_id"], version)
    return {"current": version, "public_key": updates.public_key_b64(),
            "update": updates.payload(rel, dev["id"]) if rel is not None else None}


@router.get("/api/client/version")
def client_version_legacy(conn=Depends(db.get_db)):
    """Для клиента 1.0.5 (первый вариант автообновления: без подписи, по SHA-256 с этого же сервера):
    версия, опубликованная в «Обновлениях» для всех компаний, — та же, что отдаёт /download/client.
    Так ПК на 1.0.5 сами переходят на новую версию, а дальше обновляются уже по подписи."""
    rel = updates.site_release(conn)
    if rel is None:
        return {"version": None}
    return {"version": rel["version"], "file": rel["file_name"], "size": rel["size"], "sha256": rel["sha256"],
            "url": "/download/client"}


@router.get("/api/update/file/{rid}")
def device_update_file(rid: int, request: Request, d: int = 0, e: int = 0, s: str = "",
                       conn=Depends(db.get_db)):
    """Установщик по билету из /api/update (без токена ПК). Range: bytes=N- — докачка (206)."""
    if not updates.ticket_ok(rid, d, e, s):
        raise HTTPException(403, "Ссылка на обновление недействительна или устарела")
    dev = conn.execute("SELECT d.*, c.is_active AS company_active FROM devices d JOIN companies c "
                       "ON c.id=d.company_id WHERE d.id=?", (d,)).fetchone()
    if not dev or not dev["company_active"] or services.device_status(dev) != "active":
        raise HTTPException(403, "Устройство не активно")
    updates.activate_due(conn)
    rel = conn.execute("SELECT * FROM app_releases WHERE id=? AND published=1", (rid,)).fetchone()
    if rel is None or not updates.in_scope(rel, dev["company_id"]):
        raise HTTPException(404, "Обновление не найдено или снято с публикации")
    path = os.path.join(updates.updates_dir(), rel["stored_name"])
    try:
        size = os.path.getsize(path)
    except OSError:
        raise HTTPException(404, "Файл обновления пропал с сервера")
    start, end, status = 0, size - 1, 200
    headers = {"Accept-Ranges": "bytes", "Content-Disposition": f'attachment; filename="{rel["file_name"]}"'}
    m = re.fullmatch(r"bytes=(\d+)-(\d*)", request.headers.get("range", "").strip())
    if m:
        start = int(m.group(1))
        if start >= size:
            return Response(status_code=416, headers={"Content-Range": f"bytes */{size}"})
        if m.group(2):
            end = min(int(m.group(2)), size - 1)
            if end < start:
                return Response(status_code=416, headers={"Content-Range": f"bytes */{size}"})
        status = 206
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    length = end - start + 1
    headers["Content-Length"] = str(length)
    if start == 0:
        conn.execute("UPDATE app_releases SET downloads=downloads+1 WHERE id=?", (rid,))
        conn.commit()

    def stream():
        with open(path, "rb") as f:
            f.seek(start)
            left = length
            while left > 0:
                chunk = f.read(min(updates.CHUNK, left))
                if not chunk:
                    break
                left -= len(chunk)
                yield chunk

    return StreamingResponse(stream(), status_code=status, headers=headers, media_type="application/octet-stream")


# ---------------------------------------------------------------------------
# Суперадмин
# ---------------------------------------------------------------------------
def _go(msg: str = "", err: bool = False):
    return redirect("/admin/updates", msg, err=err)


def _release(conn, rid: int):
    rel = conn.execute("SELECT * FROM app_releases WHERE id=?", (rid,)).fetchone()
    if rel is None:
        raise HTTPException(404, "Такой версии нет")
    return rel


@router.get("/admin/updates")
def admin_updates(request: Request, conn=Depends(require_admin), msg: str = "", err: int = 0):
    updates.activate_due(conn)
    releases = [dict(r) for r in conn.execute("SELECT * FROM app_releases ORDER BY created_at DESC, id DESC")]
    companies = conn.execute("SELECT id, login, name FROM companies ORDER BY login").fetchall()
    names = {c["id"]: c["name"] or c["login"] for c in companies}
    devices = updates.devices_overview(conn)
    for r in releases:
        ids = updates.companies_of(r)
        r["scope_ids"] = ids
        r["scope_text"] = ", ".join(names.get(i, f"#{i}") for i in sorted(ids)) if ids else "все компании"
        r["on_version"] = sum(1 for d in devices if updates.vkey(d["client_version"]) == updates.vkey(r["version"]))
        r["waiting"] = sum(1 for d in devices if d["target"] == r["version"])
        r["publish_at_input"] = (r["publish_at"] or "")[:16].replace(" ", "T")
    versions: dict[str, int] = {}
    for d in devices:
        versions[d["client_version"] or "?"] = versions.get(d["client_version"] or "?", 0) + 1
    versions_sorted = sorted(versions.items(), key=lambda kv: updates.vkey(kv[0]) or (0,), reverse=True)
    site = updates.site_release(conn)
    return templates.TemplateResponse(request, "admin_updates.html", {
        "title": "Обновления клиента", "logout_url": "/admin/logout", "admin_nav": "updates",
        "csrf": csrf_token(request), "releases": releases, "companies": companies, "devices": devices,
        "versions": versions_sorted, "site_version": site["version"] if site else "",
        "public_key": updates.public_key_b64(), "now": updates.dt_text(updates.ts()), "tz_name": TZ,
        "max_mb": updates.MAX_UPLOAD // (1024 * 1024), "msg": msg, "err": err})


@router.post("/admin/updates")
async def admin_update_upload(request: Request):
    """Загрузка установщика. Тело (до сотен МБ) разбирается только ПОСЛЕ проверки входа суперадмина."""
    if request.session.get("role") != "admin":
        return redirect("/admin/login")
    form = await request.form(max_files=1, max_fields=200)
    try:
        if not csrf_ok(request, form.get("csrf")):
            return _go("Страница устарела — обновите её и повторите", err=True)
        file = form.get("file")
        if not isinstance(file, UploadFile) or not file.filename:
            return _go("Выберите файл установщика RetixHub_Setup_<версия>.exe", err=True)
        conn = db.connect()
        try:
            _, ver = await run_in_threadpool(
                updates.save_upload, file.file, file.filename, conn,
                version=str(form.get("version") or ""), notes=str(form.get("notes") or ""),
                scope=str(form.get("scope") or "all"), companies=form.getlist("companies"),
                publish=bool(form.get("publish")), publish_at=str(form.get("publish_at") or ""), admin="admin")
            when = conn.execute("SELECT publish_at FROM app_releases WHERE version=?", (ver,)).fetchone()[0]
        except updates.UpdateError as e:
            return _go(str(e), err=True)
        finally:
            conn.close()
    finally:
        await form.close()
    return _go(f"Версия {ver} загружена" + (
        " и опубликована — ПК начнут обновляться в течение 10 минут" if form.get("publish") else
        f" и опубликуется {updates.dt_text(when)} — до этого ПК её не видят" if when else
        " (черновик — ПК её пока не видят)"))


ACTIONS = {"publish": "опубликована", "unpublish": "снята с публикации", "schedule": "опубликуется",
           "unschedule": "— публикация по расписанию отменена", "save": "изменена"}


@router.post("/admin/updates/{rid}")
def admin_update_change(request: Request, rid: int, csrf: str = Form(""), action: str = Form(""),
                        notes: str = Form(None), scope: str = Form("all"), companies: list[str] = Form([]),
                        publish_at: str = Form(""), conn=Depends(require_admin)):
    if not csrf_ok(request, csrf):
        return _go("Страница устарела — обновите её и повторите", err=True)
    updates.activate_due(conn)
    rel = _release(conn, rid)
    if action not in ACTIONS:
        raise HTTPException(400, "Неизвестное действие")
    info, done = "", ACTIONS[action]
    if action == "schedule":
        if rel["published"]:
            return _go(f"Версия {rel['version']} уже опубликована", err=True)
        try:
            when = updates.parse_publish_at(publish_at)
        except updates.UpdateError as e:
            return _go(str(e), err=True)
        if not when:
            return _go("Укажите дату и время публикации", err=True)
        info, done = f"на {when}", f"опубликуется {updates.dt_text(when)}"
    if action == "publish":
        conn.execute("UPDATE app_releases SET published=1, published_at=?, publish_at=NULL WHERE id=?",
                     (updates.ts(), rid))
    elif action == "unpublish":
        conn.execute("UPDATE app_releases SET published=0, publish_at=NULL WHERE id=?", (rid,))
    elif action == "schedule":
        conn.execute("UPDATE app_releases SET publish_at=? WHERE id=?", (when, rid))
    elif action == "unschedule":
        conn.execute("UPDATE app_releases SET publish_at=NULL WHERE id=?", (rid,))
    else:
        try:
            scope_ids = updates.scope_json(scope, companies)
        except updates.UpdateError as e:
            return _go(str(e), err=True)
        conn.execute("UPDATE app_releases SET notes=?, companies=? WHERE id=?",
                     (str(notes if notes is not None else rel["notes"]).strip()[:2000], scope_ids, rid))
        info = "компании: " + (scope_ids or "все")
    updates.log(conn, "update_" + action, f"{rel['version']} {info}".strip())
    conn.commit()
    return _go(f"Версия {rel['version']} {done}")


@router.post("/admin/updates/{rid}/delete")
def admin_update_delete(request: Request, rid: int, csrf: str = Form(""), conn=Depends(require_admin)):
    if not csrf_ok(request, csrf):
        return _go("Страница устарела — обновите её и повторите", err=True)
    rel = _release(conn, rid)
    conn.execute("DELETE FROM app_releases WHERE id=?", (rid,))
    updates.log(conn, "update_delete", rel["version"])
    conn.commit()
    try:
        os.remove(os.path.join(updates.updates_dir(), rel["stored_name"]))
    except OSError:
        pass
    return _go(f"Версия {rel['version']} удалена")


@router.get("/admin/updates/{rid}/file")
def admin_update_file(rid: int, conn=Depends(require_admin)):
    """Суперадмину — скачать установщик (поставить ПК вручную)."""
    rel = _release(conn, rid)
    path = os.path.join(updates.updates_dir(), rel["stored_name"])
    if not os.path.isfile(path):
        raise HTTPException(404, "Файл обновления пропал с сервера")
    return FileResponse(path, filename=rel["file_name"], media_type="application/octet-stream")
