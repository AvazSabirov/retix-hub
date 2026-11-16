"""Обновление клиента Retix Hub через суперадмина — та же логика, что у касс Retix (Retix Cloud).

Суперадмин (/admin/updates):
    загружает установщик RetixHub_Setup_<версия>.exe (версия читается из свойств самого exe),
    выбирает — всем компаниям или только некоторым, публикует / снимает с публикации,
    публикует по расписанию (дата и время, TZ), удаляет. Видно, какой ПК на какой версии
    и что у него с обновлением.

Клиент (Bearer-токен ПК):
    в каждом запросе шлёт свою версию (X-Retix-Version) и что у него с обновлением
    (X-Retix-Update-State: none, downloading:1.0.6, ready:…, installing:…, failed:…, error:…);
    каждый ответ /api/… несёт подсказку
        X-Retix-Update       версия, до которой ПК должен обновиться, или «none»
        X-Retix-Update-Sha   первые 16 знаков SHA-256 установщика
    — изменилась подсказка, клиент сразу спрашивает подробности:
    GET /api/update                    что ставить: версия, что нового, подписанный манифест
    GET /api/update/file/{id}?d&e&s    сам установщик по билету (Range — докачка)

Что предлагается ПК: самая новая ОПУБЛИКОВАННАЯ версия для его компании, новее версии ПК.

Подпись. Манифест {app, kind, version, file, size, sha256} (JSON) подписан закрытым ключом
Ed25519 сервера (DATA_DIR/update_sign.key, создаётся сам). Открытый ключ зашит в клиент
(client_config.json → update_public_keys). Клиент берёт версию, размер и SHA-256 ТОЛЬКО из
подписанного манифеста и сверяет SHA-256 скачанного файла. Подменить установщик по дороге или
подложить свой файл на сервер без закрытого ключа нельзя — клиент его не запустит.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config import DATA_DIR, SECRET_KEY, TZ

MAX_UPLOAD = 300 * 1024 * 1024          # установщик Retix Hub — десятки МБ
CHUNK = 256 * 1024
MANIFEST_KIND = "retixhub-update"
APP = "Retix Hub"
TICKET_SECONDS = 3600                   # ссылка на файл действует час (докачка — в эти же час)
STATE_RE = re.compile(r"^(none|(downloading|ready|installing|failed|error):\d{1,5}(\.\d{1,5}){1,3})$")

# что ПК сообщает о себе (X-Retix-Update-State) -> текст для людей
STATE_TITLES = {
    "downloading": "скачивает {v}",
    "ready": "{v} скачана, ставится",
    "installing": "устанавливает {v}",
    "failed": "{v} не установилась",
    "error": "{v}: ошибка загрузки",
}


class UpdateError(ValueError):
    """Текст — для суперадмина."""


def updates_dir() -> str:
    path = os.path.join(DATA_DIR, "updates")
    os.makedirs(path, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Время (публикация по расписанию — по часам компаний, TZ)
# ---------------------------------------------------------------------------
def now_local() -> datetime:
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(TZ)).replace(tzinfo=None, microsecond=0)
    except Exception:  # noqa: BLE001 — нет базы часовых поясов: время сервера
        return datetime.now().replace(microsecond=0)


def ts(dt: datetime | None = None) -> str:
    return (dt or now_local()).strftime("%Y-%m-%d %H:%M:%S")


def parse_ts(text: str) -> datetime:
    s = str(text or "").strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d.%m.%Y %H:%M"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    raise ValueError(s)


def dt_text(s) -> str:
    """«2026-10-10 22:00:00» -> «10.10.2026 22:00»."""
    try:
        return parse_ts(s).strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return str(s or "")


# ---------------------------------------------------------------------------
# Версии
# ---------------------------------------------------------------------------
_VER_RE = re.compile(r"^\d{1,5}(\.\d{1,5}){1,3}$")


def vkey(version):
    """«1.0.6» -> (1, 0, 6, 0) — сравнение версий; не версия -> None."""
    v = str(version or "").strip()
    if not _VER_RE.match(v):
        return None
    parts = [int(p) for p in v.split(".")]
    return tuple(parts + [0] * (4 - len(parts)))


def clean_version(version) -> str:
    """«1.0.6.0» -> «1.0.6» (четвёртый ноль Windows добавляет сама)."""
    k = vkey(version)
    if k is None:
        return ""
    parts = list(k)
    while len(parts) > 3 and parts[-1] == 0:
        parts.pop()
    return ".".join(str(p) for p in parts)


def newer(a, b) -> bool:
    """a новее b (b пусто / не версия — любая версия новее)."""
    ka, kb = vkey(a), vkey(b)
    if ka is None:
        return False
    return kb is None or ka > kb


# ---------------------------------------------------------------------------
# Свойства exe: версия и название (без сторонних библиотек)
# ---------------------------------------------------------------------------
_FIXED_SIG = b"\xbd\x04\xef\xfe"        # VS_FIXEDFILEINFO.dwSignature


def _utf16_value(data: bytes, key: str) -> str:
    """Значение строки StringFileInfo (ProductName, FileVersion…) или ""."""
    needle = (key + "\0").encode("utf-16-le")
    i = data.find(needle)
    if i < 0:
        return ""
    j = i + len(needle)
    while j + 1 < len(data) and data[j:j + 2] == b"\0\0":   # выравнивание
        j += 2
    end = j
    while end + 1 < len(data) and data[end:end + 2] != b"\0\0":
        end += 2
    try:
        return data[j:end].decode("utf-16-le").strip()
    except UnicodeDecodeError:
        return ""


def exe_info(path: str, limit: int = 32 * 1024 * 1024) -> dict:
    """Установщик -> {"version": «1.0.6» или "", "product": «Retix Hub» или ""}.
    UpdateError — это вообще не программа Windows."""
    with open(path, "rb") as f:
        data = f.read(limit)
    if data[:2] != b"MZ":
        raise UpdateError("Это не программа Windows (.exe) — загрузите RetixHub_Setup_<версия>.exe")
    version = ""
    i = data.find(_FIXED_SIG)
    while i != -1 and not version:
        if i + 16 <= len(data) and int.from_bytes(data[i + 4:i + 8], "little") == 0x00010000:
            ms = int.from_bytes(data[i + 8:i + 12], "little")
            ls = int.from_bytes(data[i + 12:i + 16], "little")
            version = clean_version(f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}")
        i = data.find(_FIXED_SIG, i + 4)
    if not version:
        version = clean_version(_utf16_value(data, "FileVersion"))
    return {"version": version, "product": _utf16_value(data, "ProductName")}


# ---------------------------------------------------------------------------
# Подпись (Ed25519)
# ---------------------------------------------------------------------------
def key_file() -> str:
    return os.path.join(DATA_DIR, "update_sign.key")


def private_key() -> Ed25519PrivateKey:
    """Закрытый ключ подписи: UPDATE_SIGN_KEY (base64) или DATA_DIR/update_sign.key.
    Нет файла — создаётся (права 600). Потеря ключа = клиенты не примут новые обновления,
    пока не поставят клиент с новым открытым ключом вручную: ключ — в бэкап вместе с базой."""
    value = os.getenv("UPDATE_SIGN_KEY", "").strip()
    if not value:
        path = key_file()
        if not os.path.exists(path):
            raw = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(base64.b64encode(raw).decode())
        with open(path) as f:
            value = f.read().strip()
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(value))


def public_key_b64() -> str:
    """Открытый ключ — его вписывают в client/client_config.json (update_public_keys)."""
    pub = private_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode()


def sign_manifest(version: str, file_name: str, size: int, sha256: str) -> tuple[str, str]:
    """-> (манифест base64, подпись base64)."""
    body = json.dumps({"app": APP, "kind": MANIFEST_KIND, "version": version, "file": file_name,
                       "size": int(size), "sha256": sha256},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = private_key().sign(body)
    return base64.b64encode(body).decode("ascii"), base64.b64encode(sig).decode("ascii")


# ---------------------------------------------------------------------------
# Журнал
# ---------------------------------------------------------------------------
def log(conn, action: str, details: str = "") -> None:
    conn.execute("INSERT INTO audit_log(company_id, action, details) VALUES (NULL,?,?)", (action, details[:500]))


# ---------------------------------------------------------------------------
# Публикация по расписанию
# ---------------------------------------------------------------------------
def parse_publish_at(text) -> str:
    """«2026-10-10T22:00» (поле datetime-local) -> «2026-10-10 22:00:00»; пусто -> "".
    UpdateError — не время или время уже прошло."""
    s = str(text or "").strip()
    if not s:
        return ""
    try:
        dt = parse_ts(s)
    except ValueError:
        raise UpdateError(f"«{s}» — не дата и время (пример: 10.10.2026 22:00)")
    if dt <= now_local():
        raise UpdateError(f"Время {dt:%d.%m.%Y %H:%M} уже прошло — укажите будущее или опубликуйте сразу")
    return ts(dt)


def activate_due(conn) -> None:
    """Опубликовать версии, время публикации которых наступило. Пишет в базу,
    только когда такие есть (зовётся при обращении ПК, сайта, суперадмина)."""
    due = conn.execute("SELECT id, version, publish_at FROM app_releases WHERE published=0 "
                       "AND publish_at IS NOT NULL AND publish_at<=?", (ts(),)).fetchall()
    for rel in due:
        n = conn.execute("UPDATE app_releases SET published=1, published_at=?, publish_at=NULL "
                         "WHERE id=? AND published=0 AND publish_at=?",
                         (rel["publish_at"], rel["id"], rel["publish_at"])).rowcount
        if n:                       # другой запрос мог опубликовать раньше
            log(conn, "update_publish", f"{rel['version']} по расписанию на {rel['publish_at']}")
        conn.commit()


# ---------------------------------------------------------------------------
# Что предлагать ПК
# ---------------------------------------------------------------------------
def companies_of(rel) -> set[int]:
    try:
        ids = json.loads(rel["companies"] or "[]")
    except (TypeError, ValueError):
        ids = []
    return {int(x) for x in ids if str(x).isdigit()}


def in_scope(rel, company_id) -> bool:
    ids = companies_of(rel)
    return not ids or int(company_id) in ids


def pick(conn, company_id: int, version: str):
    """Выпуск, до которого обновить ПК этой компании с версии version, или None."""
    activate_due(conn)
    rows = conn.execute("SELECT * FROM app_releases WHERE published=1").fetchall()
    cands = [r for r in rows if in_scope(r, company_id) and newer(r["version"], version)]
    return max(cands, key=lambda r: vkey(r["version"])) if cands else None


def _ticket_sig(rid: int, device_id: int, exp: int) -> str:
    return hmac.new(SECRET_KEY.encode(), f"update:{rid}:{device_id}:{exp}".encode(), hashlib.sha256).hexdigest()


def ticket_url(rid: int, device_id: int) -> str:
    """Ссылка на установщик без токена ПК: токен меняется (ротация), а скачивание идёт
    в отдельном потоке — старый токен в нём сервер счёл бы копией входа."""
    exp = int(time.time()) + TICKET_SECONDS
    return f"/api/update/file/{rid}?d={device_id}&e={exp}&s={_ticket_sig(rid, device_id, exp)}"


def ticket_ok(rid: int, device_id: int, exp: int, sig: str) -> bool:
    return exp >= time.time() and hmac.compare_digest(_ticket_sig(rid, device_id, exp), str(sig or ""))


def payload(rel, device_id: int) -> dict:
    return {"id": rel["id"], "version": rel["version"], "notes": rel["notes"] or "", "size": rel["size"],
            "sha256": rel["sha256"], "file_name": rel["file_name"], "published_at": rel["published_at"],
            "manifest": rel["manifest"], "signature": rel["signature"], "url": ticket_url(rel["id"], device_id)}


def note_device(conn, dev, request, response) -> None:
    """Каждый запрос ПК: запомнить версию и состояние обновления, ответить подсказкой.
    Сбой здесь не должен ломать работу сети."""
    try:
        version = request.headers.get("x-retix-version", "").strip()[:32]
        state = request.headers.get("x-retix-update-state", "").strip()[:40]
        if version and vkey(version) and version != dev["client_version"]:
            conn.execute("UPDATE devices SET client_version=? WHERE id=?", (version, dev["id"]))
            conn.commit()
        if state and STATE_RE.match(state) and state != (dev["update_state"] or ""):
            conn.execute("UPDATE devices SET update_state=?, update_state_at=? WHERE id=?", (state, ts(), dev["id"]))
            conn.commit()
        rel = pick(conn, dev["company_id"], version or dev["client_version"])
        if rel is None:
            response.headers["X-Retix-Update"] = "none"
        else:
            response.headers["X-Retix-Update"] = rel["version"]
            response.headers["X-Retix-Update-Sha"] = rel["sha256"][:16]
    except sqlite3.Error:
        pass


def state_text(state, client_version: str = "") -> str:
    """«ready:1.0.6» -> «1.0.6 скачана, ставится»; ПК уже на этой версии или пусто -> ""."""
    kind, _, ver = str(state or "").partition(":")
    if not ver or kind not in STATE_TITLES or (client_version and not newer(ver, client_version)):
        return ""
    return STATE_TITLES[kind].format(v=ver)


# ---------------------------------------------------------------------------
# Сайт: «Скачать» на главной
# ---------------------------------------------------------------------------
def site_release(conn):
    """Самая новая ОПУБЛИКОВАННАЯ версия для ВСЕХ компаний (пилот и черновики — нет), файл
    которой есть на сервере. None — нечего (тогда сайт отдаёт downloads/, как раньше)."""
    activate_due(conn)
    rows = conn.execute("SELECT * FROM app_releases WHERE published=1 AND companies=''").fetchall()
    for rel in sorted((r for r in rows if vkey(r["version"])), key=lambda r: vkey(r["version"]), reverse=True):
        if os.path.isfile(os.path.join(updates_dir(), rel["stored_name"])):
            return rel
    return None


# ---------------------------------------------------------------------------
# Загрузка установщика (суперадмин)
# ---------------------------------------------------------------------------
def scope_json(scope: str, companies) -> str:
    if scope != "some":
        return ""
    ids = sorted({int(c) for c in companies or [] if str(c).isdigit()})
    if not ids:
        raise UpdateError("Выберите хотя бы одну компанию или «Всем компаниям»")
    return json.dumps(ids)


def save_upload(src, file_name: str, conn, version: str = "", notes: str = "", scope: str = "all",
                companies=(), publish: bool = False, publish_at: str = "", admin: str = "") -> tuple[int, str]:
    """Файл установщика (открытый на чтение) -> новая запись app_releases. UpdateError — текст для страницы."""
    scope_ids = scope_json(scope, companies)
    publish_at = parse_publish_at(publish_at)
    if publish and publish_at:
        raise UpdateError("Либо «Опубликовать сразу», либо дата и время публикации — не оба сразу")
    folder = updates_dir()
    tmp = os.path.join(folder, f"upload_{uuid.uuid4().hex}.part")
    h, size = hashlib.sha256(), 0
    try:
        with open(tmp, "wb") as out:
            while True:
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise UpdateError(f"Файл больше {MAX_UPLOAD // (1024 * 1024)} МБ")
                h.update(chunk)
                out.write(chunk)
        if size == 0:
            raise UpdateError("Файл пустой — выберите установщик")
        info = exe_info(tmp)
        if info["product"] and info["product"].lower() != APP.lower():
            raise UpdateError(f"Это не установщик Retix Hub (в свойствах exe: «{info['product']}»)")
        typed = clean_version(version)
        if version.strip() and not typed:
            raise UpdateError(f"«{version}» — не версия (пример: 1.0.6)")
        if info["version"] and typed and vkey(typed) != vkey(info["version"]):
            raise UpdateError(f"В свойствах exe версия {info['version']}, а указано {typed} — не тот файл?")
        ver = info["version"] or typed
        if not ver:
            raise UpdateError("Версию из exe прочитать не удалось — укажите её в поле «Версия»")
        if conn.execute("SELECT 1 FROM app_releases WHERE version=?", (ver,)).fetchone():
            raise UpdateError(f"Версия {ver} уже загружена. Чтобы заменить файл — сначала удалите её")
        sha = h.hexdigest()
        name = f"RetixHub_Setup_{ver}.exe"
        manifest, signature = sign_manifest(ver, name, size, sha)
        stored = f"RetixHub_Setup_{ver}_{sha[:8]}.exe"
        os.replace(tmp, os.path.join(folder, stored))
        now = ts()
        rid = conn.execute(
            "INSERT INTO app_releases(version, file_name, stored_name, size, sha256, manifest, signature, notes, "
            "companies, published, published_at, publish_at, created_at, created_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ver, name, stored, size, sha, manifest, signature, str(notes or "").strip()[:2000], scope_ids,
             1 if publish else 0, now if publish else None, publish_at or None, now, admin)).lastrowid
        log(conn, "update_upload", f"{ver}: {size} байт, SHA-256 {sha[:16]}…"
            + (", опубликовано" if publish else f", опубликуется {publish_at}" if publish_at else ", черновик"))
        conn.commit()
        return rid, ver
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def devices_overview(conn) -> list[dict]:
    """ПК с версией и тем, до чего каждый должен обновиться."""
    activate_due(conn)
    rows = conn.execute(
        "SELECT d.id, d.company_id, d.name, d.ip, d.client_version, d.update_state, d.update_state_at, "
        "d.last_handshake, d.last_rx_at, d.last_seen, c.login AS company_login, c.name AS company_name "
        "FROM devices d JOIN companies c ON c.id=d.company_id "
        "WHERE c.is_active=1 AND d.is_blocked=0 ORDER BY c.login, d.name").fetchall()
    releases = conn.execute("SELECT * FROM app_releases WHERE published=1").fetchall()
    out = []
    for d in rows:
        cands = [r for r in releases if in_scope(r, d["company_id"]) and newer(r["version"], d["client_version"])]
        item = dict(d)
        item["target"] = max(cands, key=lambda r: vkey(r["version"]))["version"] if cands else ""
        item["state_text"] = state_text(d["update_state"], d["client_version"])
        out.append(item)
    return out
