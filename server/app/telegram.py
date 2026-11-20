"""Telegram-бот: группа компании получает запросы на подключение новых ПК и одобряет их кнопками.

Как подключить группу: в кабинете компании «Подключить группу Telegram» — сервер выдаёт одноразовый код
(действует LINK_TTL). Ссылка t.me/<бот>?startgroup=<код> добавляет бота в выбранную группу, и Telegram сам
отправляет туда «/start <код>»; без ссылки — команда «/link@<бот> <код>» в группе. Бот запоминает группу
у компании. Дальше каждый новый ПК, который ждёт одобрения (и ПК, чей вход скопирован на другой компьютер),
приходит в группу сообщением с кнопками «Одобрить» и «Заблокировать». Нажать может любой участник группы:
кого добавить в группу, решает администратор компании. Кто нажал — в журнале компании.

Бот сам спрашивает Telegram о новых сообщениях (getUpdates, long polling): входящих адресов и вебхуков не нужно.
Отправка — через очередь в своём потоке: запросы ПК не ждут Telegram.

Токен бота задаёт суперадмин («Настройки»): хранится в базе зашифрованным (services.seal), бот перезапускается
сразу, без перезапуска сервера. TELEGRAM_BOT_TOKEN в .env — только если в суперадмине токен не задан.
"""
import html
import json
import logging
import queue
import re
import secrets
import threading
import time
import urllib.error
import urllib.request

from . import db, services
from .config import TELEGRAM_API, TELEGRAM_BOT_TOKEN

log = logging.getLogger("telegram")

TOKEN = ""              # действующий токен (apply): из суперадмина или из .env
TOKEN_KEY = "telegram_token"
TOKEN_RE = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{30,64}$")
LINK_TTL = 900          # сек — код из кабинета действует 15 минут
POLL_TIMEOUT = 25       # сек — long polling getUpdates
ALLOWED_UPDATES = ["message", "callback_query", "my_chat_member"]
CALLBACK_RE = re.compile(r"^(ap|bl):(\d{1,10})(?::(\d{1,10}))?$")   # ap:ПК[:роль]
CODE_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

bot_username = ""       # из getMe: для ссылки и команд в кабинете
last_error = ""         # что мешает боту работать (видно суперадмину в «Настройках»)
_stop: threading.Event | None = None
_apply_lock = threading.Lock()
_outbox: "queue.Queue[tuple[str, dict]]" = queue.Queue(maxsize=1000)


class TelegramError(Exception):
    def __init__(self, code: int, description: str, params: dict | None = None):
        super().__init__(f"{code} {description}")
        self.code, self.description, self.params = code, description, params or {}


def enabled() -> bool:
    return bool(TOKEN)


def _api(method: str, params: dict | None = None, timeout: float = 15, token: str | None = None):
    """Вызов Bot API; result ответа или TelegramError. Токен — только в адресе запроса, в журнал не попадает."""
    req = urllib.request.Request(f"{TELEGRAM_API}/bot{token or TOKEN}/{method}", data=json.dumps(params or {}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — адрес из настроек сервера
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read())
        except (ValueError, OSError):
            raise TelegramError(e.code, f"HTTP {e.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise TelegramError(0, type(e).__name__ + ": " + str(getattr(e, "reason", e))) from None
    if not isinstance(data, dict) or not data.get("ok"):
        data = data if isinstance(data, dict) else {}
        raise TelegramError(int(data.get("error_code") or 0), str(data.get("description") or "нет ответа"),
                            data.get("parameters") if isinstance(data.get("parameters"), dict) else {})
    return data.get("result")


# ---------- отправка ----------

def _queue(method: str, params: dict) -> None:
    if not enabled():
        return
    try:
        _outbox.put_nowait((method, params))
    except queue.Full:
        log.warning("Telegram: очередь отправки переполнена, сообщение пропущено")


def send(chat_id, text: str, buttons: list | None = None) -> None:
    if not chat_id:
        return
    params = {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if buttons:
        params["reply_markup"] = {"inline_keyboard": buttons}
    _queue("sendMessage", params)


def _migrate(conn, old, new) -> None:
    """Группа стала супергруппой — у неё новый id."""
    if not old or not new:
        return
    with db.write_lock:
        conn.execute("UPDATE companies SET tg_chat_id=? WHERE tg_chat_id=?", (str(new), str(old)))
        conn.commit()


def deliver(method: str, params: dict, tries: int = 3):
    """Отправить сейчас (поток отправки). Ошибки — в журнал сервера, исключений нет."""
    for attempt in range(tries):
        try:
            return _api(method, params)
        except TelegramError as e:
            if e.code == 429:                      # слишком часто — Telegram говорит, сколько ждать
                time.sleep(min(int(e.params.get("retry_after") or 5), 60))
                continue
            new = e.params.get("migrate_to_chat_id")
            if new and params.get("chat_id"):
                conn = db.connect()
                try:
                    _migrate(conn, params["chat_id"], new)
                finally:
                    conn.close()
                params = dict(params, chat_id=new)
                continue
            if e.code == 403 or "chat not found" in e.description.lower():
                log.warning("Telegram %s: бот не может писать в группу (%s)", method, e.description)
                return None
            if e.code == 0 and attempt < tries - 1:   # нет связи с Telegram — ещё раз чуть позже
                time.sleep(5)
                continue
            if e.code == 400 and "message is not modified" in e.description:
                return None
            log.warning("Telegram %s: %s", method, e.description)
            return None
    return None


def drain() -> int:
    """Отправить всё из очереди сейчас (тесты и остановка сервера)."""
    n = 0
    while True:
        try:
            method, params = _outbox.get_nowait()
        except queue.Empty:
            return n
        deliver(method, params)
        n += 1


def _sender(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            method, params = _outbox.get(timeout=1)
        except queue.Empty:
            continue
        try:
            deliver(method, params)
        except Exception:  # noqa: BLE001
            log.exception("Telegram: ошибка отправки")


# ---------- тексты ----------

def _esc(value) -> str:
    return html.escape(str(value or ""), quote=False)


def _who(user: dict) -> str:
    name = " ".join(x for x in (user.get("first_name"), user.get("last_name")) if x) or "без имени"
    if user.get("username"):
        name += f" (@{user['username']})"
    return name[:100]


ROLE_BUTTONS_MAX = 12   # больше ролей — одобрить с ролью можно в кабинете


def request_buttons(device_id: int, roles: list | None = None) -> list:
    """Кнопки под запросом. Есть роли в компании — «Одобрить» для каждой роли (по две в ряд) и без роли."""
    roles = (roles or [])[:ROLE_BUTTONS_MAX]
    if not roles:
        return [[{"text": "✅ Одобрить", "callback_data": f"ap:{device_id}"},
                 {"text": "⛔ Заблокировать", "callback_data": f"bl:{device_id}"}]]
    keys = [{"text": f"✅ {r['name']}", "callback_data": f"ap:{device_id}:{r['id']}"} for r in roles]
    rows = [keys[i:i + 2] for i in range(0, len(keys), 2)]
    rows.append([{"text": "✅ Без роли", "callback_data": f"ap:{device_id}:0"},
                 {"text": "⛔ Заблокировать", "callback_data": f"bl:{device_id}"}])
    return rows


def request_text(company, dev, reason: str = "new", from_ip: str = "") -> str:
    title = {"new": "🖥 <b>Новый компьютер ждёт одобрения</b>",
             "token_reuse": "⚠️ <b>Вход скопирован на другой компьютер</b>",
             "pending": "🕓 <b>Ждёт одобрения</b>"}.get(reason, "🖥 <b>Компьютер ждёт одобрения</b>")
    lines = [title, f"Компания: {_esc(company['name'] or company['login'])}", f"Имя: {_esc(dev['name'])}"]
    if dev["hostname"]:
        lines.append(f"Компьютер: {_esc(dev['hostname'])}")
    lines.append(f"Адрес в сети: {_esc(dev['ip'])}")
    if from_ip:
        lines.append(f"Внешний IP: {_esc(from_ip)}")
    if dev["client_version"]:
        lines.append(f"Retix Hub: {_esc(dev['client_version'])}")
    if reason == "token_reuse":
        lines.append("\nЭтим входом пользуются два компьютера, поэтому ПК отключён от сети. Одобрите, только если "
                     "уверены, что это тот же компьютер (например, после переустановки Windows).")
    return "\n".join(lines)


def notify_pending(conn, device_id: int, reason: str = "new", from_ip: str = "") -> None:
    """ПК ждёт одобрения — сообщение с кнопками в группу компании (если она подключена)."""
    if not enabled():
        return
    dev = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    company = conn.execute("SELECT * FROM companies WHERE id=?", (dev["company_id"],)).fetchone() if dev else None
    if not company or not company["tg_chat_id"] or services.device_status(dev) != "pending":
        return
    send(company["tg_chat_id"], request_text(company, dev, reason, from_ip),
         request_buttons(dev["id"], services.list_roles(conn, company["id"])))


# ---------- привязка группы (кабинет) ----------

def new_link_code(conn, company) -> str:
    code = secrets.token_urlsafe(12)
    with db.write_lock:
        conn.execute("UPDATE companies SET tg_link_code=?, tg_link_at=? WHERE id=?",
                     (code, int(time.time()), company["id"]))
        conn.commit()
    return code


def link_code(company) -> str:
    """Действующий код компании или ''."""
    if company["tg_link_code"] and time.time() - company["tg_link_at"] < LINK_TTL:
        return company["tg_link_code"]
    return ""


def link_url(code: str) -> str:
    return f"https://t.me/{bot_username}?startgroup={code}" if bot_username and code else ""


def unlink(conn, company, actor: str) -> None:
    chat = company["tg_chat_id"]
    with db.write_lock:
        conn.execute("UPDATE companies SET tg_chat_id='', tg_chat_title='', tg_link_code='', tg_link_at=0 "
                     "WHERE id=?", (company["id"],))
        services.audit(conn, company["id"], "telegram_unlink", f"{company['tg_chat_title']} ({actor})")
        conn.commit()
    if chat:
        send(chat, f"Группа отключена от компании {_esc(company['name'] or company['login'])}: "
                   "запросы на подключение сюда больше не приходят.")


# ---------- входящие ----------

def _reply(chat_id, text: str) -> None:
    send(chat_id, text)


def _help_text() -> str:
    bot = f"@{bot_username}" if bot_username else ""
    return ("Это бот Retix Hub. Он присылает в группу компании запросы на подключение новых компьютеров: "
            "одобрить или заблокировать — кнопками под сообщением.\n\n"
            f"Подключить группу: кабинет компании → «Telegram» → «Подключить группу», затем ссылка или команда "
            f"<code>/link{bot} КОД</code> в группе.\n<code>/pending{bot}</code> — кто ждёт одобрения сейчас.\n"
            f"<code>/pass{bot} ИМЯ ПК</code> — ID и пароль RustDesk этого ПК для подключения через облако RustDesk "
            "(если оно включено в кабинете и ПК управляется без согласия).")


def _on_link(conn, chat: dict, user: dict, code: str) -> None:
    chat_id = chat.get("id")
    if not code:
        _reply(chat_id, _help_text())
        return
    if chat.get("type") not in ("group", "supergroup"):
        _reply(chat_id, "Добавьте бота в группу компании и отправьте команду с кодом там, а не в личном чате.")
        return
    company = conn.execute("SELECT * FROM companies WHERE tg_link_code=? AND tg_link_at>?",
                           (code, int(time.time()) - LINK_TTL)).fetchone() if CODE_RE.match(code) else None
    if not company:
        _reply(chat_id, "Код не найден или устарел. Получите новый в кабинете компании: «Telegram» → "
                        "«Подключить группу».")
        return
    title = str(chat.get("title") or "")[:100]
    with db.write_lock:
        conn.execute("UPDATE companies SET tg_chat_id=?, tg_chat_title=?, tg_link_code='', tg_link_at=0 WHERE id=?",
                     (str(chat_id), title, company["id"]))
        services.audit(conn, company["id"], "telegram_link", f"{title} ({_who(user)})")
        conn.commit()
    bot = f"@{bot_username}" if bot_username else ""
    _reply(chat_id, f"✅ Группа подключена к компании <b>{_esc(company['name'] or company['login'])}</b>.\n"
                    "Сюда будут приходить запросы на подключение новых компьютеров — одобрить или заблокировать "
                    f"можно кнопками под сообщением.\n<code>/pending{bot}</code> — кто ждёт одобрения сейчас.")
    _on_pending(conn, chat, quiet=True)


def _on_pending(conn, chat: dict, quiet: bool = False) -> None:
    chat_id = chat.get("id")
    companies = conn.execute("SELECT * FROM companies WHERE tg_chat_id=? AND tg_chat_id<>''",
                             (str(chat_id),)).fetchall()
    if not companies:
        if not quiet:
            _reply(chat_id, "Эта группа не подключена ни к одной компании.\n\n" + _help_text())
        return
    sent = 0
    for c in companies:
        for d in conn.execute("SELECT * FROM devices WHERE company_id=? AND is_approved=0 AND is_blocked=0 "
                              "ORDER BY id LIMIT 20", (c["id"],)).fetchall():
            send(chat_id, request_text(c, d, "pending"), request_buttons(d["id"], services.list_roles(conn, c["id"])))
            sent += 1
    if not sent and not quiet:
        _reply(chat_id, "Никто не ждёт одобрения.")


def _on_pass(conn, chat: dict, user: dict, arg: str) -> None:
    """/pass ИМЯ — ID и пароль RustDesk ПК компании этой группы (как кнопка «пароль для подключения» в кабинете)."""
    chat_id = chat.get("id")
    companies = conn.execute("SELECT * FROM companies WHERE tg_chat_id=? AND tg_chat_id<>'' AND is_active=1",
                             (str(chat_id),)).fetchall()
    if not companies:
        _reply(chat_id, "Эта группа не подключена ни к одной компании.\n\n" + _help_text())
        return
    want = " ".join(arg.split()).casefold()
    if not want:
        bot = f"@{bot_username}" if bot_username else ""
        _reply(chat_id, f"Укажите компьютер: <code>/pass{bot} Касса 2</code> (имя или IP из кабинета).")
        return
    found = [(c, d) for c in companies
             for d in conn.execute("SELECT * FROM devices WHERE company_id=? ORDER BY id", (c["id"],)).fetchall()
             if want in (" ".join(str(d["name"]).split()).casefold(), str(d["ip"]))]
    if len(found) != 1:
        _reply(chat_id, f"Компьютер «{_esc(arg.strip())}» не найден." if not found else
               f"Компьютеров «{_esc(arg.strip())}» несколько — укажите IP-адрес из кабинета.")
        return
    company, dev = found[0]
    try:
        r = services.give_remote_password(conn, company, dev, f"Telegram: {_who(user)}")
    except ValueError as e:
        _reply(chat_id, "⛔ " + _esc(str(e)))
        return
    _reply(chat_id, f"🔑 <b>{_esc(r['name'])}</b> — RustDesk\nID: <code>{_esc(r['rustdesk_id'])}</code>\n"
                    f"Пароль: <code>{_esc(r['password'])}</code>\n\nПодключитесь в ближайшие 2 минуты: после сеанса "
                    f"компьютер сам сменит пароль. Запросил: {_esc(_who(user))}")


def notify_remote_password(company, r: dict, where: str) -> None:
    """В группу компании: пароль RustDesk выдан (не сам пароль — только кому и где)."""
    if enabled() and company["tg_chat_id"]:
        send(company["tg_chat_id"], f"🔑 Пароль RustDesk для <b>{_esc(r['name'])}</b> ({_esc(r['ip'])}) выдан "
                                    f"{_esc(where)}. После сеанса компьютер сменит его сам.")


def _on_callback(conn, cq: dict) -> None:
    msg = cq.get("message") or {}
    chat_id = str((msg.get("chat") or {}).get("id") or "")
    user = cq.get("from") or {}

    def answer(text: str, alert: bool = False):
        _queue("answerCallbackQuery", {"callback_query_id": cq.get("id"), "text": text[:200], "show_alert": alert})

    def close(result: str):   # кнопки убираем, в сообщении — чем закончилось
        if msg.get("message_id"):
            _queue("editMessageText", {"chat_id": msg["chat"]["id"], "message_id": msg["message_id"],
                                       "text": _esc(msg.get("text") or "") + "\n\n" + result,
                                       "parse_mode": "HTML", "disable_web_page_preview": True})

    m = CALLBACK_RE.match(str(cq.get("data") or ""))
    if not m:
        answer("Неизвестная кнопка")
        return
    dev = conn.execute("SELECT d.*, c.tg_chat_id, c.is_active AS company_active FROM devices d "
                       "JOIN companies c ON c.id=d.company_id WHERE d.id=?", (int(m.group(2)),)).fetchone()
    if not dev or not chat_id or dev["tg_chat_id"] != chat_id:
        answer("Компьютер не найден: его удалили или группа отключена от компании", alert=True)
        close("— компьютер удалён")
        return
    if not dev["company_active"]:
        answer("Компания отключена", alert=True)
        return
    status = services.device_status(dev)
    if status != "pending":
        done = "одобрен" if status == "active" else "заблокирован"
        answer(f"Уже решено: {done}")
        close(f"— уже {done}")
        return
    action = "approve" if m.group(1) == "ap" else "block"
    role = m.group(3) if action == "approve" else None   # None — кнопка без роли из старых сообщений
    who = _who(user)
    try:
        msg_text = services.device_action(conn, dev["company_id"], dev["id"], action, role or "",
                                          actor=f"Telegram: {who}")
    except (LookupError, ValueError) as e:   # роль успели удалить в кабинете — сообщение с кнопками остаётся
        answer(f"{e}. Выберите другую роль или одобрите в кабинете" if role else str(e), alert=True)
        return
    named = msg_text.partition(", роль ")[2]   # «…одобрено, роль «Склад»»
    answer(("Одобрено" + (f", роль {named}" if named else "")) if action == "approve" else "Заблокировано")
    close(("✅ Одобрил: " if action == "approve" else "⛔ Заблокировал: ") + _esc(who)
          + (f" · роль {_esc(named)}" if named else ""))


def _on_member(conn, upd: dict) -> None:
    """Бота удалили из группы — группа больше не подключена."""
    status = ((upd.get("new_chat_member") or {}).get("status")) or ""
    chat_id = str((upd.get("chat") or {}).get("id") or "")
    if status in ("left", "kicked") and chat_id:
        with db.write_lock:
            rows = conn.execute("SELECT id, tg_chat_title FROM companies WHERE tg_chat_id=?", (chat_id,)).fetchall()
            for r in rows:
                services.audit(conn, r["id"], "telegram_unlink",
                               f"{r['tg_chat_title']} (бота удалили из группы: {_who(upd.get('from') or {})})")
            conn.execute("UPDATE companies SET tg_chat_id='', tg_chat_title='' WHERE tg_chat_id=?", (chat_id,))
            conn.commit()


def handle_update(conn, upd: dict) -> None:
    if "callback_query" in upd:
        _on_callback(conn, upd["callback_query"])
        return
    if "my_chat_member" in upd:
        _on_member(conn, upd["my_chat_member"])
        return
    msg = upd.get("message")
    if not isinstance(msg, dict):
        return
    chat = msg.get("chat") or {}
    if msg.get("migrate_to_chat_id"):
        _migrate(conn, chat.get("id"), msg["migrate_to_chat_id"])
        return
    if chat.get("title") and chat.get("id"):   # группу переименовали — название в кабинете тоже новое
        conn.execute("UPDATE companies SET tg_chat_title=? WHERE tg_chat_id=? AND tg_chat_title<>?",
                     (str(chat["title"])[:100], str(chat["id"]), str(chat["title"])[:100]))
        conn.commit()
    text = str(msg.get("text") or "").strip()
    if not text.startswith("/"):
        return
    head, _, arg = text.partition(" ")
    cmd, _, target = head[1:].partition("@")
    if target and bot_username and target.lower() != bot_username.lower():
        return   # команда другому боту
    cmd = cmd.lower()
    if cmd in ("start", "link"):
        _on_link(conn, chat, msg.get("from") or {}, arg.strip())
    elif cmd == "pending":
        _on_pending(conn, chat)
    elif cmd in ("pass", "rustdesk"):
        _on_pass(conn, chat, msg.get("from") or {}, arg)
    elif cmd == "help":
        _reply(chat.get("id"), _help_text())


def _set_error(token: str, text: str) -> None:
    global last_error
    if token == TOKEN:   # ошибка прежнего бота (токен уже сменили) — не показываем
        last_error = text


def _poller(stop: threading.Event, token: str) -> None:
    global bot_username
    offset, backoff = 0, 5
    while not stop.is_set():
        try:
            if not bot_username:
                name = str((_api("getMe", token=token) or {}).get("username") or "")
                if token == TOKEN:
                    bot_username = name
                log.warning("Telegram-бот @%s запущен", name)
            updates = _api("getUpdates", {"offset": offset, "timeout": POLL_TIMEOUT,
                                          "allowed_updates": ALLOWED_UPDATES}, timeout=POLL_TIMEOUT + 10, token=token)
            backoff = 5
            _set_error(token, "")
        except TelegramError as e:
            if stop.is_set():
                return
            if e.code in (401, 404):
                log.error("Telegram: токен бота не подходит (%s) — бот выключен", e.description)
                _set_error(token, f"Telegram не принимает токен ({e.description}). Задайте новый.")
                return
            if e.code == 409:
                log.warning("Telegram: этим ботом уже пользуется другая программа или у него вебхук (%s)",
                            e.description)
                _set_error(token, "Этим ботом пользуется другая программа или у него настроен вебхук.")
            elif e.code:
                log.warning("Telegram getUpdates: %s", e.description)
                _set_error(token, f"Telegram: {e.description}")
            else:
                _set_error(token, f"Нет связи с api.telegram.org ({e.description})")
            stop.wait(backoff)
            backoff = min(backoff * 2, 300)
            continue
        for upd in updates or []:
            if not isinstance(upd, dict):
                continue
            offset = max(offset, int(upd.get("update_id") or 0) + 1)
            conn = db.connect()
            try:
                handle_update(conn, upd)
            except Exception:  # noqa: BLE001
                log.exception("Telegram: ошибка обработки")
            finally:
                conn.close()


# ---------- токен бота (суперадмин → «Настройки») ----------

def saved_token(conn) -> tuple[str, str]:
    """(токен, откуда: 'admin' — задан в суперадмине, 'env' — из .env, '' — нет)."""
    row = conn.execute("SELECT value FROM settings WHERE key=?", (TOKEN_KEY,)).fetchone()
    token = services.unseal(row["value"]) if row else ""
    if token:
        return token, "admin"
    return (TELEGRAM_BOT_TOKEN, "env") if TELEGRAM_BOT_TOKEN else ("", "")


def check_token(token: str) -> str:
    """Спросить Telegram, чей это токен: username бота. TelegramError — не подходит или нет связи."""
    me = _api("getMe", token=token, timeout=15) or {}
    if not me.get("is_bot") or not me.get("username"):
        raise TelegramError(0, "это не токен бота")
    return str(me["username"])


def bot_id(token: str) -> str:
    return token.split(":", 1)[0] if token else ""


def apply(token: str, username: str = "") -> None:
    """Запустить бота с этим токеном (прежний останавливается); '' — бота нет."""
    global TOKEN, bot_username, last_error, _stop
    with _apply_lock:
        if _stop:
            _stop.set()
            _stop = None
        TOKEN, bot_username, last_error = token, username, ""
        if token:
            _stop = threading.Event()
            threading.Thread(target=_poller, args=(_stop, token), daemon=True, name="tg-poll").start()
            threading.Thread(target=_sender, args=(_stop,), daemon=True, name="tg-send").start()


def set_token(conn, token: str) -> tuple[str, int]:
    """Суперадмин задал токен: проверить у Telegram, сохранить, перезапустить бота. (username, сколько групп
    отключено). Другой бот (другой номер до «:») не состоит в группах компаний — их нужно подключить заново."""
    token = token.strip()
    if not TOKEN_RE.match(token):
        raise ValueError("Это не похоже на токен бота: он выглядит как 123456789:AAH… (выдаёт @BotFather)")
    try:
        username = check_token(token)
    except TelegramError as e:
        if e.code == 0 and e.description != "это не токен бота":
            raise ValueError(f"Нет связи с api.telegram.org — токен не проверен, бот не изменён ({e.description})") \
                from None
        raise ValueError(f"Telegram не принял токен: {e.description}") from None
    old, _ = saved_token(conn)
    unlinked = 0
    with db.write_lock:
        conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)", (TOKEN_KEY, services.seal(token)))
        if bot_id(old) and bot_id(old) != bot_id(token):
            unlinked = conn.execute("UPDATE companies SET tg_chat_id='', tg_chat_title='', tg_link_code='', "
                                    "tg_link_at=0 WHERE tg_chat_id<>''").rowcount
        services.audit(conn, None, "telegram_token", f"@{username}" + (f", групп отключено: {unlinked}" if unlinked else ""))
        conn.commit()
    apply(token, username)
    return username, unlinked


def delete_token(conn) -> str:
    """Убрать токен из суперадмина. Остаётся токен из .env, если он есть; иначе бот выключается."""
    with db.write_lock:
        conn.execute("DELETE FROM settings WHERE key=?", (TOKEN_KEY,))
        services.audit(conn, None, "telegram_token", "удалён")
        conn.commit()
    token, _ = saved_token(conn)
    apply(token)
    return token


def start() -> None:
    conn = db.connect()
    try:
        token, _ = saved_token(conn)
    finally:
        conn.close()
    apply(token)


def stop() -> None:
    apply("")
