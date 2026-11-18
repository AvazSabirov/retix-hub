"""Опубликовать новую версию клиента прямо на сервере — без скачивания и загрузки через суперадмина.

    ./publish.sh                 последний GitHub Release: скачать установщик и опубликовать всем компаниям
    ./publish.sh 1.0.19          эту версию
    ./publish.sh --draft         загрузить черновиком (опубликовать потом в суперадмин → «Обновления»)
    ./publish.sh --file /data/RetixHub_Setup_1.0.19.exe   файл, который уже лежит на сервере

publish.sh запускает внутри контейнера: python -m app.publish …
Установщик проверяется так же, как при загрузке через суперадмина (название программы и версия из свойств exe),
и подписывается ключом обновлений сервера. Что нового — из описания GitHub Release (раздел CHANGELOG).
Закрытый репозиторий — GITHUB_TOKEN в .env (токен с правом чтения Contents этого репозитория).
"""
import argparse
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request

from . import db, updates

REPO = os.getenv("GITHUB_REPO", "AvazSabirov/retix-hub")
ASSET_RE = re.compile(r"^RetixHub_Setup_(\d+(?:\.\d+){1,3})\.exe$")
CHUNK = 256 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):   # переход сделаем сами — без токена (хранилище GitHub его не ждёт)
        return None


def _open(url: str, accept: str, token: str = ""):
    headers = {"Accept": accept, "User-Agent": "retixhub-publish", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        return opener.open(urllib.request.Request(url, headers=headers), timeout=60)
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
            return urllib.request.urlopen(urllib.request.Request(
                e.headers["Location"], headers={"User-Agent": "retixhub-publish"}), timeout=60)
        if e.code in (401, 403, 404):
            raise SystemExit(f"GitHub ответил {e.code} на {url}. Закрытый репозиторий — укажите GITHUB_TOKEN в .env "
                             "(чтение Contents), версия — проверьте, что такой Release есть.") from e
        raise


def release_info(version: str = "", token: str = "") -> dict:
    """Release из GitHub: версия, установщик (id, имя, размер), что нового."""
    path = f"tags/v{version}" if version else "latest"
    with _open(f"https://api.github.com/repos/{REPO}/releases/{path}", "application/vnd.github+json", token) as r:
        rel = json.load(r)
    asset = next((a for a in rel.get("assets") or [] if ASSET_RE.match(a.get("name") or "")), None)
    if not asset:
        raise SystemExit(f"В Release {rel.get('tag_name')} нет файла RetixHub_Setup_<версия>.exe")
    return {"version": ASSET_RE.match(asset["name"]).group(1), "asset_id": asset["id"], "name": asset["name"],
            "size": asset.get("size") or 0, "notes": release_notes(rel.get("body") or "")}


def release_notes(body: str) -> str:
    """Из описания Release — только «Что нового» (до черты «---»), без заголовка."""
    text = body.split("\n---", 1)[0]
    text = re.sub(r"^\s*##\s*Что нового\s*", "", text.strip())
    return text.strip()[:2000]


def download(asset_id: int, dest: str, token: str = "") -> int:
    url = f"https://api.github.com/repos/{REPO}/releases/assets/{asset_id}"
    size = 0
    with _open(url, "application/octet-stream", token) as r, open(dest, "wb") as out:
        while True:
            chunk = r.read(CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > updates.MAX_UPLOAD:
                raise SystemExit("Файл больше допустимого размера установщика")
            out.write(chunk)
    return size


def publish_file(path: str, notes: str = "", now: bool = True, version: str = "") -> str:
    db.init()
    conn = db.connect()
    try:
        with open(path, "rb") as f:
            _, ver = updates.save_upload(f, os.path.basename(path), conn, version=version, notes=notes,
                                         publish=now, admin="publish.sh")
        return ver
    finally:
        conn.close()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="publish.sh", description="Опубликовать версию клиента Retix Hub")
    p.add_argument("version", nargs="?", default="", help="версия Release (по умолчанию — последний)")
    p.add_argument("--file", help="установщик, уже лежащий на сервере (внутри контейнера: /data/…)")
    p.add_argument("--notes", default=None, help="что нового (по умолчанию — из описания Release)")
    p.add_argument("--draft", action="store_true", help="загрузить черновиком, не публиковать")
    a = p.parse_args(argv)
    if a.version and not updates.clean_version(a.version.lstrip("v")):
        p.error(f"«{a.version}» — не версия (пример: 1.0.19)")
    token = os.getenv("GITHUB_TOKEN", "").strip()
    try:
        if a.file:
            ver = publish_file(a.file, a.notes or "", not a.draft, a.version.lstrip("v"))
        else:
            info = release_info(a.version.lstrip("v"), token)
            print(f"GitHub Release v{info['version']}: {info['name']}, {info['size'] // 1024} КБ — скачиваю…")
            fd, tmp = tempfile.mkstemp(prefix="publish_", suffix=".exe", dir=updates.updates_dir())
            os.close(fd)
            try:
                download(info["asset_id"], tmp, token)
                ver = publish_file(tmp, info["notes"] if a.notes is None else a.notes, not a.draft, info["version"])
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
    except updates.UpdateError as e:
        print(f"Не опубликовано: {e}", file=sys.stderr)
        return 1
    print(f"Версия {ver} " + ("загружена черновиком — опубликуйте в суперадмин → «Обновления»" if a.draft else
                              "опубликована всем компаниям — ПК обновятся сами в течение 10 минут"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
