# Правила репозитория Retix Hub

## Версии
- Любое изменение, которое уходит в `main`, поднимает версию **и клиента, и сервера** («облака»):
  - клиент: `VERSION` в `client/retixhub_client.py` и раздел этой версии в `client/CHANGELOG.md`
    (его текст попадает в описание GitHub Release);
  - сервер: `APP_VERSION` в `server/app/config.py`.
- Версии клиента и сервера одинаковые. Тест `test_server_version_matches_client` проверяет это.
- Новая `VERSION` в `main` сама собирает установщик и GitHub Release `v<версия>` (`.github/workflows/client.yml`).
- Версия сервера видна в шапке суперадмина («сервер X.Y.Z»), в `/api` и в журнале при старте.
