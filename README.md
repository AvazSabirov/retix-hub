# Retix Hub — WireGuard-сеть компаний

```
server/   FastAPI + WireGuard + iptables в Docker, SQLite, кабинеты компаний и суперадмина
client/   Python-клиент для Windows (Tkinter), сборка в RetixHub.exe
```

## Как это устроено

* Сервер — центр «звезды»: `10.66.0.1`. Каждая компания получает свою подсеть `10.66.N.0/24`.
* Клиент получает `AllowedIPs = 10.66.N.0/24, 10.66.0.1/32` — **интернет идёт мимо VPN**.
  На сервере нет NAT, а цепочка `RETIX_FWD` заканчивается `DROP` — выйти в интернет через сервер нельзя,
  даже если поменять конфиг руками.
* Между компаниями трафик запрещён. Внутри компании по умолчанию разрешены только ping и SMB (445)
  к компьютеру с общей папкой. Галочка «любой трафик между ПК» в кабинете открывает всё внутри компании.
* База SQLite (`/root/hub/vpn.db` на хосте) — источник правды. При старте контейнера и каждые 5 минут
  `wg0` и iptables пересобираются из базы.
* Кабинет компании видит только свою компанию: `company_id` берётся из сессии, а не из запроса.

## 1. Сервер

Требования: Ubuntu 20.04+ (модуль WireGuard в ядре), Docker + compose, nginx.

```bash
cd server
cp .env.example .env      # укажите WG_ENDPOINT, SUPERADMIN_PASSWORD
docker compose up -d --build
docker logs -f retixhub  # «Retix Hub запущен, server pubkey …»

ufw allow 51820/udp       # если включён ufw
```

nginx: пример в `server/nginx-hub.retix.uz.conf` (SSL через certbot). API слушает только `127.0.0.1:8100`.

Проверка на сервере:
```bash
wg show                                # интерфейс wg0 и пиры
iptables -S RETIX_FWD                   # правила между клиентами
sqlite3 /root/hub/vpn.db 'select login, subnet_index from companies'
```

> Если `iptables -V` на хосте показывает `legacy` — поставьте в `.env` `IPTABLES=iptables-legacy`.
> Все данные — в `/root/hub` на хосте (база, `server.key`, `secret.key`, `downloads/`); другая папка — `HUB_DATA` в `.env`.
> Бэкап — это папка `/root/hub`. Без `server.key` всем клиентам придётся
> переподключаться.
>
> Сервер уже работал с данными в `server/data/`? Перенесите их один раз:
> `docker compose down && mkdir -p /root/hub && cp -a data/. /root/hub/ && docker compose up -d`

### Адреса на hub.retix.uz

| Адрес | Что там |
|---|---|
| `https://hub.retix.uz/` | публичная страница: что такое Retix Hub, как работает, скачать клиент |
| `https://hub.retix.uz/api/...` | все запросы клиентов (справка: `/api`) |
| `https://hub.retix.uz/cabinet` | кабинет компании |
| `https://hub.retix.uz/admin` | суперадмин (ссылки на главной нет) |
| `https://hub.retix.uz/download/client` | скачать клиент — положите `RetixHub_Setup_<версия>.exe` в `/root/hub/downloads/` |

DNS: A-запись `hub.retix.uz` → IP сервера. SSL: `certbot --nginx -d hub.retix.uz`.
Порт WireGuard (UDP 51820) идёт на тот же адрес — клиент подключается к `hub.retix.uz:51820`.

## 2. Кабинеты

* `https://hub.retix.uz/admin` — суперадмин (логин/пароль из `.env`): создаёт компании.
  У каждой два пароля: **кабинета** (для админа компании) и **подключения** (вводят в клиенте на ПК).
* `https://hub.retix.uz/cabinet` — кабинет компании: список ПК, online/offline, одобрение, блок,
  удаление, отметка «📁 ПК с общей папкой», имя папки, смена паролей.

«Удалить» — если на ПК сохранён пароль компании, он зарегистрируется снова (это и есть авто-добавление).
Чтобы запретить навсегда — «Блок». Чтобы выкинуть всех — смена пароля подключения с галочкой «отключить все ПК».

## 3. Клиент (Windows)

Пользователям раздаётся один файл — установщик `RetixHub_Setup_<версия>.exe`. Внутри: программа,
`client_config.json` и официальный WireGuard (ставится сам, если его нет).

### Сборка в GitHub

Workflow `.github/workflows/client.yml` собирает установщик на Windows:
* push с изменениями в `client/` → установщик лежит в **Actions → запуск → Artifacts**;
* тег `v<версия>` (например `v1.0.0`) → ещё и **Releases** с установщиком.
  Тег должен совпадать с `VERSION` в `client/retixhub_client.py`.

Выпуск новой версии: поменять `VERSION` в `client/retixhub_client.py`, закоммитить, затем либо
```bash
git tag v1.0.1
git push origin v1.0.1
```
либо на GitHub: **Releases → Draft a new release** → тег `v1.0.1` → **Publish release** — установщик
соберётся и прикрепится к релизу сам (через 3–5 минут).

### Сборка на своём ПК

Нужны Windows 10/11 x64, Python 3.10+ (64-бит) и [Inno Setup 6.3+](https://jrsoftware.org/isdl.php).
```
cd client
:: при необходимости поменяйте server_url в client_config.json
build.bat
```
`build.bat`: ставит зависимости → PyInstaller (`RetixHub.spec`, onedir) → самопроверка собранного exe
(`RetixHub.exe --selftest`: Tcl/Tk, cryptography, SSL, иконка) → скачивает WireGuard MSI с проверкой подписи
(`get_wireguard.ps1`) → Inno Setup (`RetixHub.iss`). Результат: `client\dist\RetixHub_Setup_<версия>.exe`.

### Установщик

* Без вопросов: окно UAC и полоса прогресса. Обновление — тот же установщик поверх; запущенный клиент
  закрывается (VPN держит служба WireGuard, связь не рвётся). Более старую версию поверх новой не ставит.
* Ярлыки: рабочий стол и «Пуск». Автозапуск создаёт сам клиент (задача Планировщика).
* Тихая установка на много ПК: `RetixHub_Setup_<версия>.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART`.
* Удаление (Параметры → Приложения): снимает туннель, блок в `hosts`, правило firewall и автозапуск.
  WireGuard и `C:\ProgramData\RetixHub\` остаются — после повторной установки ПК вернётся в сеть сам.
* На сайт: положите установщик в `/root/hub/downloads/` на сервере — по кнопке «Скачать» отдаётся самый новый
  `RetixHub_Setup_*.exe`.

Что делает клиент:
1. Окно входа: сервер, логин компании, пароль компании, имя ПК. Ключ WireGuard генерируется на ПК,
   на сервер уходит только публичный.
2. Ставит туннель как службу Windows `WireGuardTunnel$retixhub` — VPN работает, даже если окно закрыто,
   и поднимается после перезагрузки.
3. Каждые 8 секунд проверяет сервер и handshake:
   * сервер недоступен → статус 🔴, туннель не трогает и ждёт;
   * сервер вернулся → переустанавливает туннель (заново определяет IP сервера) → 🟢;
   * нет handshake → переподключается (интервал растёт 1 → 10 мин);
   * устройство удалили / сбросили токены → сам регистрируется снова (если пароль сохранён);
   * заблокировали → снимает туннель.
4. Показывает пользователей компании (online/offline, 📁 у ПК с папкой) и пишет их имена в `hosts`,
   поэтому `\\pc1\share` работает по имени.
5. На ПК, отмеченном как «📁», сам добавляет правило firewall «RetixHub SMB» (445 из подсети компании).
6. Кнопки: «Открыть общую папку», «Подключить диск…» (`net use` + сохранение логина через `cmdkey`),
   «Переподключить», «Выйти из сети». Автозапуск при входе в Windows через Планировщик заданий.

Данные клиента: `C:\ProgramData\RetixHub\` (доступ только SYSTEM и администраторам;
приватный ключ, токен и пароль зашифрованы DPAPI). Журнал: `client.log` там же.

## 4. Настройка ПК с общей папкой (PC1)

1. Установить клиент, войти. В кабинете нажать «Сделать 📁» напротив PC1.
2. Создать локального пользователя для папки (например `share_user`) и дать ему права на `share`
   (Свойства → Доступ и Безопасность). Гостевой доступ в Windows 10/11 выключен — нужен пользователь.
3. На остальных ПК: «Подключить диск…» → логин `pc1\share_user` и пароль — сохранится в Windows.

## 5. Переход на Retix Hub

1. Поднять сервер, создать компанию, поставить клиент на PC1 и 1–2 ПК — проверить папку.
2. Поставить клиент на остальные ПК; прежний VPN держать параллельно пару дней.
3. Удалить прежний VPN.

## Тесты

```bash
pip install -r server/requirements.txt -r client/requirements.txt pytest httpx
python -m pytest tests/test_server.py tests/test_client.py -q   # 114 тестов, ~2 мин
sudo python3 tests/e2e_network.py                               # 52 проверки на настоящей сети
```

* `test_server.py` — суперадмин, регистрация, лимиты, изоляция компаний, кабинет, блок/одобрение,
  смена паролей, правила iptables, XSS/SQL-инъекции, параллельная регистрация (60 ПК одновременно).
* `test_client.py` — логика клиента против живого сервера: вход, падение/возврат сервера, потеря связи,
  удаление/блокировка/одобрение ПК, смена пароля, hosts, firewall, выход.
* `e2e_network.py` — стенд из Linux network namespaces: настоящий сервер управляет WireGuard и iptables,
  4 ПК в двух компаниях. Проверяет связь, SMB к ПК с папкой, изоляцию (в т.ч. с подделанным конфигом и
  чужим IP), что интернет не идёт через VPN, перезагрузку сервера, блокировку, удаление, отключение компании.
  Нужны root, iproute2, wireguard-tools, iptables, netcat-openbsd (и модуль WireGuard или wireguard-go).

## Разработка

```bash
cd server && pip install -r requirements.txt
DATA_DIR=./devdata WG_DRY_RUN=1 COOKIE_SECURE=0 SUPERADMIN_PASSWORD=test python -m app.main
```
`WG_DRY_RUN=1` — wg и iptables не вызываются, команды только пишутся в лог.

API клиента: `POST /api/register`, `GET /api/me`, `GET /api/peers`, `POST /api/heartbeat`, `GET /api/ping`.
