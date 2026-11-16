#!/usr/bin/env bash
# Сборка и запуск (или обновление) Retix Hub в Docker — без docker compose.
#   cd server && cp .env.example .env && nano .env && ./run.sh
# Повторный запуск = обновление: образ пересобирается, контейнер пересоздаётся.
# Данные (база, ключи, downloads/) — на хосте в HUB_DATA из .env, по умолчанию /root/hub.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then
    echo "Нет .env: cp .env.example .env и заполните WG_ENDPOINT, SUPERADMIN_PASSWORD" >&2
    exit 1
fi
HUB_DATA=$(grep -E '^HUB_DATA=' .env | tail -n 1 | cut -d= -f2- || true)
HUB_DATA=${HUB_DATA:-/root/hub}
mkdir -p "$HUB_DATA"

docker build -t retixhub .
docker rm -f retixhub >/dev/null 2>&1 || true
# --network host: wg0 и правила iptables создаются на хосте
docker run -d --name retixhub --restart unless-stopped \
    --network host \
    --cap-add NET_ADMIN --cap-add SYS_MODULE \
    --device /dev/net/tun \
    --env-file .env \
    -v "$HUB_DATA":/data \
    -v /lib/modules:/lib/modules:ro \
    retixhub

echo "Retix Hub запущен, данные: $HUB_DATA"
sleep 3
docker logs --tail 20 retixhub
