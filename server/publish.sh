#!/usr/bin/env bash
# Опубликовать новую версию клиента сразу с сервера (без скачивания и загрузки через суперадмина):
#   ./publish.sh                 последний GitHub Release → скачать установщик и опубликовать всем компаниям
#   ./publish.sh 1.0.19          эту версию
#   ./publish.sh --draft         загрузить черновиком (опубликовать потом в суперадмин → «Обновления»)
#   ./publish.sh --file /root/RetixHub_Setup_1.0.19.exe   установщик, который уже лежит на сервере
# Закрытый репозиторий: GITHUB_TOKEN=<токен с чтением Contents> в .env и ./run.sh (контейнер берёт .env при запуске).
set -euo pipefail
cd "$(dirname "$0")"

HUB_DATA=$(grep -E '^HUB_DATA=' .env 2>/dev/null | tail -n 1 | cut -d= -f2- || true)
HUB_DATA=${HUB_DATA:-/root/hub/data}

args=()
while [ $# -gt 0 ]; do
    if [ "$1" = "--file" ] && [ $# -ge 2 ]; then
        # файл на хосте -> в папку данных, которую видит контейнер (/data)
        src=$2
        [ -f "$src" ] || { echo "Нет файла $src" >&2; exit 1; }
        mkdir -p "$HUB_DATA/incoming"
        cp -f "$src" "$HUB_DATA/incoming/"
        args+=(--file "/data/incoming/$(basename "$src")")
        shift 2
    else
        args+=("$1")
        shift
    fi
done

docker exec retixhub python -m app.publish ${args[@]+"${args[@]}"}
