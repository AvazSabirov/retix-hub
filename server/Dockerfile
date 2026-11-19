FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends wireguard-tools iptables iproute2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV DATA_DIR=/data PYTHONUNBUFFERED=1
VOLUME ["/data"]
# docker ps показывает unhealthy, если API не отвечает (сеть контейнера — сеть хоста, API на API_HOST:API_PORT)
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://%s:%s/api/ping' % (os.getenv('API_HOST','127.0.0.1'), os.getenv('API_PORT','8100')), timeout=5)"
CMD ["python", "-m", "app.main"]
