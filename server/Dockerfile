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
CMD ["python", "-m", "app.main"]
