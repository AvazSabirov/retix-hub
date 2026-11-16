"""Общие фикстуры. Сервер работает в WG_DRY_RUN — wg/iptables перехватываются."""
import base64
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.update(
    DATA_DIR=tempfile.mkdtemp(prefix="retix-test-"), WG_DRY_RUN="1", COOKIE_SECURE="0",
    SUPERADMIN_LOGIN="admin", SUPERADMIN_PASSWORD="supersecret", WG_ENDPOINT="vpn.test.uz:51820")
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "client"))

import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402


def new_pubkey() -> str:
    raw = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


@pytest.fixture(scope="session")
def app():
    from app.main import app as fastapi_app
    return fastapi_app


@pytest.fixture()
def net(monkeypatch):
    """Последнее состояние, которое сервер отправил в wg и iptables."""
    from app import services
    state = {"peers": {}, "rules": [], "calls": 0}

    def sync_peers(desired):
        state["peers"] = dict(desired)
        state["calls"] += 1

    def apply_firewall(rules):
        state["rules"] = list(rules)

    monkeypatch.setattr(services.wg, "sync_peers", sync_peers)
    monkeypatch.setattr(services.wg, "apply_firewall", apply_firewall)
    return state


@pytest.fixture()
def clean(app, net):
    """Чистая база и счётчики попыток перед каждым тестом."""
    from fastapi.testclient import TestClient
    from app import db
    from app.auth import limiter
    with TestClient(app):  # lifespan: db.init()
        pass
    conn = db.connect()
    conn.executescript("DELETE FROM token_history; DELETE FROM messages; DELETE FROM devices; DELETE FROM companies;"
                       "DELETE FROM audit_log; DELETE FROM sqlite_sequence;")
    conn.commit()
    conn.close()
    limiter._fails.clear()
    yield


class Ctx:
    """Удобные помощники для сценариев."""

    def __init__(self, app):
        from fastapi.testclient import TestClient
        self.TestClient = TestClient
        self.app = app
        self.api = TestClient(app)
        self.admin = TestClient(app)
        r = self.admin.post("/admin/login", data={"login": "admin", "password": "supersecret"}, follow_redirects=False)
        assert r.headers["location"] == "/admin"

    def company(self, login, join="join123", cab="cab123", max_devices=20, name="", approval=False):
        """Компания. Новые компании по умолчанию ждут одобрения ПК; большинству сценариев оно
        не нужно — approval=False выключает его, как галочка в кабинете."""
        r = self.admin.post("/admin/companies", data={"login": login, "name": name or login, "cabinet_password": cab,
                                                      "join_password": join, "max_devices": max_devices})
        assert "создана" in r.text, r.text[:400]
        from app import db
        conn = db.connect()
        cid = conn.execute("SELECT id FROM companies WHERE login=?", (login,)).fetchone()[0]
        if not approval:
            conn.execute("UPDATE companies SET require_approval=0 WHERE id=?", (cid,))
            conn.commit()
        conn.close()
        return cid

    def register(self, company, name="PC", hostname="", join="join123", key=None, expect=200):
        key = key or new_pubkey()
        r = self.api.post("/api/register", json={"company_login": company, "join_password": join,
                                                 "device_name": name, "hostname": hostname, "public_key": key,
                                                 "client_version": "test"})
        assert r.status_code == expect, (r.status_code, r.text)
        return (r.json() | {"_key": key}) if r.status_code == 200 else r

    def cabinet(self, login, password="cab123"):
        c = self.TestClient(self.app)
        r = c.post("/cabinet/login", data={"login": login, "password": password}, follow_redirects=False)
        assert r.headers["location"] == "/cabinet", r.headers["location"]
        return c

    def h(self, token):
        return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def ctx(clean, app):
    return Ctx(app)
