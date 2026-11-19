"""Исправления аудита 1.0.26: попытки входа, подтверждение ключа, сессии, CSRF, заголовки, wg/iptables, журнал."""
import base64
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from conftest import new_pubkey


def client_module():
    """retixhub_client — проверка, что клиент считает подтверждение так же, как сервер."""
    import sys
    import types
    try:
        import tkinter  # noqa: F401
    except ImportError:
        tk = types.ModuleType("tkinter"); tk.Tk = tk.Toplevel = tk.Canvas = tk.Label = tk.Frame = object
        sys.modules["tkinter"] = tk
        for sub in ("messagebox", "simpledialog", "ttk"):
            sys.modules[f"tkinter.{sub}"] = types.ModuleType(sub)
    import retixhub_client
    return retixhub_client


def keypair():
    priv = X25519PrivateKey.generate()
    raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode(), base64.b64encode(pub).decode()


def register(ctx, company, key, extra=None, join="join123", name="PC"):
    return ctx.api.post("/api/register", json={"company_login": company, "join_password": join, "device_name": name,
                                               "public_key": key, "client_version": "1.0.26", **(extra or {})})


# ---------------------------------------------------------------- попытки входа

class TestLoginLimits:
    def test_success_elsewhere_does_not_reset_admin_failures(self, ctx):
        """Раньше: 9 неверных паролей суперадмина, успешная регистрация своего ПК — счётчик обнулён, и снова."""
        ctx.company("alpha")
        key = new_pubkey()
        ctx.register("alpha", key=key)
        c = ctx.TestClient(ctx.app)
        codes = []
        for i in range(12):
            codes.append(c.post("/admin/login", data={"login": "admin", "password": f"guess{i}"},
                                follow_redirects=False).status_code)
            ctx.register("alpha", key=key)          # успех в другом входе
        assert codes[:10] == [303] * 10 and codes[10:] == [429, 429]
        r = c.post("/admin/login", data={"login": "admin", "password": "supersecret"}, follow_redirects=False)
        assert r.status_code == 429                  # и верный пароль — после паузы

    def test_cabinet_success_resets_only_its_own_login(self, ctx):
        ctx.company("one"); ctx.company("two", cab="cab999")
        c = ctx.TestClient(ctx.app)
        for i in range(9):
            c.post("/cabinet/login", data={"login": "two", "password": f"x{i}"}, follow_redirects=False)
        ctx.cabinet("one")                            # успешный вход в другую компанию
        for i in range(1):
            c.post("/cabinet/login", data={"login": "two", "password": "y"}, follow_redirects=False)
        r = c.post("/cabinet/login", data={"login": "two", "password": "cab999"}, follow_redirects=False)
        assert r.status_code == 429

    def test_office_registrations_do_not_block_cabinet(self, ctx):
        ctx.company("beta")
        for _ in range(10):
            ctx.register("beta", join="old-wrong", expect=401)
        ctx.cabinet("beta")                           # раньше — 429 на 10 минут
        ctx.register("beta", expect=429)              # регистрация этой компании с этого IP — пауза, как раньше

    def test_other_company_not_blocked(self, ctx):
        ctx.company("cc1"); ctx.company("cc2")
        for _ in range(10):
            ctx.register("cc1", join="bad", expect=401)
        ctx.register("cc1", expect=429)
        ctx.register("cc2")

    def test_ip_limit_across_logins(self, ctx):
        from app import auth
        ctx.company("gamma")
        c = ctx.TestClient(ctx.app)
        for i in range(auth.ip_limiters["cabinet"].limit):
            c.post("/cabinet/login", data={"login": f"nobody{i}", "password": "x"}, follow_redirects=False)
        assert c.post("/cabinet/login", data={"login": "gamma", "password": "cab123"},
                      follow_redirects=False).status_code == 429

    def test_limiter_memory_bounded(self):
        from app.auth import RateLimiter
        lim = RateLimiter(limit=3, window=600, max_keys=100)
        for i in range(1000):
            lim.check(f"ip{i}")                       # проверка без неудач ключ не хранит
        assert lim._fails == {}
        for i in range(1000):
            lim.fail(f"ip{i}")
        assert len(lim._fails) <= 100
        lim.fail("x"); lim.fail("x"); lim.fail("x")
        assert lim.blocked("x")

    def test_superadmin_long_password_exact(self, ctx, monkeypatch):
        """bcrypt видит 72 байта — совпадение первых 72 байт не пускает."""
        from app.routers import admin
        long_pw = "p" * 80
        monkeypatch.setattr(admin, "SUPERADMIN_PASSWORD", long_pw)
        monkeypatch.setattr(admin, "_admin_hash", "")
        assert admin.superadmin_ok("admin", long_pw)
        assert not admin.superadmin_ok("admin", "p" * 72 + "q" * 8)
        assert not admin.superadmin_ok("root", long_pw)
        monkeypatch.setattr(admin, "_admin_hash", "")


# ---------------------------------------------------------------- подтверждение ключа

class TestKeyProof:
    def proof(self, ctx, priv, pub, ts=None):
        rc_shim = client_module()
        info = ctx.api.get("/api/ping").json()
        ts = info["time"] if ts is None else ts
        return {"proof": rc_shim.key_proof(priv, info["server_public_key"], pub, ts), "proof_ts": ts}

    def test_ping_gives_server_key(self, ctx):
        from app import wg
        assert ctx.api.get("/api/ping").json()["server_public_key"] == wg.server_public_key()

    def test_reregister_by_public_key_only_is_refused(self, ctx):
        ctx.company("firm")
        priv, pub = keypair()
        first = register(ctx, "firm", pub, self.proof(ctx, priv, pub))
        assert first.status_code == 200
        stolen = register(ctx, "firm", pub)                       # только открытый ключ
        assert stolen.status_code == 403 and "не подтверждён" in stolen.json()["detail"]
        wrong_priv, _ = keypair()
        assert register(ctx, "firm", pub, self.proof(ctx, wrong_priv, pub)).status_code == 403
        assert register(ctx, "firm", pub, self.proof(ctx, priv, pub, ts=int(time.time()) - 3600)).status_code == 403
        # прежний вход ПК при этом цел
        assert ctx.api.get("/api/me", headers=ctx.h(first.json()["token"])).status_code == 200
        again = register(ctx, "firm", pub, self.proof(ctx, priv, pub))   # сам ПК — с подтверждением
        assert again.status_code == 200 and again.json()["ip"] == first.json()["ip"]
        from app import db
        conn = db.connect()
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='device_reregister_denied'").fetchone()[0] == 3

    def test_old_client_device_keeps_old_behaviour(self, ctx):
        """ПК ещё на старой версии — повторная регистрация без подтверждения, как раньше (переход без поломок)."""
        ctx.company("old")
        key = new_pubkey()
        ctx.api.post("/api/register", json={"company_login": "old", "join_password": "join123", "device_name": "PC",
                                            "public_key": key, "client_version": "1.0.25"})
        assert ctx.api.post("/api/register", json={"company_login": "old", "join_password": "join123",
                                                   "device_name": "PC", "public_key": key,
                                                   "client_version": "1.0.25"}).status_code == 200

    def test_new_device_needs_no_proof(self, ctx):
        ctx.company("fresh")
        assert register(ctx, "fresh", new_pubkey()).status_code == 200


# ---------------------------------------------------------------- сессии, CSRF, заголовки

class TestWeb:
    def test_cabinet_sessions_end_after_password_change(self, ctx):
        cid = ctx.company("sess")
        other = ctx.cabinet("sess")
        me = ctx.cabinet("sess")
        r = me.post("/cabinet/cabinet-password", data={"old_password": "cab123", "new_password": "newpass1"})
        assert "изменён" in r.text
        assert me.get("/cabinet", follow_redirects=False).status_code == 200          # эта сессия осталась
        assert other.get("/cabinet", follow_redirects=False).headers["location"] == "/cabinet/login"
        ctx.admin.post(f"/admin/companies/{cid}/passwords", data={"cabinet_password": "byadmin1"})
        assert me.get("/cabinet", follow_redirects=False).headers["location"] == "/cabinet/login"

    def test_admin_session_ends_when_password_changes(self, ctx, monkeypatch):
        from app.routers import admin
        assert ctx.admin.get("/admin", follow_redirects=False).status_code == 200
        monkeypatch.setattr(admin, "SUPERADMIN_PASSWORD", "another-password")
        assert ctx.admin.get("/admin", follow_redirects=False).headers["location"] == "/admin/login"

    def test_foreign_origin_rejected(self, ctx):
        ctx.company("orig")
        cab = ctx.cabinet("orig")
        for headers in ({"Origin": "https://evil.retix.uz"}, {"Origin": "null"},
                        {"Referer": "https://evil.example/page"}):
            r = cab.post("/cabinet/settings", data={"share_ports": "445"}, headers=headers, follow_redirects=False)
            assert r.status_code == 403, headers
            r = ctx.admin.post("/admin/companies", data={"login": "zzz", "cabinet_password": "123456",
                                                         "join_password": "123456"}, headers=headers)
            assert r.status_code == 403
        r = cab.post("/cabinet/settings", data={"share_ports": "445", "share_name": "share"},
                     headers={"Origin": "http://testserver"}, follow_redirects=False)
        assert r.status_code == 303 and "err" not in r.headers["location"]
        # API ПК (Bearer-токен, не cookie) проверка не касается
        assert ctx.api.post("/api/register", json={}, headers={"Origin": "https://evil"}).status_code == 422

    def test_security_headers(self, ctx):
        r = ctx.api.get("/")
        assert r.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "strict-transport-security" not in r.headers          # COOKIE_SECURE=0 в тестах


# ---------------------------------------------------------------- сервер: wg, iptables, журнал

class TestServerStability:
    def test_firewall_jump_moved_to_top(self, monkeypatch):
        """Docker поставил свои цепочки выше — переход в RETIX_FWD снова первый, старый убран, DOCKER-USER тоже."""
        from app import wg
        chains = {"FORWARD": ["-A FORWARD -j DOCKER-USER", "-A FORWARD -j DOCKER-FORWARD",
                              "-A FORWARD -i wg0 -j RETIX_FWD"],
                  "INPUT": ["-A INPUT -i wg0 -j RETIX_IN"], "DOCKER-USER": ["-A DOCKER-USER -j RETURN"]}

        def run(args, input=None, check=True):
            if args[0].endswith("-restore"):
                return ""
            op, chain = args[2], args[3]
            if op == "-S":
                return "\n".join([f"-P {chain} ACCEPT", *chains[chain]])
            if op == "-I":
                chains[chain].insert(0, f"-A {chain} " + " ".join(args[5:]))
            if op == "-D":
                del chains[chain][int(args[4]) - 1]
            return ""

        monkeypatch.setattr(wg, "DRY_RUN", False)
        monkeypatch.setattr(wg, "run", run)
        monkeypatch.setattr(wg, "ok", lambda args: args[3] in chains)
        wg.apply_firewall([])
        assert chains["FORWARD"] == ["-A FORWARD -i wg0 -j RETIX_FWD", "-A FORWARD -j DOCKER-USER",
                                     "-A FORWARD -j DOCKER-FORWARD"]
        assert chains["INPUT"] == ["-A INPUT -i wg0 -j RETIX_IN"]
        assert chains["DOCKER-USER"][0] == "-A DOCKER-USER -i wg0 -j RETIX_FWD"
        before = {k: list(v) for k, v in chains.items()}
        wg.apply_firewall([])                                  # уже на месте — ничего не меняется
        assert chains == before

    def test_interface_recreated(self, clean, monkeypatch):
        from app import db, monitor, services, wg
        calls = []
        monkeypatch.setattr(wg, "DRY_RUN", False)
        monkeypatch.setattr(wg, "interface_exists", lambda: False)
        monkeypatch.setattr(wg, "setup_interface", lambda: calls.append("setup"))
        monkeypatch.setattr(services, "reconcile", lambda conn=None: calls.append("reconcile") or True)
        conn = db.connect()
        assert monitor.ensure_interface(conn) and calls == ["setup", "reconcile"]
        monkeypatch.setattr(wg, "interface_exists", lambda: True)
        assert not monitor.ensure_interface(conn) and calls == ["setup", "reconcile"]

    def test_audit_cleanup(self, ctx):
        from app import db, monitor
        cid = ctx.company("aud")
        conn = db.connect()
        conn.execute("INSERT INTO audit_log(company_id, action, created_at) VALUES (?, 'old', '2020-01-01 00:00:00')",
                     (cid,))
        conn.commit()
        assert monitor.cleanup(conn) == 1
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='company_create'").fetchone()[0] == 1

    def test_log_upload_chunked_too_big(self, ctx):
        from app import db
        ctx.company("logs")
        d = ctx.register("logs")
        conn = db.connect()
        conn.execute("UPDATE devices SET log_requested_at=1")
        conn.commit()

        def gen():
            for _ in range(20):
                yield b"x" * 100_000

        r = ctx.api.post("/api/log", content=gen(), headers=ctx.h(d["token"]))
        assert r.status_code == 413
