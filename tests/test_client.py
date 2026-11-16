"""Клиент: сценарии подключения против живого сервера (uvicorn), туннель Windows подменён."""
import os
import queue
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

import pytest
import requests

from conftest import ROOT, fake_setup, new_pubkey

# tkinter может отсутствовать на Linux-сервере сборки — для логики клиента он не нужен
try:
    import tkinter  # noqa: F401
except ImportError:
    tk = types.ModuleType("tkinter"); tk.Tk = tk.Toplevel = object
    sys.modules["tkinter"] = tk
    for sub in ("messagebox", "simpledialog", "ttk"):
        sys.modules[f"tkinter.{sub}"] = types.ModuleType(sub)

import retixhub_client as rc  # noqa: E402

PORT = 8197
BASE = f"http://127.0.0.1:{PORT}"


class Server:
    def __init__(self):
        self.data = tempfile.mkdtemp(prefix="retix-srv-")
        self.proc = None

    def start(self):
        env = os.environ | {"DATA_DIR": self.data, "WG_DRY_RUN": "1", "COOKIE_SECURE": "0", "API_PORT": str(PORT),
                            "SUPERADMIN_LOGIN": "admin", "SUPERADMIN_PASSWORD": "supersecret",
                            "WG_ENDPOINT": "vpn.test.uz:51820",
                            # токен меняется почти на каждом запросе: все сценарии проверяют и ротацию
                            "TOKEN_ROTATE_SECONDS": "0"}
        self.proc = subprocess.Popen([sys.executable, "-m", "app.main"], cwd=ROOT / "server", env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                requests.get(BASE + "/api/ping", timeout=0.5)
                return
            except requests.RequestException:
                time.sleep(0.1)
        raise RuntimeError("server did not start")

    def stop(self):
        self.proc.terminate(); self.proc.wait()


@pytest.fixture(scope="module")
def server():
    s = Server(); s.start()
    admin = requests.Session()
    admin.post(BASE + "/admin/login", data={"login": "admin", "password": "supersecret"})
    s.admin = admin
    yield s
    s.stop()


_n = [0]


@pytest.fixture()
def company(server):
    """Новая компания на каждый тест + сессия её кабинета."""
    _n[0] += 1
    login = f"co{_n[0]}"
    server.admin.post(BASE + "/admin/companies", data={"login": login, "name": login, "cabinet_password": "cab123",
                                                       "join_password": "join123", "max_devices": 20})
    cab = requests.Session()
    cab.post(BASE + "/cabinet/login", data={"login": login, "password": "cab123"})
    # новые компании ждут одобрения ПК; в сценариях оно включается явно (test_pending_then_approved)
    cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445"})
    return types.SimpleNamespace(login=login, cab=cab)


class FakeTunnel:
    """Ведёт себя как служба WireGuardTunnel$retixhub."""

    def __init__(self):
        self.state = "missing"; self.hs = 0; self.installs = 0; self.starts = 0; self.conf = ""
        self.handshake_works = True; self.wg_installed = True; self.probe_ok = True

    def installed(self): return self.wg_installed
    build_conf = staticmethod(rc.Tunnel.build_conf)
    def service_state(self): return self.state

    def install(self, conf):
        self.state = "running"; self.installs += 1; self.conf = conf
        self.hs = int(time.time()) if self.handshake_works else 0

    def uninstall(self): self.state = "missing"; self.hs = 0
    def start(self): self.starts += 1; self.state = "running"
    def last_handshake(self): return self.hs
    def probe(self, ip): return self.state == "running" and self.probe_ok and self.hs > 0


class Client:
    """Один «компьютер»: своё состояние и свой туннель."""

    def __init__(self, tmp: Path, hostname="BUH-01"):
        tmp.mkdir(parents=True, exist_ok=True)
        self.state = rc.State(tmp / "state.json"); self.state.set(server_url=BASE)
        self.tunnel = FakeTunnel()
        self.fw = []
        self.hostname = hostname
        self.events_seen = []
        self.w = rc.Worker(self.state, queue.Queue(), tunnel=self.tunnel)

    def step(self, n=1):
        for _ in range(n):
            self.w.step()
        return self.last()

    def last(self):
        st = None
        while not self.w.events.empty():
            kind, data = self.w.events.get()
            self.events_seen.append((kind, data))
            if kind == "status":
                st = data
            elif kind == "peers":
                self.peers = data["peers"]
        return st


@pytest.fixture(autouse=True)
def patch_windows(monkeypatch):
    calls = []
    monkeypatch.setattr(rc, "run", lambda args, timeout=60: (calls.append(args), (0, ""))[1])
    monkeypatch.setattr(rc, "ensure_autostart", lambda: calls.append(["autostart"]))
    return calls


@pytest.fixture()
def make_client(tmp_path, monkeypatch):
    fw = []
    monkeypatch.setattr(rc, "ensure_firewall", lambda subnet, ports="445": fw.append((subnet, ports)))
    clients = []

    def make(hostname="BUH-01"):
        c = Client(tmp_path / f"c{len(clients)}", hostname)
        c.fw = fw
        clients.append(c)
        monkeypatch.setattr(rc.socket, "gethostname", lambda: hostname)
        return c
    return make


def login(c, company, password="join123", remember=True, name="Бухгалтерия"):
    return c.w.login(BASE, company.login, password, name, remember)


def device_id(company, name):
    return next(p["id"] for p in company_peers(company) if p["name"] == name)


def company_peers(company):
    page = company.cab.get(BASE + "/cabinet").text
    import re
    ids = re.findall(r'/cabinet/devices/(\d+)/rename".*?value="([^"]*)"', page, flags=re.S)
    return [{"id": int(i), "name": n} for i, n in ids]


# ================================================================== сценарии

def test_first_run_needs_login(make_client):
    c = make_client()
    assert c.step()["status"] == rc.Status.NEED_LOGIN
    assert c.tunnel.installs == 0


def test_login_errors(make_client, company):
    c = make_client()
    assert login(c, company, "wrong") == "Неверный логин или пароль компании"
    c.state.set(server_url="http://127.0.0.1:1")
    assert "Сервер недоступен" in c.w.login("http://127.0.0.1:1", company.login, "join123", "PC", True)


def test_login_connect_online(make_client, company, patch_windows):
    c = make_client()
    assert login(c, company) is None
    assert c.step()["status"] == rc.Status.CONNECTING      # туннель поставлен
    st = c.step()
    assert st["status"] == rc.Status.ONLINE and "10.66." in st["text"]
    assert c.tunnel.installs == 1
    assert "AllowedIPs = 10.66." in c.tunnel.conf and "0.0.0.0" not in c.tunnel.conf
    assert "Endpoint = vpn.test.uz:51820" in c.tunnel.conf
    assert ["autostart"] in patch_windows


def test_steady_state_does_not_reinstall(make_client, company):
    c = make_client(); login(c, company)
    c.step(5)
    assert c.tunnel.installs == 1


def test_secrets_not_plain_in_state(make_client, company):
    c = make_client(); login(c, company)
    raw = c.state.path.read_text()
    # на Windows — DPAPI; на Linux помечено plain:, но поле token/ключ никогда не лежит без префикса
    assert '"token": "plain:' in raw or '"token": "dpapi:' in raw


def test_restart_keeps_session(make_client, company, tmp_path):
    c = make_client(); login(c, company); c.step(2)
    # «перезагрузка ПК»: новый процесс клиента с тем же state.json и туннелем
    w2 = rc.Worker(rc.State(c.state.path), queue.Queue(), tunnel=c.tunnel)
    w2.step()
    assert c.tunnel.installs == 1                         # конфиг тот же — не переставляем
    kinds = [w2.events.get()[1].get("status") for _ in range(w2.events.qsize())]
    assert rc.Status.ONLINE in kinds


def test_server_down_and_back(make_client, company, server):
    c = make_client(); login(c, company); c.step(2)
    server.stop()
    st = c.step()
    assert st["status"] == rc.Status.SERVER_DOWN
    assert c.tunnel.state == "running"                  # туннель не трогаем
    c.tunnel.hs = 0                                     # handshake пропал, пока сервер лежал
    c.step()
    server.start()
    st = c.step()
    assert st["status"] == rc.Status.CONNECTING and c.tunnel.installs == 2   # переподключились
    assert c.step()["status"] == rc.Status.ONLINE


def test_server_blip_with_live_handshake_no_reinstall(make_client, company, server):
    c = make_client(); login(c, company); c.step(2)
    server.stop(); c.step(); server.start()
    assert c.step()["status"] == rc.Status.ONLINE and c.tunnel.installs == 1


def test_handshake_lost_backoff(make_client, company):
    c = make_client(); login(c, company); c.step(2)
    c.tunnel.handshake_works = False
    c.tunnel.hs = 0
    c.w.last_install = 0                                 # прошло больше минуты
    c.step()
    assert c.tunnel.installs == 2 and c.w.reinstall_backoff == 120
    c.step()
    assert c.tunnel.installs == 2                        # сразу же не дёргаем
    c.w.last_install = 0; c.step()
    assert c.w.reinstall_backoff == 240
    c.tunnel.handshake_works = True; c.w.last_install = 0; c.step(2)
    assert c.w.reinstall_backoff == 60                   # связь вернулась — сброс


def test_service_stopped_is_started(make_client, company):
    c = make_client(); login(c, company); c.step(2)
    c.tunnel.state = "stopped"
    c.step()
    assert c.tunnel.starts == 1


def test_service_removed_is_reinstalled(make_client, company):
    c = make_client(); login(c, company); c.step(2)
    c.tunnel.uninstall()                                 # кто-то удалил туннель вручную
    c.step()
    assert c.tunnel.installs == 2


def test_server_reboot_stale_session_reinstalls(make_client, company, server):
    """Сервер перезагрузился: handshake у клиента ещё «свежий», но сессия на сервере потеряна."""
    c = make_client(); login(c, company); c.step(2)
    server.stop(); c.step()
    c.tunnel.probe_ok = False                            # ping через туннель не проходит
    server.start()
    c.step()
    assert c.tunnel.installs == 2


def test_stale_session_without_noticing_outage(make_client, company):
    """Сервер перезагрузился между проверками клиента: API всё время отвечал, а туннель мёртв."""
    c = make_client(); login(c, company); c.step(2)
    c.tunnel.probe_ok = False
    st = c.step()
    assert st["status"] == rc.Status.CONNECTING           # не «Подключено», хотя handshake свежий
    c.w.last_install = 0                                 # прошла минута — переподключаемся
    c.step()
    assert c.tunnel.installs == 2
    c.tunnel.probe_ok = True
    assert c.step()["status"] == rc.Status.ONLINE


def test_force_reconnect(make_client, company):
    c = make_client(); login(c, company); c.step(2)
    c.w.force_reconnect(); c.step()
    assert c.tunnel.installs == 2


def test_device_deleted_auto_reregisters(make_client, company):
    c = make_client(); login(c, company); c.step(2)
    ip = c.w.cfg["ip"]
    company.cab.post(BASE + f"/cabinet/devices/{c.w.cfg['device_id']}/delete")
    c.step(4)
    assert c.tunnel.installs == 2                        # после перерегистрации туннель переставлен
    assert c.w.cfg["ip"] == ip                           # тот же ключ, свободный IP — тот же адрес
    assert c.w.cfg["status"] == "active"
    assert c.step()["status"] == rc.Status.ONLINE


def test_kick_all_with_new_password_needs_login(make_client, company):
    c = make_client(); login(c, company); c.step(2)
    company.cab.post(BASE + "/cabinet/join-password", data={"new_password": "newpass1", "kick_all": "1"})
    c.step()                                             # токен отозван -> пробуем сохранённый пароль
    st = c.step()
    assert st["status"] == rc.Status.NEED_LOGIN and "изменён" in st["text"]
    assert c.state.get("join_password") == ""          # старый пароль забыт
    assert login(c, company, "newpass1") is None
    assert c.step(2)["status"] == rc.Status.ONLINE


def test_no_remember_password(make_client, company):
    c = make_client(); login(c, company, remember=False); c.step(2)
    company.cab.post(BASE + f"/cabinet/devices/{c.w.cfg['device_id']}/delete")
    assert c.step(3)["status"] == rc.Status.NEED_LOGIN


def test_pending_then_approved(make_client, company):
    company.cab.post(BASE + "/cabinet/settings", data={"require_approval": "1", "share_name": "share", "share_ports": "445"})
    c = make_client(); login(c, company)
    assert c.step()["status"] == rc.Status.PENDING and c.tunnel.installs == 0
    company.cab.post(BASE + f"/cabinet/devices/{c.w.cfg['device_id']}/approve")
    c.step()
    assert c.step()["status"] == rc.Status.ONLINE


def test_blocked_and_unblocked(make_client, company):
    c = make_client(); login(c, company); c.step(2)
    company.cab.post(BASE + f"/cabinet/devices/{c.w.cfg['device_id']}/block")
    assert c.step()["status"] == rc.Status.BLOCKED and c.tunnel.state == "missing"
    company.cab.post(BASE + f"/cabinet/devices/{c.w.cfg['device_id']}/unblock")
    c.step()
    assert c.step()["status"] == rc.Status.ONLINE and c.tunnel.state == "running"


def test_company_disabled(make_client, company, server):
    c = make_client(); login(c, company); c.step(2)
    import re
    cid = re.search(rf'/admin/companies/(\d+)">Открыть</a></td>\s*</tr>', server.admin.get(BASE + "/admin").text)
    page = server.admin.get(BASE + "/admin").text
    cid = re.findall(r"<b>(co\d+)</b>.*?/admin/companies/(\d+)", page, flags=re.S)
    cid = dict(cid)[company.login]
    server.admin.post(BASE + f"/admin/companies/{cid}/update", data={"name": "x", "max_devices": 5})
    assert c.step()["status"] == rc.Status.BLOCKED and c.tunnel.state == "missing"


def test_peers_list(make_client, company):
    a = make_client("PC1"); login(a, company, name="Склад"); a.step(2)
    b = make_client("BUH-01"); login(b, company, name="Бухгалтерия"); b.step(2)
    b.step()
    names = {p["name"]: p for p in b.peers}
    assert set(names) == {"Склад", "Бухгалтерия"} and names["Бухгалтерия"]["is_me"]
    assert names["Склад"]["ip"] == a.w.cfg["ip"]


def test_hosts_never_touched(make_client, company, patch_windows):
    """1.0.1: файл hosts не трогаем совсем (антивирусы, например Dr.Web, блокируют запись)."""
    assert not hasattr(rc, "update_hosts") and not hasattr(rc, "HOSTS_FILE")
    a = make_client("PC1"); login(a, company, name="A"); a.step(2)
    b = make_client("PC2"); login(b, company, name="B"); b.step(3)
    b.w.logout()
    assert not any("hosts" in " ".join(map(str, c)).lower() for c in patch_windows)


def test_firewall_on_every_pc(make_client, company):
    """Общие папки и ping открыты из подсети компании на каждом ПК, без отметки «ПК с папкой»."""
    a = make_client("PC1"); login(a, company, name="Склад"); a.step(2)
    assert a.fw[-1] == (a.w.cfg["subnet"], "445,4899")      # общие папки + Radmin Server
    n = len(a.fw)
    a.step(2)
    assert len(a.fw) == n                                 # без изменений — не трогаем
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445,139"})
    a.step()
    assert a.fw[-1] == (a.w.cfg["subnet"], "445,139,4899")
    a.w.logout()
    assert a.fw[-1][0] is None


def test_power_off_and_on(make_client, company):
    c = make_client(); login(c, company); c.step(2)
    c.w.set_enabled(False)
    st = c.step()
    assert st["status"] == rc.Status.OFF and c.tunnel.state == "missing"
    assert c.step()["status"] == rc.Status.OFF and c.tunnel.installs == 1    # выключено — не ставим
    # «перезагрузка»: остаётся выключенным
    w2 = rc.Worker(rc.State(c.state.path), queue.Queue(), tunnel=c.tunnel); w2.step()
    assert c.tunnel.state == "missing"
    c.w.set_enabled(True)
    c.step()
    assert c.step()["status"] == rc.Status.ONLINE and c.tunnel.installs == 2
    assert c.state.get("token")                          # вход сохранён — пароль не нужен


def test_messages_between_pcs(make_client, company):
    a = make_client("PC1"); login(a, company, name="Склад"); a.step(2)
    b = make_client("PC2"); login(b, company, name="Бухгалтерия"); b.step(2)
    assert a.w.send_message(b.w.cfg["device_id"], "Отчёт готов") is None
    b.step()
    msgs = [d for k, d in b.events_seen if k == "messages"]
    assert msgs and msgs[-1]["messages"][0]["text"] == "Отчёт готов"
    assert msgs[-1]["messages"][0]["from_name"] == "Склад"
    b.step()
    assert len([1 for k, _ in b.events_seen if k == "messages"]) == 1      # повторно не приходит
    assert "не найден" in a.w.send_message(999999, "x")


def test_natural_sort():
    names = ["10 zoo kassa", "2 zoo kassa", "01 zoo kassa", "ALPHA"]
    assert sorted(names, key=rc.natural_key) == ["01 zoo kassa", "2 zoo kassa", "10 zoo kassa", "ALPHA"]


def test_wireguard_missing(make_client, company, monkeypatch):
    c = make_client(); c.tunnel.wg_installed = False
    monkeypatch.setattr(rc, "install_wireguard_if_needed", lambda: False)
    st = c.step()
    assert st["status"] == rc.Status.ERROR and "WireGuard" in st["text"]


def test_isolation_from_client_side(make_client, server, company):
    other_login = company.login + "x"
    server.admin.post(BASE + "/admin/companies", data={"login": other_login, "cabinet_password": "cab123",
                                                       "join_password": "join123", "max_devices": 5})
    other = requests.Session()
    other.post(BASE + "/cabinet/login", data={"login": other_login, "password": "cab123"})
    other.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445"})  # без одобрения
    a = make_client("A1"); login(a, company, name="A"); a.step(2)
    b = make_client("B1"); b.w.login(BASE, other_login, "join123", "B", True); b.step(2)
    a.step(); b.step()
    assert {p["name"] for p in a.peers} == {"A"} and {p["name"] for p in b.peers} == {"B"}
    assert a.w.cfg["subnet"] != b.w.cfg["subnet"]


def test_build_conf_format():
    cfg = {"address": "10.66.1.2/32", "server_public_key": "S" * 43 + "=", "endpoint": "vpn:51820",
           "allowed_ips": "10.66.1.0/24, 10.66.0.1/32", "keepalive": 25}
    conf = rc.Tunnel.build_conf(cfg, "P" * 43 + "=")
    assert conf.splitlines()[:3] == ["[Interface]", "PrivateKey = " + "P" * 43 + "=", "Address = 10.66.1.2/32"]
    assert "PersistentKeepalive = 25" in conf


def test_smb_check_closed_port():
    # на 127.0.0.1 порт 445 закрыт -> понятная причина, а не пустой ответ
    msg = rc.smb_check("127.0.0.1", timeout=0.5)
    assert msg.startswith("Компьютер не отвечает") and "\\\\" not in msg


def test_radmin_ports_and_command(tmp_path):
    assert rc.lan_ports({"share_ports": "445", "radmin_port": 4899}) == "445,4899"
    assert rc.lan_ports({"share_ports": "445,4899"}) == "445,4899"           # без повтора
    assert rc.lan_ports({}) == "445,4899"
    exe = tmp_path / "Radmin.exe"; exe.write_bytes(b"MZ")
    assert rc.find_radmin_viewer(str(exe)) == exe                            # сохранённый путь
    assert rc.radmin_args(exe, "10.66.1.5", "full") == [str(exe), "/connect:10.66.1.5:4899"]
    assert rc.radmin_args(exe, "10.66.1.5", "view")[-1] == "/noinput"
    assert rc.radmin_args(exe, "10.66.1.5", "files")[-1] == "/file"


# ================================================================== 1.0.5: один вход — один ПК, проверки, автообновление

def test_token_rotation_keeps_working(make_client, company, tmp_path):
    c = make_client(); login(c, company); c.step(2)
    tokens = set()
    for _ in range(5):
        tokens.add(c.state.get("token"))
        assert c.step()["status"] == rc.Status.ONLINE
    assert len(tokens) >= 3                               # токен действительно меняется
    c2 = Client(tmp_path / "c0")                          # перезапуск программы: новый токен уже на диске
    c2.tunnel = c.tunnel; c2.w.tunnel = c.tunnel
    assert c2.step()["status"] == rc.Status.ONLINE


def test_copied_login_disconnects_both(make_client, company, tmp_path, server):
    import shutil
    a = make_client(); login(a, company); a.step(2)
    (tmp_path / "clone").mkdir()
    shutil.copy(a.state.path, tmp_path / "clone" / "state.json")   # кто-то скопировал вход на другой ПК
    b = Client(tmp_path / "clone", "CLONE")
    statuses = []
    for _ in range(3):
        for c in (b, b, a, a):
            statuses.append((c.step() or {}).get("status"))   # шаг «токен отозван» статуса не шлёт
    # копия работает, только пока оригинал не пришёл со своим токеном; дальше в сети нет ни одного
    assert rc.Status.ONLINE not in statuses[4:], statuses
    assert "ждёт одобрения" in company.cab.get(BASE + "/cabinet").text
    cid = next(int(i) for i in __import__("re").findall(r"/admin/companies/(\d+)", server.admin.get(BASE + "/admin").text)
               if company.login in server.admin.get(BASE + f"/admin/companies/{i}").text)
    assert "token_reuse" in server.admin.get(BASE + f"/admin/companies/{cid}").text


def test_logout_revokes_token_on_server(make_client, company):
    c = make_client(); login(c, company); c.step(2)
    token = c.state.get("token")
    c.w.logout()
    assert c.state.get("token") == ""
    assert requests.get(BASE + "/api/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert login(c, company) is None and c.step(2)["status"] == rc.Status.ONLINE


GOOD_CFG = {"ip": "10.66.1.2", "address": "10.66.1.2/32", "subnet": "10.66.1.0/24", "server_ip": "10.66.0.1",
            "allowed_ips": "10.66.1.0/24, 10.66.0.1/32", "server_public_key": "S" * 43 + "=",
            "endpoint": "hub.retix.uz:51820", "keepalive": 25, "share_ports": "445", "radmin_port": 4899}


@pytest.mark.parametrize("field,value", [
    ("allowed_ips", "0.0.0.0/0"), ("allowed_ips", "10.66.1.0/24, 192.168.0.0/16"),
    ("endpoint", "hub.retix.uz:51820\nPostUp = calc.exe"), ("endpoint", "hub:99999"),
    ("server_public_key", "S" * 43 + "=\nDNS = 1.1.1.1"), ("address", "10.66.1.2/32\nTable = off"),
    ("address", "10.66.1.3/32"), ("subnet", "any"), ("subnet", "0.0.0.0/0"), ("ip", "10.66.2.5"),
    ("share_ports", "445 remoteip=any"), ("keepalive", "25\n"), ("server_ip", "8.8.8.8")])
def test_check_cfg_rejects_foreign_values(field, value):
    rc.check_cfg(GOOD_CFG)
    with pytest.raises((ValueError, TypeError)):
        rc.check_cfg(GOOD_CFG | {field: value})


def test_bad_server_config_not_installed(make_client, company):
    c = make_client(); login(c, company)
    good = c.w.api.me()
    c.w.api.me = lambda: good | {"allowed_ips": "0.0.0.0/0"}   # подменённый сервер: весь трафик через себя
    st = c.step()
    assert st["status"] == rc.Status.ERROR and c.tunnel.installs == 0


def test_peer_ip_check():
    assert rc.peer_ip_ok("10.66.1.5", "10.66.1.0/24")
    for bad in ("10.66.2.5", "8.8.8.8", "10.66.1.5 & calc", "evil.com\\share", "", None, "010.66.1.5"):
        assert not rc.peer_ip_ok(bad, "10.66.1.0/24"), bad


def test_ping_does_not_use_shell(monkeypatch):
    calls = []
    monkeypatch.setattr(rc, "WINDOWS", True)
    monkeypatch.setattr(rc.subprocess, "CREATE_NEW_CONSOLE", 0x10, raising=False)
    monkeypatch.setattr(rc.subprocess, "Popen", lambda args, **kw: calls.append(args))
    peer = {"name": "Kassa1 & calc.exe & rem", "ip": "10.66.1.5"}
    rc.App.ping(types.SimpleNamespace(selected_peer=lambda: peer))
    assert calls == [["ping", "-t", "10.66.1.5"]]
    peer["ip"] = "10.66.1.5 & calc.exe"
    with pytest.raises(ValueError):
        rc.App.ping(types.SimpleNamespace(selected_peer=lambda: peer))
    assert len(calls) == 1


@pytest.fixture()
def releases(server, tmp_path, monkeypatch):
    """Выпуски через суперадмина на живом сервере; после теста — удалить."""
    import re
    monkeypatch.setattr(rc, "UPDATE_DIR", tmp_path / "update")
    page = server.admin.get(BASE + "/admin/updates").text
    ns = types.SimpleNamespace(pub=re.search(r'id="pubkey">([^<]+)<', page).group(1),
                               csrf=re.search(r'name="csrf" value="([^"]+)"', page).group(1), launched=[], notified=[])
    monkeypatch.setattr(rc, "UPDATE_PUBLIC_KEYS", [ns.pub])

    def upload(version="9.9.9", publish=True):
        data = fake_setup(version)
        r = server.admin.post(BASE + "/admin/updates", data={"csrf": ns.csrf, **({"publish": "1"} if publish else {})},
                              files={"file": ("setup.exe", data, "application/octet-stream")})
        assert f"Версия {version} загружена" in r.text, r.text[:300]
        return data

    def updater(c):
        u = rc.Updater(c.state, c.w.api, on_update=ns.notified.append, launcher=ns.launched.append)
        c.w.api.on_hint = u.note_hint
        return u
    ns.upload, ns.updater = upload, updater
    yield ns
    page = server.admin.get(BASE + "/admin/updates").text
    for rid in set(re.findall(r"/admin/updates/(\d+)/file", page)):
        server.admin.post(BASE + f"/admin/updates/{rid}/delete", data={"csrf": ns.csrf})


def test_update_end_to_end(make_client, company, releases, server):
    c = make_client(); login(c, company); c.step(2)
    u = releases.updater(c)
    assert u.check() is None and c.state.get("update_state") == "none"          # обновлять нечего
    data = releases.upload("9.9.9")
    c.step()                                                                    # подсказка в обычном ответе
    assert u.wake.is_set() and u.last_hint == "9.9.9"
    assert u.check() == "9.9.9"
    path = releases.launched[0]
    assert path.read_bytes() == data and path.parent == rc.UPDATE_DIR and releases.notified == ["9.9.9"]
    assert c.state.get("update_state") == "installing:9.9.9"
    c.step()                                                                    # состояние ушло на сервер
    assert "устанавливает 9.9.9" in server.admin.get(BASE + "/admin/updates").text
    assert u.check() is None and len(releases.launched) == 1                    # не встала — не раньше чем через час


def test_update_with_foreign_signature_rejected(make_client, company, releases, monkeypatch):
    c = make_client(); login(c, company); c.step(2)
    releases.upload("9.9.9")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(rc, "UPDATE_PUBLIC_KEYS", [__import__("base64").b64encode(other).decode()])
    u = releases.updater(c)
    assert u.check() is None and releases.launched == []
    assert c.state.get("update_state") == "error:9.9.9"
    assert c.state.get("update_pubkey") == ""            # зашитый ключ главнее: сервер его не подменит


def test_update_key_pinned_on_first_contact(make_client, company, releases, monkeypatch):
    c = make_client(); login(c, company); c.step(2)
    monkeypatch.setattr(rc, "UPDATE_PUBLIC_KEYS", [])                           # ключ в клиент не вписан
    data = releases.upload("9.9.9")
    u = releases.updater(c)
    assert u.check() == "9.9.9" and releases.launched[0].read_bytes() == data
    assert c.state.get("update_pubkey") == releases.pub                         # запомнен
    # сервер сменил ключ (или подменён) — запомненный не меняется, чужая подпись не ставится
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    c.state.set(update_pubkey=__import__("base64").b64encode(other).decode(), update_attempt={})
    assert u.check() is None and len(releases.launched) == 1
    assert c.state.get("update_state") == "error:9.9.9"


def test_update_tampered_manifest_rejected(releases):
    import base64
    import json
    good = {"app": "Retix Hub", "kind": "retixhub-update", "version": "9.9.9", "size": 10, "sha256": "a" * 64}
    body = base64.b64encode(json.dumps(good).encode()).decode()
    with pytest.raises(rc.UpdateError):                                         # подпись от другого тела
        rc.verify_manifest({"manifest": body, "signature": base64.b64encode(b"x" * 64).decode()}, [releases.pub])
    with pytest.raises(rc.UpdateError):
        rc.verify_manifest({"manifest": "!!", "signature": ""}, [releases.pub])


def test_update_resumes_partial_download(make_client, company, releases):
    c = make_client(); login(c, company); c.step(2)
    data = releases.upload("9.9.9")
    rc.UPDATE_DIR.mkdir(parents=True)
    (rc.UPDATE_DIR / "RetixHub_Setup_9.9.9.part").write_bytes(data[:100_000])  # оборвалось на трети
    (rc.UPDATE_DIR / "RetixHub_Setup_9.9.8.exe").write_bytes(b"old")           # прошлая версия — удалится
    u = releases.updater(c)
    assert u.check() == "9.9.9"
    assert releases.launched[0].read_bytes() == data
    assert sorted(f.name for f in rc.UPDATE_DIR.iterdir()) == ["RetixHub_Setup_9.9.9.exe"]


def test_update_corrupted_partial_retried(make_client, company, releases):
    c = make_client(); login(c, company); c.step(2)
    data = releases.upload("9.9.9")
    rc.UPDATE_DIR.mkdir(parents=True)
    (rc.UPDATE_DIR / "RetixHub_Setup_9.9.9.part").write_bytes(b"X" * 100_000)  # испорченный кусок
    u = releases.updater(c)
    assert u.check() is None and c.state.get("update_state") == "error:9.9.9"
    assert not (rc.UPDATE_DIR / "RetixHub_Setup_9.9.9.part").exists()          # испорченное удалено
    assert u.check() == "9.9.9" and releases.launched[0].read_bytes() == data


def test_update_draft_and_same_version_ignored(make_client, company, releases):
    c = make_client(); login(c, company); c.step(2)
    releases.upload("9.9.9", publish=False)
    releases.upload(rc.VERSION)
    u = releases.updater(c)
    assert u.check() is None and releases.launched == []


def test_update_result_after_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "UPDATE_DIR", tmp_path / "update")
    st = rc.State(tmp_path / "s.json")
    st.set(update_attempt={"version": rc.VERSION, "at": int(time.time())}, update_state="installing:" + rc.VERSION)
    rc.UPDATE_DIR.mkdir(); (rc.UPDATE_DIR / "RetixHub_Setup_x.exe").write_bytes(b"MZ")
    rc.Updater(st, api=None)                                                    # встало
    assert st.get("update_state") == "none" and st.get("update_attempt") == {} and not any(rc.UPDATE_DIR.iterdir())
    st.set(update_attempt={"version": "99.0.0", "at": int(time.time()) - 3600})
    rc.Updater(st, api=None)                                                    # версия так и старая
    assert st.get("update_state") == "failed:99.0.0"
    st.set(update_attempt={"version": "99.0.0", "at": int(time.time())}, update_state="installing:99.0.0")
    rc.Updater(st, api=None)                                                    # установщик ещё работает
    assert st.get("update_state") == "installing:99.0.0"


def test_launch_installer_detached(monkeypatch):
    calls = []
    monkeypatch.setattr(rc.subprocess, "Popen", lambda args, **kw: calls.append(args))
    rc.launch_installer(Path("C:/ProgramData/RetixHub/update/RetixHub_Setup_1.0.6.exe"))
    args = calls[0]
    assert args[:4] == ["cmd", "/c", "start", ""] and "/VERYSILENT" in args and args[-1] == "/AUTOUPDATE=1"
