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
    tk = types.ModuleType("tkinter"); tk.Tk = tk.Toplevel = tk.Canvas = tk.Label = tk.Frame = object
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
    return _new_company(server)


@pytest.fixture()
def company2(server):
    """Вторая компания (переключение между компаниями)."""
    return _new_company(server)


def _new_company(server):
    _n[0] += 1
    login = f"co{_n[0]}"
    server.admin.post(BASE + "/admin/companies", data={"login": login, "name": login, "cabinet_password": "cab123",
                                                       "join_password": "join123", "max_devices": 20})
    cab = requests.Session()
    cab.post(BASE + "/cabinet/login", data={"login": login, "password": "cab123"})
    # новые компании ждут одобрения ПК; в сценариях оно включается явно (test_pending_then_approved)
    cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445"})
    return types.SimpleNamespace(login=login, cab=cab)


class FakeLan:
    """Локальная сеть для FakeTunnel: какой туннель на каком «ip:порт» и что заблокировано."""

    def __init__(self):
        self.hosts = {}        # "192.168.1.10:51001" -> FakeTunnel
        self.blocked = False   # пакеты по локальной сети не проходят (firewall, изоляция Wi-Fi)


class FakeTunnel:
    """Ведёт себя как служба WireGuardTunnel$retixhub (и wg show / wg set для прямых путей)."""

    def __init__(self, lan=None, lan_ip="", port=0):
        self.state = "missing"; self.hs = 0; self.installs = 0; self.starts = 0; self.conf = ""
        self.handshake_works = True; self.wg_installed = True; self.probe_ok = True
        self.lan, self.lan_ip, self.port, self.key = lan, lan_ip, 0, ""
        self.server = ("", "")              # пир сервера из конфига: (ключ, AllowedIPs)
        self.violations = []                # кто-то тронул пира сервера — так быть не должно
        self.peers = {}                    # прямые пиры: ключ -> {endpoint, allowed_ips, handshake, rx}
        self.sets = []                     # вызовы wg set (для проверок)
        self.ports = []                    # вызовы wg set listen-port
        # от этих соседей keepalive не приходит (WireGuard молчит, пока получает наши), только ответ на ping
        self.quiet_keys = set()
        self.nudges = []                   # кому слали ping через прямой путь (ответ — при следующем wg show)
        self._listen(port)

    def _listen(self, port):
        """Туннель слушает этот UDP-порт в локальной сети (как WireGuard: при запуске — случайный)."""
        if self.lan is not None and self.lan_ip:
            self.lan.hosts = {ep: t for ep, t in self.lan.hosts.items() if t is not self}
            self.lan.hosts[f"{self.lan_ip}:{port}"] = self
        self.port = port

    def installed(self): return self.wg_installed
    build_conf = staticmethod(rc.Tunnel.build_conf)
    def service_state(self): return self.state

    @staticmethod
    def _conf_value(conf, name):
        return next((line.split("=", 1)[1].strip() for line in conf.splitlines() if line.startswith(name)), "")

    def install(self, conf):
        """Ключ интерфейса — из PrivateKey конфига (как у настоящего туннеля), пир сервера — из [Peer]."""
        import base64
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as K
        self.key = base64.b64encode(K.from_private_bytes(base64.b64decode(
            self._conf_value(conf, "PrivateKey"))).public_key().public_bytes_raw()).decode()
        self.server = (self._conf_value(conf, "PublicKey"), self._conf_value(conf, "AllowedIPs").replace(" ", ""))
        self.state = "running"; self.installs += 1; self.conf = conf; self.peers = {}
        self.hs = int(time.time()) if self.handshake_works else 0
        if self.port:
            self._listen(40000 + int.from_bytes(os.urandom(2), "big") % 9000)   # новый запуск — новый порт

    def reboot(self):
        """Перезагрузка ПК: служба WireGuard поднимается сама с конфигом, но без пиров, добавленных на лету."""
        self.install(self.conf)
        self.installs -= 1

    def uninstall(self): self.state = "missing"; self.hs = 0; self.peers = {}
    def start(self): self.starts += 1; self.state = "running"

    def last_handshake(self, key=""):
        assert key, "handshake сервера — по ключу сервера, а не самый свежий из всех пиров"
        return self.hs

    def probe(self, ip): return self.state == "running" and self.probe_ok and self.hs > 0

    # --- wg show dump / wg set
    def _exchange(self):
        """Handshake и keepalive по локальной сети: оба знают друг друга, адрес верный, сеть не закрыта."""
        now = int(time.time())
        for key, p in self.peers.items():
            other = self.lan.hosts.get(p["endpoint"]) if self.lan else None
            if (other and not self.lan.blocked and other.state == "running" and other.key == key
                    and self.key in other.peers):
                p["handshake"] = other.peers[self.key]["handshake"] = now
                if key not in self.quiet_keys or self.nudges:   # на ping сосед отвечает данными
                    p["rx"] += 32
                if self.key not in other.quiet_keys:
                    other.peers[self.key]["rx"] += 32
                # роуминг WireGuard: адрес, откуда пришло — внешний адрес роутера, если сосед из другого офиса
                wan = rc.wan_endpoint_ok(p["endpoint"])
                mine = next((ep for ep, t in self.lan.hosts.items() if t is self and rc.wan_endpoint_ok(ep) == wan), "")
                other.peers[self.key]["endpoint"] = mine

    def dump(self):
        if self.state != "running":
            return None
        self._exchange()
        self.nudges = []
        peers = {k: dict(v) for k, v in self.peers.items()}
        if self.server[0]:
            peers[self.server[0]] = {"endpoint": "203.0.113.1:51820", "allowed_ips": self.server[1],
                                     "handshake": self.hs, "rx": 1}
        return {"listen_port": self.port, "peers": peers, "public_key": self.key}

    def saved_conf(self): return self.conf

    def nudge(self, ip):
        self.nudges.append(ip)

    def set_peer(self, key, endpoint="", allowed_ips=None, keepalive=None):
        if key == self.server[0]:
            self.violations.append(("set", key))
        self.sets.append((key, endpoint, allowed_ips, keepalive))
        p = self.peers.setdefault(key, {"endpoint": "", "allowed_ips": "", "handshake": 0, "rx": 0})
        if endpoint:
            p["endpoint"] = endpoint
        if allowed_ips is not None:
            p["allowed_ips"] = allowed_ips
        return True

    def remove_peer(self, key):
        if key == self.server[0]:
            self.violations.append(("remove", key))
        self.peers.pop(key, None)
    def set_listen_port(self, port): self.ports.append(port); self._listen(port); return True


LAN_NOW = {"addrs": []}   # что вернёт local_addresses() — адреса того ПК, чей шаг идёт
NICS_NOW = {"nics": []}   # что вернёт local_nics() — сетевые карты того ПК, чей шаг идёт
REAL_LOCAL_ADDRESSES = rc.local_addresses


class Client:
    """Один «компьютер»: своё состояние и свой туннель."""

    def __init__(self, tmp: Path, hostname="BUH-01", lan=None, lan_ip="", port=0):
        tmp.mkdir(parents=True, exist_ok=True)
        self.state = rc.State(tmp / "state.json"); self.state.set(server_url=BASE)
        self.tunnel = FakeTunnel(lan, lan_ip, port)
        self.lan_addrs = [f"{lan_ip}/24"] if lan_ip else []
        self.nics = []                      # сетевые карты (включение по сети): [{"addr", "mac"}]
        self.fw = []
        self.hostname = hostname
        self.events_seen = []
        self.w = rc.Worker(self.state, queue.Queue(), tunnel=self.tunnel)

    def step(self, n=1):
        for _ in range(n):
            LAN_NOW["addrs"] = self.lan_addrs
            NICS_NOW["nics"] = self.nics
            self.w.lan_checked = 0          # адреса перечитываются на каждом шаге
            self.w.nics_checked = 0
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
    monkeypatch.setattr(rc, "local_addresses", lambda: None if LAN_NOW["addrs"] is None else list(LAN_NOW["addrs"]))
    monkeypatch.setattr(rc, "ensure_autostart", lambda: calls.append(["autostart"]))
    monkeypatch.setattr(rc, "local_nics", lambda: [dict(n) for n in NICS_NOW["nics"]])
    return calls


@pytest.fixture()
def make_client(tmp_path, monkeypatch):
    fw = []
    monkeypatch.setattr(rc, "ensure_firewall", lambda subnet, ports="445": fw.append((subnet, ports)))
    clients = []

    def make(hostname="BUH-01", lan=None, lan_ip="", port=0):
        c = Client(tmp_path / f"c{len(clients)}", hostname, lan, lan_ip, port)
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


def test_rename_from_client(make_client, company):
    a = make_client("PC1"); login(a, company, name="Склад"); a.step(2)
    b = make_client("BUH-01"); login(b, company, name="Бухгалтерия"); b.step(2)
    assert a.w.rename("  ") == "Введите имя компьютера."
    assert a.w.rename(" Склад  №2 ") is None
    assert a.state.get("device_name") == "Склад №2" and a.w.cfg["device_name"] == "Склад №2"
    b.step()
    assert {p["name"] for p in b.peers} == {"Склад №2", "Бухгалтерия"}
    # повторный вход (токен сброшен) — имя то же, а не прежнее
    a.state.set(token=""); a.step(2)
    assert a.w.cfg["device_name"] == "Склад №2"


def test_rename_in_cabinet_survives_reregister(make_client, company):
    c = make_client(); login(c, company, name="Старое"); c.step(2)
    company.cab.post(BASE + f"/cabinet/devices/{device_id(company, 'Старое')}/rename", data={"value": "Касса"})
    c.step()
    assert c.state.get("device_name") == "Касса"
    c.state.set(token=""); c.step(2)
    assert c.w.cfg["device_name"] == "Касса"


def test_rename_server_down(make_client, company):
    c = make_client(); login(c, company); c.step(2)
    c.state.set(server_url="http://127.0.0.1:1")
    assert "Сервер недоступен" in c.w.rename("Новое")
    assert c.state.get("device_name") == "Бухгалтерия"


def test_peer_link_icons():
    assert rc.peer_link({"direct": True, "direct_wan": True}, True) == "wan"
    assert rc.peer_link({"direct": True}, True) == "lan"
    assert rc.peer_link({}, True) == "server"
    assert rc.peer_link({"direct": True}, False) == "off"
    pytest.importorskip("PIL")
    for kind in rc.LINK_COLORS:
        img = rc.render_link_icon(kind)
        assert img.size == (16, 16) and img.getbbox()


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


def test_group_peers_by_role():
    """Список в окне: группы по ролям из кабинета, по их порядку; без роли — последней группой."""
    peers = [{"name": "Касса 10", "role": "", "role_pos": 2}, {"name": "Склад 2", "role": "Склад", "role_pos": 1},
             {"name": "Админ", "role": "Администраторы", "role_pos": 0}, {"name": "Касса 2", "role": "", "role_pos": 2},
             {"name": "Склад 1", "role": "Склад", "role_pos": 1}]
    groups = rc.group_peers(peers)
    assert [(g, [p["name"] for p in ps]) for g, ps in groups] == [
        ("Администраторы", ["Админ"]), ("Склад", ["Склад 1", "Склад 2"]), (rc.NO_ROLE, ["Касса 2", "Касса 10"])]
    # ролей нет (или старый сервер без ролей) — один список без заголовков
    assert rc.group_peers([{"name": "B"}, {"name": "A"}]) == [("", [{"name": "A"}, {"name": "B"}])]
    assert rc.group_peers([]) == []


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
    assert c.state.get("update_pins") == {}               # зашитый ключ главнее: сервер его не подменит


def test_update_key_pinned_on_first_contact(make_client, company, releases, monkeypatch):
    c = make_client(); login(c, company); c.step(2)
    monkeypatch.setattr(rc, "UPDATE_PUBLIC_KEYS", [])                           # ключ в клиент не вписан
    data = releases.upload("9.9.9")
    u = releases.updater(c)
    assert u.check() == "9.9.9" and releases.launched[0].read_bytes() == data
    assert c.state.get("update_pins") == {BASE: releases.pub}                   # запомнен для этого сервера
    # сервер сменил ключ (или подменён) — запомненный не меняется, чужая подпись не ставится
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    c.state.set(update_pins={BASE: __import__("base64").b64encode(other).decode()}, update_attempt={})
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


# ================================================================== несколько компаний: переключение

def _devices_of(company):
    return company_peers(company)


def test_add_second_company_and_switch(make_client, company, company2):
    c = make_client(); login(c, company, name="Бух"); c.step(2)
    ip_a, key_a = c.w.cfg["ip"], c.state.keypair()[1]
    assert c.w.login(BASE, company2.login, "join123", "Бух", True) is None   # добавить вторую
    st = c.step(2)
    assert st["status"] == rc.Status.ONLINE and c.w.cfg["subnet"] != rc.ipaddress.IPv4Network(ip_a + "/24", False).with_prefixlen
    ip_b, key_b = c.w.cfg["ip"], c.state.keypair()[1]
    assert key_b != key_a and ip_b.split(".")[2] != ip_a.split(".")[2]      # свой ключ — для сервера другой ПК
    assert f"Address = {ip_b}/32" in c.tunnel.conf and c.fw[-1][0] == c.w.cfg["subnet"]
    profiles = c.state.profiles()
    assert [p["active"] for p in profiles] == [True, False]
    assert profiles[1]["company_login"] == company.login and profiles[1]["company_name"] == company.login
    # обратно в первую: тот же ключ, тот же IP, тот же ПК в кабинете — без пароля
    assert c.w.switch_to(profiles[1]["key"]) is None
    assert c.step(2)["status"] == rc.Status.ONLINE
    assert c.w.cfg["ip"] == ip_a and c.state.keypair()[1] == key_a and f"Address = {ip_a}/32" in c.tunnel.conf
    assert len(_devices_of(company)) == 1 and len(_devices_of(company2)) == 1
    # и ещё раз во вторую: токен у неё сохранился (ротация не мешает)
    key2 = next(p["key"] for p in c.state.profiles() if not p["active"])
    assert c.w.switch_to(key2) is None and c.step(2)["status"] == rc.Status.ONLINE and c.w.cfg["ip"] == ip_b


def test_add_company_wrong_password_keeps_current(make_client, company, company2):
    c = make_client(); login(c, company); c.step(2)
    ip, token = c.w.cfg["ip"], c.state.get("token")
    assert "Неверный" in c.w.login(BASE, company2.login, "wrong", "PC", True)
    assert c.state.get("company_login") == company.login and c.state.get("token") == token
    assert c.state.profiles() == [p for p in c.state.profiles() if p["active"]]   # ничего лишнего не сохранилось
    assert c.step()["status"] == rc.Status.ONLINE and c.w.cfg["ip"] == ip


def test_login_again_into_listed_company_reuses_key(make_client, company, company2):
    c = make_client(); login(c, company); c.step(2)
    key_a = c.state.keypair()[1]
    c.w.login(BASE, company2.login, "join123", "PC", True); c.step(2)
    assert c.w.login(BASE, company.login, "join123", "PC", True) is None     # через «Добавить», а она уже есть
    c.step(2)
    assert c.state.keypair()[1] == key_a and len(_devices_of(company)) == 1   # не дубль, а тот же ПК


def test_forget_company_revokes_its_login(make_client, company, company2):
    c = make_client(); login(c, company); c.step(2)
    c.w.login(BASE, company2.login, "join123", "PC", True); c.step(2)
    saved = next(p for p in c.state.profiles() if not p["active"])
    old_token = rc.unprotect(c.state.data["profiles"][saved["key"]]["token"])
    c.w.forget_company(saved["key"])
    assert [p["company_login"] for p in c.state.profiles()] == [company2.login]
    assert requests.get(BASE + "/api/me", headers={"Authorization": f"Bearer {old_token}"}).status_code == 401
    c.w.forget_company(c.state.current_key())                                # текущую так не убрать
    assert c.state.get("company_login") == company2.login


def test_logout_then_login_other_company_works(make_client, company, company2):
    c = make_client(); login(c, company); c.step(2)
    c.w.logout()
    assert c.w.login(BASE, company2.login, "join123", "PC", True) is None    # раньше: 409 «ключ в другой компании»
    assert c.step(2)["status"] == rc.Status.ONLINE
    assert [p["company_login"] for p in c.state.profiles()] == [company2.login]   # вышли — в списке не держим


def test_update_key_pinned_per_server(tmp_path):
    st = rc.State(tmp_path / "s.json")
    st.set(update_pubkey="A" * 43 + "=")                                     # 1.0.6: один запомненный ключ
    assert (st.get("update_pins") or {}) == {}                                 # ещё не по серверам — берётся старый
    st.set(update_pins={"https://a": "B" * 43 + "="})
    assert st.get("update_pins")["https://a"] == "B" * 43 + "="


def test_launch_installer_detached(monkeypatch):
    calls = []
    monkeypatch.setattr(rc.subprocess, "Popen", lambda args, **kw: calls.append(args))
    rc.launch_installer(Path("C:/ProgramData/RetixHub/update/RetixHub_Setup_1.0.6.exe"))
    args = calls[0]
    assert args[:4] == ["cmd", "/c", "start", ""] and "/VERYSILENT" in args and args[-1] == "/AUTOUPDATE=1"
    assert len(calls) == 1                                       # из исходников страховочный перезапуск не нужен
    monkeypatch.setattr(rc.sys, "frozen", True, raising=False)
    monkeypatch.setattr(rc.sys, "executable", r"C:\Program Files\RetixHub\RetixHub.exe")
    rc.launch_installer(Path("C:/ProgramData/RetixHub/update/RetixHub_Setup_1.0.6.exe"))
    watchdog = calls[-1]
    assert watchdog.startswith('cmd /s /c "ping -n 241 127.0.0.1') and 'find /I "RetixHub.exe"' in watchdog
    assert watchdog.endswith('|| start "" "C:\\Program Files\\RetixHub\\RetixHub.exe" --minimized"')


def test_hidden_peers_in_client(make_client, company):
    a = make_client("A1"); login(a, company, name="Офис"); a.step(2)
    b = make_client("B1"); login(b, company, name="Касса"); b.step(2)
    company.cab.post(BASE + f"/cabinet/devices/{b.w.cfg['device_id']}/peers_off")
    b.step(); a.step()
    assert b.w.cfg["show_peers"] is False and [p["name"] for p in b.peers] == ["Касса"]   # только он сам
    assert {p["name"] for p in a.peers} == {"Офис", "Касса"}
    assert b.w.send_message(a.w.cfg["device_id"], "привет") and a.w.send_message(b.w.cfg["device_id"], "касса?") is None
    assert b.step()["status"] == rc.Status.ONLINE                                     # сеть работает как раньше


# ================================================================== прямой путь по локальной сети

def mark_online(server, public_ip="203.0.113.5", names=None):
    """Как будто монитор сервера видит пакеты WireGuard от ПК: он онлайн и выходит в интернет с public_ip
    (один офис за одним роутером — один внешний IP)."""
    import sqlite3
    conn = sqlite3.connect(Path(server.data) / "vpn.db", timeout=10)
    now = int(time.time())
    where, args = ("", ()) if names is None else (f" WHERE name IN ({','.join('?' * len(names))})", tuple(names))
    conn.execute("UPDATE devices SET endpoint=?||':'||(40000+id), last_handshake=?, last_rx_at=?" + where,
                 (public_ip, now, now) + args)
    conn.commit(); conn.close()


def full_lan(company, on=True):
    data = {"share_name": "share", "share_ports": "445"} | ({"full_lan": "1"} if on else {})
    company.cab.post(BASE + "/cabinet/settings", data=data)


def lan_pair(make_client, company, server, lan=None, public_ip="203.0.113.5"):
    """Два ПК одного офиса: 192.168.1.10 и .11, компания с «любым трафиком между ПК»."""
    lan = lan or FakeLan()
    full_lan(company)
    a = make_client("PC1", lan, "192.168.1.10", 51001); login(a, company, name="Склад"); a.step(2)
    b = make_client("PC2", lan, "192.168.1.11", 51002); login(b, company, name="Бухгалтерия"); b.step(2)
    mark_online(server, public_ip)
    return lan, a, b


def direct_peer(c, other):
    return c.tunnel.peers.get(other.state.keypair()[1])


def test_direct_path_same_lan(make_client, company, server):
    """ПК одного офиса: после handshake по локальной сети трафик к соседу идёт напрямую (AllowedIPs /32),
    а пир сервера не меняется — остальные ПК по-прежнему через сервер."""
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step(); b.step()
    pa, pb = direct_peer(a, b), direct_peer(b, a)
    assert pa and pa["allowed_ips"] == f"{b.w.cfg['ip']}/32" and pa["endpoint"] == f"192.168.1.11:{b.tunnel.port}"
    assert pb and pb["allowed_ips"] == f"{a.w.cfg['ip']}/32"
    assert a.w.direct.active_ids() == [b.w.cfg["device_id"]] and b.w.direct.active_ids() == [a.w.cfg["device_id"]]
    assert a.w.cfg["server_public_key"] not in a.tunnel.peers               # пира сервера не трогаем
    assert any(k == b.state.keypair()[1] and ka == rc.DIRECT_KEEPALIVE for k, _, _, ka in a.tunnel.sets)
    assert a.tunnel.installs == 1                                           # без переустановки туннеля
    peers = {p["name"]: p for p in a.peers}
    assert peers["Бухгалтерия"]["direct"] and not peers["Склад"]["direct"]
    # сервер знает о прямом пути — видно в кабинете
    mark_online(server)
    assert "напрямую: Бухгалтерия" in company.cab.get(BASE + "/cabinet").text
    # firewall: входящие UDP на порт туннеля из локальной сети
    assert a.state.get("fw_direct") == a.tunnel.port


def test_direct_needs_full_lan(make_client, company, server, patch_windows):
    """Без «любого трафика между ПК» прямых путей нет: правила сервера (ping, папки, Radmin) обходить нельзя.
    Адреса локальной сети серверу при этом не отправляются."""
    lan = FakeLan()
    a = make_client("PC1", lan, "192.168.1.10", 51001); login(a, company, name="A"); a.step(2)
    b = make_client("PC2", lan, "192.168.1.11", 51002); login(b, company, name="B"); b.step(2)
    mark_online(server)
    a.step(2); b.step(2)
    assert a.w.cfg["direct"] == [] and not a.tunnel.peers and not b.tunnel.peers
    assert a.w.lan == [] and not a.state.get("fw_direct")


def test_direct_turned_off_returns_to_server(make_client, company, server):
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step(); b.step()
    assert direct_peer(a, b)["allowed_ips"]
    full_lan(company, on=False)
    a.step(); b.step()
    assert not a.tunnel.peers and not b.tunnel.peers and a.w.direct.active_ids() == []
    assert a.state.get("fw_direct") == 0


def test_direct_other_office_not_neighbors(make_client, company, server):
    """Другой внешний IP — другой офис: в 192.168.1.0/24 там совсем другие компьютеры."""
    lan, a, b = lan_pair(make_client, company, server)
    mark_online(server, "198.51.100.7", names=["Бухгалтерия"])
    a.step(); b.step()
    assert a.w.cfg["direct"] == [] and not a.tunnel.peers and not b.tunnel.peers


def test_direct_lan_blocked_falls_back(make_client, company, server, monkeypatch):
    """Пакеты по локальной сети не проходят (изоляция Wi-Fi, чужой firewall): сосед удаляется,
    трафик остаётся через сервер, новая попытка — не сразу."""
    monkeypatch.setattr(rc, "DIRECT_PROBE_SECONDS", -1)
    lan, a, b = lan_pair(make_client, company, server)
    lan.blocked = True
    a.step()
    assert direct_peer(a, b) and not direct_peer(a, b)["allowed_ips"]   # проверка: трафик ещё через сервер
    a.step()
    assert not a.tunnel.peers and a.w.direct.active_ids() == []
    a.step()
    assert not a.tunnel.peers                                          # повтор — после DIRECT_RETRY_FAILED


def test_direct_lost_falls_back(make_client, company, server, monkeypatch):
    """Прямой путь работал и пропал (ноутбук ушёл из офиса): от соседа нет пакетов — снова через сервер."""
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step()
    assert direct_peer(a, b)["allowed_ips"]
    lan.blocked = True
    monkeypatch.setattr(rc, "DIRECT_RX_TIMEOUT", -1)
    a.step()
    assert not a.tunnel.peers and a.w.direct.active_ids() == []


def test_direct_lan_retry_in_common_slot(make_client, company, server, monkeypatch):
    """Путь пропал у обоих ПК в разное время — оба повторяют в начале общего окна по часам сервера, а не
    каждый через своё время: иначе проверка одного попадала на паузу другого раз за разом."""
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step(); b.step()
    assert direct_peer(a, b)["allowed_ips"]
    lan.blocked = True
    monkeypatch.setattr(rc, "DIRECT_RX_TIMEOUT", -1)
    a.step()
    time.sleep(1.2)                                                        # B замечает обрыв позже A
    b.step()
    ka, kb = b.state.keypair()[1], a.state.keypair()[1]
    ua, ub = a.w.direct.backoff[ka][0], b.w.direct.backoff[kb][0]
    for u, c in ((ua, a), (ub, b)):
        t = (u + c.w.direct.clock) % rc.DIRECT_RETRY_LOST
        assert min(t, rc.DIRECT_RETRY_LOST - t) < 1e-3 and time.time() < u <= time.time() + rc.DIRECT_RETRY_LOST + 1
    assert abs(ua - ub) < 1.5 or abs(abs(ua - ub) - rc.DIRECT_RETRY_LOST) < 1.5   # одно окно (или соседнее)
    # окно наступило — оба пробуют снова одновременно и соединяются
    lan.blocked = False
    monkeypatch.setattr(rc, "DIRECT_RX_TIMEOUT", 35)
    for c, k in ((a, ka), (b, kb)):
        c.w.direct.backoff[k] = (time.time() - 1, c.w.direct.backoff[k][1])
    a.step(); b.step(); a.step(); b.step()
    assert direct_peer(a, b)["allowed_ips"] and direct_peer(b, a)["allowed_ips"]


def test_direct_quiet_neighbor_kept_by_ping(make_client, company, server, monkeypatch):
    """WireGuard соседа молчит (получает наши keepalive и потому своих не шлёт) — путь жив: программа шлёт
    соседу ping через прямой путь, ответ приходит. Без ping такой путь закрывался через 35 с."""
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step(); b.step()
    assert direct_peer(a, b)["allowed_ips"]
    a.tunnel.quiet_keys = {b.state.keypair()[1]}
    monkeypatch.setattr(rc, "DIRECT_NUDGE_AFTER", 0.2)
    monkeypatch.setattr(rc, "DIRECT_RX_TIMEOUT", 1.0)
    for _ in range(4):
        time.sleep(0.4); a.step()
    assert direct_peer(a, b)["allowed_ips"] and a.w.direct.active_ids() == [b.w.cfg["device_id"]]
    assert a.tunnel.nudges == [b.w.cfg["ip"]]                              # ping — соседу по адресу в сети компании
    # без ping (как раньше) — молчание принимается за обрыв
    monkeypatch.setattr(rc, "DIRECT_NUDGE_AFTER", 10 ** 6)
    a.tunnel.nudges = []
    time.sleep(1.2); a.step()
    assert direct_peer(a, b) is None


def test_direct_neighbor_blocked_is_removed(make_client, company, server):
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step()
    assert direct_peer(a, b)["allowed_ips"]
    company.cab.post(BASE + f"/cabinet/devices/{b.w.cfg['device_id']}/block")
    a.step()
    assert not a.tunnel.peers


def test_direct_survives_server_outage(make_client, company, server):
    """Сервер лёг — прямые пути остаются: ПК одного офиса продолжают видеть друг друга."""
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step()
    server.stop()
    try:
        st = a.step()
        assert st["status"] == rc.Status.LAN_ONLY and direct_peer(a, b)["allowed_ips"]
        assert "напрямую" in st["text"]
        peers = {p["name"]: p for p in a.peers}
        assert peers["Бухгалтерия"]["online"] and peers["Бухгалтерия"]["direct"]
    finally:
        server.start()


def test_direct_reset_on_reinstall(make_client, company, server):
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step()
    assert a.w.direct.active_ids()
    a.w.force_reconnect(); a.step()                        # туннель переустановлен — пиров в нём нет
    assert a.w.direct.active_ids() == [] and not a.tunnel.peers
    a.step(); b.step(); a.step()
    assert direct_peer(a, b)["allowed_ips"]


def test_direct_path_survives_unreadable_lan_addresses(make_client, company, server):
    """PowerShell не успел прочитать адреса — это не «локальной сети нет»: порт и прямой путь остаются,
    сервер не перестаёт называть ПК соседом (раньше путь «моргал» у обоих ПК)."""
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step(); b.step()
    assert direct_peer(a, b)["allowed_ips"]
    a.lan_addrs = None
    a.step(); mark_online(server); b.step()
    assert a.w.lan == ["192.168.1.10/24"] and a.state.get("fw_direct") == a.tunnel.port
    assert direct_peer(a, b)["allowed_ips"] and direct_peer(b, a)["allowed_ips"]


def test_direct_neighbor_kept_after_short_rx_gap(make_client, company, server):
    """Сервер 60 с не видел пакетов от соседа (потерялся keepalive): «в сети» уже нет, но соседа для прямого
    пути он ещё называет — работающий путь не закрывается."""
    import sqlite3
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step(); b.step()
    conn = sqlite3.connect(Path(server.data) / "vpn.db", timeout=10)
    conn.execute("UPDATE devices SET last_rx_at=? WHERE name='Бухгалтерия'", (int(time.time()) - 60,))
    conn.commit(); conn.close()
    a.step()
    assert direct_peer(a, b)["allowed_ips"]
    conn = sqlite3.connect(Path(server.data) / "vpn.db", timeout=10)
    conn.execute("UPDATE devices SET last_rx_at=? WHERE name='Бухгалтерия'", (int(time.time()) - 200,))
    conn.commit(); conn.close()
    a.step()
    assert direct_peer(a, b) is None                     # действительно пропал — путь закрыт


def test_direct_neighbors_validation():
    cfg = {"direct_enabled": True, "ip": "10.66.3.2", "subnet": "10.66.3.0/24", "server_ip": "10.66.0.1",
           "server_public_key": "S" * 43 + "="}
    good = {"id": 5, "public_key": "A" * 43 + "=", "ip": "10.66.3.7", "endpoints": ["192.168.1.11:51002"]}
    assert rc.direct_neighbors(cfg | {"direct": [good]}) == [good]
    assert rc.direct_neighbors(cfg | {"direct_enabled": False, "direct": [good]}) == []
    bad = [
        good | {"ip": "10.66.4.7"},                        # чужая подсеть
        good | {"ip": "10.66.3.2"},                        # свой адрес
        good | {"ip": "10.66.0.1"},                        # сервер
        good | {"public_key": "S" * 43 + "="},             # ключ сервера
        good | {"public_key": "x\nAllowedIPs=0.0.0.0/0"},
        good | {"endpoints": ["8.8.8.8:53"]},              # интернет — не локальная сеть
        good | {"endpoints": ["10.66.3.9:51820"]},          # сеть Retix Hub
        good | {"endpoints": ["127.0.0.1:51820", "169.254.1.1:1"]},
        good | {"endpoints": ["192.168.1.11:0"]},
        good | {"endpoints": ["192.168.1.11"]},
        {"id": 1},
    ]
    assert rc.direct_neighbors(cfg | {"direct": bad}) == []
    assert rc.direct_neighbors(cfg | {"direct": [good]}, own_key=good["public_key"]) == []
    mixed = rc.direct_neighbors(cfg | {"direct": [good | {"endpoints": ["8.8.8.8:1", "10.0.5.3:51002"]}]})
    assert mixed[0]["endpoints"] == ["10.0.5.3:51002"]


def test_wg_dump_and_handshake_parsing(monkeypatch):
    out = ("PRIV\tPUB\t51234\toff\n"
           "SRV=\t(none)\t203.0.113.1:51820\t10.66.3.0/24,10.66.0.1/32\t1700000000\t100\t200\t25\n"
           "NB=\t(none)\t(none)\t(none)\t0\t0\t0\t10\n")
    d = rc.parse_wg_dump(out)
    assert d["listen_port"] == 51234
    assert d["peers"]["NB="] == {"endpoint": "", "allowed_ips": "", "handshake": 0, "rx": 0}
    assert d["peers"]["SRV="]["handshake"] == 1700000000
    monkeypatch.setattr(rc, "run", lambda args, timeout=60: (0, "SRV=\t1700000000\nNB=\t1800000000\n"))
    assert rc.Tunnel.last_handshake("SRV=") == 1700000000      # прямой сосед не маскирует связь с сервером
    assert rc.Tunnel.last_handshake("GONE=") == 0
    assert rc.Tunnel.last_handshake() == 1800000000


def test_local_addresses_filter(monkeypatch):
    out = ("1: lo    inet 127.0.0.1/8 scope host lo\n"
           "2: eth0    inet 192.168.1.15/24 brd 192.168.1.255 scope global eth0\n"
           "3: wifi    inet 169.254.3.4/16 scope link wifi\n"
           "4: retixhub    inet 10.66.3.2/32 scope global retixhub\n"
           "5: wan    inet 8.8.4.4/24 scope global wan\n"
           "6: office    inet 10.1.2.3/8 scope global office\n")
    monkeypatch.setattr(rc, "WINDOWS", False)
    monkeypatch.setattr(rc, "run", lambda args, timeout=60: (0, out))
    assert REAL_LOCAL_ADDRESSES() == ["192.168.1.15/24", "10.1.2.3/8"]
    monkeypatch.setattr(rc, "run", lambda args, timeout=60: (1, "timeout"))
    assert REAL_LOCAL_ADDRESSES() is None


# ------------------------------------------------------------------ сохранённые соседи (без сервера)

def established(make_client, company, server):
    lan, a, b = lan_pair(make_client, company, server)
    a.step(); b.step(); a.step(); b.step()
    assert direct_peer(a, b)["allowed_ips"] and direct_peer(b, a)["allowed_ips"]
    return lan, a, b


def restart(c):
    """Программа перезапущена: новый Worker с тем же state.json (память о прошлом запуске — только на диске)."""
    c.state = rc.State(c.state.path)
    c.w = rc.Worker(c.state, queue.Queue(), tunnel=c.tunnel)
    c.peers = []


def server_down(server):
    class Down:
        def __enter__(self): server.stop()
        def __exit__(self, *a): server.start()
    return Down()


def test_direct_cache_saved(make_client, company, server):
    lan, a, b = established(make_client, company, server)
    cache = a.state.get("direct_cache")
    (n,) = cache["neighbors"]
    assert n["public_key"] == b.state.keypair()[1] and n["ip"] == b.w.cfg["ip"] and n["name"] == "Бухгалтерия"
    assert n["endpoints"][0] == f"192.168.1.11:{b.tunnel.port}"
    assert cache["my_port"] == a.tunnel.port and cache["cfg"]["server_public_key"] == a.w.cfg["server_public_key"]
    import json
    raw = json.dumps(cache)
    assert a.state.keypair()[0] not in raw and "token" not in raw   # в списке нет секретов


def test_reboot_without_internet_uses_saved_neighbors(make_client, company, server):
    """Оба ПК перезагрузились без интернета: туннель без прямых пиров, порт новый — прямой путь
    поднимается по сохранённому списку (порт возвращается прежний), в окне — «Только локальная сеть»."""
    lan, a, b = established(make_client, company, server)
    port_a, port_b = a.tunnel.port, b.tunnel.port
    with server_down(server):
        for c in (a, b):
            c.tunnel.reboot(); restart(c)
        assert a.tunnel.port != port_a and not a.tunnel.peers
        a.step(); b.step()
        assert (a.tunnel.port, b.tunnel.port) == (port_a, port_b)   # прежний порт — соседи его знают
        st = a.step(); b.step()
        assert st["status"] == rc.Status.LAN_ONLY, st
        assert direct_peer(a, b)["allowed_ips"] == a.state.get("direct_cache")["neighbors"][0]["ip"] + "/32"
        assert direct_peer(b, a)["allowed_ips"]
        assert st["cfg"]["ip"] and st["cfg"]["company"]
        peers = {p["name"]: p for p in a.peers}
        assert peers["Бухгалтерия"]["online"] and peers["Бухгалтерия"]["direct"]
    # сервер вернулся — обычная работа, прямой путь снова от сервера
    for _ in range(3):
        st = a.step(); b.step()
    assert st["status"] == rc.Status.ONLINE and direct_peer(a, b)["allowed_ips"]


def test_saved_neighbors_expire(make_client, company, server):
    lan, a, b = established(make_client, company, server)
    cache = a.state.get("direct_cache")
    a.state.set(direct_cache=dict(cache, saved_at=int(time.time()) - (rc.DIRECT_CACHE_DAYS * 86400 + 60)))
    with server_down(server):
        a.tunnel.reboot(); restart(a)
        st = a.step(); a.step()
        assert st["status"] == rc.Status.SERVER_DOWN and not a.tunnel.peers


def test_expired_cache_closes_live_paths(make_client, company, server):
    """Сервер недоступен дольше срока: работавшие прямые пути закрываются."""
    lan, a, b = established(make_client, company, server)
    with server_down(server):
        assert a.step()["status"] == rc.Status.LAN_ONLY
        cache = a.state.get("direct_cache")
        a.state.set(direct_cache=dict(cache, saved_at=int(time.time()) - rc.DIRECT_CACHE_DAYS * 86400 - 60))
        st = a.step()
        assert st["status"] == rc.Status.SERVER_DOWN and not a.tunnel.peers


def test_server_list_replaces_saved(make_client, company, server):
    """Сосед заблокирован, пока ПК на связи с сервером, — из сохранённого списка он исчезает сразу,
    и без сервера прямого пути к нему уже нет."""
    lan, a, b = established(make_client, company, server)
    company.cab.post(BASE + f"/cabinet/devices/{b.w.cfg['device_id']}/block")
    a.step()
    assert a.state.get("direct_cache")["neighbors"] == []
    with server_down(server):
        a.tunnel.reboot(); restart(a)
        st = a.step(); a.step()
        assert st["status"] == rc.Status.SERVER_DOWN and not a.tunnel.peers


def test_saved_cleared_on_logout_and_full_lan_off(make_client, company, server):
    lan, a, b = established(make_client, company, server)
    full_lan(company, on=False)
    a.step()
    assert a.state.get("direct_cache") == {}
    full_lan(company); mark_online(server)
    a.step(); b.step(); a.step(); b.step(); a.step()
    assert a.state.get("direct_cache")["neighbors"]
    b.w.logout()
    assert b.state.get("direct_cache") == {}


def test_tampered_cache_is_validated(make_client, company, server):
    """Подменённый список (файл только для администраторов, но всё же): чужая подсеть, интернет-адрес,
    ключ сервера — не попадают в WireGuard; пир сервера не удаляется, даже если ключ сервера в списке другой."""
    lan, a, b = established(make_client, company, server)
    cache = a.state.get("direct_cache")
    srv_key = a.w.cfg["server_public_key"]
    bad = [{"id": 9, "public_key": "A" * 43 + "=", "ip": "10.66.99.5", "endpoints": ["192.168.1.50:5000"],
            "verified_at": int(time.time())},
           {"id": 8, "public_key": "B" * 43 + "=", "ip": cache["neighbors"][0]["ip"], "endpoints": ["8.8.8.8:53"],
            "verified_at": int(time.time())},
           {"id": 7, "public_key": srv_key, "ip": cache["neighbors"][0]["ip"], "endpoints": ["192.168.1.9:1"],
            "verified_at": int(time.time())}]
    a.state.set(direct_cache=dict(cache, neighbors=bad, cfg=dict(cache["cfg"], server_public_key="C" * 43 + "=")))
    with server_down(server):
        a.step(); a.step()
    assert not a.tunnel.peers and not a.tunnel.violations and a.tunnel.server[0] == srv_key


def test_port_kept_after_reinstall(make_client, company, server):
    lan, a, b = established(make_client, company, server)
    port = a.tunnel.port
    a.w.force_reconnect(); a.step()                      # туннель переустановлен — WireGuard взял новый порт
    assert a.tunnel.port != port
    a.step()
    assert a.tunnel.port == port and a.tunnel.ports[-1] == port


# ------------------------------------------------------------------ обход всех состояний

def db_exec(server, sql, args=()):
    import sqlite3
    conn = sqlite3.connect(Path(server.data) / "vpn.db", timeout=10)
    conn.execute(sql, args); conn.commit(); conn.close()


NO_DIRECT = {rc.Status.OFF, rc.Status.BLOCKED, rc.Status.NEED_LOGIN, rc.Status.PENDING}


def check_invariants(c, st):
    """Правила, которые держатся в любом состоянии."""
    t = c.tunnel
    assert not t.violations, f"тронули пира сервера: {t.violations}"
    status = st and st["status"]
    assert status in {getattr(rc.Status, k) for k in dir(rc.Status) if not k.startswith("_")}, st
    if status in NO_DIRECT:
        assert not any(p["allowed_ips"] for p in t.peers.values()), (status, t.peers)
        assert not c.w.direct.active_ids(), status
    if status == rc.Status.LAN_ONLY:
        assert c.w.direct.active_ids()
    cfg = c.w.cfg or (c.state.get("direct_cache") or {}).get("cfg") or {}
    for key, p in t.peers.items():
        if p["allowed_ips"]:
            ip = p["allowed_ips"].removesuffix("/32")
            assert p["allowed_ips"].endswith("/32") and ip != cfg.get("ip")
            assert rc.peer_ip_ok(ip, cfg.get("subnet")), (ip, cfg.get("subnet"))
            assert rc.lan_endpoint_ok(p["endpoint"]), p["endpoint"]


def walk(c, n=1):
    st = None
    for _ in range(n):
        st = c.step()
        check_invariants(c, st)
    return st


def is_direct(c, other):
    p = direct_peer(c, other)
    return bool(p and p["allowed_ips"])


def test_state_machine_walk(make_client, company, company2, server, monkeypatch):
    """Два ПК одного офиса проходят через все состояния; после каждого шага — check_invariants."""
    monkeypatch.setattr(rc, "DIRECT_RETRY_LOST", 0)
    monkeypatch.setattr(rc, "DIRECT_RETRY_FAILED", 0)
    lan, a, b = established(make_client, company, server)
    def both(n=1):                       # шаги по очереди: A, B, A, B…
        st = None
        for _ in range(n):
            st = walk(a); walk(b)
        return st
    S = rc.Status

    # 1. в сети, напрямую
    mark_online(server)
    assert both()["status"] == S.ONLINE and is_direct(a, b) and is_direct(b, a)

    # 2. сервер пропал → «Только локальная сеть»
    server.stop()
    try:
        assert both()["status"] == S.LAN_ONLY

        # 3. OFF без сервера: туннель снят, прямых путей нет
        a.w.set_enabled(False)
        assert walk(a)["status"] == S.OFF and a.tunnel.state == "missing"

        # 4. ON без сервера: туннель из последнего конфига, прямой путь снова
        a.w.set_enabled(True)
        walk(a); walk(b)
        st = both(2)
        assert st["status"] == S.LAN_ONLY and is_direct(a, b) and is_direct(b, a)

        # 5. служба остановлена (без сервера) — запускается, локальная сеть работает
        a.tunnel.state = "stopped"
        assert walk(a)["status"] == S.LAN_ONLY and a.tunnel.state == "running"
    finally:
        server.start()

    # 6. сервер вернулся
    mark_online(server)
    st = both(3)
    assert st["status"] == S.ONLINE and is_direct(a, b)

    # 7. B снова ждёт одобрения → у B прямых путей нет, A его убирает
    db_exec(server, "UPDATE devices SET is_approved=0 WHERE id=?", (b.w.cfg["device_id"],))
    assert walk(b)["status"] == S.PENDING and not b.tunnel.peers
    assert b.state.get("direct_cache") == {}
    walk(a)
    assert not direct_peer(a, b)

    # 8. одобрен → снова напрямую
    db_exec(server, "UPDATE devices SET is_approved=1 WHERE id=?", (b.w.cfg["device_id"],))
    mark_online(server); walk(b, 2); mark_online(server)
    both(3)
    assert is_direct(a, b) and is_direct(b, a)

    # 9. B заблокирован → туннель B снят, A его убирает; разблокирован → всё вернулось
    company.cab.post(BASE + f"/cabinet/devices/{b.w.cfg['device_id']}/block")
    assert walk(b)["status"] == S.BLOCKED and b.tunnel.state == "missing"
    walk(a)
    assert not direct_peer(a, b)
    company.cab.post(BASE + f"/cabinet/devices/{b.w.cfg['device_id']}/unblock")
    walk(b, 3); mark_online(server); both(3)
    assert is_direct(a, b) and is_direct(b, a)

    # 10. A входит во вторую компанию (без «любого трафика»): чужих соседей нет ни в туннеле, ни в списке
    assert login(a, company2, name="Склад") is None
    walk(a, 2)
    assert not a.tunnel.peers and a.state.get("direct_cache") == {}
    key1 = rc.State.profile_key(BASE, company.login)
    key2 = rc.State.profile_key(BASE, company2.login)
    assert a.state.profiles() and a.state.get("profiles")[key1]["direct_cache"]["neighbors"]

    # 11. без сервера переключаемся обратно: туннель ещё второй компании — соседей первой в него не кладём
    server.stop()
    try:
        assert a.w.switch_to(key1) is None
        st = walk(a)
        assert st["status"] == S.SERVER_DOWN and not a.tunnel.peers
    finally:
        server.start()
    mark_online(server)
    walk(a, 3); mark_online(server); both(3)
    assert walk(a)["status"] == S.ONLINE and is_direct(a, b)

    # 12. «любой трафик» выключен → прямых путей нет, список очищен
    full_lan(company, on=False)
    both()
    assert not a.tunnel.peers and not b.tunnel.peers and a.state.get("direct_cache") == {}

    # 13. выход из сети
    full_lan(company); mark_online(server); both(3)
    assert is_direct(a, b)
    a.w.logout()
    st = a.last()
    check_invariants(a, st)
    assert st["status"] == S.NEED_LOGIN and not a.tunnel.peers and a.state.get("direct_cache") == {}
    assert a.state.get("fw_direct") == 0
    walk(b)
    assert not direct_peer(b, a)
    assert key2 in a.state.get("profiles")


# ================================================================== прямой путь через интернет (разные офисы)

OFFICE_A, OFFICE_B = "81.95.10.5", "84.54.20.7"


def wan_pair(make_client, company, server):
    """Два ПК разных офисов: у каждого своя локальная сеть и свой роутер с внешним адресом. Сосед доступен
    по внешнему адресу, только если оба шлют друг другу (FakeTunnel: handshake, когда пиры есть у обоих)."""
    net = FakeLan()
    full_lan(company)
    a = make_client("PC1", net, "192.168.1.10", 51001); login(a, company, name="Ташкент"); a.step(2)
    b = make_client("PC2", net, "192.168.5.11", 51002); login(b, company, name="Самарканд"); b.step(2)
    mark_online(server, OFFICE_A, names=["Ташкент"]); mark_online(server, OFFICE_B, names=["Самарканд"])
    for c, pub in ((a, OFFICE_A), (b, OFFICE_B)):
        net.hosts[f"{pub}:{40000 + c.w.cfg['device_id']}"] = c.tunnel    # «дверь» в роутере офиса
    return net, a, b


def test_direct_path_wan(make_client, company, server):
    """ПК разных офисов: сервер даёт внешние адреса, оба пробуют одновременно — связь напрямую через интернет.
    Пир сервера не трогается, туннель не переустанавливается."""
    net, a, b = wan_pair(make_client, company, server)
    a.step(); b.step(); a.step(); b.step()
    pa, pb = direct_peer(a, b), direct_peer(b, a)
    assert pa and pa["allowed_ips"] == f"{b.w.cfg['ip']}/32"
    assert pa["endpoint"] == f"{OFFICE_B}:{40000 + b.w.cfg['device_id']}"
    assert pb and pb["allowed_ips"] == f"{a.w.cfg['ip']}/32" and pb["endpoint"].startswith(OFFICE_A)
    assert a.w.cfg["direct"] == [] and [n["id"] for n in a.w.cfg["direct_wan"]] == [b.w.cfg["device_id"]]
    assert a.w.direct.wan_ids() == {b.w.cfg["device_id"]} and a.w.direct.active_ids() == [b.w.cfg["device_id"]]
    assert any(ka == rc.DIRECT_KEEPALIVE_WAN for k, _, _, ka in a.tunnel.sets if k == b.state.keypair()[1])
    assert a.tunnel.violations == [] and a.tunnel.installs == 1
    peers = {p["name"]: p for p in a.peers}
    assert peers["Самарканд"]["direct"] and peers["Самарканд"]["direct_wan"]
    mark_online(server, OFFICE_A, names=["Ташкент"]); mark_online(server, OFFICE_B, names=["Самарканд"])
    assert "напрямую: Самарканд" in company.cab.get(BASE + "/cabinet").text
    # прямой путь через интернет не сохраняется для работы без интернета (он без сервера не найдётся)
    assert a.state.get("direct_cache")["neighbors"] == []


def test_wan_nat_not_passable_falls_back_in_common_slot(make_client, company, server, monkeypatch):
    """Роутер не умеет (симметричный NAT): handshake не проходит — трафик остаётся через сервер, а новая
    попытка — в начале общего окна по часам сервера, у обоих ПК в одно и то же время."""
    monkeypatch.setattr(rc, "DIRECT_PROBE_WAN", -1)
    net, a, b = wan_pair(make_client, company, server)
    net.blocked = True
    a.step(); b.step()
    assert direct_peer(a, b) and not direct_peer(a, b)["allowed_ips"]     # проверка — трафик ещё через сервер
    a.step(); b.step()
    assert not a.tunnel.peers and not b.tunnel.peers and a.w.direct.active_ids() == []
    ka, kb = b.state.keypair()[1], a.state.keypair()[1]
    ua, ub = a.w.direct.backoff[ka][0], b.w.direct.backoff[kb][0]
    assert abs(ua - ub) < 2 and time.time() < ua <= time.time() + rc.DIRECT_SLOT_WAN_FAILED
    assert abs((ua + a.w.direct.clock) % rc.DIRECT_SLOT_WAN_FAILED) < 1e-3 or \
        abs((ua + a.w.direct.clock) % rc.DIRECT_SLOT_WAN_FAILED - rc.DIRECT_SLOT_WAN_FAILED) < 1e-3
    a.step()
    assert not a.tunnel.peers                                              # до окна не пробуем
    # окно наступило, роутер «починили» — оба пробуют снова и соединяются
    net.blocked = False
    monkeypatch.setattr(rc, "DIRECT_PROBE_WAN", 25)
    for c, k in ((a, ka), (b, kb)):
        c.w.direct.backoff[k] = (time.time() - 1, c.w.direct.backoff[k][1])
    a.step(); b.step(); a.step(); b.step()
    assert direct_peer(a, b)["allowed_ips"] and direct_peer(b, a)["allowed_ips"]


def test_wan_lost_falls_back(make_client, company, server, monkeypatch):
    net, a, b = wan_pair(make_client, company, server)
    a.step(); b.step(); a.step()
    assert direct_peer(a, b)["allowed_ips"]
    net.blocked = True
    monkeypatch.setattr(rc, "DIRECT_RX_TIMEOUT", 10 ** 6)                  # таймаут локальной сети не при чём
    monkeypatch.setattr(rc, "DIRECT_RX_TIMEOUT_WAN", -1)
    a.step()
    assert not a.tunnel.peers and a.w.direct.active_ids() == []
    until = a.w.direct.backoff[b.state.keypair()[1]][0]
    assert time.time() < until <= time.time() + rc.DIRECT_SLOT_WAN_LOST + 1


def test_wan_kept_while_server_down(make_client, company, server):
    """Сервер лёг, интернет есть — прямой путь через интернет продолжает работать."""
    net, a, b = wan_pair(make_client, company, server)
    a.step(); b.step(); a.step(); b.step()
    server.stop()
    try:
        st = a.step()
        assert st["status"] == rc.Status.LAN_ONLY and direct_peer(a, b)["allowed_ips"]
        peers = {p["name"]: p for p in a.peers}
        assert peers["Самарканд"]["online"] and peers["Самарканд"]["direct_wan"]
    finally:
        server.start()


def test_wan_off_when_full_lan_off(make_client, company, server):
    net, a, b = wan_pair(make_client, company, server)
    a.step(); b.step(); a.step()
    assert direct_peer(a, b)["allowed_ips"]
    full_lan(company, on=False)
    a.step(); b.step()
    assert not a.tunnel.peers and not b.tunnel.peers


def test_wan_neighbors_validation():
    cfg = {"direct_enabled": True, "ip": "10.66.3.2", "subnet": "10.66.3.0/24", "server_ip": "10.66.0.1",
           "server_public_key": "S" * 43 + "="}
    good = {"id": 5, "public_key": "A" * 43 + "=", "ip": "10.66.3.7", "endpoints": ["84.54.20.7:40005"]}
    assert rc.wan_neighbors(cfg | {"direct_wan": [good]}) == [good | {"wan": True}]
    assert rc.wan_neighbors(cfg | {"direct_enabled": False, "direct_wan": [good]}) == []
    assert rc.wan_neighbors(cfg | {"direct_wan": [good]}, skip={good["public_key"]}) == []   # уже сосед по LAN
    bad = [
        good | {"ip": "10.66.4.7"}, good | {"ip": "10.66.3.2"}, good | {"ip": "10.66.0.1"},
        good | {"public_key": "S" * 43 + "="}, good | {"public_key": "x\nAllowedIPs=0.0.0.0/0"},
        good | {"endpoints": ["192.168.1.11:51002"]},       # локальная сеть — не интернет
        good | {"endpoints": ["100.64.1.1:40005"]},          # CGNAT
        good | {"endpoints": ["127.0.0.1:1", "10.66.3.9:51820", "84.54.20.7:0", "84.54.20.7", "[::1]:5"]},
        {"id": 1},
    ]
    assert rc.wan_neighbors(cfg | {"direct_wan": bad}) == []
    # локальные адреса через «интернет»-список не проходят и наоборот
    assert rc.direct_neighbors(cfg | {"direct": [good]}) == []


def test_wan_slots_align_across_clocks():
    """Окно попыток считается по часам сервера: ПК с отстающими часами попадает в тот же момент."""
    on_time, behind = rc.DirectPaths(None), rc.DirectPaths(None)
    on_time.clock, behind.clock = 0.0, 7.0                 # часы второго ПК отстают на 7 с
    t = 1_700_000_123.0
    assert on_time.next_slot(t, 600) == behind.next_slot(t - 7, 600) + 7 == 1_700_000_400.0


def test_heartbeat_reports_wan_support(make_client, company, server):
    import sqlite3
    a = make_client("PC1"); login(a, company, name="A"); a.step(2)
    conn = sqlite3.connect(Path(server.data) / "vpn.db", timeout=10)
    assert conn.execute("SELECT wan_ok FROM devices WHERE name='A'").fetchone()[0] == 1
    conn.close()


# ================================================================== меню управления через Radmin Viewer

def test_radmin_menu_only_with_server_there_and_viewer_here(tmp_path):
    viewer = tmp_path / "Radmin.exe"; viewer.write_bytes(b"MZ")
    assert rc.radmin_menu_allowed({"radmin_server": True}, viewer)
    assert not rc.radmin_menu_allowed({"radmin_server": True}, None)          # здесь нет Radmin Viewer
    assert not rc.radmin_menu_allowed({"radmin_server": False}, viewer)       # там нет Radmin Server
    assert not rc.radmin_menu_allowed({}, viewer)                             # старый клиент не сообщил
    assert not rc.radmin_menu_allowed(None, viewer)
    assert not rc.radmin_server_installed()                                   # не Windows — нет


def test_radmin_server_reported_to_other_pcs(make_client, company, monkeypatch):
    has = {"v": True}
    monkeypatch.setattr(rc, "radmin_server_installed", lambda: has["v"])
    a = make_client("PC1"); login(a, company, name="Касса"); a.step(2)
    b = make_client("PC2"); login(b, company, name="Офис"); b.step(2)
    a.step()
    assert {p["name"]: p["radmin_server"] for p in a.peers} == {"Касса": True, "Офис": True}
    has["v"] = False
    b.w.radmin_checked = 0                 # следующая проверка — сразу (обычно раз в 5 минут)
    b.step(); a.step()
    assert {p["name"]: p["radmin_server"] for p in a.peers}["Офис"] is False


# ================================================================== 1.0.16: удалённое управление (RustDesk)

FAKE_RUSTDESK = Path("C:/Program Files/RustDesk/rustdesk.exe")


class FakeRustDesk:
    """RustDesk одного ПК: настройки (--option), постоянный пароль (--password), идёт ли сеанс."""

    def __init__(self, installed=True):
        self.options, self.password, self.calls = {}, "", []
        self.installed, self.sessions = installed, False
        self.service = "running" if installed else "missing"   # служба RustDesk: running / stopped / missing


RD_NOW = {"rd": None}   # RustDesk того ПК, чей шаг идёт


@pytest.fixture()
def fake_rustdesk(monkeypatch, patch_windows):
    def run(args, timeout=60):
        patch_windows.append(args)
        rd = RD_NOW["rd"]
        if rd and args and args[0] == str(FAKE_RUSTDESK):
            rd.calls.append(list(args[1:]))
            if args[1] == "--option" and len(args) == 4:
                rd.options[args[2]] = args[3]
            elif args[1] == "--option" and len(args) == 3:
                return 0, rd.options.get(args[2], "") + "\n"
            elif args[1] == "--password":
                rd.password = args[2]
                return 0, "Done!\n"
        return 0, ""
    monkeypatch.setattr(rc, "run", run)
    monkeypatch.setattr(rc, "run_rd", run)
    monkeypatch.setattr(rc.Worker, "REMOTE_ASYNC", False)   # в тестах — сразу, без своего потока
    monkeypatch.setattr(rc, "rustdesk_exe", lambda: FAKE_RUSTDESK if RD_NOW["rd"] and RD_NOW["rd"].installed else None)
    monkeypatch.setattr(rc, "rustdesk_session_active", lambda port=rc.REMOTE_PORT: RD_NOW["rd"].sessions)
    monkeypatch.setattr(rc, "rustdesk_service_state", lambda: RD_NOW["rd"].service)
    monkeypatch.setattr(rc, "rustdesk_ready", lambda: RD_NOW["rd"].service == "running")
    monkeypatch.setattr(rc, "RUSTDESK_START_WAIT", 0)
    monkeypatch.setattr(rc, "rustdesk_msi_product", lambda: None)

    def sc(args, timeout=60):
        if args[:2] == ["sc", "start"] and RD_NOW["rd"].start_works:
            RD_NOW["rd"].service = "running"
        return run(args, timeout)
    monkeypatch.setattr(FakeRustDesk, "start_works", True, raising=False)
    monkeypatch.setattr(rc, "run", sc)
    yield patch_windows
    RD_NOW["rd"] = None


def allow_control(company, name):
    """Кабинет: этому ПК можно управлять другими."""
    r = company.cab.post(BASE + f"/cabinet/devices/{device_id(company, name)}/control_on")
    assert "может управлять" in r.text


def controller(make_client, company, name="Админ"):
    """ПК, которому администратор разрешил управлять другими (без своего RustDesk — только для списка)."""
    c = make_client("ADMIN-PC"); login(c, company, name=name)
    allow_control(company, name)
    return c


def step_as(c, rd, n=1):
    RD_NOW["rd"] = rd
    return c.step(n)


def _set_online(server, *names, used_ago=None):
    import sqlite3
    conn = sqlite3.connect(Path(server.data) / "vpn.db", timeout=10)
    now = int(time.time())
    for name in names:
        conn.execute("UPDATE devices SET last_handshake=?, last_rx_at=? WHERE name=?", (now, now, name))
        if used_ago is not None:
            conn.execute("UPDATE devices SET remote_used_at=? WHERE name=?", (now - used_ago, name))
    conn.commit(); conn.close()


def test_remote_control_end_to_end(make_client, company, server, fake_rustdesk):
    calls = fake_rustdesk
    a, rda = make_client("PC1"), FakeRustDesk()
    login(a, company, name="Склад"); step_as(a, rda, 2)
    b, rdb = make_client("PC2"), FakeRustDesk()
    login(b, company, name="Касса"); step_as(b, rdb, 2)
    assert rda.calls == [] and rdb.calls == []                  # выключено в кабинете — RustDesk не трогаем
    assert a.w.remote_connect(b.w.cfg["device_id"])[1] == "Удалённое управление выключено в кабинете компании"

    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "auto"})
    step_as(b, rdb, 2)
    assert rdb.options == {} and b.w.remote_ok is False         # управлять некому — RustDesk на B не открыт
    RD_NOW["rd"] = rda
    assert a.w.remote_connect(b.w.cfg["device_id"])[1].startswith("Администратор компании не разрешил")
    allow_control(company, "Склад")
    step_as(b, rdb, 2); step_as(a, rda, 2)
    # RustDesk на B пускает только A — единственный ПК, которому разрешено управлять
    assert rdb.options["direct-server"] == "Y" and rdb.options["whitelist"] == a.w.cfg["ip"]
    assert rdb.options["approve-mode"] == "password"
    # серверы RustDesk не участвуют: вместо них — сервер Retix Hub внутри VPN
    assert rdb.options["custom-rendezvous-server"] == rdb.options["relay-server"] == "10.66.0.1"
    assert len(rdb.password) >= 12 and b.state.get("remote_pw_pending") == ""
    rules = [" ".join(c) for c in calls if c[:1] == ["netsh"] and "add" in c]
    assert any("RetixHub RustDesk only VPN (out)" in r and "action=block" in r and "10.67.0.0" in r for r in rules)
    assert any(f"name=RetixHub RustDesk " in r and f"remoteip={a.w.cfg['ip']}" in r and "localport=21118" in r
               for r in rules)
    # A управляет, но им самим управлять некому: его RustDesk подключений не принимает
    assert rda.options.get("direct-server") in (None, "N") and a.w.remote_ok is False

    _set_online(server, "Склад", "Касса")
    step_as(a, rda)
    peer_b = next(p for p in a.peers if p["name"] == "Касса")
    RD_NOW["rd"] = rda
    assert peer_b["remote"] is True and rc.remote_menu_allowed(peer_b, a.w.cfg)
    assert not rc.remote_menu_allowed(next(p for p in a.peers if p["is_me"]), a.w.cfg)
    res, err = a.w.remote_connect(peer_b["id"])
    assert err is None and res["ip"] == b.w.cfg["ip"] and res["password"] == rdb.password
    assert rc.rustdesk_args(FAKE_RUSTDESK, res["ip"], res["port"], "control", res["password"]) == \
        [str(FAKE_RUSTDESK), "--connect", b.w.cfg["ip"], "--password", rdb.password]

    # пароль выдан: пока идёт сеанс — не меняется, после — новый, и сервер выдаёт уже его
    first = rdb.password
    _set_online(server, "Касса", used_ago=300)
    rdb.sessions = True
    step_as(b, rdb)
    assert rdb.password == first
    rdb.sessions = False
    step_as(b, rdb)
    assert rdb.password == first                     # сеанс проверяется не чаще раза в 30 с
    b.w.remote_session_checked = 0
    step_as(b, rdb)
    assert rdb.password != first
    RD_NOW["rd"] = rda
    assert a.w.remote_connect(peer_b["id"])[0]["password"] == rdb.password

    # выключили в кабинете — RustDesk больше не принимает подключения
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "off"})
    step_as(b, rdb)
    assert rdb.options["direct-server"] == "N" and b.state.get("remote_applied") == ""
    step_as(a, rda)
    assert all(p["remote"] is False for p in a.peers)


def test_remote_ask_mode_and_install(make_client, company, server, fake_rustdesk, monkeypatch):
    rd = FakeRustDesk(installed=False)
    installs = []
    monkeypatch.setattr(rc, "install_rustdesk",
                        lambda: (installs.append(1), setattr(rd, "installed", True), setattr(rd, "service", "running"))[0]
                        or True)
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "ask"})
    controller(make_client, company)
    c = make_client("PC1"); login(c, company, name="Касса"); step_as(c, rd, 2)
    assert installs == [1] and c.state.get("rustdesk_by_retix") is True     # поставлен этой программой
    assert rd.options["approve-mode"] == "click" and rd.password == ""       # с согласием — пароль не нужен
    assert c.w.remote_ok is True
    rc.uninstall_remote(c.state)
    assert rd.calls[-1] == ["--uninstall"] and c.state.get("rustdesk_by_retix") is False


def test_remote_not_configured_not_ready(make_client, company, fake_rustdesk, monkeypatch):
    """Служба RustDesk не ответила — ПК не говорит серверу «готов», и настройки повторяются."""
    rd = FakeRustDesk()
    monkeypatch.setattr(rc, "configure_rustdesk", lambda exe, opts: False)
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "auto"})
    controller(make_client, company)
    c = make_client("PC1"); login(c, company, name="Касса"); step_as(c, rd, 2)
    assert c.w.remote_ok is False and c.state.get("remote_applied") == "" and rd.password == ""


def test_rustdesk_helpers(tmp_path, monkeypatch):
    opts = rc.rustdesk_options("auto", "10.66.3.0/24", "10.66.0.1")
    assert opts["whitelist"] == "10.66.3.0/24" and opts["direct-access-port"] == "21118"
    assert rc.rustdesk_options("ask", "10.66.3.0/24", "10.66.0.1")["approve-mode"] == "click"
    assert opts["enable-tunnel"] == opts["enable-terminal"] == "N" and opts["access-mode"] == "custom"
    exe = Path("C:/RD/rustdesk.exe")
    assert rc.rustdesk_args(exe, "10.66.3.5", 21118, "files") == [str(exe), "--file-transfer", "10.66.3.5"]
    assert rc.rustdesk_args(exe, "10.66.3.5", 21200, "control")[2] == "10.66.3.5:21200"
    pw = rc.new_remote_password()
    assert rc.REMOTE_PW_RE.match(pw) and pw != rc.new_remote_password()
    for name in ("rustdesk-1.4.2-x86_64.exe", "rustdesk-1.10.0-x86_64.exe", "rustdesk-1.9.9-x86_64.exe"):
        (tmp_path / name).write_bytes(b"MZ")
    monkeypatch.setattr(rc, "app_dir", lambda: tmp_path)
    assert rc.rustdesk_installer().name == "rustdesk-1.10.0-x86_64.exe"       # самая новая версия
    assert not rc.remote_menu_allowed({"remote": True}, {"remote": {"mode": "off"}})
    assert not rc.remote_menu_allowed({"remote": True}, {})                    # старый сервер


def test_run_rd_does_not_wait_for_children():
    """1.0.17: rustdesk.exe --silent-install запускает службу и значок у часов, они наследуют вывод.
    subprocess.run с каналами ждал их вечно (и после таймаута) — висел весь цикл программы."""
    t = time.time()
    code, out = rc.run_rd(["sh", "-c", "(sleep 20 &); echo Done!"], timeout=10)
    assert code == 0 and "Done!" in out and time.time() - t < 5
    t = time.time()
    assert rc.run_rd(["sleep", "20"], timeout=1) == (-1, "timeout") and time.time() - t < 5


def test_remote_work_never_blocks_main_loop(make_client, company, monkeypatch):
    """RustDesk завис (установка, служба не отвечает) — основной цикл идёт дальше, второй раз не запускается."""
    import threading
    release, started = threading.Event(), []

    def stuck(now, cfg):
        started.append(1)
        release.wait(30)
    monkeypatch.setattr(rc.Worker, "_remote_work", lambda self, now, cfg: stuck(now, cfg))
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "auto"})
    c = make_client("PC1"); login(c, company, name="Касса")
    t = time.time()
    assert c.step(3)["status"] == rc.Status.ONLINE and time.time() - t < 10
    assert started == [1]                       # пока прошлая работа идёт — новую не начинаем
    release.set(); c.w.remote_job.join(5)
    c.step()
    assert len(started) == 2
    release.set()


def test_remote_half_installed_rustdesk_is_repaired(make_client, company, fake_rustdesk, monkeypatch):
    """1.0.18: после оборванной установки (1.0.16) rustdesk.exe есть, а службы RustDesk нет. Такой RustDesk
    не настраивается (--option пишет только себе, --password — os error 2): ставим его заново."""
    rd = FakeRustDesk()
    rd.service = "missing"
    installs = []
    monkeypatch.setattr(rc, "install_rustdesk", lambda: (installs.append(1), setattr(rd, "service", "running"))[0] or True)
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "auto"})
    controller(make_client, company)
    c = make_client("PC1"); login(c, company, name="N11"); step_as(c, rd, 2)
    assert installs == [1] and c.w.remote_ok is True and rd.password
    assert c.state.get("rustdesk_by_retix") is True


def test_remote_stopped_service_started_or_not_configured(make_client, company, fake_rustdesk, patch_windows):
    """Служба RustDesk остановлена — запускаем; не поднялась — ничего не настраиваем и не говорим «готов»."""
    rd = FakeRustDesk()
    rd.service = "stopped"
    rd.start_works = False
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "auto"})
    controller(make_client, company)
    c = make_client("PC1"); login(c, company, name="N11"); step_as(c, rd, 2)
    assert ["sc", "start", "RustDesk"] in patch_windows
    assert c.w.remote_ok is False and rd.options == {} and rd.password == ""
    rd.start_works = True
    step_as(c, rd)
    assert rd.service == "running" and c.w.remote_ok is True and rd.options["direct-server"] == "Y" and rd.password


def test_peers_sorted_by_name_offline_stays_in_place():
    peers = [{"name": "Касса 10", "online": True}, {"name": "склад", "online": False},
             {"name": "Касса 2", "online": False}, {"name": "Бухгалтерия", "online": True}]
    assert [p["name"] for p in rc.sort_peers(peers)] == ["Бухгалтерия", "Касса 2", "Касса 10", "склад"]


def test_remote_user_choice_own_password_and_off(make_client, company, server, fake_rustdesk):
    """Пользователь ПК сам решает, как им управлять (только строже администратора): свой пароль сервер
    не узнаёт и не выдаёт; «запретить» — RustDesk подключений не принимает."""
    import sqlite3
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "auto"})
    a, rda = controller(make_client, company, "Склад"), FakeRustDesk()
    step_as(a, rda)
    b, rdb = make_client("PC2"), FakeRustDesk()
    login(b, company, name="Касса"); step_as(b, rdb, 2)
    server_pw = rdb.password
    assert server_pw and rdb.options["approve-mode"] == "password"

    assert b.w.set_remote_access("own", "short") .startswith("Пароль")
    assert b.w.set_remote_access("own", "") == "Придумайте пароль."
    assert b.w.set_remote_access("own", "My-Secret#2026") is None
    stored = b.state.get("remote_own_pw")      # через protect(): на Windows — DPAPI, не открытым текстом
    assert stored.startswith("dpapi:" if rc.WINDOWS else "plain:") and rc.unprotect(stored) == "My-Secret#2026"
    step_as(b, rdb, 2)
    assert rdb.password == "My-Secret#2026" and rdb.options["approve-mode"] == "password"
    conn = sqlite3.connect(Path(server.data) / "vpn.db", timeout=10)
    row = conn.execute("SELECT remote_pw, remote_local FROM devices WHERE ip=?", (b.w.cfg["ip"],)).fetchone()
    conn.close()
    assert row == ("", "own")                       # сервер не знает ни свой пароль, ни прежний
    _set_online(server, "Склад", "Касса")
    RD_NOW["rd"] = rda
    res, err = a.w.remote_connect(b.w.cfg["device_id"])
    assert err is None and res["mode"] == "own" and res["password"] == ""

    assert b.w.set_remote_access("off") is None
    step_as(b, rdb)
    assert rdb.options["direct-server"] == "N" and b.w.remote_ok is False
    RD_NOW["rd"] = rda
    assert "так решил его пользователь" in a.w.remote_connect(b.w.cfg["device_id"])[1]

    assert b.w.set_remote_access("") is None       # снова как администратор — новый пароль от программы
    step_as(b, rdb, 2)
    assert rdb.options["direct-server"] == "Y" and rdb.password not in ("My-Secret#2026", server_pw)
    RD_NOW["rd"] = rda
    assert a.w.remote_connect(b.w.cfg["device_id"])[0]["password"] == rdb.password


def test_combine_remote_mode():
    c = rc.combine_remote_mode
    assert c("auto", "", False) == "auto" and c("ask", "", False) == "ask" and c("off", "", True) == "off"
    assert c("auto", "ask", False) == "ask" and c("auto", "off", True) == "off"
    assert c("ask", "own", True) == "own" and c("auto", "own", False) == "ask"   # без пароля — только согласие
    assert c("off", "own", True) == "off"                                        # администратор выключил
    with pytest.raises(ValueError):
        rc.rustdesk_options("auto", "", "10.66.0.1")                             # пустой whitelist пустил бы всех


def test_remote_broken_msi_rustdesk_removed_then_installed(make_client, company, fake_rustdesk, monkeypatch):
    """1.0.19: на ПК стоял RustDesk из MSI без службы. Установщик-exe поверх MSI не ставит («Cannot install the
    EXE package over an existing MSI installation») — сломанный MSI удаляется тихо, потом ставится RustDesk."""
    rd = FakeRustDesk()
    rd.service = "missing"
    steps = []
    guid = "{CD24A421-5DFB-4EC7-9E1A-7930D58ADA49}"
    monkeypatch.setattr(rc, "rustdesk_msi_product", lambda: guid)
    monkeypatch.setattr(rc, "remove_rustdesk_msi", lambda product: steps.append(("msi", product)) or True)
    monkeypatch.setattr(rc, "install_rustdesk",
                        lambda: steps.append(("install",)) or setattr(rd, "service", "running") or True)
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "ask"})
    controller(make_client, company)
    c = make_client("PC1"); login(c, company, name="Касса"); step_as(c, rd, 2)
    assert steps == [("msi", guid), ("install",)] and c.w.remote_ok is True


def test_msi_guid_parse_and_remove(monkeypatch):
    assert rc.MSI_GUID_RE.search("MsiExec.exe /qn /X {CD24A421-5DFB-4EC7-9E1A-7930D58ADA49}").group(0) == \
        "{CD24A421-5DFB-4EC7-9E1A-7930D58ADA49}"
    calls = []
    monkeypatch.setattr(rc, "run_rd", lambda args, timeout=30: (calls.append(args), (1605, ""))[1])
    assert rc.remove_rustdesk_msi("{CD24A421-5DFB-4EC7-9E1A-7930D58ADA49}") is True    # уже удалён — тоже успех
    assert calls[-1] == ["msiexec", "/x", "{CD24A421-5DFB-4EC7-9E1A-7930D58ADA49}", "/qn", "/norestart"]
    monkeypatch.setattr(rc, "run_rd", lambda args, timeout=30: (1603, "ошибка"))
    assert rc.remove_rustdesk_msi("{CD24A421-5DFB-4EC7-9E1A-7930D58ADA49}") is False


def test_stop_service_mark_cleared_before_install(tmp_path, monkeypatch):
    """1.0.19: с stop-service = 'Y' в настройках RustDesk его установщик не создаёт службу (оставалось от
    прежнего RustDesk). Перед установкой отметка снимается, остальные настройки не трогаются."""
    cfg = tmp_path / "RustDesk" / "config" / "RustDesk2.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("rendezvous_server = ''\n\n[options]\nstop-service = 'Y'\nwhitelist = '10.66.1.5'\n", "utf-8")
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("SystemRoot", str(tmp_path / "nowin"))
    assert rc.clear_rustdesk_stop_service() is True
    assert cfg.read_text("utf-8") == "rendezvous_server = ''\n\n[options]\nwhitelist = '10.66.1.5'\n"
    assert rc.clear_rustdesk_stop_service() is False                      # уже чисто — файл не трогаем
    calls = []
    cfg.write_text("[options]\nstop-service = 'Y'\n", "utf-8")
    setup = tmp_path / "rustdesk-1.5.3-x86_64.exe"; setup.write_bytes(b"MZ")
    monkeypatch.setattr(rc, "app_dir", lambda: tmp_path)
    monkeypatch.setattr(rc, "run_rd", lambda args, timeout=30: (calls.append(cfg.read_text("utf-8")), (0, ""))[1])
    monkeypatch.setattr(rc, "rustdesk_exe", lambda: None)
    monkeypatch.setattr(rc.time, "sleep", lambda s: None)
    rc.install_rustdesk()
    assert calls and "stop-service" not in calls[0]                        # к началу установки отметки уже нет


def test_menu_repair_rustdesk(make_client, company, fake_rustdesk, patch_windows, monkeypatch, tmp_path):
    """Меню «Управление»: установить/запустить службу RustDesk и переустановить RustDesk."""
    rd = FakeRustDesk()
    c = make_client("PC1"); login(c, company, name="Касса"); step_as(c, rd)
    RD_NOW["rd"] = rd
    installs = []
    monkeypatch.setattr(rc, "install_rustdesk", lambda: installs.append(1) or setattr(rd, "service", "running") or True)
    monkeypatch.setattr(rc, "rustdesk_installer", lambda: tmp_path / "rustdesk-1.5.3-x86_64.exe")

    assert c.w.repair_rustdesk() == (True, "RustDesk работает, служба запущена.") and installs == []
    rd.service = "stopped"
    assert c.w.repair_rustdesk() == (True, "Служба RustDesk запущена.") and ["sc", "start", "RustDesk"] in patch_windows
    rd.service = "missing"
    ok, text = c.w.repair_rustdesk()
    assert ok and installs == [1] and c.state.get("rustdesk_by_retix") is True
    ok, text = c.w.repair_rustdesk(reinstall=True)                      # работает — всё равно переставить
    assert ok and installs == [1, 1] and text == "RustDesk установлен, служба работает."
    # RustDesk после починки никуда, кроме сети Retix Hub, не ходит — даже если удалённое управление выключено
    assert any("RetixHub RustDesk only VPN (out)" in " ".join(a) and "action=block" in " ".join(a) for a in patch_windows)
    assert "Служба RustDesk:  работает" in c.w.rustdesk_status() and "Управлять этим ПК:  нельзя" in c.w.rustdesk_status()
    monkeypatch.setattr(rc, "rustdesk_installer", lambda: None)
    rd.service = "missing"
    ok, text = c.w.repair_rustdesk()
    assert not ok and "Установщика RustDesk нет" in text


# ================================================================== включение по сети (Wake-on-LAN)

REAL_LOCAL_NICS = rc.local_nics


def test_local_nics_parses_powershell(monkeypatch):
    out = ("192.168.1.15/24 AA-BB-CC-DD-EE-FF\r\n10.66.1.2/32 \r\n169.254.3.4/16 11-22-33-44-55-66\r\n"
           "127.0.0.1/8 \r\n192.168.1.15/24 AA-BB-CC-DD-EE-FF\r\n172.16.0.9/16 \r\n192.168.7.2/32 AA-BB-CC-00-00-01\r\n"
           "10.0.0.5/8 02-00-4C-4F-4F-50\r\n")
    monkeypatch.setattr(rc, "WINDOWS", True)
    monkeypatch.setattr(rc, "run", lambda args, timeout=60: (0, out))
    assert REAL_LOCAL_NICS() == [{"addr": "192.168.1.15/24", "mac": "AA:BB:CC:DD:EE:FF"},
                                 {"addr": "10.0.0.5/8", "mac": "02:00:4C:4F:4F:50"}]
    monkeypatch.setattr(rc, "run", lambda args, timeout=60: (1, "timeout"))
    assert REAL_LOCAL_NICS() is None


def test_magic_packet_and_job_check():
    assert rc.clean_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert rc.clean_mac("01:00:5e:00:00:01") == "" and rc.clean_mac("FF:FF:FF:FF:FF:FF") == "" and rc.clean_mac("x") == ""
    pkt = rc.magic_packet("AA:BB:CC:DD:EE:FF")
    assert len(pkt) == 102 and pkt[:6] == b"\xff" * 6 and pkt[6:12] == bytes.fromhex("AABBCCDDEEFF")
    nics = [{"addr": "192.168.1.15/24", "mac": "AA:BB:CC:DD:EE:01"}]
    assert rc.wake_job_ok({"mac": "AA:BB:CC:DD:EE:02", "broadcast": "192.168.1.255"}, nics)
    # пакет — только на широковещательный адрес своей сети: сервер не может «направить» его куда-то ещё
    assert not rc.wake_job_ok({"mac": "AA:BB:CC:DD:EE:02", "broadcast": "192.168.2.255"}, nics)
    assert not rc.wake_job_ok({"mac": "AA:BB:CC:DD:EE:02", "broadcast": "8.8.8.8"}, nics)
    assert not rc.wake_job_ok({"mac": "AA:BB:CC:DD:EE:02", "broadcast": "192.168.1.255"}, None)
    assert not rc.wake_job_ok({"mac": "bad", "broadcast": "192.168.1.255"}, nics)
    assert not rc.wake_job_ok("мусор", nics)


def test_wake_on_lan_end_to_end(make_client, company, server, monkeypatch):
    sent = []
    monkeypatch.setattr(rc, "send_magic_packet", lambda mac, bcast: (sent.append((mac, bcast)), True)[1])
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "ask"})
    a = make_client("KASSA"); a.nics = [{"addr": "192.168.1.20/24", "mac": "AA:BB:CC:DD:EE:01"}]
    login(a, company, name="Касса"); a.step(2)
    b = make_client("SKLAD"); b.nics = [{"addr": "192.168.1.30/24", "mac": "AA:BB:CC:DD:EE:02"}]
    login(b, company, name="Склад"); b.step(2)
    assert a.w.cfg["wol"] is True and a.w.nics == a.nics
    import sqlite3
    conn = sqlite3.connect(Path(server.data) / "vpn.db", timeout=10)
    kassa = device_id(company, "Касса")
    assert "AA:BB:CC:DD:EE:01" in conn.execute("SELECT nics FROM devices WHERE id=?", (kassa,)).fetchone()[0]
    _set_online(server, "Склад")                                 # Касса выключена, Склад в сети
    r = company.cab.post(BASE + f"/cabinet/devices/{kassa}/wake")
    assert "отправлена через Склад" in r.text
    b.step()
    assert sent == [("AA:BB:CC:DD:EE:01", "192.168.1.255")]
    b.step()
    assert len(sent) == 1                                       # команда выполняется один раз

    # из программы: только ПК, которому администратор разрешил управлять
    _set_online(server, "Склад"); b.step()
    peer = next(p for p in b.peers if p["name"] == "Касса")
    assert not rc.wake_menu_allowed(peer)
    assert "разрешил управлять" in b.w.wake_peer(kassa)[1]
    allow_control(company, "Склад")
    _set_online(server, "Склад"); b.step()
    peer = next(p for p in b.peers if p["name"] == "Касса")
    assert rc.wake_menu_allowed(peer) and not rc.wake_menu_allowed(next(p for p in b.peers if p["is_me"]))
    time.sleep(0.01)
    conn.execute("UPDATE wake_requests SET created_at=created_at-60 WHERE target_id=?", (kassa,)); conn.commit()
    msg, err = b.w.wake_peer(kassa)
    assert err is None and "отправлена через Склад" in msg
    b.step()
    assert len(sent) == 2

    # удалённое управление выключили — MAC больше не сообщается, команды не принимаются
    company.cab.post(BASE + "/cabinet/settings", data={"share_name": "share", "share_ports": "445",
                                                       "remote_mode": "off"})
    b.step()
    assert b.w.cfg["wol"] is False and b.w.nics is None


def test_wake_job_for_foreign_network_ignored(make_client, company, monkeypatch):
    sent = []
    monkeypatch.setattr(rc, "send_magic_packet", lambda mac, bcast: sent.append((mac, bcast)))
    c = make_client(); c.nics = [{"addr": "192.168.1.30/24", "mac": "AA:BB:CC:DD:EE:02"}]
    login(c, company); c.step(2)
    c.w.cfg = dict(c.w.cfg, wol=True, wake=[{"mac": "AA:BB:CC:DD:EE:01", "broadcast": "10.20.30.255"},
                                            {"mac": "AA:BB:CC:DD:EE:01", "broadcast": "192.168.1.255"}])
    c.w._wol_step(time.time())
    assert sent == [("AA:BB:CC:DD:EE:01", "192.168.1.255")]


# ================================================================== журнал программы по запросу администратора

def test_pack_log_fits_limit():
    body = os.urandom(300_000)                                  # не сжимается
    data = rc.pack_log("заголовок\n", body, limit=100_000)
    import gzip
    text = gzip.decompress(data)
    assert len(data) <= 100_000 and text.startswith("заголовок\n".encode()) and body.endswith(text[-1000:])


def test_log_request_end_to_end(make_client, company, server, monkeypatch, tmp_path):
    logs = tmp_path / "logs"; logs.mkdir()
    (logs / "client.log.1").write_text("старая строка\n", encoding="utf-8")
    (logs / "client.log").write_text("строка журнала\n" * 1000, encoding="utf-8")
    monkeypatch.setattr(rc, "log_dir", lambda: logs)
    c = make_client("KASSA-01")
    login(c, company, name="Касса"); c.step(2)
    assert c.w.cfg["log_request"] is False
    pc = device_id(company, "Касса")
    r = company.cab.post(BASE + f"/cabinet/devices/{pc}/log_request")
    assert "Журнал Касса запрошен" in r.text
    c.step()
    page = company.cab.get(BASE + "/cabinet").text
    import re
    m = re.search(r'href="/cabinet/logs/(\d+)"', page)
    assert m, page[-3000:]
    text = company.cab.get(BASE + f"/cabinet/logs/{m.group(1)}").text
    assert text.startswith(f"Retix Hub {rc.VERSION} — журнал программы")
    assert "ПК: Касса" in text and "старая строка" in text and text.rstrip().endswith("строка журнала")
    assert c.state.get("token") not in text and "join123" not in text   # без секретов
    c.step()
    assert c.w.cfg["log_request"] is False
    assert len(re.findall(r'href="/cabinet/logs/', company.cab.get(BASE + "/cabinet").text)) == 1   # один раз


# ================================================================== сборка для Windows 8.1

def test_win81_build_config():
    """Один установщик для 8.1/10/11: на 8.1 — своя сборка (Python 3.11, старая cryptography) и WireGuard 0.5.3."""
    import re
    client = ROOT / "client"
    iss = (client / "RetixHub.iss").read_text(encoding="utf-8-sig")
    assert re.search(r"^MinVersion=6\.3", iss, re.M)                       # ставится на 8.1
    files = [l for l in iss.splitlines() if l.startswith("Source:")]
    win10 = [l for l in files if "Check: not IsWin81" in l]
    win81 = [l for l in files if re.search(r"Check: IsWin81\b", l)]
    assert any("{#DistDir}" in l for l in win10) and any("wireguard\\wireguard-amd64" in l for l in win10)
    assert any("{#Dist81Dir}" in l for l in win81) and any("wireguard81\\wireguard-amd64" in l for l in win81)
    # программа и WireGuard — только с условием: на ПК не попадают обе сборки сразу
    assert not [l for l in files if ("DistDir" in l or "wireguard" in l) and "IsWin81" not in l]
    assert "ucrtbase.dll" in iss                                           # 8.1 без UCRT — понятная ошибка
    # cryptography для 8.1 — собрана до Rust 1.78 (ему нужна Windows 10)
    pins = (client / "requirements-win81.txt").read_text(encoding="utf-8")
    m = re.search(r"^cryptography==(\d+)\.(\d+)\.(\d+)$", pins, re.M)
    assert m and tuple(map(int, m.groups())) <= (42, 0, 5)
    bat = (client / "build.bat").read_text(encoding="utf-8")
    assert "-c requirements-win81.txt" in bat and "--distpath dist81" in bat and "call :selftest dist81\\RetixHub" in bat
    wg = (client / "get_wireguard.ps1").read_text(encoding="utf-8-sig")
    assert "Get-WireGuard 'wireguard81'" in wg and "'0.5.3'" in wg
    wf = (ROOT / ".github/workflows/client.yml").read_text(encoding="utf-8")
    assert "python-version: '3.11'" in wf and "PY81: ${{ steps.py311.outputs.python-path }}" in wf


# ================================================================== блокировка программы паролем этого ПК

def test_lock_password_hash():
    stored = rc.hash_lock_pw("1234", rounds=1000)
    assert "1234" not in stored and stored.startswith("pbkdf2$1000$")
    assert rc.check_lock_pw("1234", stored) and not rc.check_lock_pw("12345", stored)
    assert rc.hash_lock_pw("1234", rounds=1000) != stored            # своя соль каждый раз
    assert not rc.check_lock_pw("1234", "") and not rc.check_lock_pw("1234", "pbkdf2$x$y$z")


def test_lock_settings(make_client):
    c = make_client()
    w = c.w
    assert not w.lock_ready()
    assert c.state.get("lock_minutes") == rc.LOCK_DEFAULT_MINUTES == 10
    assert w.set_lock(True, 10).startswith("Придумайте пароль")      # без пароля блокировать нечем
    assert w.set_lock(True, 7, "1234").startswith("Выберите")
    assert w.set_lock(True, 10, "12 3").startswith("Пароль")          # пробелы нельзя
    assert w.set_lock(True, 10, "ключ1") is None and w.lock_ready()
    assert w.check_unlock("ключ1") and not w.check_unlock("ключ2")
    assert "ключ1" not in c.state.path.read_text("utf-8")           # на диске — только хэш
    assert w.set_lock(False, 5) is None and not w.lock_ready() and c.state.get("lock_minutes") == 5
    assert w.check_unlock("ключ1")                                    # пароль остался — включить можно без него
    assert w.set_lock(True, 5) is None and w.lock_ready()


def test_own_access_password_locks_program(make_client, company):
    """Пароль доступа «по моему паролю» — он же пароль блокировки программы."""
    c = make_client(); login(c, company); c.step(2)
    assert c.w.set_remote_access("own", "My-Secret#2026") is None
    assert c.w.lock_ready() and c.w.check_unlock("My-Secret#2026")


def test_forgotten_lock_reset_by_company_password(make_client, company):
    a = make_client("PC-A"); login(a, company, remember=True); a.step(2)
    a.w.set_lock(True, 10, "1111")
    assert a.w.reset_lock("wrong-pass") == "Неверный пароль подключения компании."
    assert a.w.lock_ready()
    assert a.w.reset_lock("join123") is None and not a.w.lock_ready()
    # пароль подключения не сохранён — его проверяет сервер (повторный вход тем же ключом)
    b = make_client("PC-B"); login(b, company, remember=False, name="Склад"); b.step(2)
    b.w.set_lock(True, 10, "2222")
    assert b.w.reset_lock("wrong-pass") and b.w.lock_ready()
    assert b.w.reset_lock("join123") is None and not b.w.lock_ready()
    assert b.step(2)["status"] == rc.Status.ONLINE   # вход переподключил туннель — сеть снова работает
