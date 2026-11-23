"""
Сквозной тест на НАСТОЯЩЕЙ сети: Linux network namespaces + WireGuard + iptables.

    sudo python3 tests/e2e_network.py

Стенд:
    srv     — сервер Retix Hub (настоящее приложение, WG_DRY_RUN=0) 192.168.77.1
    a1, a2, a3 — ПК компании alpha (a1 — с общей папкой)
    b1      — ПК компании beta
    inet    — «интернет» за сервером (203.0.113.9)
    r1, r2  — роутеры двух других офисов компании gamma (NAT, как дома: MASQUERADE и закрытый вход)
              внешние адреса 11.0.0.11 и 11.0.0.12, у сервера в этой «сети интернета» — 11.0.0.1
    w1, w2  — ПК за r1 (192.168.10.2) и за r2 (192.168.20.2): прямой путь через интернет
Клиентами управляет настоящая логика retixhub_client.Worker, вместо службы Windows — LinuxTunnel.
Нужны: root, iproute2, wireguard-tools, iptables, netcat-openbsd, iperf3, conntrack,
(ядро с WireGuard или wireguard-go).
"""
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "client"))
try:
    import tkinter  # noqa: F401
except ImportError:
    tk = types.ModuleType("tkinter"); tk.Tk = tk.Toplevel = object
    sys.modules["tkinter"] = tk
    for _s in ("messagebox", "simpledialog", "ttk"):
        sys.modules[f"tkinter.{_s}"] = types.ModuleType(_s)
import retixhub_client as rc  # noqa: E402

API = "http://192.168.77.1:8100"
NS = {"srv": "192.168.77.1", "a1": "192.168.77.11", "a2": "192.168.77.12", "a3": "192.168.77.13",
      "b1": "192.168.77.21"}
# офисы за NAT: ПК -> (роутер, адрес ПК в его локальной сети, внешний адрес роутера)
WAN = {"w1": ("r1", "192.168.10.2", "11.0.0.11"), "w2": ("r2", "192.168.20.2", "11.0.0.12")}
KERNEL_WG = subprocess.run("ip link add rxprobe type wireguard && ip link del rxprobe", shell=True,
                           capture_output=True).returncode == 0

results: list[tuple[str, bool, str]] = []


def sh(cmd: str, check=True) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd}\n{r.stdout}{r.stderr}")
    return r


def nsx(ns: str, cmd: str, check=True):
    return sh(f"ip netns exec {ns} {cmd}", check)


def check(name: str, cond: bool, info: str = ""):
    results.append((name, bool(cond), info))
    print(("  ✅ " if cond else "  ❌ ") + name + (f"  [{info}]" if info and not cond else ""))


def ping(ns, ip, src=None) -> bool:
    s = f"-I {src} " if src else ""
    return nsx(ns, f"ping -c 1 -W 1 {s}{ip}", check=False).returncode == 0


def ping_retry(ns, ip, tries=6) -> bool:
    return any(ping(ns, ip) for _ in range(tries))


def tcp(ns, ip, port) -> bool:
    return nsx(ns, f"nc -z -w 2 {ip} {port}", check=False).returncode == 0


def make_wg_iface(ns, name):
    if KERNEL_WG:
        nsx(ns, f"ip link add {name} type wireguard")
    else:
        nsx(ns, f"wireguard-go {name}")
        for _ in range(30):
            if nsx(ns, f"ip link show {name}", check=False).returncode == 0:
                break
            time.sleep(0.1)


# ------------------------------------------------------------------ стенд

def teardown():
    sh("pkill -f 'app.main' ", check=False)
    sh("pkill -f 'nc -lk'", check=False)
    for ns in list(NS) + ["inet"] + list(WAN) + [r for r, _, _ in WAN.values()]:
        # процессы внутри namespace (wireguard-go) держат его живым — завершаем их
        sh(f"ip netns pids {ns} 2>/dev/null | xargs -r kill -9", check=False)
        sh(f"ip netns del {ns}", check=False)
        sh(f"ip link del v-{ns}", check=False)
    sh("ip link del rxbr", check=False)
    sh("ip link del rxwan", check=False)
    sh("rm -f /var/run/wireguard/wg-*.sock /var/run/wireguard/wg0.sock", check=False)
    time.sleep(0.5)


def setup():
    teardown()
    sh("ip link add rxbr type bridge && ip addr add 192.168.77.254/24 dev rxbr && ip link set rxbr up")
    for ns, ip in NS.items():
        sh(f"ip netns add {ns}")
        sh(f"ip link add v-{ns} type veth peer name eth0 netns {ns}")
        sh(f"ip link set v-{ns} master rxbr up")
        nsx(ns, "ip link set lo up")
        nsx(ns, f"ip addr add {ip}/24 dev eth0")
        nsx(ns, "ip link set eth0 up")
        if ns != "srv":
            nsx(ns, "ip route add default via 192.168.77.254")  # «свой интернет» клиента — мимо VPN
    # «интернет» за сервером
    sh("ip netns add inet")
    sh("ip link add srv-up netns srv type veth peer name eth0 netns inet")
    nsx("srv", "ip addr add 203.0.113.1/24 dev srv-up"); nsx("srv", "ip link set srv-up up")
    nsx("inet", "ip addr add 203.0.113.9/24 dev eth0"); nsx("inet", "ip link set eth0 up"); nsx("inet", "ip link set lo up")
    nsx("inet", "ip route add default via 203.0.113.1")
    # «интернет» между офисами: сервер 11.0.0.1 и роутеры r1, r2 на одном мосту
    sh("ip link add rxwan type bridge && ip link set rxwan up")
    sh("ip link add v-srvwan type veth peer name srv-wan netns srv && ip link set v-srvwan master rxwan up")
    nsx("srv", "ip addr add 11.0.0.1/24 dev srv-wan"); nsx("srv", "ip link set srv-wan up")
    for pc, (router, lan_ip, wan_ip) in WAN.items():
        net = lan_ip.rsplit(".", 1)[0]
        sh(f"ip netns add {router}"); sh(f"ip netns add {pc}")
        sh(f"ip link add v-{router} type veth peer name wan netns {router} && ip link set v-{router} master rxwan up")
        sh(f"ip link add lan netns {router} type veth peer name eth0 netns {pc}")
        for cmd in ("ip link set lo up", f"ip addr add {wan_ip}/24 dev wan", "ip link set wan up",
                    f"ip addr add {net}.1/24 dev lan", "ip link set lan up", "ip route add default via 11.0.0.1",
                    "sysctl -qw net.ipv4.ip_forward=1",
                    "iptables -t nat -A POSTROUTING -o wan -j MASQUERADE",
                    # как домашний роутер: снаружи — только ответы на своё
                    "iptables -A INPUT -i wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "iptables -A INPUT -i wan -j DROP",
                    "iptables -A FORWARD -i wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "iptables -A FORWARD -i wan -j DROP"):
            nsx(router, cmd)
        for cmd in ("ip link set lo up", f"ip addr add {lan_ip}/24 dev eth0", "ip link set eth0 up",
                    f"ip route add default via {net}.1"):
            nsx(pc, cmd)


class ServerProc:
    def __init__(self):
        self.data = tempfile.mkdtemp(prefix="retix-e2e-")
        self.proc = None

    def start(self):
        if nsx("srv", "ip link show wg0", check=False).returncode != 0 and not KERNEL_WG:
            make_wg_iface("srv", "wg0")  # без модуля ядра интерфейс создаёт wireguard-go
        env = (f"DATA_DIR={self.data} WG_DRY_RUN=0 COOKIE_SECURE=0 API_HOST=0.0.0.0 API_PORT=8100 "
               f"MONITOR_EVERY=2 SUPERADMIN_LOGIN=admin SUPERADMIN_PASSWORD=supersecret "
               f"WG_ENDPOINT=192.168.77.1:51820")
        self.log = open(Path(self.data) / "server.log", "a")
        self.proc = subprocess.Popen(f"ip netns exec srv env {env} {sys.executable} -m app.main", shell=True,
                                     cwd=ROOT / "server", stdout=self.log, stderr=self.log)
        for _ in range(100):
            try:
                requests.get(API + "/api/ping", timeout=0.5)
                return
            except requests.RequestException:
                time.sleep(0.1)
        raise RuntimeError("server did not start:\n" + (Path(self.data) / "server.log").read_text())

    def stop(self):
        sh("pkill -f 'app.main'", check=False)
        if self.proc:
            self.proc.wait()


class LinuxTunnel:
    """То же, что служба WireGuard на Windows, но в network namespace."""

    def __init__(self, ns, iface):
        self.ns, self.iface = ns, iface

    def installed(self): return True
    build_conf = staticmethod(rc.Tunnel.build_conf)

    def service_state(self):
        return "running" if nsx(self.ns, f"ip link show {self.iface}", check=False).returncode == 0 else "missing"

    def install(self, conf: str):
        self.conf = conf
        self.uninstall()
        make_wg_iface(self.ns, self.iface)
        address, allowed, lines = "", [], []
        for line in conf.splitlines():
            if line.startswith("Address"):
                address = line.split("=", 1)[1].strip()
                continue
            if line.startswith("AllowedIPs"):
                allowed = [x.strip() for x in line.split("=", 1)[1].split(",")]
            lines.append(line)
        f = Path(tempfile.mkstemp(suffix=".conf")[1]); f.write_text("\n".join(lines) + "\n")
        nsx(self.ns, f"wg setconf {self.iface} {f}"); f.unlink()
        nsx(self.ns, f"ip addr add {address} dev {self.iface}")
        nsx(self.ns, f"ip link set {self.iface} up")
        for cidr in allowed:
            nsx(self.ns, f"ip route replace {cidr} dev {self.iface}")
        nsx(self.ns, f"ping -c 1 -W 1 10.66.0.1", check=False)  # первый пакет запускает handshake

    def uninstall(self):
        nsx(self.ns, f"ip link del {self.iface}", check=False)
        time.sleep(0.2)

    def start(self): pass

    def probe(self, ip):
        return any(nsx(self.ns, f"ping -c 1 -W 1 {ip}", check=False).returncode == 0 for _ in range(2))

    def nudge(self, ip):
        threading.Thread(target=nsx, args=(self.ns, f"ping -c 1 -W 1 {ip}"), kwargs={"check": False},
                         daemon=True).start()

    def last_handshake(self, key=""):
        r = nsx(self.ns, f"wg show {self.iface} latest-handshakes", check=False)
        times = {x.split()[0]: int(x.split()[1]) for x in r.stdout.splitlines() if len(x.split()) == 2}
        return times.get(key, 0) if key else max(times.values(), default=0)

    def dump(self):
        r = nsx(self.ns, f"wg show {self.iface} dump", check=False)
        return rc.parse_wg_dump(r.stdout) if r.returncode == 0 else None

    def set_peer(self, key, endpoint="", allowed_ips=None, keepalive=None):
        cmd = f"wg set {self.iface} peer {key}"
        if endpoint:
            cmd += f" endpoint {endpoint}"
        if allowed_ips is not None:
            cmd += f" allowed-ips {allowed_ips or chr(34) * 2}"
        if keepalive is not None:
            cmd += f" persistent-keepalive {keepalive}"
        return nsx(self.ns, cmd, check=False).returncode == 0

    def remove_peer(self, key):
        nsx(self.ns, f"wg set {self.iface} peer {key} remove", check=False)

    def saved_conf(self):
        return getattr(self, "conf", "")

    def set_listen_port(self, port):
        return nsx(self.ns, f"wg set {self.iface} listen-port {port}", check=False).returncode == 0


class Pc:
    def __init__(self, ns, hostname, company, name):
        self.ns, self.hostname, self.company, self.name = ns, hostname, company, name
        d = Path(tempfile.mkdtemp(prefix=f"retix-{ns}-"))
        self.state = rc.State(d / "state.json"); self.state.set(server_url=API)
        self.tunnel = LinuxTunnel(ns, f"wg-{ns}")
        self.w = rc.Worker(self.state, queue.Queue(), tunnel=self.tunnel)
        self.peers = []

    def _host(self):
        rc.socket.gethostname = lambda: self.hostname
        lan_ip = NS.get(self.ns) or WAN[self.ns][1]
        rc.local_addresses = lambda: [f"{lan_ip}/24"]   # адрес ПК в своей «офисной» сети

    def login(self, password="join123"):
        self._host()
        return self.w.login(API, self.company, password, self.name, True)

    def step(self, n=1):
        st = None
        for _ in range(n):
            self._host()
            self.w.step()
            while not self.w.events.empty():
                kind, data = self.w.events.get()
                if kind == "status":
                    st = data
                elif kind == "peers":
                    self.peers = data["peers"]
        return st

    def reboot(self):
        """Перезагрузка ПК: служба WireGuard поднимается сама с конфигом (без пиров, добавленных на лету,
        и с новым случайным портом), программа запускается заново — помнит только state.json."""
        self.tunnel.install(self.tunnel.conf)
        self.state = rc.State(self.state.path)
        self.w = rc.Worker(self.state, queue.Queue(), tunnel=self.tunnel)
        self.peers = []

    def until(self, status, tries=12):
        st = None
        for _ in range(tries):
            st = self.step()
            if st and st["status"] == status:
                return st
            time.sleep(0.5)
        return st

    @property
    def ip(self): return self.w.cfg["ip"]

    @property
    def dev_id(self): return self.w.cfg["device_id"]


def server_peers():
    return set(nsx("srv", "wg show wg0 peers", check=False).stdout.split())


# ------------------------------------------------------------------ сценарии

def main():
    if os.geteuid() != 0:
        sys.exit("нужен root")
    for tool in ("ip", "wg", "iptables", "nc", "ping", "iperf3", "conntrack", "tc"):
        if not shutil.which(tool):
            sys.exit(f"нет {tool}")
    print(f"WireGuard: {'модуль ядра' if KERNEL_WG else 'wireguard-go (userspace)'}")
    import logging
    client_log = Path(tempfile.mkdtemp(prefix="retix-e2e-log-")) / "client.log"
    logging.basicConfig(filename=client_log, level=logging.INFO, format="%(asctime)s %(threadName)s %(message)s")
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    print(f"журнал клиентов: {client_log}")
    rc.run = lambda args, timeout=60: (0, "")
    rc.ensure_firewall = lambda subnet, ports="445": None
    rc.ensure_autostart = lambda: None

    setup()
    srv = ServerProc(); srv.start()
    try:
        run_scenarios(srv)
    finally:
        srv.stop()
        teardown()

    ok = sum(r[1] for r in results)
    print(f"\nИТОГО: {ok}/{len(results)} проверок пройдено")
    sys.exit(0 if ok == len(results) else 1)


def run_scenarios(srv: ServerProc):
    admin = requests.Session()
    admin.post(API + "/admin/login", data={"login": "admin", "password": "supersecret"})
    for login in ("alpha", "beta"):
        admin.post(API + "/admin/companies", data={"login": login, "name": login.title(), "cabinet_password": "cab123",
                                                   "join_password": "join123", "max_devices": 10})
        # новые компании по умолчанию ждут одобрения ПК — в этих сценариях оно не нужно
        cab = requests.Session(); cab.post(API + "/cabinet/login", data={"login": login, "password": "cab123"})
        cab.post(API + "/cabinet/settings", data={"share_name": "share", "share_ports": "445"})
    cab_a = requests.Session(); cab_a.post(API + "/cabinet/login", data={"login": "alpha", "password": "cab123"})

    a1 = Pc("a1", "PC1", "alpha", "Склад PC1")
    a2 = Pc("a2", "BUH-01", "alpha", "Бухгалтерия")
    a3 = Pc("a3", "SPARE", "alpha", "Запасной")
    b1 = Pc("b1", "BETA-PC", "beta", "Beta PC")
    # «сервисы» на ПК: 445 = SMB общей папки, 4899 = Radmin Server, 22 = любой другой порт
    for ns in ("a1", "a2"):
        for port in (445, 4899, 22):
            subprocess.Popen(f"ip netns exec {ns} nc -lk {port}", shell=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen("ip netns exec srv nc -lk 2222", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    print("\n1. Регистрация и подключение")
    for pc in (a1, a2, a3, b1):
        check(f"{pc.name}: вход по логину/паролю компании", pc.login() is None)
        st = pc.until(rc.Status.ONLINE)
        check(f"{pc.name}: статус «Подключено»", st and st["status"] == rc.Status.ONLINE, str(st))
    check("IP выданы из подсетей компаний", a1.ip.startswith("10.66.1.") and b1.ip.startswith("10.66.2."),
          f"{a1.ip} {b1.ip}")
    check("на сервере 4 пира WireGuard", len(server_peers()) == 4, str(server_peers()))

    print("\n2. Связь внутри компании")
    check("PC1 ↔ Бухгалтерия: ping", ping_retry("a1", a2.ip) and ping_retry("a2", a1.ip))
    check("ПК → сервер 10.66.0.1: ping", ping_retry("a1", "10.66.0.1"))

    print("\n3. Общие папки (SMB) между всеми ПК компании")
    a2.step()
    check("Бухгалтерия → PC1:445 (SMB) открыт", tcp("a2", a1.ip, 445))
    check("PC1 → Бухгалтерия:445 (SMB) открыт", tcp("a1", a2.ip, 445))
    check("Бухгалтерия → PC1:4899 (Radmin Server) открыт", tcp("a2", a1.ip, 4899))
    check("Бухгалтерия → PC1:22 закрыт (только ping, папки и Radmin)", not tcp("a2", a1.ip, 22))

    print("\n4. Изоляция компаний")
    check("Beta → PC1 alpha: ping не проходит", not ping("b1", a1.ip))
    check("клиент beta не видит alpha в списке", {p["name"] for p in (b1.step() and b1.peers)} == {"Beta PC"})
    # злоумышленник правит свой конфиг: пускает всё через туннель
    nsx("b1", f"wg set wg-b1 peer {b1.w.cfg['server_public_key']} allowed-ips 0.0.0.0/0")
    nsx("b1", "ip route replace 10.66.1.0/24 dev wg-b1")
    nsx("b1", "ip route replace 203.0.113.0/24 dev wg-b1")
    check("Beta с подменённым конфигом → PC1 alpha: ping блокирует сервер", not ping("b1", a1.ip))
    check("Beta с подменённым конфигом → PC1:445 блокирует сервер", not tcp("b1", a1.ip, 445))
    check("Beta с подменённым конфигом → PC1:4899 (Radmin) блокирует сервер", not tcp("b1", a1.ip, 4899))

    print("\n5. Интернет НЕ идёт через VPN")
    route = nsx("a2", "ip route get 8.8.8.8").stdout
    check("у клиента интернет идёт через свою сеть, не через wg", "dev eth0" in route and "wg-" not in route, route.strip())
    check("контроль: сервер сам видит «интернет»", ping("srv", "203.0.113.9"))
    check("клиент не может выйти в «интернет» через сервер", not ping("b1", "203.0.113.9"))

    print("\n6. Подмена IP")
    nsx("b1", f"ip addr add {a2.ip}/32 dev wg-b1")
    check("Beta с чужим IP (Бухгалтерии) не достучится до PC1", not ping("b1", a1.ip, src=a2.ip))
    b1.w.force_reconnect(); b1.until(rc.Status.ONLINE)   # клиент сам вернул правильный конфиг

    print("\n7. Сервисы самого сервера закрыты из VPN")
    check("ПК → 10.66.0.1:2222 закрыт", not tcp("a1", "10.66.0.1", 2222))
    check("контроль: тот же порт доступен с локальной сети", tcp("a1", "192.168.77.1", 2222))

    print("\n8. Режим «любой трафик внутри компании»")
    cab_a.post(API + "/cabinet/settings", data={"full_lan": "1", "share_name": "share", "share_ports": "445"})
    check("full_lan: Бухгалтерия → PC1:22 открыт", tcp("a2", a1.ip, 22))
    check("full_lan: Beta всё ещё не проходит", not ping("b1", a1.ip))
    cab_a.post(API + "/cabinet/settings", data={"share_name": "share", "share_ports": "445"})
    check("full_lan выключен: PC1:22 снова закрыт", not tcp("a2", a1.ip, 22))

    print("\n9. Онлайн-статус на сервере")
    time.sleep(3)
    a2.step()
    online = {p["name"]: p["online"] for p in a2.peers}
    check("сервер видит ПК alpha онлайн (по handshake)", online.get("Склад PC1") and online.get("Бухгалтерия"), str(online))

    direct_lan(srv, cab_a, a1, a2, a3, b1)
    speed_limit(admin, cab_a, a1, a2)

    print("\n11. Блокировка ПК")
    cab_a.post(API + f"/cabinet/devices/{a2.dev_id}/block")
    check("пир Бухгалтерии удалён с сервера", a2.w.state.keypair()[1] not in server_peers())
    check("заблокированный ПК не достучится до PC1", not ping("a2", a1.ip))
    st = a2.step()
    check("клиент показывает «Заблокировано» и снял туннель",
          st["status"] == rc.Status.BLOCKED and a2.tunnel.service_state() == "missing", str(st))
    cab_a.post(API + f"/cabinet/devices/{a2.dev_id}/unblock")
    a2.until(rc.Status.ONLINE)
    check("после разблокировки связь вернулась", ping_retry("a2", a1.ip))

    print("\n12. Удаление ПК → авто-перерегистрация")
    old_ip = a3.ip
    cab_a.post(API + f"/cabinet/devices/{a3.dev_id}/delete")
    check("удалённый ПК отрезан", not ping("a3", a1.ip))
    st = a3.until(rc.Status.ONLINE)
    check("клиент сам зарегистрировался заново (пароль сохранён)", st["status"] == rc.Status.ONLINE, str(st))
    check("тот же IP", a3.ip == old_ip, f"{old_ip} -> {a3.ip}")
    check("связь восстановлена", ping_retry("a3", a1.ip))

    print("\n13. Сервер упал и поднялся (перезагрузка)")
    srv.stop()
    nsx("srv", "ip link del wg0", check=False)            # как после ребута: интерфейса нет
    time.sleep(0.5)
    st = a1.step()
    check("клиент: «Сервер недоступен», туннель не удалён",
          st["status"] == rc.Status.SERVER_DOWN and a1.tunnel.service_state() == "running", str(st))
    check("связи нет, пока сервер лежит", not ping("a2", a1.ip))
    srv.start()
    check("сервер восстановил пиров из базы", len(server_peers()) == 4, str(server_peers()))
    for pc in (a1, a2):
        pc.until(rc.Status.ONLINE)
    check("после возврата сервера PC1 ↔ Бухгалтерия снова связаны", ping_retry("a2", a1.ip) and ping_retry("a1", a2.ip))
    check("SMB снова доступен", tcp("a2", a1.ip, 445))
    check("изоляция после рестарта на месте", not ping("b1", a1.ip))

    print("\n14. Отключение компании")
    page = admin.get(API + "/admin").text
    import re
    beta_id = dict(re.findall(r"<b>(\w+)</b>.*?/admin/companies/(\d+)", page, flags=re.S))["beta"]
    admin.post(API + f"/admin/companies/{beta_id}/update", data={"name": "Beta", "max_devices": 10})
    st = b1.step()
    check("клиент beta: «Заблокировано», туннель снят", st["status"] == rc.Status.BLOCKED, str(st))
    check("пиров beta на сервере нет", b1.w.state.keypair()[1] not in server_peers())
    check("alpha продолжает работать", ping_retry("a2", a1.ip))

    print("\n15. Смена пароля подключения с отключением всех")
    cab_a.post(API + "/cabinet/join-password", data={"new_password": "newpass1", "kick_all": "1"})
    a3.step()
    st = a3.step()
    check("клиент просит новый пароль", st["status"] == rc.Status.NEED_LOGIN and "изменён" in st["text"], str(st))
    check("вход с новым паролем", a3.login("newpass1") is None)
    check("снова онлайн", a3.until(rc.Status.ONLINE)["status"] == rc.Status.ONLINE)

    print("\n16. Выход из сети")
    a3.w.logout()
    check("туннель удалён", a3.tunnel.service_state() == "missing")

    direct_wan(admin)


def direct_peers(pc) -> dict:
    """Прямые пиры ПК (все, кроме сервера): ключ -> {endpoint, allowed_ips, …}."""
    d = pc.tunnel.dump() or {"peers": {}}
    return {k: v for k, v in d["peers"].items() if "," not in v["allowed_ips"]}   # у сервера — подсеть,10.66.0.1/32


def settle(*pcs, rounds=4):
    for _ in range(rounds):
        for pc in pcs:
            pc.step()
        time.sleep(0.5)
        for pc in pcs:
            pc.w.direct.poll()      # то, что Worker делает раз в секунду между шагами


def direct_lan(srv, cab_a, a1, a2, a3, b1):
    print("\n10. Прямой путь по локальной сети")
    rc.DIRECT_KEEPALIVE, rc.DIRECT_RX_TIMEOUT = 1, 8   # в тесте путь «пропадает» быстрее
    cab_a.post(API + "/cabinet/settings", data={"full_lan": "1", "share_name": "share", "share_ports": "445"})
    settle(a1, a2)
    time.sleep(2.5)                 # монитор сервера (каждые 2 с) видит адреса ПК
    settle(a1, a2)
    k1, k2 = a1.w.state.keypair()[1], a2.w.state.keypair()[1]
    p12, p21 = direct_peers(a1).get(k2, {}), direct_peers(a2).get(k1, {})
    check("PC1 → Бухгалтерия: напрямую по локальному адресу (AllowedIPs /32)",
          p12.get("allowed_ips") == f"{a2.ip}/32" and p12.get("endpoint", "").startswith("192.168.77.12:"),
          f"{p12} direct={a1.w.cfg.get('direct')} lan={a1.w.lan} port={a1.w.direct.listen_port}")
    check("Бухгалтерия → PC1: напрямую", p21.get("allowed_ips") == f"{a1.ip}/32", str(p21))
    check("пир сервера не изменился (подсеть компании — через сервер)",
          a1.w.cfg["server_public_key"] in (a1.tunnel.dump() or {"peers": {}})["peers"]
          and len(direct_peers(a1)) == 1)
    a1.step()
    check("в программе Бухгалтерия отмечена «напрямую»",
          any(p["name"] == "Бухгалтерия" and p.get("direct") for p in a1.peers), str(a1.peers))
    page = cab_a.get(API + "/cabinet").text
    check("кабинет показывает прямые пути", page.count("напрямую: 1 ПК") >= 2 and ">Бухгалтерия<" in page and ">Склад PC1<" in page)

    # доказательство: сервер больше не пропускает трафик между ними, а связь есть
    drop = [f"FORWARD -s {a1.ip} -d {a2.ip} -j DROP", f"FORWARD -s {a2.ip} -d {a1.ip} -j DROP"]
    for rule in drop:
        nsx("srv", f"iptables -I {rule}")
    check("ping PC1 ↔ Бухгалтерия идёт мимо сервера", ping_retry("a1", a2.ip) and ping_retry("a2", a1.ip))
    check("SMB PC1 ← Бухгалтерия мимо сервера", tcp("a2", a1.ip, 445))
    check("контроль: Запасной (ещё не сообщил адреса) — через сервер", ping_retry("a1", a3.ip))
    for rule in drop:
        nsx("srv", f"iptables -D {rule}")

    print("\n    чужие не пролезут прямым путём")
    b1.step(2)
    check("Beta (та же локальная сеть, другая компания) прямых пиров не получает", not direct_peers(b1))
    port1 = a1.tunnel.dump()["listen_port"]
    nsx("b1", f"wg set wg-b1 peer {k1} endpoint 192.168.77.11:{port1} allowed-ips {a1.ip}/32 persistent-keepalive 1")
    time.sleep(1)
    check("Beta сам добавил PC1 в свой WireGuard — PC1 его не знает, связи нет", not ping("b1", a1.ip))
    nsx("b1", f"wg set wg-b1 peer {k1} remove")

    print("\n    прямой путь пропал → снова через сервер")
    lan_drop = [("a1", "INPUT -s 192.168.77.12 -p udp -j DROP"), ("a2", "INPUT -s 192.168.77.11 -p udp -j DROP")]
    for ns, rule in lan_drop:
        nsx(ns, f"iptables -I {rule}")
    a1.step(); a2.step()            # последние пакеты, пришедшие до блокировки
    time.sleep(rc.DIRECT_RX_TIMEOUT + 2)
    a1.step(); a2.step()
    check("сосед без пакетов удалён из WireGuard", not direct_peers(a1) and not direct_peers(a2),
          f"{direct_peers(a1)} {direct_peers(a2)}")
    check("связь PC1 ↔ Бухгалтерия идёт через сервер", ping_retry("a1", a2.ip) and ping_retry("a2", a1.ip))
    for ns, rule in lan_drop:
        nsx(ns, f"iptables -D {rule}")

    print("\n    «любой трафик» выключен → прямых путей нет")
    a1.w.direct.backoff.clear(); a2.w.direct.backoff.clear()
    settle(a1, a2)
    check("после восстановления сети прямой путь вернулся", direct_peers(a1).get(k2, {}).get("allowed_ips") == f"{a2.ip}/32")

    print("\n    нет интернета, оба ПК перезагрузились → прямой путь по сохранённым соседям")
    ip1, ip2 = a1.ip, a2.ip            # после перезагрузки конфигурации от сервера ещё нет
    srv.stop()
    nsx("srv", "ip link del wg0", check=False)          # сервера нет совсем: ни API, ни WireGuard
    for pc in (a1, a2):
        pc.reboot()
    check("после перезагрузки прямых пиров в туннеле нет", not direct_peers(a1) and not direct_peers(a2))
    settle(a1, a2, rounds=3)
    st = a1.step()
    check("клиент: «Только локальная сеть»", st and st["status"] == rc.Status.LAN_ONLY, str(st))
    check("прямой путь поднят по сохранённому списку",
          direct_peers(a1).get(k2, {}).get("allowed_ips") == f"{ip2}/32"
          and direct_peers(a2).get(k1, {}).get("allowed_ips") == f"{ip1}/32",
          f"{direct_peers(a1)} {direct_peers(a2)}")
    check("ping PC1 ↔ Бухгалтерия без сервера", ping_retry("a1", ip2) and ping_retry("a2", ip1))
    check("SMB PC1 ← Бухгалтерия без сервера", tcp("a2", ip1, 445))
    check("в программе Бухгалтерия «в сети», напрямую",
          any(p["name"] == "Бухгалтерия" and p["online"] and p.get("direct") for p in a1.peers), str(a1.peers))
    a1.w.set_enabled(False)
    st = a1.step()
    check("OFF без сервера: туннель снят", st["status"] == rc.Status.OFF and a1.tunnel.service_state() == "missing", str(st))
    a1.w.set_enabled(True)
    settle(a1, a2, rounds=3)
    check("ON без сервера: туннель из последнего конфига, снова напрямую",
          a1.step()["status"] == rc.Status.LAN_ONLY and ping_retry("a1", ip2) and ping_retry("a2", ip1))
    check("контроль: Запасной (не сосед) без сервера недоступен", not ping("a1", a3.ip))
    srv.start()
    for pc in (a1, a2):
        pc.until(rc.Status.ONLINE)
    settle(a1, a2)
    check("сервер вернулся: «В сети», прямой путь на месте",
          a1.step()["status"] == rc.Status.ONLINE and direct_peers(a1).get(k2, {}).get("allowed_ips") == f"{a2.ip}/32")
    cab_a.post(API + "/cabinet/settings", data={"share_name": "share", "share_ports": "445"})
    a1.step(); a2.step()
    check("прямые пиры удалены у обоих", not direct_peers(a1) and not direct_peers(a2))
    check("PC1 → Бухгалтерия:22 снова закрыт (правила сервера снова действуют)", not tcp("a2", a1.ip, 22))
    check("ping через сервер работает", ping_retry("a2", a1.ip))


# ------------------------------------------------------------------ скорость через сервер

def iperf(src_ns, dst_ns, dst_ip, seconds=3) -> float:
    """Мбит/с по TCP от src к dst (через туннель)."""
    import json
    srv_proc = subprocess.Popen(f"ip netns exec {dst_ns} iperf3 -s -1 -p 5201", shell=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    r = nsx(src_ns, f"timeout {seconds + 15} iperf3 -c {dst_ip} -p 5201 -t {seconds} -J --connect-timeout 3000",
            check=False)
    srv_proc.kill()
    try:
        return json.loads(r.stdout)["end"]["sum_received"]["bits_per_second"] / 1e6
    except (ValueError, KeyError):
        return 0.0


def company_id(admin, login) -> str:
    import re
    page = admin.get(API + "/admin").text
    return dict(re.findall(r"<b>(\w+)</b>.*?/admin/companies/(\d+)", page, flags=re.S))[login]


def speed_limit(admin, cab_a, a1, a2):
    print("\n10б. Скорость через сервер (tc на wg0)")
    # iperf3 на порту 5201: на время замеров открываем его между ПК (как порт в кабинете)
    cab_a.post(API + "/cabinet/settings", data={"share_name": "share", "share_ports": "445,5201"})
    cid = company_id(admin, "alpha")
    form = {"name": "Alpha", "max_devices": 10, "is_active": "1"}
    free = iperf("a1", "a2", a2.ip)
    check("без ограничения: PC1 → Бухгалтерия быстрее 20 Мбит/с", free > 20, f"{free:.1f}")

    admin.post(API + f"/admin/companies/{cid}/update", data=form | {"speed_limit": "5"})
    qdisc = nsx("srv", "tc qdisc show dev wg0").stdout
    check("на wg0 появилась очередь HTB", "htb 1:" in qdisc, qdisc)
    got = iperf("a1", "a2", a2.ip)
    check("компания 5 Мбит/с: PC1 → Бухгалтерия не быстрее", 3 < got < 5.8, f"{got:.1f}")
    got = iperf("a2", "a1", a1.ip)
    check("и в обратную сторону — та же сумма компании", 3 < got < 5.8, f"{got:.1f}")

    admin.post(API + f"/admin/companies/{cid}/update", data=form | {"speed_limit": "0"})
    admin.post(API + f"/admin/companies/{cid}/devices/{a2.dev_id}/speed", data={"value": "2"})
    got = iperf("a1", "a2", a2.ip)
    check("ПК 2 Мбит/с: Бухгалтерия получает не быстрее", 1.2 < got < 2.4, f"{got:.1f}")
    police = "police" in nsx("srv", "tc filter show dev wg0 parent ffff:", check=False).stdout
    if police:
        got = iperf("a2", "a1", a1.ip)
        check("ПК 2 Мбит/с: отправляет не быстрее", 1.0 < got < 2.6, f"{got:.1f}")
    else:
        print("    (ядро без act_police: ограничение отправки с ПК здесь не проверить)")
        got = iperf("a2", "a1", a1.ip)
        check("PC1 без ограничения получает быстро (ограничен только приём Бухгалтерии)", got > 20, f"{got:.1f}")

    admin.post(API + f"/admin/companies/{cid}/devices/{a2.dev_id}/speed", data={"value": ""})
    qdisc = nsx("srv", "tc qdisc show dev wg0").stdout
    check("ограничения сняты — очередей на wg0 нет", "htb" not in qdisc and "ingress" not in qdisc, qdisc)
    got = iperf("a1", "a2", a2.ip)
    check("снова быстро", got > 20, f"{got:.1f}")
    cab_a.post(API + "/cabinet/settings", data={"share_name": "share", "share_ports": "445"})


# ------------------------------------------------------------------ прямой путь через интернет

def server_rx(pc) -> int:
    """Сколько сервер принял по WireGuard от этого ПК (байт)."""
    for line in nsx("srv", "wg show wg0 transfer").stdout.splitlines():
        key, rx, _ = line.split()
        if key == pc.w.state.keypair()[1]:
            return int(rx)
    return 0


def direct_wan(admin):
    print("\n17. Прямой путь через интернет: два офиса за разными роутерами (NAT)")
    admin.post(API + "/admin/companies", data={"login": "gamma", "name": "Gamma", "cabinet_password": "cab123",
                                               "join_password": "join123", "max_devices": 10})
    cab = requests.Session(); cab.post(API + "/cabinet/login", data={"login": "gamma", "password": "cab123"})
    cab.post(API + "/cabinet/settings", data={"full_lan": "1", "share_name": "share", "share_ports": "445"})
    rc.DIRECT_KEEPALIVE_WAN, rc.DIRECT_RX_TIMEOUT_WAN = 2, 8   # в тесте путь «пропадает» быстрее
    w1, w2 = Pc("w1", "TASH-PC", "gamma", "Ташкент"), Pc("w2", "SAM-PC", "gamma", "Самарканд")
    for pc in (w1, w2):
        check(f"{pc.name} (за NAT): вход и «Подключено»",
              pc.login() is None and pc.until(rc.Status.ONLINE)["status"] == rc.Status.ONLINE)
    check("через сервер Ташкент ↔ Самарканд связаны", ping_retry("w1", w2.ip) and ping_retry("w2", w1.ip))
    time.sleep(2.5)                 # монитор сервера (каждые 2 с) видит внешние адреса ПК
    settle(w1, w2, rounds=3)
    time.sleep(2)
    settle(w1, w2, rounds=3)
    k1, k2 = w1.w.state.keypair()[1], w2.w.state.keypair()[1]
    p12, p21 = direct_peers(w1).get(k2, {}), direct_peers(w2).get(k1, {})
    check("сервер видит ПК по внешним адресам роутеров",
          [n["endpoints"][0].split(":")[0] for n in w1.w.cfg.get("direct_wan") or []] == ["11.0.0.12"],
          str(w1.w.cfg.get("direct_wan")))
    check("Ташкент → Самарканд: напрямую через роутер Самарканда (AllowedIPs /32)",
          p12.get("allowed_ips") == f"{w2.ip}/32" and p12.get("endpoint", "").startswith("11.0.0.12:"), str(p12))
    check("Самарканд → Ташкент: напрямую через роутер Ташкента",
          p21.get("allowed_ips") == f"{w1.ip}/32" and p21.get("endpoint", "").startswith("11.0.0.11:"), str(p21))
    w1.step()
    check("в программе Самарканд отмечен «напрямую через интернет»",
          any(p["name"] == "Самарканд" and p.get("direct_wan") for p in w1.peers), str(w1.peers))

    drop = [f"FORWARD -s {w1.ip} -d {w2.ip} -j DROP", f"FORWARD -s {w2.ip} -d {w1.ip} -j DROP"]
    for rule in drop:
        nsx("srv", f"iptables -I {rule}")
    check("ping Ташкент ↔ Самарканд идёт мимо сервера", ping_retry("w1", w2.ip) and ping_retry("w2", w1.ip))
    before = server_rx(w1)
    nsx("w1", f"ping -c 40 -i 0.05 -s 1200 -q {w2.ip}", check=False)
    grown = server_rx(w1) - before
    check("40 КБ ping не прошли через сервер (сервер принял от ПК < 8 КБ)", grown < 8000, f"{grown} байт")
    for rule in drop:
        nsx("srv", f"iptables -D {rule}")

    print("\n    путь через интернет пропал → снова через сервер")
    cut = [("r1", "FORWARD -i wan -s 11.0.0.12 -j DROP"), ("r2", "FORWARD -i wan -s 11.0.0.11 -j DROP")]
    for ns, rule in cut:                                  # между офисами пакеты больше не ходят
        nsx(ns, f"iptables -I {rule}")
    w1.step(); w2.step()
    time.sleep(rc.DIRECT_RX_TIMEOUT_WAN + 2)
    w1.step(); w2.step()
    check("сосед без пакетов удалён", not direct_peers(w1).get(k2, {}).get("allowed_ips")
          and not direct_peers(w2).get(k1, {}).get("allowed_ips"), f"{direct_peers(w1)} {direct_peers(w2)}")
    check("связь через сервер работает", ping_retry("w1", w2.ip) and ping_retry("w2", w1.ip))
    for ns, rule in cut:
        nsx(ns, f"iptables -D {rule}")

    print("\n    роутер с симметричным NAT (новый порт на каждый адрес) → прямого пути нет, работает сервер")
    nsx("r2", "iptables -t nat -R POSTROUTING 1 -o wan -j MASQUERADE --random-fully")
    nsx("r1", "conntrack -F", check=False); nsx("r2", "conntrack -F", check=False)
    for pc in (w1, w2):
        pc.w.direct.backoff.clear()
    rc.DIRECT_PROBE_WAN = 6
    for _ in range(3):
        settle(w1, w2, rounds=3)
        time.sleep(2.5)
    check("прямого пути нет", not direct_peers(w1).get(k2, {}).get("allowed_ips")
          and not direct_peers(w2).get(k1, {}).get("allowed_ips"), f"{direct_peers(w1)} {direct_peers(w2)}")
    check("клиент ждёт общего окна для новой попытки", k2 in w1.w.direct.backoff and k1 in w2.w.direct.backoff)
    check("ping через сервер работает", ping_retry("w1", w2.ip) and ping_retry("w2", w1.ip))

    print("\n    роутер снова обычный → прямой путь вернулся")
    nsx("r2", "iptables -t nat -R POSTROUTING 1 -o wan -j MASQUERADE")
    nsx("r2", "conntrack -F", check=False)
    w2.step(); time.sleep(2.5)       # сервер узнаёт новый внешний порт Самарканда
    for pc in (w1, w2):
        pc.w.direct.backoff.clear()
    rc.DIRECT_PROBE_WAN = 25
    settle(w1, w2, rounds=3); time.sleep(2); settle(w1, w2, rounds=3)
    check("напрямую снова", direct_peers(w1).get(k2, {}).get("allowed_ips") == f"{w2.ip}/32"
          and direct_peers(w2).get(k1, {}).get("allowed_ips") == f"{w1.ip}/32", f"{direct_peers(w1)} {direct_peers(w2)}")

    print("\n    «любой трафик» выключен → прямых путей нет, правила сервера снова действуют")
    cab.post(API + "/cabinet/settings", data={"share_name": "share", "share_ports": "445"})
    w1.step(); w2.step()
    check("прямые пиры удалены у обоих", not direct_peers(w1) and not direct_peers(w2))
    check("ping через сервер работает", ping_retry("w1", w2.ip))


if __name__ == "__main__":
    main()
