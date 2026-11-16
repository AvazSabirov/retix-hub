"""
Сквозной тест на НАСТОЯЩЕЙ сети: Linux network namespaces + WireGuard + iptables.

    sudo python3 tests/e2e_network.py

Стенд:
    srv     — сервер Retix Hub (настоящее приложение, WG_DRY_RUN=0) 192.168.77.1
    a1, a2, a3 — ПК компании alpha (a1 — с общей папкой)
    b1      — ПК компании beta
    inet    — «интернет» за сервером (203.0.113.9)
Клиентами управляет настоящая логика retixhub_client.Worker, вместо службы Windows — LinuxTunnel.
Нужны: root, iproute2, wireguard-tools, iptables, netcat-openbsd, (ядро с WireGuard или wireguard-go).
"""
import os
import queue
import shutil
import subprocess
import sys
import tempfile
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
    for ns in list(NS) + ["inet"]:
        # процессы внутри namespace (wireguard-go) держат его живым — завершаем их
        sh(f"ip netns pids {ns} 2>/dev/null | xargs -r kill -9", check=False)
        sh(f"ip netns del {ns}", check=False)
        sh(f"ip link del v-{ns}", check=False)
    sh("ip link del rxbr", check=False)
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

    def last_handshake(self):
        r = nsx(self.ns, f"wg show {self.iface} latest-handshakes", check=False)
        try:
            return max(int(x.split()[1]) for x in r.stdout.splitlines() if x.strip())
        except ValueError:
            return 0


class Pc:
    def __init__(self, ns, hostname, company, name):
        self.ns, self.hostname, self.company, self.name = ns, hostname, company, name
        d = Path(tempfile.mkdtemp(prefix=f"retix-{ns}-"))
        self.hosts = d / "hosts"; self.hosts.write_text("127.0.0.1 localhost\n")
        self.state = rc.State(d / "state.json"); self.state.set(server_url=API)
        self.tunnel = LinuxTunnel(ns, f"wg-{ns}")
        self.w = rc.Worker(self.state, queue.Queue(), tunnel=self.tunnel, hosts_file=self.hosts)
        self.peers = []

    def _host(self):
        rc.socket.gethostname = lambda: self.hostname

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
    for tool in ("ip", "wg", "iptables", "nc", "ping"):
        if not shutil.which(tool):
            sys.exit(f"нет {tool}")
    print(f"WireGuard: {'модуль ядра' if KERNEL_WG else 'wireguard-go (userspace)'}")
    rc.run = lambda args, timeout=60: (0, "")
    rc.ensure_smb_firewall = lambda subnet, ports="445": None
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
    cab_a = requests.Session(); cab_a.post(API + "/cabinet/login", data={"login": "alpha", "password": "cab123"})

    a1 = Pc("a1", "PC1", "alpha", "Склад PC1")
    a2 = Pc("a2", "BUH-01", "alpha", "Бухгалтерия")
    a3 = Pc("a3", "SPARE", "alpha", "Запасной")
    b1 = Pc("b1", "BETA-PC", "beta", "Beta PC")
    # «сервисы» на ПК: 445 = SMB общей папки, 22 = любой другой порт
    for ns in ("a1", "a2"):
        for port in (445, 22):
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

    print("\n3. Общая папка (\\\\PC1\\share)")
    cab_a.post(API + f"/cabinet/devices/{a1.dev_id}/share")
    a2.step()
    check("клиент видит, где общая папка", a2.w.cfg["share"] and a2.w.cfg["share"]["ip"] == a1.ip)
    check("hosts: PC1 → его VPN-адрес", f"{a1.ip}\tpc1" in a2.hosts.read_text())
    check("Бухгалтерия → PC1:445 (SMB) открыт", tcp("a2", a1.ip, 445))
    check("Бухгалтерия → PC1:22 закрыт (только папка)", not tcp("a2", a1.ip, 22))
    check("PC1 → Бухгалтерия:445 закрыт (она не хранит папку)", not tcp("a1", a2.ip, 445))

    print("\n4. Изоляция компаний")
    check("Beta → PC1 alpha: ping не проходит", not ping("b1", a1.ip))
    check("клиент beta не видит alpha в списке", {p["name"] for p in (b1.step() and b1.peers)} == {"Beta PC"})
    # злоумышленник правит свой конфиг: пускает всё через туннель
    nsx("b1", f"wg set wg-b1 peer {b1.w.cfg['server_public_key']} allowed-ips 0.0.0.0/0")
    nsx("b1", "ip route replace 10.66.1.0/24 dev wg-b1")
    nsx("b1", "ip route replace 203.0.113.0/24 dev wg-b1")
    check("Beta с подменённым конфигом → PC1 alpha: ping блокирует сервер", not ping("b1", a1.ip))
    check("Beta с подменённым конфигом → PC1:445 блокирует сервер", not tcp("b1", a1.ip, 445))

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

    print("\n10. Блокировка ПК")
    cab_a.post(API + f"/cabinet/devices/{a2.dev_id}/block")
    check("пир Бухгалтерии удалён с сервера", a2.w.state.keypair()[1] not in server_peers())
    check("заблокированный ПК не достучится до PC1", not ping("a2", a1.ip))
    st = a2.step()
    check("клиент показывает «Заблокировано» и снял туннель",
          st["status"] == rc.Status.BLOCKED and a2.tunnel.service_state() == "missing", str(st))
    cab_a.post(API + f"/cabinet/devices/{a2.dev_id}/unblock")
    a2.until(rc.Status.ONLINE)
    check("после разблокировки связь вернулась", ping_retry("a2", a1.ip))

    print("\n11. Удаление ПК → авто-перерегистрация")
    old_ip = a3.ip
    cab_a.post(API + f"/cabinet/devices/{a3.dev_id}/delete")
    check("удалённый ПК отрезан", not ping("a3", a1.ip))
    st = a3.until(rc.Status.ONLINE)
    check("клиент сам зарегистрировался заново (пароль сохранён)", st["status"] == rc.Status.ONLINE, str(st))
    check("тот же IP", a3.ip == old_ip, f"{old_ip} -> {a3.ip}")
    check("связь восстановлена", ping_retry("a3", a1.ip))

    print("\n12. Сервер упал и поднялся (перезагрузка)")
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

    print("\n13. Отключение компании")
    page = admin.get(API + "/admin").text
    import re
    beta_id = dict(re.findall(r"<b>(\w+)</b>.*?/admin/companies/(\d+)", page, flags=re.S))["beta"]
    admin.post(API + f"/admin/companies/{beta_id}/update", data={"name": "Beta", "max_devices": 10})
    st = b1.step()
    check("клиент beta: «Заблокировано», туннель снят", st["status"] == rc.Status.BLOCKED, str(st))
    check("пиров beta на сервере нет", b1.w.state.keypair()[1] not in server_peers())
    check("alpha продолжает работать", ping_retry("a2", a1.ip))

    print("\n14. Смена пароля подключения с отключением всех")
    cab_a.post(API + "/cabinet/join-password", data={"new_password": "newpass1", "kick_all": "1"})
    a3.step()
    st = a3.step()
    check("клиент просит новый пароль", st["status"] == rc.Status.NEED_LOGIN and "изменён" in st["text"], str(st))
    check("вход с новым паролем", a3.login("newpass1") is None)
    check("снова онлайн", a3.until(rc.Status.ONLINE)["status"] == rc.Status.ONLINE)

    print("\n15. Выход из сети")
    a3.w.logout()
    check("туннель удалён, hosts очищен", a3.tunnel.service_state() == "missing" and "RetixHub" not in a3.hosts.read_text())


if __name__ == "__main__":
    main()
