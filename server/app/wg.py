"""Тонкая обёртка над ip / wg / iptables."""
import base64
import hashlib
import hmac
import logging
import os
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .config import (DRY_RUN, IPTABLES, NET_PREFIX, SERVER_CIDR, SERVER_KEY_FILE, TC,
                     WG_IF, WG_PORT)

log = logging.getLogger("wg")


def run(args: list[str], input: str | None = None, check: bool = True) -> str:
    if DRY_RUN:
        log.info("[dry-run] %s", " ".join(args))
        if input:
            log.info("[dry-run stdin]\n%s", input)
        return ""
    r = subprocess.run(args, input=input, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def ok(args: list[str]) -> bool:
    if DRY_RUN:
        return True
    return subprocess.run(args, capture_output=True).returncode == 0


# ---------- ключи ----------

def valid_pubkey(key: str) -> bool:
    try:
        return len(key) == 44 and len(base64.b64decode(key, validate=True)) == 32
    except Exception:
        return False


def _ensure_server_key() -> X25519PrivateKey:
    if not os.path.exists(SERVER_KEY_FILE):
        priv = X25519PrivateKey.generate()
        raw = priv.private_bytes(serialization.Encoding.Raw,
                                 serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        with open(SERVER_KEY_FILE, "w") as f:
            f.write(base64.b64encode(raw).decode())
        os.chmod(SERVER_KEY_FILE, 0o600)
    with open(SERVER_KEY_FILE) as f:
        return X25519PrivateKey.from_private_bytes(base64.b64decode(f.read().strip()))


_server_pub: str | None = None


def server_public_key() -> str:
    global _server_pub
    if _server_pub is None:
        pub = _ensure_server_key().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        _server_pub = base64.b64encode(pub).decode()
    return _server_pub


_server_priv: X25519PrivateKey | None = None


def key_proof(public_key: str, ts: int) -> str:
    """Подтверждение, что у ПК есть закрытый ключ WireGuard к public_key (повторная регистрация):
    HMAC-SHA256 от X25519(ключ сервера, ключ ПК) — то же самое ПК считает своим закрытым ключом и ключом сервера.
    '' — ключ ПК не годится для обмена (нулевая точка и т. п.)."""
    global _server_priv
    if _server_priv is None:
        _server_priv = _ensure_server_key()
    try:
        shared = _server_priv.exchange(X25519PublicKey.from_public_bytes(base64.b64decode(public_key)))
    except Exception:  # noqa: BLE001 — ключ малого порядка, не 32 байта
        return ""
    return hmac.new(shared, f"retixhub-register|{public_key}|{int(ts)}".encode(), hashlib.sha256).hexdigest()


# ---------- интерфейс ----------

def setup_interface() -> None:
    _ensure_server_key()
    if DRY_RUN or not ok(["ip", "link", "show", WG_IF]):
        run(["ip", "link", "add", WG_IF, "type", "wireguard"])
    run(["wg", "set", WG_IF, "listen-port", str(WG_PORT), "private-key", SERVER_KEY_FILE])
    run(["ip", "address", "replace", SERVER_CIDR, "dev", WG_IF])
    run(["ip", "link", "set", WG_IF, "up"])
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            if f.read().strip() == "1":
                return  # уже включён (обычно Docker) — писать и шуметь в журнале незачем
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except OSError as e:
        log.warning("ip_forward выключен и не записан (%s): ПК компании не увидят друг друга — "
                    "включите на хосте: sysctl -w net.ipv4.ip_forward=1", e)


def interface_exists() -> bool:
    return ok(["ip", "link", "show", WG_IF])


def current_peers() -> dict[str, str]:
    """Пиры wg0: public_key -> allowed-ips (как их печатает wg, '(none)' — пусто)."""
    out = run(["wg", "show", WG_IF, "allowed-ips"], check=False)
    peers = {}
    for line in out.splitlines():
        key, _, ips = line.strip().partition("\t")
        if key:
            ips = ips.strip()
            peers[key] = "" if ips == "(none)" else " ".join(sorted(ips.split()))
    return peers


def sync_peers(desired: dict[str, str]) -> None:
    """desired: public_key -> ip. Приводит wg0 к этому состоянию. Меняется только разница: на сервере с сотнями
    ПК раньше каждый вызов запускал wg на каждого пира (секунды под общим локом базы)."""
    have = current_peers()
    for pub in have.keys() - desired.keys():
        run(["wg", "set", WG_IF, "peer", pub, "remove"])
    for pub, ip in desired.items():
        if have.get(pub) != f"{ip}/32":
            run(["wg", "set", WG_IF, "peer", pub, "allowed-ips", f"{ip}/32"])


def dump() -> list[dict]:
    """Состояние пиров: endpoint, latest handshake, трафик."""
    out = run(["wg", "show", WG_IF, "dump"], check=False)
    peers = []
    for line in out.splitlines()[1:]:  # первая строка — сам интерфейс
        p = line.split("\t")
        if len(p) >= 7:
            peers.append({
                "public_key": p[0],
                "endpoint": "" if p[2] == "(none)" else p[2],
                "latest_handshake": int(p[4] or 0),
                "rx": int(p[5] or 0),
                "tx": int(p[6] or 0),
            })
    return peers


# ---------- firewall ----------

def apply_firewall(forward_rules: list[str]) -> None:
    """
    Свои цепочки RETIX_FWD (трафик между клиентами) и RETIX_IN (трафик к самому
    серверу из туннеля). Пересобираются целиком, чужие правила не трогаем.
    """
    lines = [
        "*filter",
        ":RETIX_FWD - [0:0]",
        ":RETIX_IN - [0:0]",
        "-F RETIX_FWD",
        "-F RETIX_IN",
        "-A RETIX_FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        *forward_rules,
        "-A RETIX_FWD -j DROP",  # между компаниями и в интернет — нельзя
        "-A RETIX_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "-A RETIX_IN -p icmp -j ACCEPT",  # ping 10.66.0.1
        "-A RETIX_IN -j DROP",  # остальные сервисы сервера из VPN закрыты
        "COMMIT",
        "",
    ]
    run([f"{IPTABLES}-restore", "-w", "--noflush"], input="\n".join(lines))
    jumps = [("FORWARD", "RETIX_FWD"), ("INPUT", "RETIX_IN")]
    # Docker при перезапуске ставит свои цепочки в начало FORWARD — трафик из VPN к портам контейнеров прошёл бы
    # раньше RETIX_FWD. DOCKER-USER Docker не трогает и проходит первой — переход есть и там.
    if not DRY_RUN and ok([IPTABLES, "-w", "-S", "DOCKER-USER"]):
        jumps.append(("DOCKER-USER", "RETIX_FWD"))
    for chain, target in jumps:
        _ensure_first(chain, target)


def _ensure_first(chain: str, target: str) -> None:
    """Переход «-i wg0 -j target» — первым правилом цепочки и ровно один раз. Сначала вставляем новый, потом
    убираем лишние: без окна, когда трафик из wg0 шёл бы мимо своих правил."""
    rule = ["-i", WG_IF, "-j", target]
    want = f"-A {chain} -i {WG_IF} -j {target}"
    if not DRY_RUN:
        rules = [r for r in run([IPTABLES, "-w", "-S", chain], check=False).splitlines() if r.startswith("-A ")]
        if rules and rules[0] == want and rules.count(want) == 1:
            return
    run([IPTABLES, "-w", "-I", chain, "1", *rule])
    if DRY_RUN:
        return
    rules = [r for r in run([IPTABLES, "-w", "-S", chain], check=False).splitlines() if r.startswith("-A ")]
    for num in sorted((i for i, r in enumerate(rules, 1) if r == want and i > 1), reverse=True):
        run([IPTABLES, "-w", "-D", chain, str(num)], check=False)


# ---------- скорость через сервер (tc) ----------
# Трафик между ПК через сервер входит в wg0 от одного ПК и выходит из wg0 к другому. Поэтому:
#  * выход wg0 (к ПК) — HTB: класс компании (по подсети получателя) ограничивает всю компанию,
#    класс ПК внутри него — то, что ПК получает. Прямой путь мимо сервера сюда не попадает.
#  * вход wg0 (от ПК) — police по адресу отправителя: то, что ПК отправляет.
# Ограничений нет — на wg0 нет ни одной очереди, как раньше.

SHAPING_DEFAULT = 0xfffe      # класс без ограничения: всё, что не попало в ограниченные
_shaping_applied: str | None = None


def _minor(company: int, host: int = 0) -> str:
    """classid в hex (tc читает минор как hex): компания N — 1:N, её ПК .H — 1:NNHH, остальные ПК — 1:NN01."""
    return f"1:{(company << 8 | host) if host else company:x}"


def _burst(mbit: int) -> str:
    return f"{max(mbit * 1_000_000 // 8 // 20, 64 * 1024)}b"   # ~50 мс на скорости, не меньше 64 КБ


def shaping_script(limits: list[dict], fair: bool = True, police: bool = True) -> list[str]:
    """limits: [{"subnet": N, "mbit": на компанию или 0, "devices": [(H, мбит), …]}] -> команды tc -batch.
    fair — fq_codel в каждом классе (копирование файла не тормозит Radmin того же ПК),
    police — ограничение того, что ПК отправляет (вход wg0)."""
    if not limits:
        return []
    d = WG_IF
    leaf = (lambda cls: [f"qdisc add dev {d} parent {cls} fq_codel"]) if fair else (lambda cls: [])
    out = [f"qdisc add dev {d} root handle 1: htb default {SHAPING_DEFAULT:x}",
           f"class add dev {d} parent 1: classid 1:{SHAPING_DEFAULT:x} htb rate 10gbit quantum 1514",
           *leaf(f"1:{SHAPING_DEFAULT:x}"),
           *([f"qdisc add dev {d} handle ffff: ingress"] if police else [])]
    for c in limits:
        n, total = int(c["subnet"]), int(c["mbit"] or 0)
        devices = [(int(h), min(int(m), total) if total else int(m)) for h, m in c.get("devices") or [] if m]
        if total:
            share = max(total * 1000 // (len(devices) + 1), 8)       # гарантия поровну, остальное — взаймы
            rest = _minor(n, 1)
            out += [f"class add dev {d} parent 1: classid {_minor(n)} htb rate {total}mbit ceil {total}mbit quantum 1514",
                    f"class add dev {d} parent {_minor(n)} classid {rest} htb rate {share}kbit ceil {total}mbit quantum 1514",
                    *leaf(rest),
                    f"filter add dev {d} parent 1: protocol ip prio 2 u32 match ip dst {NET_PREFIX}.{n}.0/24 flowid {rest}"]
        for h, mbit in devices:
            cls, ip = _minor(n, h), f"{NET_PREFIX}.{n}.{h}"
            parent, rate = (_minor(n), f"{share}kbit") if total else ("1:", f"{mbit}mbit")
            out += [f"class add dev {d} parent {parent} classid {cls} htb rate {rate} ceil {mbit}mbit quantum 1514",
                    *leaf(cls),
                    f"filter add dev {d} parent 1: protocol ip prio 1 u32 match ip dst {ip}/32 flowid {cls}"]
            if police:
                out.append(f"filter add dev {d} parent ffff: protocol ip prio 1 u32 match ip src {ip}/32 "
                           f"police rate {mbit}mbit burst {_burst(mbit)} drop flowid :1")
    return out


def _shaping_present() -> bool:
    return DRY_RUN or "htb 1:" in run([TC, "qdisc", "show", "dev", WG_IF], check=False)


def _clear_shaping() -> None:
    for kind in ("root", "ingress"):
        run([TC, "qdisc", "del", "dev", WG_IF, kind], check=False)


# что делать, если в ядре нет модуля: сначала без fq_codel, потом и без ограничения отправки
SHAPING_VARIANTS = (
    (True, True, ""),
    (False, True, "без fq_codel (нет sch_fq_codel): классы с одной очередью"),
    (False, False, "без ограничения отправки с ПК (нет act_police): ограничены приём ПК и сумма компании"),
)


def apply_shaping(limits: list[dict]) -> None:
    """Приводит очереди wg0 к ограничениям из базы. Ничего не изменилось — tc не трогаем (кроме проверки,
    что очереди на месте). Ядро не умеет часть — урезанный вариант; не умеет ничего — ограничения сняты
    целиком: лучше без них, чем наполовину."""
    global _shaping_applied
    key = repr(limits)
    if key == _shaping_applied and (not limits or _shaping_present()):
        return
    _clear_shaping()
    _shaping_applied = None
    errors = []
    for fair, police, note in SHAPING_VARIANTS if limits else ():
        try:
            run([TC, "-batch", "-"], input="\n".join(shaping_script(limits, fair, police)) + "\n")
        except RuntimeError as e:
            _clear_shaping()
            errors.append(str(e).splitlines()[0] if str(e) else "?")
            continue
        if note:
            log.warning("ограничение скорости %s. Ошибка tc: %s", note, errors[0])
        break
    else:
        if limits:
            log.warning("ограничение скорости не применено, на wg0 его нет: %s", "; ".join(errors))
            return
    _shaping_applied = key
