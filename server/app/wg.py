"""Тонкая обёртка над ip / wg / iptables."""
import base64
import logging
import os
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .config import (DRY_RUN, IPTABLES, SERVER_CIDR, SERVER_KEY_FILE, WG_IF,
                     WG_PORT)

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


# ---------- интерфейс ----------

def setup_interface() -> None:
    _ensure_server_key()
    if DRY_RUN or not ok(["ip", "link", "show", WG_IF]):
        run(["ip", "link", "add", WG_IF, "type", "wireguard"])
    run(["wg", "set", WG_IF, "listen-port", str(WG_PORT), "private-key", SERVER_KEY_FILE])
    run(["ip", "address", "replace", SERVER_CIDR, "dev", WG_IF])
    run(["ip", "link", "set", WG_IF, "up"])
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except OSError as e:
        # Docker на хосте обычно уже включил ip_forward
        log.warning("ip_forward не записан (%s) — проверьте sysctl на хосте", e)


def current_peers() -> set[str]:
    out = run(["wg", "show", WG_IF, "peers"], check=False)
    return {line.strip() for line in out.splitlines() if line.strip()}


def sync_peers(desired: dict[str, str]) -> None:
    """desired: public_key -> ip. Приводит wg0 к этому состоянию."""
    for pub in current_peers() - desired.keys():
        run(["wg", "set", WG_IF, "peer", pub, "remove"])
    for pub, ip in desired.items():
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
    for chain, target in (("FORWARD", "RETIX_FWD"), ("INPUT", "RETIX_IN")):
        rule = [chain, "-i", WG_IF, "-j", target]
        if DRY_RUN or not ok([IPTABLES, "-w", "-C", *rule]):
            run([IPTABLES, "-w", "-I", *rule[:1], "1", *rule[1:]])
