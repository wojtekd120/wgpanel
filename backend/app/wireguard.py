import ipaddress
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .validators import validate_cidr, validate_wg_key


@dataclass(frozen=True)
class WgDumpPeer:
    public_key: str
    preshared_key: str
    endpoint: str | None
    allowed_ips: list[str]
    latest_handshake: int
    transfer_rx: int
    transfer_tx: int
    persistent_keepalive: str


def run_wg_dump(interface: str) -> str:
    result = subprocess.run(
        ["wg", "show", interface, "dump"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout


def parse_wg_dump(dump: str) -> list[WgDumpPeer]:
    lines = [line for line in dump.splitlines() if line.strip()]
    peers: list[WgDumpPeer] = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 8:
            continue
        public_key, preshared_key, endpoint, allowed_ips, handshake, rx, tx, keepalive = fields
        validate_wg_key(public_key)
        peers.append(
            WgDumpPeer(
                public_key=public_key,
                preshared_key=preshared_key,
                endpoint=None if endpoint == "(none)" else endpoint,
                allowed_ips=[] if allowed_ips == "(none)" else allowed_ips.split(","),
                latest_handshake=int(handshake),
                transfer_rx=int(rx),
                transfer_tx=int(tx),
                persistent_keepalive=keepalive,
            )
        )
    return peers


def generate_keypair() -> tuple[str, str]:
    private = subprocess.run(
        ["wg", "genkey"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    public = subprocess.run(
        ["wg", "pubkey"],
        input=private + "\n",
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    validate_wg_key(private)
    validate_wg_key(public)
    return private, public


def allocate_next_ip(network_cidr: str, used_ips: set[str]) -> str:
    network = ipaddress.ip_network(validate_cidr(network_cidr))
    reserved = {str(network.network_address), str(network.broadcast_address)}
    for ip in network.hosts():
        ip_s = str(ip)
        if ip_s.endswith(".1"):
            continue
        if ip_s not in used_ips and ip_s not in reserved:
            return ip_s
    raise ValueError("No free IP addresses available")


def render_server_peer_block(name: str, public_key: str, assigned_ip: str, disabled: bool = False) -> str:
    validate_wg_key(public_key)
    prefix = "# disabled " if disabled else ""
    return (
        f"\n# wgpanel peer: {name}\n"
        f"[Peer]\n"
        f"{prefix}PublicKey = {public_key}\n"
        f"{prefix}AllowedIPs = {assigned_ip}/32\n"
    )


def append_peer_to_config(base_config: str, peer_block: str) -> str:
    return base_config.rstrip() + "\n" + peer_block.lstrip()


def strip_wgpanel_peer_blocks(config_text: str) -> str:
    lines = config_text.splitlines()
    kept: list[str] = []
    index = 0
    while index < len(lines):
        if lines[index].startswith("# wgpanel peer: "):
            index += 1
            if index < len(lines) and lines[index].strip() == "[Peer]":
                index += 1
                while index < len(lines) and not lines[index].strip().startswith("["):
                    index += 1
                continue
        kept.append(lines[index])
        index += 1
    return "\n".join(kept).rstrip() + "\n"


def render_config_with_active_peers(base_config: str, peers: list[tuple[str, str, str, bool]]) -> str:
    stripped = strip_wgpanel_peer_blocks(base_config)
    active_blocks = [
        render_server_peer_block(name, public_key, assigned_ip)
        for name, public_key, assigned_ip, disabled in peers
        if not disabled
    ]
    return stripped.rstrip() + "\n\n" + "\n".join(block.lstrip() for block in active_blocks)


def render_client_config(
    private_key: str,
    assigned_ip: str,
    server_public_key: str,
    endpoint: str,
    dns: str,
    allowed_ips: str,
) -> str:
    validate_wg_key(private_key)
    validate_wg_key(server_public_key)
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {assigned_ip}/32\n"
        f"DNS = {dns}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {allowed_ips}\n"
        "PersistentKeepalive = 25\n"
    )


def read_config(path: Path) -> str:
    return path.read_text(encoding="utf-8")
