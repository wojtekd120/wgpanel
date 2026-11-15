import ipaddress
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from time import time

from .validators import validate_cidr, validate_wg_key

INTERFACE_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")
DISABLED_BEGIN = "# wgpanel-disabled-begin: "
DISABLED_PREFIX = "# wgpanel-disabled "
DISABLED_END = "# wgpanel-disabled-end"


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


@dataclass(frozen=True)
class ConfigPeerBlock:
    text: str
    public_key: str | None
    allowed_ips: list[str]


def validate_interface_name(name: str) -> str:
    if not INTERFACE_RE.fullmatch(name):
        raise ValueError("Invalid WireGuard interface name")
    return name


def config_path_for_interface(interface: str) -> Path:
    return Path("/etc/wireguard") / f"{validate_interface_name(interface)}.conf"


def run_wg_dump(interface: str) -> str:
    validate_interface_name(interface)
    result = subprocess.run(
        ["wg", "show", interface, "dump"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout


def run_wg_interfaces() -> list[str]:
    result = subprocess.run(
        ["wg", "show", "interfaces"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return [validate_interface_name(item) for item in result.stdout.split() if item.strip()]


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


def allocate_next_ip(network_cidr: str, used_ips: set[str], server_address: str | None = None) -> str:
    network = ipaddress.ip_network(validate_cidr(network_cidr))
    server_ip = ipaddress.ip_address(server_address) if server_address else None
    if server_ip and server_ip not in network:
        raise ValueError("Server address must belong to the client address pool")
    reserved = {str(network.network_address), str(network.broadcast_address)}
    if server_ip:
        reserved.add(str(server_ip))
    for ip in network.hosts():
        ip_s = str(ip)
        if ip_s not in used_ips and ip_s not in reserved:
            return ip_s
    raise ValueError("No free IP addresses available")


def render_server_peer_block(name: str, public_key: str, assigned_ip: str, disabled: bool = False) -> str:
    validate_wg_key(public_key)
    allowed_ips = normalize_server_allowed_ips(assigned_ip)
    prefix = "# disabled " if disabled else ""
    return (
        f"\n# wgpanel peer: {name}\n"
        f"[Peer]\n"
        f"{prefix}PublicKey = {public_key}\n"
        f"{prefix}AllowedIPs = {allowed_ips}\n"
    )


def append_peer_to_config(base_config: str, peer_block: str) -> str:
    return base_config.rstrip() + "\n" + peer_block.lstrip()


def parse_config_peer_blocks(config_text: str) -> list[ConfigPeerBlock]:
    lines = config_text.splitlines()
    blocks: list[ConfigPeerBlock] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() != "[Peer]":
            index += 1
            continue
        start = index
        index += 1
        public_key: str | None = None
        allowed_ips: list[str] = []
        while index < len(lines) and not lines[index].strip().startswith("["):
            line = lines[index].strip()
            if "=" in line and not line.startswith("#"):
                key, value = [part.strip() for part in line.split("=", 1)]
                if key.lower() == "publickey":
                    public_key = value
                elif key.lower() == "allowedips":
                    allowed_ips = [item.strip() for item in value.split(",") if item.strip()]
            index += 1
        blocks.append(ConfigPeerBlock("\n".join(lines[start:index]).rstrip() + "\n", public_key, allowed_ips))
    return blocks


def unmanaged_used_ips(config_text: str, managed_public_keys: set[str]) -> set[str]:
    used: set[str] = set()
    for block in parse_config_peer_blocks(config_text):
        if block.public_key and block.public_key in managed_public_keys:
            continue
        for allowed in block.allowed_ips:
            try:
                network = ipaddress.ip_network(allowed, strict=False)
            except ValueError:
                continue
            if network.prefixlen in (32, 128):
                used.add(str(network.network_address))
    return used


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


def render_config_with_active_peers(
    base_config: str,
    peers: list[tuple[str, str, str, bool]],
    managed_public_keys: set[str] | None = None,
) -> str:
    return render_config_with_managed_keys(base_config, peers, managed_public_keys)


def render_config_with_managed_keys(
    base_config: str,
    peers: list[tuple[str, str, str, bool]],
    managed_public_keys: set[str] | None = None,
) -> str:
    """Round-trip a config while changing only managed peer membership/AllowedIPs.

    Interface directives, unmanaged peers, comments and unknown directives in an
    existing managed peer are preserved.  This is important for site-to-site
    peers which often carry PresharedKey, Endpoint or PersistentKeepalive in
    addition to AllowedIPs.
    """
    specs = {
        public_key: (name, normalize_server_allowed_ips(server_allowed_ips), disabled)
        for name, public_key, server_allowed_ips, disabled in peers
    }
    managed_keys = set(managed_public_keys or set()) | set(specs)
    lines = base_config.splitlines()
    kept: list[str] = []
    seen: set[str] = set()
    index = 0
    while index < len(lines):
        if lines[index].startswith(DISABLED_BEGIN):
            start = index
            index += 1
            encoded: list[str] = []
            while index < len(lines) and lines[index] != DISABLED_END:
                encoded.append(lines[index])
                index += 1
            if index < len(lines):
                index += 1
            block_lines = [
                line.removeprefix(DISABLED_PREFIX) if line.startswith(DISABLED_PREFIX) else line
                for line in encoded
            ]
            public_key = _public_key_from_peer_lines(block_lines)
            if public_key not in managed_keys:
                kept.extend(lines[start:index])
                continue
            spec = specs.get(public_key)
            if spec is None:
                continue
            seen.add(public_key)
            updated = _replace_peer_allowed_ips(block_lines, spec[1])
            if spec[2]:
                kept.extend(_encode_disabled_peer(spec[0], updated))
            else:
                kept.append(f"# wgpanel peer: {spec[0]}")
                kept.extend(updated)
            continue

        if lines[index].strip() != "[Peer]":
            kept.append(lines[index])
            index += 1
            continue

        start = index
        index += 1
        while index < len(lines) and not lines[index].strip().startswith("["):
            index += 1
        block_lines = lines[start:index]
        public_key = _public_key_from_peer_lines(block_lines)
        if public_key not in managed_keys:
            kept.extend(block_lines)
            continue

        spec = specs.get(public_key)
        if spec is None:
            if kept and kept[-1].startswith("# wgpanel peer: "):
                kept.pop()
            continue

        seen.add(public_key)
        updated = _replace_peer_allowed_ips(block_lines, spec[1])
        if spec[2]:
            if kept and kept[-1].startswith("# wgpanel peer: "):
                kept.pop()
            kept.extend(_encode_disabled_peer(spec[0], updated))
            continue
        if kept and kept[-1].startswith("# wgpanel peer: "):
            kept[-1] = f"# wgpanel peer: {spec[0]}"
        kept.extend(updated)

    rendered = "\n".join(kept).rstrip()
    for public_key, (name, server_allowed_ips, disabled) in specs.items():
        if public_key in seen:
            continue
        new_lines = render_server_peer_block(name, public_key, server_allowed_ips).strip().splitlines()
        if disabled:
            rendered += "\n\n" + "\n".join(_encode_disabled_peer(name, new_lines[1:]))
        else:
            rendered += "\n\n" + "\n".join(new_lines)
    return rendered.rstrip() + "\n"


def _encode_disabled_peer(name: str, block_lines: list[str]) -> list[str]:
    return [
        f"{DISABLED_BEGIN}{name}",
        *(f"{DISABLED_PREFIX}{line}" for line in block_lines),
        DISABLED_END,
    ]


def _public_key_from_peer_lines(lines: list[str]) -> str | None:
    for raw_line in lines[1:]:
        line = raw_line.strip()
        if "=" not in line or line.startswith("#"):
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if key.lower() == "publickey":
            return value
    return None


def _replace_peer_allowed_ips(lines: list[str], allowed_ips: str) -> list[str]:
    result: list[str] = []
    replaced = False
    public_key_index: int | None = None
    for raw_line in lines:
        stripped = raw_line.strip()
        if "=" in stripped and not stripped.startswith("#"):
            key = stripped.split("=", 1)[0].strip().lower()
            if key == "publickey":
                public_key_index = len(result)
            if key == "allowedips":
                if not replaced:
                    indentation = raw_line[: len(raw_line) - len(raw_line.lstrip())]
                    result.append(f"{indentation}AllowedIPs = {allowed_ips}")
                    replaced = True
                continue
        result.append(raw_line)
    if not replaced:
        insert_at = (public_key_index + 1) if public_key_index is not None else len(result)
        result.insert(insert_at, f"AllowedIPs = {allowed_ips}")
    return result


def handshake_activity_status(latest_handshake: int, now: int | None = None) -> str:
    if not latest_handshake:
        return "Never connected"
    current = int(time()) if now is None else now
    age = max(0, current - latest_handshake)
    if age < 5 * 60:
        return "Active"
    if age < 7 * 24 * 60 * 60:
        return "Recent"
    return "Stale"


def strip_managed_peer_blocks(config_text: str, managed_public_keys: set[str]) -> str:
    lines = config_text.splitlines()
    kept: list[str] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() == "[Peer]":
            start = index
            index += 1
            public_key: str | None = None
            while index < len(lines) and not lines[index].strip().startswith("["):
                line = lines[index].strip()
                if "=" in line and not line.startswith("#"):
                    key, value = [part.strip() for part in line.split("=", 1)]
                    if key.lower() == "publickey":
                        public_key = value
                index += 1
            if public_key in managed_public_keys:
                while kept and kept[-1].startswith("# wgpanel peer: "):
                    kept.pop()
                continue
            kept.extend(lines[start:index])
            continue
        kept.append(lines[index])
        index += 1
    return "\n".join(kept).rstrip() + "\n"


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


def validate_allowed_ips(value: str) -> str:
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if not parts:
        raise ValueError("Custom AllowedIPs must include at least one CIDR")
    for part in parts:
        try:
            ipaddress.ip_network(part, strict=True)
        except ValueError as exc:
            raise ValueError("Invalid AllowedIPs CIDR") from exc
    return ", ".join(parts)


def normalize_server_allowed_ips(value: str | list[str]) -> str:
    """Validate and canonicalize server-side cryptokey routing prefixes."""
    if isinstance(value, str):
        raw_parts = [part.strip() for part in value.split(",") if part.strip()]
    else:
        raw_parts = [part.strip() for part in value if part.strip()]
    if not raw_parts:
        raise ValueError("Server-side AllowedIPs must include at least one CIDR")
    normalized: list[str] = []
    for part in raw_parts:
        if "/" not in part:
            address = ipaddress.ip_address(part)
            part = f"{address}/{address.max_prefixlen}"
        try:
            network = ipaddress.ip_network(part, strict=True)
        except ValueError as exc:
            raise ValueError(f"Invalid server-side AllowedIPs CIDR: {part}") from exc
        canonical = str(network)
        if canonical not in normalized:
            normalized.append(canonical)
    return ", ".join(normalized)


def server_allowed_ips_with_assigned_ip(assigned_ip: str, additional: str | None = None) -> str:
    address = ipaddress.ip_address(assigned_ip)
    parts = [f"{address}/{address.max_prefixlen}"]
    if additional:
        parts.extend(part.strip() for part in additional.split(",") if part.strip())
    return normalize_server_allowed_ips(parts)


def allowed_ip_conflicts(
    peers: list[tuple[str, str, str]],
) -> list[tuple[str, str, str, str]]:
    """Return overlaps as (peer A, prefix A, peer B, prefix B)."""
    parsed: list[tuple[str, str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for peer_key, _peer_name, allowed_ips in peers:
        for prefix in normalize_server_allowed_ips(allowed_ips).split(", "):
            parsed.append((peer_key, prefix, ipaddress.ip_network(prefix)))
    conflicts: list[tuple[str, str, str, str]] = []
    for index, (left_key, left_prefix, left_network) in enumerate(parsed):
        for right_key, right_prefix, right_network in parsed[index + 1 :]:
            if left_key == right_key or left_network.version != right_network.version:
                continue
            if left_network.overlaps(right_network):
                conflicts.append((left_key, left_prefix, right_key, right_prefix))
    return conflicts


def read_config(path: Path) -> str:
    return path.read_text(encoding="utf-8")
