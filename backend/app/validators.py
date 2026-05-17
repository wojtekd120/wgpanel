import ipaddress
import re

from fastapi import HTTPException

WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
PEER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,62}[A-Za-z0-9]$")
SHELL_META_RE = re.compile(r"[;&|`$<>\\!()\[\]{}*?~\n\r]")


def validate_peer_name(name: str) -> str:
    stripped = " ".join(name.strip().split())
    if not PEER_NAME_RE.fullmatch(stripped) or SHELL_META_RE.search(stripped):
        raise HTTPException(status_code=422, detail="Invalid peer name")
    return stripped


def validate_wg_key(key: str) -> str:
    if not WG_KEY_RE.fullmatch(key):
        raise HTTPException(status_code=422, detail="Invalid WireGuard key")
    return key


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid IP address") from exc


def validate_cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=True))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid CIDR") from exc
