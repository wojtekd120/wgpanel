from dataclasses import dataclass
import ipaddress

from .settings import Settings


@dataclass(frozen=True)
class InterfaceProfile:
    peer_type: str
    interface: str
    server_endpoint: str
    server_public_key: str
    client_address_pool: str
    server_address: str
    client_dns: str
    client_allowed_ips: str
    ipv6_enabled: bool


def interface_profile(settings: Settings, peer_type: str) -> InterfaceProfile:
    if peer_type == "private":
        return InterfaceProfile(
            peer_type="private",
            interface=settings.interface,
            server_endpoint=settings.server_endpoint,
            server_public_key=settings.server_public_key,
            client_address_pool=settings.client_address_pool,
            server_address=settings.server_address,
            client_dns=settings.client_dns,
            client_allowed_ips=settings.client_address_pool,
            ipv6_enabled=True,
        )
    if peer_type != "guest":
        raise ValueError("Invalid peer type")
    if not settings.guest_enabled:
        raise ValueError("Guest VPN is disabled. Set WGPANEL_GUEST_ENABLED=true only after wg1 and its firewall are installed.")
    if not settings.guest_server_endpoint or not settings.guest_server_public_key:
        raise ValueError("Guest VPN endpoint and server public key must be configured")
    if settings.guest_interface == settings.interface:
        raise ValueError("Guest VPN must use a different WireGuard interface")
    guest_pool = ipaddress.ip_network(settings.guest_client_address_pool, strict=True)
    private_pool = ipaddress.ip_network(settings.client_address_pool, strict=True)
    if guest_pool.version != 4:
        raise ValueError("Guest VPN MVP requires an IPv4 address pool")
    if guest_pool.version == private_pool.version and guest_pool.overlaps(private_pool):
        raise ValueError("Guest and private WireGuard address pools overlap")
    if ipaddress.ip_address(settings.guest_server_address) not in guest_pool:
        raise ValueError("Guest server address must belong to the guest address pool")
    if settings.guest_server_public_key == settings.server_public_key:
        raise ValueError("Guest and private interfaces must not use the same server key")
    return InterfaceProfile(
        peer_type="guest",
        interface=settings.guest_interface,
        server_endpoint=settings.guest_server_endpoint,
        server_public_key=settings.guest_server_public_key,
        client_address_pool=settings.guest_client_address_pool,
        server_address=settings.guest_server_address,
        client_dns=settings.guest_client_dns,
        client_allowed_ips="0.0.0.0/0",
        ipv6_enabled=False,
    )


def profile_for_interface(settings: Settings, interface: str) -> InterfaceProfile:
    if settings.guest_enabled and interface == settings.guest_interface:
        return interface_profile(settings, "guest")
    return interface_profile(settings, "private")
