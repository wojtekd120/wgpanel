import importlib.util
from pathlib import Path

from app.guest import interface_profile
from app.settings import Settings


ROOT = Path(__file__).resolve().parents[2]


def load_preflight_module():
    path = ROOT / "scripts" / "guest_network_preflight.py"
    spec = importlib.util.spec_from_file_location("guest_network_preflight", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_guest_profile_is_ipv4_only_and_uses_separate_interface():
    settings = Settings(
        guest_enabled=True,
        guest_interface="wg1",
        guest_server_endpoint="vpn.example.test:51821",
        guest_server_public_key="G" * 43 + "=",
    )

    profile = interface_profile(settings, "guest")

    assert profile.interface == "wg1"
    assert profile.client_address_pool == "10.10.20.0/24"
    assert profile.server_address == "10.10.20.1"
    assert profile.client_allowed_ips == "0.0.0.0/0"
    assert profile.ipv6_enabled is False


def test_guest_preflight_detects_route_wg_and_docker_overlap():
    preflight = load_preflight_module()

    conflicts = preflight.overlaps(
        "10.10.20.0/24",
        [("eth0", "10.10.0.0/16"), ("docker:app", "172.18.0.0/16")],
        "wg1",
    )

    assert conflicts == [("eth0", "10.10.0.0/16")]


def test_guest_profile_rejects_overlap_with_private_pool():
    settings = Settings(
        client_address_pool="10.10.20.0/25",
        guest_enabled=True,
        guest_server_endpoint="vpn.example.test:51821",
        guest_server_public_key="G" * 43 + "=",
        guest_client_address_pool="10.10.20.0/24",
    )

    try:
        interface_profile(settings, "guest")
    except ValueError as exc:
        assert "overlap" in str(exc)
    else:
        raise AssertionError("overlapping guest pool was accepted")


def test_guest_preflight_allows_own_wg1_routes_and_peer_host_routes():
    preflight = load_preflight_module()

    conflicts = preflight.overlaps(
        "10.10.20.0/24",
        [("wg1", "10.10.20.0/24"), ("wg1", "10.10.20.2/32"), ("wg0", "10.10.10.0/24")],
        "wg1",
    )

    assert conflicts == []


def test_guest_firewall_is_fail_closed_and_idempotently_managed():
    script = (ROOT / "scripts" / "wgpanel-guest-firewall").read_text(encoding="utf-8")

    assert 'iifname "$GUEST_INTERFACE" oifname "$GUEST_INTERFACE"' in script
    assert 'iifname "$GUEST_INTERFACE" oifname "$PRIVATE_WG_INTERFACE"' in script
    assert 'iifname "$PRIVATE_WG_INTERFACE" oifname "$GUEST_INTERFACE" ct state new' in script
    assert 'iifname "$GUEST_INTERFACE" meta nfproto ipv6' in script
    assert 'iifname "$GUEST_INTERFACE" ip daddr $VPS_PUBLIC_IPV4' in script
    assert "udp dport 53" in script
    assert "tcp dport 53" in script
    assert 'ip daddr $GUEST_DNS_IPV4' in script
    assert 'iifname "$GUEST_INTERFACE" counter drop comment "WGPanel guest fail-closed fallback"' in script
    assert 'delete table inet $table_name' in script
