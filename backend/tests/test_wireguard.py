import pytest

from app.wireguard import (
    allowed_ip_conflicts,
    allocate_next_ip,
    append_peer_to_config,
    handshake_activity_status,
    parse_config_peer_blocks,
    parse_wg_dump,
    render_client_config,
    render_config_with_active_peers,
    render_server_peer_block,
    strip_wgpanel_peer_blocks,
    unmanaged_used_ips,
    validate_allowed_ips,
    server_allowed_ips_with_assigned_ip,
)


KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="
KEY_C = "C" * 43 + "="


def test_parse_wg_dump_peers():
    dump = "\n".join(
        [
            f"{KEY_A}\t51820\toff\tfwmark",
            f"{KEY_B}\t(none)\t198.51.100.4:51820\t10.8.0.2/32\t1710000000\t123\t456\t25",
        ]
    )

    peers = parse_wg_dump(dump)

    assert len(peers) == 1
    assert peers[0].public_key == KEY_B
    assert peers[0].endpoint == "198.51.100.4:51820"
    assert peers[0].allowed_ips == ["10.8.0.2/32"]
    assert peers[0].latest_handshake == 1710000000
    assert peers[0].transfer_rx == 123
    assert peers[0].transfer_tx == 456


def test_allocate_next_ip_skips_server_address_and_used_ips():
    used = {"10.8.0.2", "10.8.0.3"}

    assert allocate_next_ip("10.8.0.0/24", used, "10.8.0.1") == "10.8.0.4"


def test_allocate_next_ip_raises_when_full():
    with pytest.raises(ValueError):
        allocate_next_ip("10.8.0.0/30", {"10.8.0.2"}, "10.8.0.1")


def test_peer_config_generation():
    block = render_server_peer_block("alice laptop", KEY_B, "10.8.0.2")
    assert "PublicKey = " + KEY_B in block
    assert "AllowedIPs = 10.8.0.2/32" in block

    client = render_client_config(KEY_C, "10.8.0.2", KEY_A, "vpn.example.com:51820", "1.1.1.1", "0.0.0.0/0")
    assert "PrivateKey = " + KEY_C in client
    assert "PublicKey = " + KEY_A in client
    assert "Endpoint = vpn.example.com:51820" in client


def test_render_config_with_active_peers_removes_managed_disabled_peer():
    base = append_peer_to_config(
        "[Interface]\nAddress = 10.8.0.1/24\nListenPort = 51820\n",
        render_server_peer_block("old", KEY_B, "10.8.0.2"),
    )
    stripped = strip_wgpanel_peer_blocks(base)
    assert "wgpanel peer: old" not in stripped

    rendered = render_config_with_active_peers(
        base,
        [
            ("active", KEY_B, "10.8.0.2", False),
            ("disabled", KEY_C, "10.8.0.3", True),
        ],
    )

    assert "wgpanel peer: active" in rendered
    assert KEY_B in rendered
    assert "wgpanel-disabled-begin: disabled" in rendered
    assert KEY_C not in {block.public_key for block in parse_config_peer_blocks(rendered)}


def test_unmanaged_peer_is_preserved_when_rendering_managed_config():
    base = (
        "[Interface]\nPrivateKey = server\nPostUp = iptables rule\n\n"
        "[Peer]\n# existing phone\n"
        f"PublicKey = {KEY_C}\nAllowedIPs = 10.8.0.9/32\n"
    )

    rendered = render_config_with_active_peers(base, [("managed", KEY_B, "10.8.0.2", False)])

    assert "PostUp = iptables rule" in rendered
    assert KEY_C in rendered
    assert "AllowedIPs = 10.8.0.9/32" in rendered
    assert KEY_B in rendered
    assert "AllowedIPs = 10.8.0.2/32" in rendered


def test_disable_removes_managed_peer_but_preserves_unmanaged_peer():
    base = (
        "[Interface]\nAddress = 10.8.0.1/24\n\n"
        f"[Peer]\nPublicKey = {KEY_C}\nAllowedIPs = 10.8.0.9/32\n\n"
        f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.8.0.2/32\n"
    )

    rendered = render_config_with_active_peers(base, [("managed", KEY_B, "10.8.0.2", True)])

    assert KEY_C in rendered
    assert "wgpanel-disabled-begin: managed" in rendered
    assert KEY_B not in {block.public_key for block in parse_config_peer_blocks(rendered)}


def test_unmanaged_allowed_ips_are_considered_used():
    base = f"[Interface]\n\n[Peer]\nPublicKey = {KEY_C}\nAllowedIPs = 10.8.0.5/32\n"

    assert unmanaged_used_ips(base, {KEY_B}) == {"10.8.0.5"}


def test_custom_address_pool_skips_server_and_used_ips():
    assert allocate_next_ip("172.16.50.0/24", {"172.16.50.2"}, "172.16.50.1") == "172.16.50.3"


def test_full_split_and_custom_client_allowed_ips_rendering():
    split = render_client_config(KEY_C, "10.8.0.2", KEY_A, "vpn.example.com:51820", "1.1.1.1", "10.8.0.0/24")
    full = render_client_config(KEY_C, "10.8.0.2", KEY_A, "vpn.example.com:51820", "1.1.1.1", "0.0.0.0/0, ::/0")
    custom = validate_allowed_ips("10.8.0.0/24, 198.51.100.0/24")

    assert "AllowedIPs = 10.8.0.0/24" in split
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in full
    assert custom == "10.8.0.0/24, 198.51.100.0/24"


def test_custom_allowed_ips_rejects_invalid_cidr():
    with pytest.raises(ValueError):
        validate_allowed_ips("not-a-cidr")


def test_activity_status_calculation():
    now = 1_800_000_000

    assert handshake_activity_status(0, now=now) == "Never connected"
    assert handshake_activity_status(now - 60, now=now) == "Active"
    assert handshake_activity_status(now - 3600, now=now) == "Recent"
    assert handshake_activity_status(now - (8 * 24 * 3600), now=now) == "Stale"


def test_deleted_managed_key_is_not_preserved_as_unmanaged():
    base = (
        "[Interface]\nAddress = 10.8.0.1/24\n\n"
        f"[Peer]\nPublicKey = {KEY_C}\nAllowedIPs = 10.8.0.9/32\n\n"
        f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.8.0.2/32\n"
    )

    rendered = render_config_with_active_peers(base, [], managed_public_keys={KEY_B})

    assert KEY_B not in rendered
    assert KEY_C in rendered


def test_managed_peer_keeps_multiple_server_allowed_ips_and_unknown_directives():
    base = (
        "[Interface]\n"
        "PostUp = ip route replace 198.51.100.0/24 via 192.0.2.10 dev wg0\n"
        "PostUp = iptables -t nat -A PREROUTING -i wg0 -d 203.0.113.0/24 -j NETMAP --to 198.51.100.0/24\n\n"
        "# manually documented site peer\n"
        "[Peer]\n"
        f"PublicKey = {KEY_B}\n"
        "PresharedKey = keep-this-secret\n"
        "AllowedIPs = 192.0.2.10/32\n"
        "PersistentKeepalive = 25\n"
    )

    rendered = render_config_with_active_peers(
        base,
        [("example-site", KEY_B, "192.0.2.10/32, 198.51.100.0/24", False)],
        managed_public_keys={KEY_B},
    )

    assert "AllowedIPs = 192.0.2.10/32, 198.51.100.0/24" in rendered
    assert "PresharedKey = keep-this-secret" in rendered
    assert "PersistentKeepalive = 25" in rendered
    assert "NETMAP --to 198.51.100.0/24" in rendered
    assert "via 192.0.2.10 dev wg0" in rendered


def test_server_allowed_ips_always_include_new_assigned_host_route():
    assert server_allowed_ips_with_assigned_ip("192.0.2.11", "198.51.100.0/24") == (
        "192.0.2.11/32, 198.51.100.0/24"
    )


def test_overlapping_server_allowed_ips_are_detected_across_peers():
    conflicts = allowed_ip_conflicts(
        [
            (KEY_B, "site", "192.0.2.10/32, 198.51.100.0/24"),
            (KEY_C, "other", "192.0.2.11/32, 198.51.100.55/32"),
        ]
    )

    assert conflicts == [(KEY_B, "198.51.100.0/24", KEY_C, "198.51.100.55/32")]


def test_disable_then_enable_preserves_unknown_peer_directives():
    base = (
        "[Interface]\nAddress = 192.0.2.1/24\n\n"
        "# wgpanel peer: example-site\n"
        "[Peer]\n"
        f"PublicKey = {KEY_B}\n"
        "PresharedKey = keep-across-disable\n"
        "AllowedIPs = 192.0.2.10/32, 198.51.100.0/24\n"
        "PersistentKeepalive = 25\n"
    )
    disabled = render_config_with_active_peers(
        base,
        [("example-site", KEY_B, "192.0.2.10/32, 198.51.100.0/24", True)],
        managed_public_keys={KEY_B},
    )
    assert "# wgpanel-disabled PresharedKey = keep-across-disable" in disabled
    assert KEY_B not in {block.public_key for block in parse_config_peer_blocks(disabled)}

    enabled = render_config_with_active_peers(
        disabled,
        [("example-site", KEY_B, "192.0.2.10/32, 198.51.100.0/24", False)],
        managed_public_keys={KEY_B},
    )
    assert "PresharedKey = keep-across-disable" in enabled
    assert "PersistentKeepalive = 25" in enabled
    assert "wgpanel-disabled" not in enabled
    assert KEY_B in {block.public_key for block in parse_config_peer_blocks(enabled)}
