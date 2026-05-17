import pytest

from app.wireguard import (
    allocate_next_ip,
    append_peer_to_config,
    parse_wg_dump,
    render_client_config,
    render_config_with_active_peers,
    render_server_peer_block,
    strip_wgpanel_peer_blocks,
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

    assert allocate_next_ip("10.8.0.0/24", used) == "10.8.0.4"


def test_allocate_next_ip_raises_when_full():
    with pytest.raises(ValueError):
        allocate_next_ip("10.8.0.0/30", {"10.8.0.2"})


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
    assert "wgpanel peer: disabled" not in rendered
    assert KEY_C not in rendered
