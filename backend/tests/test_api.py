from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main
from app.db import connect, get_db, init_db
from app.settings import get_settings


KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="
KEY_C = "C" * 43 + "="


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    db_path = tmp_path / "wgpanel.db"
    config_path = tmp_path / "wg0.conf"
    config_path.write_text("[Interface]\nAddress = 10.8.0.1/24\nListenPort = 51820\n", encoding="utf-8")

    settings = main.Settings(
        database_path=db_path,
        wg_config_path=config_path,
        helper_path=Path("/usr/local/sbin/wgpanel-helper"),
        run_dir=tmp_path / "run",
        server_public_key=KEY_A,
        secure_cookies=False,
    )

    key_index = {"value": 0}

    def fake_keypair():
        key_index["value"] += 1
        public = (chr(ord("B") + key_index["value"]) * 43) + "="
        private = (chr(ord("K") + key_index["value"]) * 43) + "="
        return private, public

    monkeypatch.setattr(main, "generate_keypair", fake_keypair)
    monkeypatch.setattr(main, "apply_config_with_helper", lambda *args, **kwargs: str(tmp_path / "candidate.conf"))
    main.app.dependency_overrides[main.require_auth] = lambda: None
    main.app.dependency_overrides[get_settings] = lambda: settings

    def override_db():
        conn = connect(db_path)
        try:
            yield conn
        finally:
            conn.close()

    main.app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr("app.db.get_settings", lambda: settings)
    init_db()

    client = TestClient(main.app)
    try:
        yield client
    finally:
        main.app.dependency_overrides.clear()


def test_empty_peer_name_returns_readable_422(api_client):
    response = api_client.post("/api/peers", json={"name": "", "expires_at": None})

    assert response.status_code == 422
    assert response.json() == {"detail": "Peer name is required"}


def test_empty_expires_at_is_accepted(api_client):
    response = api_client.post("/api/peers", json={"name": "alice", "expires_at": ""})

    assert response.status_code == 200
    assert response.json()["peer"]["expires_at"] is None


def test_invalid_expires_at_returns_readable_422(api_client):
    response = api_client.post("/api/peers", json={"name": "alice", "expires_at": "not-a-date"})

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid expiration date"}


def test_sqlite_requests_are_safe_across_threads(api_client):
    def list_peers():
        response = api_client.get("/api/peers")
        assert response.status_code == 200
        return response.json()

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: list_peers(), range(8)))

    assert results == [[] for _ in range(8)]


def test_disable_enable_toggle_changes_state(api_client):
    created = api_client.post("/api/peers", json={"name": "alice"}).json()["peer"]
    peer_id = created["id"]

    disabled = api_client.post(f"/api/peers/{peer_id}/disable")
    assert disabled.status_code == 200
    assert disabled.json()["detail"] == "Peer disabled"
    assert disabled.json()["active"] is False

    enabled = api_client.post(f"/api/peers/{peer_id}/enable")
    assert enabled.status_code == 200
    assert enabled.json()["detail"] == "Peer enabled"
    assert enabled.json()["active"] is True

    toggled = api_client.post(f"/api/peers/{peer_id}/toggle")
    assert toggled.status_code == 200
    assert toggled.json()["active"] is False


def test_update_peer_metadata(api_client):
    created = api_client.post("/api/peers", json={"name": "alice"}).json()["peer"]

    updated = api_client.patch(
        f"/api/peers/{created['id']}",
        json={"name": "alice laptop", "notes": "Issued to Alice", "expires_at": None},
    )

    assert updated.status_code == 200
    assert updated.json()["name"] == "alice laptop"
    assert updated.json()["notes"] == "Issued to Alice"


def test_existing_peer_list_does_not_return_private_config(api_client):
    api_client.post("/api/peers", json={"name": "alice"})

    response = api_client.get("/api/peers")

    assert response.status_code == 200
    assert "client_config" not in response.json()[0]


def test_manual_expiry_disables_expired_managed_peers(api_client):
    created = api_client.post("/api/peers", json={"name": "alice", "expires_at": "2020-01-01T00:00:00Z"}).json()["peer"]

    expired = api_client.post("/api/maintenance/expire")

    assert expired.status_code == 200
    assert expired.json()["count"] == 1
    assert created["id"] in expired.json()["peer_ids"]
    peer = api_client.get("/api/peers").json()[0]
    assert peer["disabled"] is True


def test_invalid_custom_allowed_ips_is_readable(api_client):
    response = api_client.post(
        "/api/peers",
        json={"name": "alice", "tunnel_mode": "custom", "custom_allowed_ips": "bad"},
    )

    assert response.status_code == 422
    assert "AllowedIPs" in response.json()["detail"]


def test_docker_entrypoint_permission_logic_is_documented():
    entrypoint = Path(__file__).resolve().parents[2] / "docker-entrypoint.sh"
    text = entrypoint.read_text(encoding="utf-8")

    assert "mkdir -p /etc/wireguard" in text
    assert "chown root:wgpanel /etc/wireguard" in text
    assert "chmod 750 /etc/wireguard" in text
    assert "chown root:wgpanel /etc/wireguard/wg0.conf" in text
    assert "chmod 640 /etc/wireguard/wg0.conf" in text
    assert "chmod 644" not in text
