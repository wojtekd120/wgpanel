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

    monkeypatch.setattr(main, "generate_keypair", lambda: (KEY_C, KEY_B))
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
    assert disabled.json()["disabled"] is True

    enabled = api_client.post(f"/api/peers/{peer_id}/enable")
    assert enabled.status_code == 200
    assert enabled.json()["disabled"] is False

    toggled = api_client.post(f"/api/peers/{peer_id}/toggle")
    assert toggled.status_code == 200
    assert toggled.json()["disabled"] is True


def test_update_peer_metadata(api_client):
    created = api_client.post("/api/peers", json={"name": "alice"}).json()["peer"]

    updated = api_client.patch(
        f"/api/peers/{created['id']}",
        json={"name": "alice laptop", "notes": "Issued to Alice", "expires_at": None},
    )

    assert updated.status_code == 200
    assert updated.json()["name"] == "alice laptop"
    assert updated.json()["notes"] == "Issued to Alice"


def test_docker_entrypoint_permission_logic_is_documented():
    entrypoint = Path(__file__).resolve().parents[2] / "docker-entrypoint.sh"
    text = entrypoint.read_text(encoding="utf-8")

    assert "mkdir -p /etc/wireguard" in text
    assert "chown root:wgpanel /etc/wireguard" in text
    assert "chmod 750 /etc/wireguard" in text
    assert "chown root:wgpanel /etc/wireguard/wg0.conf" in text
    assert "chmod 640 /etc/wireguard/wg0.conf" in text
    assert "chmod 644" not in text
