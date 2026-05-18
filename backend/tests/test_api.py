from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess

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
    config_path.write_text("[Interface]\nPrivateKey = server-secret\nAddress = 10.8.0.1/24\nListenPort = 51820\n", encoding="utf-8")

    settings = main.Settings(
        database_path=db_path,
        wg_config_path=config_path,
        backup_dir=tmp_path / "backups",
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
    monkeypatch.setattr(main, "restore_backup_with_helper", lambda *args, **kwargs: None)
    main.app.dependency_overrides[main.require_auth] = lambda: None
    main.app.dependency_overrides[get_settings] = lambda: settings
    monkeypatch.setattr(main, "get_settings", lambda: settings)

    def override_db():
        conn = connect(db_path)
        try:
            yield conn
        finally:
            conn.close()

    main.app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr("app.db.get_settings", lambda: settings)
    main.ATTEMPTS.clear()
    init_db()

    client = TestClient(main.app, raise_server_exceptions=False)
    try:
        yield client
    finally:
        main.app.dependency_overrides.clear()


def test_empty_peer_name_returns_readable_422(api_client):
    response = api_client.post("/api/peers", json={"name": "", "expires_at": None})

    assert response.status_code == 422
    assert response.json() == {"detail": "Peer name is required"}


def test_browser_setup_creates_admin_and_login_works(api_client):
    response = api_client.post(
        "/api/setup",
        json={"username": "admin", "password": "correct horse battery", "confirm_password": "correct horse battery"},
    )

    assert response.status_code == 200

    settings = main.get_settings()
    with connect(settings.database_path) as conn:
        row = conn.execute("SELECT username, password_hash FROM admins WHERE username = 'admin'").fetchone()
    assert row["username"] == "admin"
    assert row["password_hash"] != "correct horse battery"

    login = api_client.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    assert login.status_code == 200


def test_setup_disabled_after_admin_exists(api_client):
    api_client.post(
        "/api/setup",
        json={"username": "admin", "password": "correct horse battery", "confirm_password": "correct horse battery"},
    )

    second = api_client.post(
        "/api/setup",
        json={"username": "admin", "password": "another strong password", "confirm_password": "another strong password"},
    )

    assert second.status_code == 409
    assert second.json()["detail"] == "Setup is already completed."


def test_short_setup_password_rejected(api_client):
    response = api_client.post(
        "/api/setup",
        json={"username": "admin", "password": "short", "confirm_password": "short"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Password must be at least 12 characters."


def test_env_hash_backward_compatibility(tmp_path, monkeypatch):
    settings = main.Settings(
        database_path=tmp_path / "wgpanel.db",
        wg_config_path=tmp_path / "wg0.conf",
        admin_password_hash=main.hash_password("legacy strong password"),
        secure_cookies=False,
    )
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr("app.db.get_settings", lambda: settings)
    init_db()
    with connect(settings.database_path) as conn:
        main.migrate_env_admin(conn, settings)
        row = conn.execute("SELECT username, password_hash FROM admins").fetchone()

    assert row["username"] == "admin"
    assert row["password_hash"] == settings.admin_password_hash


def test_empty_expires_at_is_accepted(api_client):
    response = api_client.post("/api/peers", json={"name": "alice", "expires_at": ""})

    assert response.status_code == 200
    assert response.json()["peer"]["expires_at"] is None


def test_create_peer_redacts_preview_but_returns_one_time_client_config(api_client):
    response = api_client.post("/api/peers", json={"name": "alice"})

    body = response.json()
    assert response.status_code == 200
    assert "PrivateKey = server-secret" not in body["server_config_preview"]
    assert "PrivateKey = <redacted>" in body["server_config_preview"]
    assert "PrivateKey = " in body["client_config"]


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


def test_diagnostics_returns_docker_aware_commands(api_client, monkeypatch):
    monkeypatch.setattr(main, "running_in_docker", lambda: True)
    monkeypatch.setattr(main, "run_wg_interfaces", lambda: [])
    monkeypatch.setattr(main, "run_wg_dump", lambda _interface: (_ for _ in ()).throw(RuntimeError("wg failed")))

    response = api_client.get("/api/diagnostics")

    assert response.status_code == 200
    commands = [
        fix["command"]
        for check in response.json()
        for fix in check.get("fixes", [])
    ]
    assert any("docker compose exec wgpanel" in command for command in commands)
    assert any("visudo -cf /etc/sudoers.d/wgpanel" in command for command in commands)
    assert any("mkdir -p" in command and "backups" in command for command in commands)


def test_diagnostics_helper_check_passes_when_self_test_succeeds(api_client, monkeypatch):
    def ok_run(argv, **kwargs):
        if "self-test" in argv:
            return subprocess.CompletedProcess(argv, 0, "ok", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(main.subprocess, "run", ok_run)

    response = api_client.get("/api/diagnostics")

    helper = next(check for check in response.json() if check["key"] == "helper_sudo")
    assert helper["state"] == "pass"
    assert "self-test succeeded" in helper["detail"]


def test_diagnostics_helper_check_warns_when_inconclusive(api_client, monkeypatch):
    def failed_run(argv, **kwargs):
        if "self-test" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "not allowed")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(main.subprocess, "run", failed_run)

    response = api_client.get("/api/diagnostics")

    helper = next(check for check in response.json() if check["key"] == "helper_sudo")
    assert helper["state"] == "warn"
    assert "could not be verified automatically" in helper["detail"]


def test_error_responses_are_redacted(api_client, monkeypatch):
    def fail_apply(*args, **kwargs):
        raise RuntimeError("wg failed\nPrivateKey = secret-from-error")

    monkeypatch.setattr(main, "apply_config_with_helper", fail_apply)

    response = api_client.post("/api/peers", json={"name": "alice"})

    assert response.status_code == 500
    assert "secret-from-error" not in response.json()["detail"]
    assert "PrivateKey = <redacted>" in response.json()["detail"]


def test_docker_entrypoint_permission_logic_is_documented():
    entrypoint = Path(__file__).resolve().parents[2] / "docker-entrypoint.sh"
    text = entrypoint.read_text(encoding="utf-8")

    assert "mkdir -p /etc/wireguard" in text
    assert "chown root:wgpanel /etc/wireguard" in text
    assert "chmod 750 /etc/wireguard" in text
    assert 'wg_config="/etc/wireguard/${wg_interface}.conf"' in text
    assert 'chown root:wgpanel "$wg_config"' in text
    assert 'chmod 640 "$wg_config"' in text
    assert "chmod 644" not in text


def test_backup_listing_redacted_diff_and_restore_confirmation(api_client, tmp_path):
    settings = main.get_settings()
    backup_dir = settings.backup_dir
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / "wg0.conf.20260101-120000.bak"
    backup.write_text(
        "[Interface]\nPrivateKey = backup-secret\nAddress = 10.8.0.99/24\n",
        encoding="utf-8",
    )
    settings.wg_config_path.write_text(
        "[Interface]\nPrivateKey = current-secret\nAddress = 10.8.0.1/24\n",
        encoding="utf-8",
    )

    listed = api_client.get("/api/backups")
    assert listed.status_code == 200
    assert listed.json()["backups"][0]["name"] == backup.name
    assert listed.json()["backups"][0]["interface"] == "wg0"
    assert listed.json()["backups"][0]["size"] > 0

    diff = api_client.get(f"/api/backups/{backup.name}/diff")
    assert diff.status_code == 200
    assert "backup-secret" not in diff.json()["diff"]
    assert "current-secret" not in diff.json()["diff"]
    assert "PrivateKey = <redacted>" in diff.json()["diff"]

    denied = api_client.post(f"/api/backups/{backup.name}/restore", json={"confirmation": "RESTORE wrong"})
    assert denied.status_code == 422

    restored = api_client.post(f"/api/backups/{backup.name}/restore", json={"confirmation": "RESTORE wg0"})
    assert restored.status_code == 200
    assert restored.json()["detail"] == "Backup restored"

    download = api_client.get(f"/api/backups/{backup.name}/download")
    assert download.status_code == 200
    assert "backup-secret" not in download.text
    assert "PrivateKey = <redacted>" in download.text


def test_delete_managed_peer_removes_config_and_does_not_reappear_unmanaged(api_client, monkeypatch):
    settings = main.get_settings()

    def write_candidate(_helper, _run_dir, config_text, _dry_run, _interface):
        settings.wg_config_path.write_text(config_text, encoding="utf-8")
        return str(settings.wg_config_path)

    monkeypatch.setattr(main, "apply_config_with_helper", write_candidate)
    created = api_client.post("/api/peers", json={"name": "alice"}).json()["peer"]
    managed_key = created["public_key"]
    settings.wg_config_path.write_text(
        settings.wg_config_path.read_text(encoding="utf-8")
        + f"\n[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.8.0.99/32\n",
        encoding="utf-8",
    )

    deleted = api_client.delete(f"/api/peers/{created['id']}")

    assert deleted.status_code == 200
    rendered = settings.wg_config_path.read_text(encoding="utf-8")
    assert managed_key not in rendered
    assert KEY_B in rendered

    monkeypatch.setattr(
        main,
        "run_wg_dump",
        lambda _interface: "\n".join(
            [
                f"{KEY_A}\t51820\toff\tfwmark",
                f"{KEY_B}\t(none)\t198.51.100.4:51820\t10.8.0.99/32\t0\t0\t0\toff",
            ]
        ),
    )
    dashboard = api_client.get("/api/dashboard").json()
    assert managed_key not in {peer["public_key"] for peer in dashboard["peers"]}
    assert dashboard["peers"][0]["activity_status"] == "Never connected"

    listed = api_client.get("/api/peers").json()
    public_keys = {peer["public_key"] for peer in listed}
    assert managed_key not in public_keys
    assert KEY_B in public_keys
    assert next(peer for peer in listed if peer["public_key"] == KEY_B)["managed"] is False


def test_delete_apply_failure_keeps_metadata(api_client, monkeypatch):
    created = api_client.post("/api/peers", json={"name": "alice"}).json()["peer"]

    def fail_apply(*_args, **_kwargs):
        raise RuntimeError("apply failed")

    monkeypatch.setattr(main, "apply_config_with_helper", fail_apply)
    deleted = api_client.delete(f"/api/peers/{created['id']}")

    assert deleted.status_code == 500
    listed = api_client.get("/api/peers").json()
    assert created["public_key"] in {peer["public_key"] for peer in listed}
