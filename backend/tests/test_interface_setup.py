from datetime import timedelta

import pytest

from app import main
from app.db import connect, init_db
from app.security import hash_password, new_setup_token, token_digest, utcnow, verify_password
from app.wireguard import validate_interface_name


@pytest.mark.parametrize("name", ["wg0", "wg1", "wg-test", "homevpn", "wg.prod"])
def test_interface_name_validation_accepts_safe_names(name):
    assert validate_interface_name(name) == name


@pytest.mark.parametrize("name", ["../wg0", "/etc/passwd", "wg0;rm -rf", "bad/name"])
def test_interface_name_validation_rejects_unsafe_names(name):
    with pytest.raises(ValueError):
        validate_interface_name(name)


def test_peer_metadata_is_scoped_per_interface(tmp_path, monkeypatch):
    settings = main.Settings(database_path=tmp_path / "db.sqlite", admin_password_hash=hash_password("verysecurepassword"))
    monkeypatch.setattr("app.db.get_settings", lambda: settings)
    init_db()
    with connect(settings.database_path) as conn:
        conn.execute(
            "INSERT INTO peers (name, public_key, assigned_ip, created_at, interface_name) VALUES (?, ?, ?, ?, ?)",
            ("a", "A" * 43 + "=", "10.8.0.2", utcnow().isoformat(), "wg0"),
        )
        conn.execute(
            "INSERT INTO peers (name, public_key, assigned_ip, created_at, interface_name) VALUES (?, ?, ?, ?, ?)",
            ("b", "B" * 43 + "=", "10.9.0.2", utcnow().isoformat(), "wg1"),
        )
        conn.commit()
        assert conn.execute("SELECT count(*) AS c FROM peers WHERE interface_name = 'wg0'").fetchone()["c"] == 1
        assert conn.execute("SELECT count(*) AS c FROM peers WHERE interface_name = 'wg1'").fetchone()["c"] == 1


def test_first_run_setup_token_is_single_use(tmp_path, monkeypatch):
    settings = main.Settings(database_path=tmp_path / "db.sqlite")
    monkeypatch.setattr("app.db.get_settings", lambda: settings)
    init_db()
    token = new_setup_token()
    with connect(settings.database_path) as conn:
        conn.execute(
            "INSERT INTO setup_tokens (token_digest, created_at, expires_at, used) VALUES (?, ?, ?, 0)",
            (token_digest(token), utcnow().isoformat(), (utcnow() + timedelta(minutes=30)).isoformat()),
        )
        conn.commit()
        row = conn.execute("SELECT used FROM setup_tokens WHERE token_digest = ?", (token_digest(token),)).fetchone()
        assert row["used"] == 0
        conn.execute("UPDATE setup_tokens SET used = 1 WHERE token_digest = ?", (token_digest(token),))
        conn.commit()
        assert conn.execute("SELECT used FROM setup_tokens WHERE token_digest = ?", (token_digest(token),)).fetchone()["used"] == 1


def test_password_hash_stores_no_plaintext():
    encoded = hash_password("verysecurepassword")
    assert "verysecurepassword" not in encoded
    assert verify_password("verysecurepassword", encoded)
