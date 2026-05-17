#!/usr/bin/env python3
import argparse
from getpass import getpass
from pathlib import Path

from app.db import connect, init_db
from app.security import hash_password, new_setup_token, setup_expiry, token_digest, utcnow
from app.settings import get_settings


def prompt_password() -> str:
    password = getpass("New admin password: ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters")
    return password


def reset_password(username: str) -> None:
    init_db()
    encoded = hash_password(prompt_password())
    with connect() as conn:
        row = conn.execute("SELECT id FROM admins WHERE username = ?", (username,)).fetchone()
        if row:
            conn.execute("UPDATE admins SET password_hash = ? WHERE username = ?", (encoded, username))
        else:
            conn.execute(
                "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, encoded, utcnow().isoformat()),
            )
        conn.commit()
    print(f"Password reset for admin user '{username}'.")


def create_setup_token() -> None:
    init_db()
    settings = get_settings()
    token = new_setup_token()
    expires = setup_expiry()
    with connect() as conn:
        conn.execute(
            "INSERT INTO setup_tokens (token_digest, created_at, expires_at, used) VALUES (?, ?, ?, 0)",
            (token_digest(token), utcnow().isoformat(), expires.isoformat()),
        )
        conn.commit()
    path = Path(settings.database_path).parent / "setup-token"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token, encoding="utf-8")
    path.chmod(0o600)
    print("Setup token created. Open:")
    print(f"http://127.0.0.1:8080/setup?token={token}")


def main() -> None:
    parser = argparse.ArgumentParser(description="WGPanel admin maintenance")
    sub = parser.add_subparsers(dest="command", required=True)
    reset = sub.add_parser("reset-password")
    reset.add_argument("--username", default="admin")
    sub.add_parser("create-setup-token")
    args = parser.parse_args()
    if args.command == "reset-password":
        reset_password(args.username)
    elif args.command == "create-setup-token":
        create_setup_token()


if __name__ == "__main__":
    main()
