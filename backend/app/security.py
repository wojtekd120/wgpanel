import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

PBKDF2_PREFIX = "pbkdf2_sha256"


def hash_password(password: str, iterations: int = 310_000) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "$".join(
        [
            PBKDF2_PREFIX,
            str(iterations),
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        ]
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        prefix, iterations_s, salt_b64, digest_b64 = encoded.split("$", 3)
        if prefix != PBKDF2_PREFIX:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations_s))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(48)


def new_setup_token() -> str:
    return secrets.token_urlsafe(48)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def session_expiry() -> datetime:
    return utcnow() + timedelta(hours=12)


def setup_expiry() -> datetime:
    return utcnow() + timedelta(minutes=30)
