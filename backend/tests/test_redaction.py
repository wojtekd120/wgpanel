from app.redaction import redact, redact_text
from app.security import hash_password


def test_redacts_private_keys_setup_tokens_and_password_hashes():
    password_hash = hash_password("verysecurepassword")
    text = (
        "[Interface]\n"
        "PrivateKey = server-secret\n"
        "Setup URL: http://127.0.0.1:8080/setup?token=abcdefghijklmnopqrstuvwxyzABCDEFG123456789\n"
        f"hash={password_hash}\n"
    )

    redacted = redact_text(text)

    assert "server-secret" not in redacted
    assert "abcdefghijklmnopqrstuvwxyzABCDEFG123456789" not in redacted
    assert password_hash not in redacted
    assert "PrivateKey = <redacted>" in redacted


def test_redacts_nested_error_payloads():
    payload = {
        "detail": [
            {
                "msg": "PrivateKey = client-secret",
                "hash": "pbkdf2_sha256$310000$c2FsdA==$ZGlnZXN0",
            }
        ]
    }

    redacted = redact(payload)

    assert "client-secret" not in str(redacted)
    assert "pbkdf2_sha256" not in str(redacted)
