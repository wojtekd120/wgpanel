import re
from collections.abc import Mapping

REDACTED = "<redacted>"

PRIVATE_KEY_LINE_RE = re.compile(r"^(\s*PrivateKey\s*=\s*).+$", re.IGNORECASE | re.MULTILINE)
SETUP_TOKEN_QUERY_RE = re.compile(r"([?&]token=)[A-Za-z0-9_\-]{32,}")
SETUP_TOKEN_TEXT_RE = re.compile(r"\bsetup[-_ ]?token\b[:= ]+[A-Za-z0-9_\-]{32,}", re.IGNORECASE)
PASSWORD_HASH_RE = re.compile(r"pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+")


def redact_text(value: str) -> str:
    redacted = PRIVATE_KEY_LINE_RE.sub(r"\1" + REDACTED, value)
    redacted = SETUP_TOKEN_QUERY_RE.sub(r"\1" + REDACTED, redacted)
    redacted = SETUP_TOKEN_TEXT_RE.sub("setup-token: " + REDACTED, redacted)
    redacted = PASSWORD_HASH_RE.sub(REDACTED, redacted)
    return redacted


def redact(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, Mapping):
        return {key: redact(item) for key, item in value.items()}
    return value
