"""Opaque credential minting/parsing. Only SHA-256 digests are ever persisted."""

import base64
import hashlib
import re
import secrets

ACCESS_PREFIX = "act_"
REFRESH_PREFIX = "rft_"
_BODY_RE = re.compile(r"^[A-Z2-7]{52}$")


def _mint(prefix):
    # 32 random bytes -> 52 unpadded base32 characters.
    body = base64.b32encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    return prefix + body


def mint_access_token():
    return _mint(ACCESS_PREFIX)


def mint_refresh_token():
    return _mint(REFRESH_PREFIX)


def token_kind(token):
    """Return 'access' or 'refresh', raising TokenFormatError on bad shape."""
    from .errors import TokenFormatError

    if not isinstance(token, str):
        raise TokenFormatError("credential must be a string")
    if token.startswith(ACCESS_PREFIX):
        kind = "access"
    elif token.startswith(REFRESH_PREFIX):
        kind = "refresh"
    else:
        raise TokenFormatError("credential has no recognized prefix")
    body = token[len(ACCESS_PREFIX):]
    if not _BODY_RE.match(body):
        raise TokenFormatError("credential body is malformed")
    return kind


def hash_token(token):
    """Digest used as the storage key; the raw credential is never stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password, salt=None, iterations=200_000):
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": salt.hex(),
        "hash": digest.hex(),
    }


def verify_password(password, record):
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(record["salt"]),
        record["iterations"],
    )
    import hmac

    return hmac.compare_digest(digest.hex(), record["hash"])
