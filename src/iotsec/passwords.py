"""scrypt password hashing for the dashboard login.

Format: ``scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>``. Cost parameters are
bounded when parsing so a crafted hash cannot be used to exhaust memory.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

N, R, P = 2**15, 8, 1
MAX_N = 2**20
MIN_LENGTH = 12


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=256 * 1024 * 1024, dklen=32)


def hash_password(password: str) -> str:
    if len(password) < MIN_LENGTH:
        raise ValueError(f"password must be at least {MIN_LENGTH} characters")
    salt = secrets.token_bytes(16)
    digest = _derive(password, salt, N, R, P)
    return "$".join(["scrypt", str(N), str(R), str(P),
                     base64.b64encode(salt).decode(), base64.b64encode(digest).decode()])


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = encoded.split("$")
        n_i, r_i, p_i = int(n), int(r), int(p)
        if scheme != "scrypt" or not (2 <= n_i <= MAX_N and n_i & (n_i - 1) == 0) \
                or not (1 <= r_i <= 16 and 1 <= p_i <= 4):
            return False
        expected = base64.b64decode(digest, validate=True)
        actual = _derive(password, base64.b64decode(salt, validate=True), n_i, r_i, p_i)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def is_valid_hash(encoded: str) -> bool:
    parts = encoded.split("$")
    return len(parts) == 6 and parts[0] == "scrypt"
