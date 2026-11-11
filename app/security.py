"""Password hashing helpers (stdlib only, no extra dependency)."""

import hashlib
import hmac
import os

ITERATIONS = 200_000
ALGORITHM = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"{ALGORITHM}${ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != ALGORITHM:
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(derived.hex(), digest_hex)
    except (ValueError, TypeError):
        return False
