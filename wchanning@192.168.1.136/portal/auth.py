"""Password hashing + basic validation for the AICN portal.

Uses hashlib.scrypt (Python stdlib) — a strong, memory-hard password KDF — so
there's no dependency on passlib/bcrypt. Hashes are stored self-describing:

    scrypt$<n>$<r>$<p>$<salt_hex>$<derived_hex>
"""

import hashlib
import hmac
import os
import re

# scrypt cost parameters. n must be a power of two; 2**14 is a sensible default
# for interactive logins (fast enough, still costly to brute-force).
_N = 2 ** 14
_R = 8
_P = 1
_DKLEN = 32


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P,
                        dklen=_DKLEN, maxmem=0)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_hex, dk_hex = stored.split("$")
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            n=int(n), r=int(r), p=int(p), dklen=len(expected), maxmem=0)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LEN = 8


def valid_email(email: str) -> bool:
    return bool(email) and len(email) <= 254 and bool(_EMAIL_RE.match(email))


def password_problem(password: str):
    """Return a human message if the password is unacceptable, else None."""
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    return None
