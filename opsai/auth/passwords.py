"""Password hashing with Argon2id (TZ FR-600)."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_HASHER = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""
    return _HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password against its Argon2id hash."""
    try:
        return _HASHER.verify(password_hash, password)
    except (VerifyMismatchError, ValueError, AttributeError):
        return False
