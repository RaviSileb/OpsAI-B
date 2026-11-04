"""TOTP second factor from the standard library (RFC 6238, FR-600)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

_STEP = 30
_DIGITS = 6


def generate_secret(bits: int = 160) -> str:
    """Generate a base32 TOTP secret (default 160 bits)."""
    raw = secrets.token_bytes(bits // 8)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def provisioning_uri(secret: str, username: str, issuer: str = "OpsAI") -> str:
    """Return the otpauth:// URI for authenticator apps."""
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(username)}"
        f"?secret={secret}&issuer={quote(issuer)}&digits={_DIGITS}&period={_STEP}"
    )


def _code(secret: bytes, counter: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**_DIGITS)).zfill(_DIGITS)


def current_code(secret: str, for_time: float | None = None) -> str:
    """Return the TOTP code for the given time (now by default)."""
    raw = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((for_time if for_time is not None else time.time()) // _STEP)
    return _code(raw, counter)


def verify_code(secret: str, code: str, for_time: float | None = None) -> bool:
    """Verify a code with +-1 step clock skew tolerance."""
    text = code.strip().replace(" ", "")
    if not text.isdigit() or len(text) != _DIGITS:
        return False
    try:
        raw = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    except (ValueError, binascii.Error):
        return False
    now = int((for_time if for_time is not None else time.time()) // _STEP)
    return any(
        hmac.compare_digest(_code(raw, counter), text) for counter in (now - 1, now, now + 1)
    )
