"""Personal access tokens: scoped, expiring, hashed at rest (TZ FR-604)."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from opsai.auth.rbac import Role, permissions_for

SCOPES = ("read", "analyze", "execute", "admin")
TOKEN_PREFIX = "opsai_pat_"  # nosec B105 - public prefix, not a secret
MAX_TTL_DAYS = 365

SCOPE_PERMISSIONS: dict[str, set[str]] = {
    "read": {"read"},
    "analyze": {
        "read",
        "create_session",
        "analyze",
        "manage_own_secrets",
        "syslog_listener",
        "depseudonymize",
    },
    "execute": {
        "read",
        "create_session",
        "analyze",
        "manage_own_secrets",
        "syslog_listener",
        "depseudonymize",
        "execute",
    },
    "admin": set(permissions_for(Role.ADMIN)),
}


def permissions_for_scopes(scopes: list[str]) -> set[str]:
    """Return the union of permissions granted by the scopes."""
    granted: set[str] = set()
    for scope in scopes:
        granted |= SCOPE_PERMISSIONS.get(scope, set())
    return granted


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest stored in the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class TokenInfo:
    """Token metadata (the plaintext exists only at creation)."""

    id: str
    user_id: str
    name: str
    prefix: str
    scopes: list[str]
    created_at: str
    expires_at: str
    last_used_at: str
    revoked: bool


class TokenStore:
    """Issue, verify and revoke personal access tokens."""

    def __init__(self, app_db: Path) -> None:
        self.app_db = app_db

    @staticmethod
    def _row_to_info(row: tuple) -> TokenInfo:
        return TokenInfo(
            id=row[0],
            user_id=row[1],
            name=row[2],
            prefix=row[4],
            scopes=json.loads(row[5] or "[]"),
            created_at=row[6],
            expires_at=row[7],
            last_used_at=row[8] or "",
            revoked=bool(row[9]),
        )

    def create(
        self, user_id: str, name: str, scopes: list[str], ttl_days: int = 90
    ) -> tuple[TokenInfo, str]:
        """Issue a token; the plaintext is returned once and never stored."""
        clean_scopes = sorted(set(scopes))
        if not clean_scopes:
            msg = "At least one scope is required"
            raise ValueError(msg)
        unknown = [s for s in clean_scopes if s not in SCOPES]
        if unknown:
            msg = f"Unknown scopes: {unknown}"
            raise ValueError(msg)
        if not 1 <= ttl_days <= MAX_TTL_DAYS:
            msg = f"ttl_days must be 1-{MAX_TTL_DAYS}"
            raise ValueError(msg)
        clean_name = name.strip()
        if not 1 <= len(clean_name) <= 100:
            msg = "Token name must be 1-100 characters"
            raise ValueError(msg)
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        expires = now + timedelta(days=ttl_days)
        token_id = uuid.uuid4().hex
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "INSERT INTO api_tokens (id, user_id, name, token_hash, prefix,"
                " scopes, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    token_id,
                    user_id,
                    clean_name,
                    hash_token(token),
                    token[: len(TOKEN_PREFIX) + 4],
                    json.dumps(clean_scopes),
                    now.isoformat(),
                    expires.isoformat(),
                ),
            )
            conn.commit()
        info = self.get(token_id)
        assert info is not None
        return info, token

    def get(self, token_id: str) -> TokenInfo | None:
        """Return token metadata by id, or None."""
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT id, user_id, name, token_hash, prefix, scopes, created_at,"
                " expires_at, last_used_at, revoked FROM api_tokens WHERE id = ?",
                (token_id,),
            ).fetchone()
        return self._row_to_info(row) if row else None

    def verify(self, token: str) -> TokenInfo | None:
        """Verify a presented token (revocation and expiry enforced)."""
        if not token.startswith(TOKEN_PREFIX):
            return None
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT id, user_id, name, token_hash, prefix, scopes, created_at,"
                " expires_at, last_used_at, revoked FROM api_tokens"
                " WHERE token_hash = ?",
                (hash_token(token),),
            ).fetchone()
            if row is None:
                return None
            info = self._row_to_info(row)
            if info.revoked:
                return None
            try:
                expires = datetime.fromisoformat(info.expires_at)
            except ValueError:
                return None
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires <= datetime.now(UTC):
                return None
            conn.execute(
                "UPDATE api_tokens SET last_used_at = ? WHERE id = ?",
                (datetime.now(UTC).isoformat(), info.id),
            )
            conn.commit()
        return info

    def list_for_user(self, user_id: str) -> list[TokenInfo]:
        """List the user's tokens ordered by creation time."""
        with sqlite3.connect(self.app_db) as conn:
            rows = conn.execute(
                "SELECT id, user_id, name, token_hash, prefix, scopes, created_at,"
                " expires_at, last_used_at, revoked FROM api_tokens"
                " WHERE user_id = ? ORDER BY created_at",
                (user_id,),
            ).fetchall()
        return [self._row_to_info(row) for row in rows]

    def list_all(self) -> list[TokenInfo]:
        """List all tokens ordered by creation time (admin)."""
        with sqlite3.connect(self.app_db) as conn:
            rows = conn.execute(
                "SELECT id, user_id, name, token_hash, prefix, scopes, created_at,"
                " expires_at, last_used_at, revoked FROM api_tokens ORDER BY created_at"
            ).fetchall()
        return [self._row_to_info(row) for row in rows]

    def revoke(self, token_id: str, user_id: str | None = None) -> bool:
        """Revoke a token; user_id scopes the operation to the owner."""
        with sqlite3.connect(self.app_db) as conn:
            if user_id is None:
                cursor = conn.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ?", (token_id,))
            else:
                cursor = conn.execute(
                    "UPDATE api_tokens SET revoked = 1 WHERE id = ? AND user_id = ?",
                    (token_id, user_id),
                )
            conn.commit()
        return cursor.rowcount > 0

    def prune_expired(self) -> int:
        """Delete expired tokens; return the number removed."""
        with sqlite3.connect(self.app_db) as conn:
            cursor = conn.execute(
                "DELETE FROM api_tokens WHERE expires_at < ?",
                (datetime.now(UTC).isoformat(),),
            )
            conn.commit()
        return cursor.rowcount
