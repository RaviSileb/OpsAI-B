"""Web sessions: cookie tokens with idle and absolute expiry (TZ FR-603)."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

COOKIE_NAME = "opsai_session"
CSRF_HEADER = "X-CSRF-Token"


def hash_session_token(token: str) -> str:
    """Return the SHA-256 hex digest stored in the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class WebSession:
    """Authenticated web session (plaintext token lives only in the cookie)."""

    user_id: str
    created_at: str
    last_seen_at: str
    expires_at: str
    csrf_token: str


class SessionStore:
    """Issue, touch and drop cookie sessions."""

    def __init__(
        self,
        app_db: Path,
        idle: timedelta = timedelta(minutes=30),
        absolute: timedelta = timedelta(hours=12),
    ) -> None:
        self.app_db = app_db
        self.idle = idle
        self.absolute = absolute

    def create(self, user_id: str, ip: str = "") -> tuple[str, str]:
        """Create a session; return (cookie_token, csrf_token)."""
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "INSERT INTO web_sessions (token_hash, user_id, created_at,"
                " last_seen_at, expires_at, csrf_token, ip)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    hash_session_token(token),
                    user_id,
                    now.isoformat(),
                    now.isoformat(),
                    (now + self.absolute).isoformat(),
                    csrf,
                    ip,
                ),
            )
            conn.commit()
        return token, csrf

    def get(self, token: str) -> WebSession | None:
        """Return the session, sliding idle expiry; None when expired."""
        if not token:
            return None
        now = datetime.now(UTC)
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT user_id, created_at, last_seen_at, expires_at, csrf_token"
                " FROM web_sessions WHERE token_hash = ?",
                (hash_session_token(token),),
            ).fetchone()
            if row is None:
                return None
            try:
                last_seen = datetime.fromisoformat(row[2])
                expires = datetime.fromisoformat(row[3])
            except ValueError:
                return None
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=UTC)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires <= now or now - last_seen > self.idle:
                conn.execute(
                    "DELETE FROM web_sessions WHERE token_hash = ?",
                    (hash_session_token(token),),
                )
                conn.commit()
                return None
            conn.execute(
                "UPDATE web_sessions SET last_seen_at = ? WHERE token_hash = ?",
                (now.isoformat(), hash_session_token(token)),
            )
            conn.commit()
        return WebSession(
            user_id=row[0],
            created_at=row[1],
            last_seen_at=now.isoformat(),
            expires_at=row[3],
            csrf_token=row[4],
        )

    def drop(self, token: str) -> None:
        """Delete the session (logout)."""
        if not token:
            return
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "DELETE FROM web_sessions WHERE token_hash = ?",
                (hash_session_token(token),),
            )
            conn.commit()

    def drop_for_user(self, user_id: str) -> int:
        """Delete all sessions of a user; return the number removed."""
        with sqlite3.connect(self.app_db) as conn:
            cursor = conn.execute("DELETE FROM web_sessions WHERE user_id = ?", (user_id,))
            conn.commit()
        return cursor.rowcount

    def prune_expired(self) -> int:
        """Delete expired sessions; return the number removed."""
        with sqlite3.connect(self.app_db) as conn:
            cursor = conn.execute(
                "DELETE FROM web_sessions WHERE expires_at < ?",
                (datetime.now(UTC).isoformat(),),
            )
            conn.commit()
        return cursor.rowcount
