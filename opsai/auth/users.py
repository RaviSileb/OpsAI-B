"""Local user accounts: policy, lockout, TOTP secrets (TZ FR-600)."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

from opsai.auth.passwords import hash_password
from opsai.auth.rbac import Role

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
LOCKOUT_THRESHOLD = 10
LOCKOUT_WINDOW = timedelta(minutes=15)
LOCKOUT_DURATION = timedelta(minutes=15)
USERNAME_RE = r"^[a-z0-9][a-z0-9._-]{0,63}$"


class UserValidationError(ValueError):
    """Invalid username, password or roles (maps to HTTP 400)."""


class DuplicateUserError(ValueError):
    """Username already exists (maps to HTTP 409)."""


# Bcrypt-style dummy hash keeps unknown-user timing close to a real check.
_DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


@lru_cache(maxsize=1)
def blocked_passwords() -> frozenset[str]:
    """Load the offline compromised-password blocklist (lowercased)."""
    path = Path(__file__).resolve().parent / "blocklist.txt"
    entries = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text and not text.startswith("#"):
            entries.add(text.lower())
    return frozenset(entries)


def check_password_policy(password: str) -> None:
    """Validate a password (FR-600); raise UserValidationError with a reason."""
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        msg = f"Password must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters"
        raise UserValidationError(msg)
    if password.lower() in blocked_passwords():
        msg = "Password is too common (blocklisted)"
        raise UserValidationError(msg)


def normalize_username(username: str) -> str:
    """Normalize and validate a username."""
    import re

    text = username.strip().lower()
    if not re.match(USERNAME_RE, text):
        msg = f"Invalid username {username!r}"
        raise UserValidationError(msg)
    return text


def normalize_roles(roles: list[str]) -> list[str]:
    """Validate role names; at least one role is required."""
    names = [str(r).strip().lower() for r in roles]
    if not names:
        msg = "At least one role is required"
        raise UserValidationError(msg)
    valid = {role.value for role in Role}
    unknown = [name for name in names if name not in valid]
    if unknown:
        msg = f"Unknown roles: {unknown}"
        raise UserValidationError(msg)
    return sorted(set(names))


@dataclass
class User:
    """Local user account (password hash never leaves the store)."""

    id: str
    username: str
    roles: list[str]
    enabled: bool
    auth_source: str = "local"
    totp_enabled: bool = False
    last_login_at: str = ""


class UserStore:
    """CRUD, lockout accounting and TOTP secrets over the users table."""

    def __init__(self, app_db: Path) -> None:
        self.app_db = app_db

    @staticmethod
    def _row_to_user(row: tuple) -> User:
        return User(
            id=row[0],
            username=row[1],
            roles=json.loads(row[3] or "[]"),
            enabled=bool(row[4]),
            auth_source=row[5] or "local",
            totp_enabled=bool(row[6]),
            last_login_at=row[10] or "",
        )

    def count(self) -> int:
        """Return the number of user accounts."""
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return int(row[0])

    def create(
        self, username: str, password: str, roles: list[str], auth_source: str = "local"
    ) -> User:
        """Create a user after policy and role validation."""
        name = normalize_username(username)
        check_password_policy(password)
        role_names = normalize_roles(roles)
        user_id = uuid.uuid4().hex
        try:
            with sqlite3.connect(self.app_db) as conn:
                conn.execute(
                    "INSERT INTO users (id, username, password_hash, roles, auth_source)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (user_id, name, hash_password(password), json.dumps(role_names), auth_source),
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            msg = f"Username {name!r} already exists"
            raise DuplicateUserError(msg) from exc
        user = self.get_by_id(user_id)
        assert user is not None
        return user

    def get_by_username(self, username: str) -> User | None:
        """Return the user, or None for unknown/disabled lookups stay visible."""
        try:
            name = normalize_username(username)
        except ValueError:
            return None
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, roles, enabled, auth_source,"
                " totp_secret, failed_count, first_failed_at, locked_until,"
                " last_login_at FROM users WHERE username = ?",
                (name,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_user(row)

    def get_by_id(self, user_id: str) -> User | None:
        """Return the user by id, or None."""
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, roles, enabled, auth_source,"
                " totp_secret, failed_count, first_failed_at, locked_until,"
                " last_login_at FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_user(row)

    def list_users(self) -> list[User]:
        """List all users ordered by username."""
        with sqlite3.connect(self.app_db) as conn:
            rows = conn.execute(
                "SELECT id, username, password_hash, roles, enabled, auth_source,"
                " totp_secret, failed_count, first_failed_at, locked_until,"
                " last_login_at FROM users ORDER BY username"
            ).fetchall()
        return [self._row_to_user(row) for row in rows]

    def verify(self, username: str, password: str) -> User | None:
        """Verify credentials; None covers unknown user and mismatch alike."""
        from opsai.auth.passwords import verify_password

        try:
            name = normalize_username(username)
        except ValueError:
            verify_password(_DUMMY_HASH, password)
            return None
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?", (name,)
            ).fetchone()
        candidate = row[0] if row else _DUMMY_HASH
        if not verify_password(candidate, password):
            return None
        return self.get_by_username(name)

    def set_password(self, user_id: str, password: str) -> None:
        """Set a new password after policy validation."""
        check_password_policy(password)
        with sqlite3.connect(self.app_db) as conn:
            cursor = conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(password), user_id),
            )
            conn.commit()
        if cursor.rowcount == 0:
            msg = f"Unknown user {user_id!r}"
            raise ValueError(msg)

    def set_roles(self, user_id: str, roles: list[str]) -> User:
        """Replace the user roles."""
        role_names = normalize_roles(roles)
        with sqlite3.connect(self.app_db) as conn:
            cursor = conn.execute(
                "UPDATE users SET roles = ? WHERE id = ?", (json.dumps(role_names), user_id)
            )
            conn.commit()
        if cursor.rowcount == 0:
            msg = f"Unknown user {user_id!r}"
            raise ValueError(msg)
        user = self.get_by_id(user_id)
        assert user is not None
        return user

    def set_enabled(self, user_id: str, enabled: bool) -> User:
        """Enable or disable the account."""
        with sqlite3.connect(self.app_db) as conn:
            cursor = conn.execute(
                "UPDATE users SET enabled = ? WHERE id = ?", (int(enabled), user_id)
            )
            conn.commit()
        if cursor.rowcount == 0:
            msg = f"Unknown user {user_id!r}"
            raise ValueError(msg)
        user = self.get_by_id(user_id)
        assert user is not None
        return user

    def delete(self, user_id: str) -> None:
        """Delete the account with its tokens and sessions."""
        with sqlite3.connect(self.app_db) as conn:
            conn.execute("DELETE FROM api_tokens WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM web_sessions WHERE user_id = ?", (user_id,))
            cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        if cursor.rowcount == 0:
            msg = f"Unknown user {user_id!r}"
            raise ValueError(msg)

    def locked_until(self, username: str) -> datetime | None:
        """Return the lockout expiry when the account is currently locked."""
        try:
            name = normalize_username(username)
        except ValueError:
            return None
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT locked_until FROM users WHERE username = ?", (name,)
            ).fetchone()
        if not row or not row[0]:
            return None
        try:
            until = datetime.fromisoformat(row[0])
        except ValueError:
            return None
        if until.tzinfo is None:
            until = until.replace(tzinfo=UTC)
        return until if until > datetime.now(UTC) else None

    def record_failure(self, username: str) -> None:
        """Account a failed login; lock after the threshold in the window."""
        try:
            name = normalize_username(username)
        except ValueError:
            return
        now = datetime.now(UTC)
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT failed_count, first_failed_at FROM users WHERE username = ?",
                (name,),
            ).fetchone()
            if row is None:
                return
            count, first_raw = int(row[0]), row[1]
            try:
                first = datetime.fromisoformat(first_raw) if first_raw else None
            except ValueError:
                first = None
            if first is not None and first.tzinfo is None:
                first = first.replace(tzinfo=UTC)
            if first is None or now - first > LOCKOUT_WINDOW:
                count, first = 1, now
            else:
                count += 1
            locked = now + LOCKOUT_DURATION if count >= LOCKOUT_THRESHOLD else None
            conn.execute(
                "UPDATE users SET failed_count = ?, first_failed_at = ?,"
                " locked_until = ? WHERE username = ?",
                (
                    count,
                    first.isoformat(),
                    locked.isoformat() if locked else "",
                    name,
                ),
            )
            conn.commit()

    def record_success(self, user_id: str) -> None:
        """Clear lockout counters and stamp the login time."""
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "UPDATE users SET failed_count = 0, first_failed_at = '',"
                " locked_until = '', last_login_at = ? WHERE id = ?",
                (datetime.now(UTC).isoformat(), user_id),
            )
            conn.commit()

    def set_totp_secret(self, user_id: str, secret: str) -> None:
        """Store a TOTP secret for the user."""
        with sqlite3.connect(self.app_db) as conn:
            cursor = conn.execute(
                "UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id)
            )
            conn.commit()
        if cursor.rowcount == 0:
            msg = f"Unknown user {user_id!r}"
            raise ValueError(msg)

    def get_totp_secret(self, user_id: str) -> str:
        """Return the TOTP secret (empty when 2FA is off)."""
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute("SELECT totp_secret FROM users WHERE id = ?", (user_id,)).fetchone()
        return row[0] if row else ""
