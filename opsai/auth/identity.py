"""Caller identity: PAT, web session, dev headers, desktop implicit admin."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from opsai.auth.rbac import Role, check
from opsai.auth.tokens import permissions_for_scopes

if TYPE_CHECKING:
    from opsai.app.config import Settings
    from opsai.auth.sessions import SessionStore
    from opsai.auth.tokens import TokenStore
    from opsai.auth.users import UserStore


class AuthError(Exception):
    """Identity resolution failure with an HTTP status."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass
class Credentials:
    """Raw caller credentials extracted from a request."""

    authorization: str = ""
    session_cookie: str = ""
    x_user: str = ""
    x_role: str = ""


@dataclass
class Identity:
    """Resolved caller: username, combinable roles, auth method."""

    username: str
    roles: list[Role]
    method: str  # pat | session | dev | desktop
    scopes: list[str] = field(default_factory=list)
    user_id: str = ""  # local account id (pat/session methods only)

    def allows(self, permission: str) -> bool:
        """Return True when roles and (for PAT) scopes grant the permission."""
        if not any(check(role, permission) for role in self.roles):
            return False
        if self.method == "pat" and permission not in permissions_for_scopes(self.scopes):
            return False
        return True


def _roles_or_default(names: list[str], default: Role) -> list[Role]:
    roles: list[Role] = []
    for name in names:
        try:
            roles.append(Role(str(name).lower()))
        except ValueError:
            continue
    return roles or [default]


def resolve_identity(
    creds: Credentials,
    settings: Settings,
    users: UserStore,
    tokens: TokenStore,
    sessions: SessionStore,
) -> Identity:
    """Resolve the caller; presented-but-invalid credentials fail closed."""
    auth_header = creds.authorization.strip()
    if auth_header:
        scheme, _, value = auth_header.partition(" ")
        if scheme.lower() != "bearer" or not value:
            raise AuthError(401, "Unsupported authorization scheme")
        info = tokens.verify(value.strip())
        if info is None:
            raise AuthError(401, "Invalid or expired token")
        user = users.get_by_id(info.user_id)
        if user is None or not user.enabled:
            raise AuthError(401, "Token owner is disabled or removed")
        return Identity(
            username=user.username,
            roles=_roles_or_default(user.roles, Role.VIEWER),
            method="pat",
            scopes=list(info.scopes),
            user_id=user.id,
        )
    if creds.session_cookie:
        session = sessions.get(creds.session_cookie)
        if session is None:
            raise AuthError(401, "Invalid or expired session")
        user = users.get_by_id(session.user_id)
        if user is None or not user.enabled:
            raise AuthError(401, "Session owner is disabled or removed")
        return Identity(
            username=user.username,
            roles=_roles_or_default(user.roles, Role.VIEWER),
            method="session",
            user_id=user.id,
        )
    if settings.dev_auth and (creds.x_user or creds.x_role):
        try:
            role = Role(creds.x_role.lower()) if creds.x_role else Role.VIEWER
        except ValueError:
            role = Role.VIEWER
        return Identity(username=creds.x_user.strip() or "dev", roles=[role], method="dev")
    if settings.mode == "desktop" and not settings.desktop_lock:
        # FR-605: desktop single-user is implicitly admin, no login.
        return Identity(username="local", roles=[Role.ADMIN], method="desktop")
    raise AuthError(401, "Authentication required")


def describe_identity(identity: Identity) -> dict[str, Any]:
    """Serialize the identity for /auth/me responses."""
    return {
        "username": identity.username,
        "roles": [role.value for role in identity.roles],
        "method": identity.method,
        "scopes": list(identity.scopes),
    }
