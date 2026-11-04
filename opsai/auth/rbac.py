"""Role-based access control matrix (TZ 12.2)."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    """User roles from BZ chapter 2."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    APPROVER = "approver"
    ADMIN = "admin"


_PERMISSIONS: dict[str, set[Role]] = {
    "read": {Role.VIEWER, Role.ANALYST, Role.OPERATOR, Role.APPROVER, Role.ADMIN},
    "create_session": {Role.ANALYST, Role.OPERATOR, Role.ADMIN},
    "analyze": {Role.ANALYST, Role.OPERATOR, Role.ADMIN},
    "manage_own_secrets": {Role.ANALYST, Role.OPERATOR, Role.ADMIN},
    "syslog_listener": {Role.ANALYST, Role.OPERATOR, Role.ADMIN},
    "depseudonymize": {Role.ANALYST, Role.OPERATOR, Role.ADMIN},
    "execute": {Role.OPERATOR, Role.ADMIN},
    "approve": {Role.APPROVER, Role.ADMIN},
    "admin": {Role.ADMIN},
    "read_audit": {Role.ADMIN},
}


def check(role: Role | str, permission: str) -> bool:
    """Return True when the role grants the permission."""
    try:
        parsed = role if isinstance(role, Role) else Role(str(role).lower())
    except ValueError:
        return False
    allowed = _PERMISSIONS.get(permission)
    if allowed is None:
        return False
    return parsed in allowed


def permissions_for(role: Role | str) -> set[str]:
    """Return all permissions granted to the role."""
    return {name for name in _PERMISSIONS if check(role, name)}
