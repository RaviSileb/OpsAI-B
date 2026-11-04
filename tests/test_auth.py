"""Identity tests: TOTP, users, PATs, sessions, login flows (FR-600/603/604)."""

from __future__ import annotations

import base64
import sqlite3
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from opsai.api.main import create_app
from opsai.app.bootstrap import init_app_db
from opsai.app.config import Settings
from opsai.auth.identity import AuthError, Credentials, resolve_identity
from opsai.auth.rbac import Role
from opsai.auth.sessions import SessionStore
from opsai.auth.tokens import TokenStore
from opsai.auth.totp import current_code, generate_secret, provisioning_uri, verify_code
from opsai.auth.users import (
    DuplicateUserError,
    UserStore,
    UserValidationError,
    blocked_passwords,
    check_password_policy,
)

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
RFC_VECTORS = [
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
    (20000000000, "353130"),
]
LONG_PASSWORD = "correct-horse-battery-staple-01"


def _stores(tmp_path: Path) -> tuple[UserStore, TokenStore, SessionStore]:
    settings = replace(Settings.from_env(), data_dir=tmp_path / "auth-db")
    db = init_app_db(settings)
    return UserStore(db), TokenStore(db), SessionStore(db)


def _server_client(tmp_path: Path) -> TestClient:
    settings = replace(
        Settings.from_env(),
        data_dir=tmp_path / "auth-data",
        mode="server",
        cookie_secure=False,
    )
    return TestClient(create_app(settings))


def _csrf(client: TestClient) -> dict[str, str]:
    token = client.get("/api/v1/auth/csrf").json()["csrf_token"]
    return {"X-CSRF-Token": token}


def test_totp_rfc_vectors() -> None:
    for moment, expected in RFC_VECTORS:
        assert current_code(RFC_SECRET, for_time=moment) == expected
        assert verify_code(RFC_SECRET, expected, for_time=moment)
    # +-1 step skew accepted, +-2 rejected.
    assert verify_code(RFC_SECRET, "287082", for_time=59 + 30)
    assert not verify_code(RFC_SECRET, "287082", for_time=59 + 61)
    assert not verify_code(RFC_SECRET, "000000", for_time=59)
    assert not verify_code(RFC_SECRET, "not-a-code", for_time=59)
    assert not verify_code("!!!bad-secret!!!", "287082", for_time=59)


def test_totp_secret_and_uri() -> None:
    secret = generate_secret()
    assert len(secret) >= 26
    uri = provisioning_uri(secret, "alice")
    assert uri.startswith("otpauth://totp/OpsAI:alice?secret=" + secret)
    assert verify_code(secret, current_code(secret))


def test_password_policy() -> None:
    check_password_policy(LONG_PASSWORD)
    check_password_policy("exactly-12-ch")
    with pytest.raises(UserValidationError, match="12-256"):
        check_password_policy("short")
    with pytest.raises(UserValidationError, match="blocklisted"):
        check_password_policy("Password1234")
    with pytest.raises(UserValidationError, match="blocklisted"):
        check_password_policy("administrator123")
    assert len(blocked_passwords()) > 50


def test_user_store_crud(tmp_path: Path) -> None:
    users, _, _ = _stores(tmp_path)
    assert users.count() == 0
    alice = users.create("Alice", LONG_PASSWORD, ["analyst", "viewer"])
    assert alice.username == "alice"
    assert alice.roles == ["analyst", "viewer"]
    assert users.count() == 1
    with pytest.raises(DuplicateUserError):
        users.create("alice", LONG_PASSWORD, ["viewer"])
    with pytest.raises(UserValidationError):
        users.create("bob", "short", ["viewer"])
    with pytest.raises(UserValidationError):
        users.create("bob", LONG_PASSWORD, ["nope"])
    with pytest.raises(UserValidationError):
        users.create("not an x-user!", LONG_PASSWORD, ["viewer"])
    assert users.verify("alice", LONG_PASSWORD) is not None
    assert users.verify("alice", "wrong-password-000") is None
    assert users.verify("ghost", LONG_PASSWORD) is None
    updated = users.set_roles(alice.id, ["operator"])
    assert updated.roles == ["operator"]
    disabled = users.set_enabled(alice.id, False)
    assert disabled.enabled is False
    assert [u.username for u in users.list_users()] == ["alice"]
    users.set_password(alice.id, "another-long-password-02")
    assert users.verify("alice", "another-long-password-02") is not None
    users.delete(alice.id)
    assert users.count() == 0
    with pytest.raises(ValueError, match="Unknown user"):
        users.set_roles(alice.id, ["viewer"])


def test_user_lockout_cycle(tmp_path: Path) -> None:
    users, _, _ = _stores(tmp_path)
    users.create("alice", LONG_PASSWORD, ["viewer"])
    assert users.locked_until("alice") is None
    for _ in range(9):
        users.record_failure("alice")
    assert users.locked_until("alice") is None
    users.record_failure("alice")
    assert users.locked_until("alice") is not None
    user = users.get_by_username("alice")
    assert user is not None
    users.record_success(user.id)
    assert users.locked_until("alice") is None
    users.record_failure("ghost")  # unknown users never lock anything
    assert users.locked_until("ghost") is None


def test_user_totp_secret_roundtrip(tmp_path: Path) -> None:
    users, _, _ = _stores(tmp_path)
    alice = users.create("alice", LONG_PASSWORD, ["viewer"])
    assert users.get_totp_secret(alice.id) == ""
    users.set_totp_secret(alice.id, "SECRET")
    assert users.get_by_id(alice.id) is not None
    assert users.get_by_id(alice.id).totp_enabled is True  # type: ignore[union-attr]
    assert users.get_totp_secret(alice.id) == "SECRET"


def test_token_store_roundtrip(tmp_path: Path) -> None:
    users, tokens, _ = _stores(tmp_path)
    alice = users.create("alice", LONG_PASSWORD, ["analyst"])
    info, plaintext = tokens.create(alice.id, "ci", ["read", "analyze"], ttl_days=30)
    assert plaintext.startswith("opsai_pat_")
    assert info.scopes == ["analyze", "read"]
    assert info.prefix == plaintext[:14]
    verified = tokens.verify(plaintext)
    assert verified is not None and verified.user_id == alice.id
    assert tokens.verify("bogus") is None
    assert tokens.verify("opsai_pat_" + "x" * 43) is None
    assert len(tokens.list_for_user(alice.id)) == 1
    assert tokens.revoke(info.id, alice.id) is True
    assert tokens.verify(plaintext) is None
    assert tokens.revoke("nope", alice.id) is False
    with pytest.raises(ValueError, match="scope"):
        tokens.create(alice.id, "bad", ["root"])
    with pytest.raises(ValueError, match="ttl_days"):
        tokens.create(alice.id, "bad", ["read"], ttl_days=400)
    with pytest.raises(ValueError, match="name"):
        tokens.create(alice.id, "  ", ["read"])


def test_token_expiry_and_prune(tmp_path: Path) -> None:
    users, tokens, _ = _stores(tmp_path)
    alice = users.create("alice", LONG_PASSWORD, ["viewer"])
    info, plaintext = tokens.create(alice.id, "short", ["read"], ttl_days=1)
    assert tokens.verify(plaintext) is not None
    settings = replace(Settings.from_env(), data_dir=tmp_path / "auth-db")
    from opsai.app.bootstrap import get_app_db_path

    with sqlite3.connect(get_app_db_path(settings)) as conn:
        conn.execute(
            "UPDATE api_tokens SET expires_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", info.id),
        )
        conn.commit()
    assert tokens.verify(plaintext) is None
    assert tokens.prune_expired() == 1
    assert tokens.list_for_user(alice.id) == []


def test_session_store_roundtrip(tmp_path: Path) -> None:
    users, _, sessions = _stores(tmp_path)
    alice = users.create("alice", LONG_PASSWORD, ["viewer"])
    token, csrf = sessions.create(alice.id, "127.0.0.1")
    assert token and csrf and token != csrf
    found = sessions.get(token)
    assert found is not None and found.user_id == alice.id
    assert found.csrf_token == csrf
    assert sessions.get("bogus") is None
    sessions.drop(token)
    assert sessions.get(token) is None


def test_session_expiry(tmp_path: Path) -> None:
    users, _, _ = _stores(tmp_path)
    alice = users.create("alice", LONG_PASSWORD, ["viewer"])
    settings = replace(Settings.from_env(), data_dir=tmp_path / "auth-db")
    from opsai.app.bootstrap import get_app_db_path

    db = get_app_db_path(settings)
    idle_zero = SessionStore(db, idle=timedelta(0))
    token, _ = idle_zero.create(alice.id)
    assert idle_zero.get(token) is None  # idle already exceeded
    absolute_zero = SessionStore(db, absolute=timedelta(0))
    token2, _ = absolute_zero.create(alice.id)
    assert absolute_zero.get(token2) is None
    token3, _ = absolute_zero.create(alice.id)  # pruned without a read
    _ = token3
    assert absolute_zero.prune_expired() >= 1


def test_identity_resolution(tmp_path: Path) -> None:
    users, tokens, sessions = _stores(tmp_path)
    alice = users.create("alice", LONG_PASSWORD, ["analyst"])
    _, plaintext = tokens.create(alice.id, "t", ["read"])
    cookie, _ = sessions.create(alice.id)
    server = replace(Settings.from_env(), mode="server")
    desktop = replace(Settings.from_env(), mode="desktop")

    pat = resolve_identity(
        Credentials(authorization=f"Bearer {plaintext}"), server, users, tokens, sessions
    )
    assert (pat.username, pat.method, pat.scopes) == ("alice", "pat", ["read"])
    assert pat.user_id == alice.id
    assert pat.allows("read") and not pat.allows("analyze")

    session_ident = resolve_identity(
        Credentials(session_cookie=cookie), server, users, tokens, sessions
    )
    assert session_ident.method == "session"
    assert session_ident.allows("analyze")

    with pytest.raises(AuthError) as bad:
        resolve_identity(
            Credentials(authorization="Bearer opsai_pat_nope"),
            server,
            users,
            tokens,
            sessions,
        )
    assert bad.value.status == 401
    with pytest.raises(AuthError):
        resolve_identity(Credentials(session_cookie="bogus"), server, users, tokens, sessions)
    with pytest.raises(AuthError):
        resolve_identity(Credentials(), server, users, tokens, sessions)

    dev_on = replace(server, dev_auth=True)
    dev = resolve_identity(
        Credentials(x_user="root", x_role="admin"), dev_on, users, tokens, sessions
    )
    assert (dev.username, dev.method, dev.roles) == ("root", "dev", [Role.ADMIN])
    with pytest.raises(AuthError):
        resolve_identity(
            Credentials(x_user="root", x_role="admin"), server, users, tokens, sessions
        )

    local = resolve_identity(Credentials(), desktop, users, tokens, sessions)
    assert (local.username, local.method) == ("local", "desktop")
    assert local.allows("admin")
    locked_desktop = replace(desktop, desktop_lock=True)
    with pytest.raises(AuthError):
        resolve_identity(Credentials(), locked_desktop, users, tokens, sessions)

    users.set_enabled(alice.id, False)
    with pytest.raises(AuthError, match="disabled"):
        resolve_identity(
            Credentials(authorization=f"Bearer {plaintext}"),
            server,
            users,
            tokens,
            sessions,
        )


def test_server_health_is_public(tmp_path: Path) -> None:
    client = _server_client(tmp_path)
    assert client.get("/api/v1/health/live").json() == {"status": "ok"}
    assert client.get("/api/v1/health/ready").json() == {"status": "ready"}
    assert client.get("/api/v1/sessions").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401


def test_setup_mode_first_user(tmp_path: Path) -> None:
    client = _server_client(tmp_path)
    created = client.post(
        "/api/v1/users",
        json={"username": "root", "password": LONG_PASSWORD, "roles": ["viewer"]},
    )
    assert created.status_code == 200
    assert created.json()["roles"] == ["admin"]  # setup forces admin
    second = client.post("/api/v1/users", json={"username": "bob", "password": LONG_PASSWORD})
    assert second.status_code == 401  # setup mode is over
    dup = client.post("/api/v1/users", json={"username": "root", "password": LONG_PASSWORD})
    assert dup.status_code in {401, 409}


def test_login_logout_me_flow(tmp_path: Path) -> None:
    client = _server_client(tmp_path)
    client.post("/api/v1/users", json={"username": "root", "password": LONG_PASSWORD})
    bad = client.post(
        "/api/v1/auth/login", json={"username": "root", "password": "wrong-password-000"}
    )
    assert bad.status_code == 401
    assert bad.json()["detail"] == "Invalid username or password"
    ghost = client.post("/api/v1/auth/login", json={"username": "ghost", "password": LONG_PASSWORD})
    assert ghost.json()["detail"] == "Invalid username or password"
    login = client.post("/api/v1/auth/login", json={"username": "root", "password": LONG_PASSWORD})
    assert login.status_code == 200
    assert login.json() == {"username": "root", "roles": ["admin"]}
    assert "opsai_session=" in login.headers.get("set-cookie", "")
    me = client.get("/api/v1/auth/me").json()
    assert me["method"] == "session"
    assert me["roles"] == ["admin"]
    assert client.post("/api/v1/auth/logout", headers=_csrf(client)).json() == {
        "status": "logged-out"
    }
    assert client.get("/api/v1/auth/me").status_code == 401
    events = client.get("/api/v1/audit/events", headers={"X-Role": "admin"}).status_code
    assert events == 401  # dev headers stay off without OPSAI_DEV_AUTH


def test_login_lockout(tmp_path: Path) -> None:
    client = _server_client(tmp_path)
    client.post("/api/v1/users", json={"username": "root", "password": LONG_PASSWORD})
    for _ in range(10):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "root", "password": "wrong-password-000"},
        )
        assert response.status_code == 401
    locked = client.post("/api/v1/auth/login", json={"username": "root", "password": LONG_PASSWORD})
    assert locked.status_code == 429


def _login(client: TestClient, username: str, password: str) -> None:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200


def test_users_crud_and_last_admin_guard(tmp_path: Path) -> None:
    client = _server_client(tmp_path)
    root = client.post("/api/v1/users", json={"username": "root", "password": LONG_PASSWORD}).json()
    _login(client, "root", LONG_PASSWORD)
    headers = _csrf(client)
    bob = client.post(
        "/api/v1/users",
        json={"username": "bob", "password": LONG_PASSWORD, "roles": ["viewer"]},
        headers=headers,
    ).json()
    assert bob["roles"] == ["viewer"]
    assert "password_hash" not in bob and "totp_secret" not in bob
    items = client.get("/api/v1/users").json()["items"]
    assert {u["username"] for u in items} == {"root", "bob"}
    promoted = client.patch(
        f"/api/v1/users/{bob['id']}", json={"roles": ["analyst"]}, headers=headers
    ).json()
    assert promoted["roles"] == ["analyst"]
    # Cannot remove the last admin by any path.
    assert (
        client.patch(
            f"/api/v1/users/{root['id']}", json={"roles": ["viewer"]}, headers=headers
        ).status_code
        == 409
    )
    assert (
        client.patch(
            f"/api/v1/users/{root['id']}", json={"enabled": False}, headers=headers
        ).status_code
        == 409
    )
    assert client.delete(f"/api/v1/users/{root['id']}", headers=headers).status_code == 409
    assert client.delete(f"/api/v1/users/{bob['id']}", headers=headers).json() == {
        "status": "deleted"
    }
    # A viewer cannot manage users.
    carol = client.post(
        "/api/v1/users",
        json={"username": "carol", "password": LONG_PASSWORD, "roles": ["viewer"]},
        headers=headers,
    ).json()
    _ = carol
    other = _server_client(tmp_path)
    _login(other, "carol", LONG_PASSWORD)
    assert other.get("/api/v1/users").status_code == 403
    assert (
        other.post(
            "/api/v1/users",
            json={"username": "dave", "password": LONG_PASSWORD},
            headers=_csrf(other),
        ).status_code
        == 403
    )


def test_csrf_enforced_for_cookie_mutations(tmp_path: Path) -> None:
    client = _server_client(tmp_path)
    client.post("/api/v1/users", json={"username": "root", "password": LONG_PASSWORD})
    _login(client, "root", LONG_PASSWORD)
    assert client.post("/api/v1/sessions", json={"name": "x"}).status_code == 403
    assert (
        client.post(
            "/api/v1/sessions", json={"name": "x"}, headers={"X-CSRF-Token": "bogus"}
        ).status_code
        == 403
    )
    created = client.post("/api/v1/sessions", json={"name": "x"}, headers=_csrf(client))
    assert created.status_code == 200
    assert client.get("/api/v1/sessions").status_code == 200  # reads need no CSRF


def test_pat_flow_and_scopes(tmp_path: Path) -> None:
    client = _server_client(tmp_path)
    client.post("/api/v1/users", json={"username": "root", "password": LONG_PASSWORD})
    _login(client, "root", LONG_PASSWORD)
    created = client.post(
        "/api/v1/pats",
        json={"name": "monitor", "scopes": ["read"], "ttl_days": 7},
        headers=_csrf(client),
    ).json()
    token = created["token"]
    assert token.startswith("opsai_pat_")
    listed = client.get("/api/v1/pats").json()["items"]
    assert len(listed) == 1 and "token" not in listed[0]

    api = _server_client(tmp_path)
    bearer = {"Authorization": f"Bearer {token}"}
    assert api.get("/api/v1/sessions", headers=bearer).status_code == 200
    assert api.get("/api/v1/auth/me", headers=bearer).json()["method"] == "pat"
    # FR-604 acceptance: a read token cannot create sessions or analyze.
    assert api.post("/api/v1/sessions", json={"name": "x"}, headers=bearer).status_code == 403
    preview = api.post(
        "/api/v1/analyses/preview",
        json={"session_id": "nope", "provider": "mock", "model": "mock-analysis-v1"},
        headers=bearer,
    )
    assert preview.status_code == 403
    assert client.delete(f"/api/v1/pats/{created['id']}", headers=_csrf(client)).json() == {
        "status": "revoked"
    }
    assert api.get("/api/v1/sessions", headers=bearer).status_code == 401


def test_pat_validation_and_admin_scope(tmp_path: Path) -> None:
    client = _server_client(tmp_path)
    client.post("/api/v1/users", json={"username": "root", "password": LONG_PASSWORD})
    _login(client, "root", LONG_PASSWORD)
    headers = _csrf(client)
    bad_scope = client.post("/api/v1/pats", json={"name": "x", "scopes": ["root"]}, headers=headers)
    assert bad_scope.status_code == 400
    bad_ttl = client.post(
        "/api/v1/pats",
        json={"name": "x", "scopes": ["read"], "ttl_days": 366},
        headers=headers,
    )
    assert bad_ttl.status_code == 422
    full = client.post(
        "/api/v1/pats", json={"name": "admin", "scopes": ["admin"]}, headers=headers
    ).json()["token"]
    api = _server_client(tmp_path)
    bearer = {"Authorization": f"Bearer {full}"}
    assert api.post("/api/v1/sessions", json={"name": "x"}, headers=bearer).status_code == 200
    assert api.get("/api/v1/pats?all_users=true", headers=bearer).status_code == 200


def test_password_change_and_totp_flow(tmp_path: Path) -> None:
    client = _server_client(tmp_path)
    client.post("/api/v1/users", json={"username": "root", "password": LONG_PASSWORD})
    _login(client, "root", LONG_PASSWORD)
    headers = _csrf(client)
    wrong = client.post(
        "/api/v1/users/me/password",
        json={"current": "nope-0000000000", "new": "brand-new-password-03"},
        headers=headers,
    )
    assert wrong.status_code == 401
    changed = client.post(
        "/api/v1/users/me/password",
        json={"current": LONG_PASSWORD, "new": "brand-new-password-03"},
        headers=headers,
    )
    assert changed.json() == {"status": "changed"}
    assert client.get("/api/v1/auth/me").status_code == 401  # sessions dropped
    _login(client, "root", "brand-new-password-03")

    setup = client.post("/api/v1/users/me/totp/setup", headers=_csrf(client)).json()
    assert setup["uri"].startswith("otpauth://totp/OpsAI:root")
    bad_code = client.post(
        "/api/v1/users/me/totp/confirm",
        json={"secret": setup["secret"], "code": "000000"},
        headers=_csrf(client),
    )
    assert bad_code.status_code == 401
    confirm = client.post(
        "/api/v1/users/me/totp/confirm",
        json={"secret": setup["secret"], "code": current_code(setup["secret"])},
        headers=_csrf(client),
    )
    assert confirm.json() == {"status": "enabled"}
    client.post("/api/v1/auth/logout", headers=_csrf(client))
    no_factor = client.post(
        "/api/v1/auth/login",
        json={"username": "root", "password": "brand-new-password-03"},
    )
    assert no_factor.status_code == 401
    second = client.post(
        "/api/v1/auth/login",
        json={
            "username": "root",
            "password": "brand-new-password-03",
            "totp": current_code(setup["secret"]),
        },
    )
    assert second.status_code == 200
    disabled = client.post(
        "/api/v1/users/me/totp/disable",
        json={"password": "brand-new-password-03"},
        headers=_csrf(client),
    )
    assert disabled.json() == {"status": "disabled"}


def test_auth_audit_trail(tmp_path: Path) -> None:
    client = _server_client(tmp_path)
    client.post("/api/v1/users", json={"username": "root", "password": LONG_PASSWORD})
    client.post("/api/v1/auth/login", json={"username": "root", "password": "wrong-password-000"})
    _login(client, "root", LONG_PASSWORD)
    events = client.get("/api/v1/audit/events").json()["items"]
    kinds = {e["event_type"] for e in events}
    assert {"auth.login", "auth.login_failed", "users.create"} <= kinds
    assert "wrong-password-000" not in str(events)
    assert LONG_PASSWORD not in str(events)
