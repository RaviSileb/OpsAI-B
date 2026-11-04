"""FastAPI application: health, sessions, analyses, audit (TZ ch. 13, MVP).

Endpoints live in :func:`build_api_router` so the standalone server and the
NiceGUI process share one implementation.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from jinja2 import Template
from pydantic import BaseModel, Field

from opsai import __version__
from opsai.app.bootstrap import get_app_db_path, init_app_db
from opsai.app.config import Settings
from opsai.auth.identity import (
    AuthError,
    Credentials,
    Identity,
    describe_identity,
    resolve_identity,
)
from opsai.auth.rbac import Role
from opsai.auth.sessions import COOKIE_NAME, CSRF_HEADER, SessionStore
from opsai.auth.tokens import TokenStore
from opsai.auth.users import UserStore
from opsai.connectors.base import ConnectionProfile, ReadQuery
from opsai.connectors.file import FileConnector, to_log_record
from opsai.connectors.registry import ensure_builtin_connectors
from opsai.core.audit import AuditWriter
from opsai.core.inventory import InventoryStore
from opsai.core.patterns import DrainUnavailableError, compute_templates, resolve_backend
from opsai.core.policy import ExecutionPolicy, PolicyStore
from opsai.core.query import OQLSyntaxError
from opsai.core.risk import check_policy, combine_risk
from opsai.core.saved_queries import QueryStore
from opsai.core.session import SessionManager
from opsai.core.states import TransitionError
from opsai.db.models import HostRecord
from opsai.execution.engine import (
    ApprovalRequiredError,
    ExecutionEngine,
    ExecutionError,
    TargetRequiredError,
)
from opsai.masking.engine import MaskingEngine, build_payload
from opsai.providers.base import LLMMessage, LLMRequest
from opsai.providers.factory import get_provider
from opsai.providers.meta_provider import DEFAULT_MODEL, KNOWN_MODELS, PREVIEW_MODELS
from opsai.providers.schema import ANALYSIS_JSON_SCHEMA, validate_analysis

STAGE_TTL_SECONDS = 3600
PROMPT_VERSION = "v1"

ensure_builtin_connectors()


class ProblemError(Exception):
    """RFC 9457 problem-details error."""

    def __init__(self, status: int, title: str, detail: str = "") -> None:
        super().__init__(detail)
        self.status = status
        self.title = title
        self.detail = detail


class SessionCreate(BaseModel):
    """Create-session request."""

    name: str = Field(min_length=1, max_length=200)


class IngestFile(BaseModel):
    """File ingest request."""

    path: str = Field(min_length=1, max_length=2000)
    limit_records: int = Field(default=100_000, ge=1, le=2_000_000)
    tail_lines: int | None = Field(default=None, ge=1)


class IngestRecord(BaseModel):
    """One pushed log record (generic ingest)."""

    message: str = Field(min_length=1, max_length=1_000_000)
    ts: str = ""
    level: str = Field(default="", max_length=32)
    host: str = Field(default="", max_length=255)
    service: str = Field(default="", max_length=255)
    fields: dict[str, Any] = Field(default_factory=dict, max_length=100)


class IngestBatch(BaseModel):
    """Generic push-ingest request for external shippers."""

    source: str = Field(min_length=1, max_length=64, pattern=r"^[\w][\w\-.]*$")
    records: list[IngestRecord] = Field(min_length=1, max_length=5000)


class AnalysisPreview(BaseModel):
    """Analysis preview request."""

    session_id: str
    oql: str = ""
    limit: int = Field(default=200, ge=1, le=2000)
    mode: str = Field(default="full", pattern="^(full|messages|patterns)$")
    provider: str = "mock"
    model: str = "mock-analysis-v1"


class AnalysisSend(BaseModel):
    """Analysis dispatch request (FR-324)."""

    stage_id: str
    payload_sha256: str
    confirm_findings: bool = False
    confirm_reason: str = ""


class RunCreate(BaseModel):
    """Run creation request (FR-521, FR-526)."""

    dry_run: bool = False
    run_all: bool = False
    target_overrides: dict[int, str] = Field(default_factory=dict)


class SavedQueryCreate(BaseModel):
    """Saved query request (FR-163)."""

    name: str = ""
    oql: str = ""
    shared: bool = False


class SavedQueryPatch(BaseModel):
    """Saved query update request (FR-163)."""

    name: str | None = None
    oql: str | None = None
    shared: bool | None = None


class QueryHistoryAdd(BaseModel):
    """Query history entry request (FR-163)."""

    oql: str = ""


class StepRun(BaseModel):
    """Single step run request (run = approval)."""

    command: str | None = None
    target_host_id: str | None = None
    ai_check: bool = False


class StepApprove(BaseModel):
    """Four-eyes approval request (approve = run)."""

    note: str = ""


class StepSkip(BaseModel):
    """Step skip request (reason mandatory)."""

    reason: str


class HostIn(BaseModel):
    """Host inventory record (FR-512)."""

    hostname: str = Field(min_length=1, max_length=255)
    aliases: list[str] = Field(default_factory=list)
    fqdn: str = ""
    ip_addresses: list[str] = Field(default_factory=list)
    environment: str = "other"
    os: str = "linux"
    executor_type: str = "ssh"
    connection_profile_id: str = ""


class ResolveIn(BaseModel):
    """Target resolution request (FR-510)."""

    target: str = Field(min_length=1, max_length=255)


class LoginBody(BaseModel):
    """Password login request (FR-600)."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    totp: str = Field(default="", max_length=16)


class UserCreate(BaseModel):
    """User creation request (admin)."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    roles: list[str] = Field(default_factory=lambda: ["viewer"])


class UserUpdate(BaseModel):
    """User update request (admin)."""

    roles: list[str] | None = None
    enabled: bool | None = None
    password: str | None = Field(default=None, max_length=256)


class PasswordChange(BaseModel):
    """Self-service password change."""

    current: str = Field(min_length=1, max_length=256)
    new: str = Field(min_length=1, max_length=256)


class TotpConfirm(BaseModel):
    """TOTP enrollment confirmation (secret from setup + a valid code)."""

    secret: str = Field(min_length=16, max_length=64)
    code: str = Field(min_length=6, max_length=8)


class TotpDisable(BaseModel):
    """TOTP removal request (password re-check)."""

    password: str = Field(min_length=1, max_length=256)


class PatCreate(BaseModel):
    """PAT creation request (FR-604)."""

    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=lambda: ["read"])
    ttl_days: int = Field(default=90, ge=1, le=365)


@dataclass
class ApiDeps:
    """Shared services for API endpoints and UI pages."""

    settings: Settings
    sessions: SessionManager
    audit: AuditWriter
    execution: ExecutionEngine
    users: UserStore
    tokens: TokenStore
    web_sessions: SessionStore
    queries: QueryStore
    stages: dict[str, dict[str, Any]] = field(default_factory=dict)
    engines: dict[str, MaskingEngine] = field(default_factory=dict)

    def engine_for(self, session_id: str) -> MaskingEngine:
        """Return the session-scoped masking engine (FR-403)."""
        engine = self.engines.get(session_id)
        if engine is None:
            engine = MaskingEngine(presidio=self.settings.presidio_mode)
            self.engines[session_id] = engine
        return engine


def create_deps(settings: Settings) -> ApiDeps:
    """Create services for the given settings."""
    init_app_db(settings)
    app_db = get_app_db_path(settings)
    audit = AuditWriter(app_db)
    execution = ExecutionEngine(
        settings=settings,
        app_db=app_db,
        audit=audit,
        inventory=InventoryStore(app_db),
        policies=PolicyStore(app_db),
    )
    return ApiDeps(
        settings=settings,
        sessions=SessionManager(
            settings.data_dir,
            settings.session_limit_bytes,
            backend=settings.session_backend,
            postgres_dsn=settings.postgres_dsn,
        ),
        audit=audit,
        execution=execution,
        users=UserStore(app_db),
        tokens=TokenStore(app_db),
        web_sessions=SessionStore(
            app_db,
            idle=timedelta(minutes=settings.session_idle_minutes),
            absolute=timedelta(hours=settings.session_absolute_hours),
        ),
        queries=QueryStore(app_db),
    )


def _credentials_from_request(request: Request) -> Credentials:
    return Credentials(
        authorization=request.headers.get("authorization", ""),
        session_cookie=request.cookies.get(COOKIE_NAME, ""),
        x_user=request.headers.get("x-user", ""),
        x_role=request.headers.get("x-role", ""),
    )


def _identify(request: Request) -> Identity:
    deps: ApiDeps = request.app.state.deps
    settings: Settings = request.app.state.settings
    try:
        return resolve_identity(
            _credentials_from_request(request),
            settings,
            deps.users,
            deps.tokens,
            deps.web_sessions,
        )
    except AuthError as exc:
        raise ProblemError(exc.status, "Unauthorized", exc.detail) from exc


def _require(permission: str) -> Any:
    async def guard(request: Request) -> Identity:
        identity = _identify(request)
        if not identity.allows(permission):
            raise ProblemError(403, "Forbidden", f"User '{identity.username}' lacks '{permission}'")
        return identity

    return guard


def _problem_handler(request: Request, exc: ProblemError) -> JSONResponse:
    _ = request
    return JSONResponse(
        status_code=exc.status,
        media_type="application/problem+json",
        content={"title": exc.title, "status": exc.status, "detail": exc.detail},
    )


def _oql_handler(request: Request, exc: OQLSyntaxError) -> JSONResponse:
    _ = request
    return JSONResponse(
        status_code=400,
        media_type="application/problem+json",
        content={"title": "Invalid OQL", "status": 400, "detail": str(exc)},
    )


def _value_handler(request: Request, exc: ValueError) -> JSONResponse:
    _ = request
    return JSONResponse(
        status_code=404,
        media_type="application/problem+json",
        content={"title": "Not found", "status": 404, "detail": str(exc)},
    )


def _execution_handler(request: Request, exc: ExecutionError) -> JSONResponse:
    _ = request
    status = 409 if isinstance(exc, (ApprovalRequiredError, TargetRequiredError)) else 400
    title = "Needs decision" if status == 409 else "Execution error"
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        content={
            "title": title,
            "status": status,
            "detail": str(exc),
            "code": type(exc).__name__,
        },
    )


def _transition_handler(request: Request, exc: TransitionError) -> JSONResponse:
    _ = request
    return JSONResponse(
        status_code=409,
        media_type="application/problem+json",
        content={"title": "Invalid transition", "status": 409, "detail": str(exc)},
    )


def _current_user(request: Request) -> str:
    """Return the caller username from the resolved identity."""
    return _identify(request).username


def _load_system_prompt(language: str) -> str:
    prompt_path = Path(__file__).resolve().parent.parent / "prompts" / f"system_{language}.jinja"
    if not prompt_path.exists():
        prompt_path = prompt_path.with_name("system_en.jinja")
    rendered: str = Template(prompt_path.read_text(encoding="utf-8")).render()
    return rendered


def _provider_for(name: str, settings: Settings) -> Any:
    try:
        return get_provider(name, settings)
    except ValueError as exc:
        raise ProblemError(400, "Unknown provider", str(exc)) from exc


def _deep_depseudonymize(
    node: Any, mapping: dict[str, str], engine: MaskingEngine
) -> tuple[Any, list[str]]:
    unknown: list[str] = []
    if isinstance(node, str):
        restored, found = engine.depseudonymize(node, mapping)
        unknown.extend(found)
        return restored, unknown
    if isinstance(node, list):
        items: list[Any] = []
        for item in node:
            value, found = _deep_depseudonymize(item, mapping, engine)
            unknown.extend(found)
            items.append(value)
        return items, unknown
    if isinstance(node, dict):
        result: dict[str, Any] = {}
        for key, value in node.items():
            restored, found = _deep_depseudonymize(value, mapping, engine)
            unknown.extend(found)
            result[str(key)] = restored
        return result, unknown
    return node, unknown


def build_api_router(deps: ApiDeps) -> APIRouter:  # noqa: C901 - declarative route table
    """Build the /api/v1 router over shared services."""
    router = APIRouter()
    settings = deps.settings

    @router.get("/api/v1/health/live")
    async def health_live() -> dict[str, str]:
        return {"status": "ok"}

    @router.get("/api/v1/health/ready")
    async def health_ready() -> dict[str, str]:
        if not get_app_db_path(settings).exists():
            raise ProblemError(503, "Not ready", "Application database is missing")
        return {"status": "ready"}

    @router.get("/api/v1/metrics", response_class=PlainTextResponse)
    async def metrics() -> str:
        items = deps.sessions.list_sessions()
        records = sum(i["record_count"] for i in items)
        with sqlite3.connect(get_app_db_path(settings)) as conn:
            analyses = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            audits = conn.execute("SELECT COUNT(*) FROM audit_event").fetchone()[0]
        lines = [
            f"opsai_sessions_total {len(items)}",
            f"opsai_ingest_records_total {records}",
            f"opsai_analyses_total {analyses}",
            f"opsai_audit_events_total {audits}",
        ]
        return "\n".join(lines) + "\n"

    @router.get("/api/v1/providers")
    async def list_providers(identity: Identity = Depends(_require("analyze"))) -> dict[str, Any]:
        _ = identity
        return {
            "live": settings.ai_live,
            "providers": [
                {"name": "mock", "models": ["mock-analysis-v1"], "live": False},
                {
                    "name": "meta",
                    "models": list(KNOWN_MODELS),
                    "preview_models": list(PREVIEW_MODELS),
                    "default_model": DEFAULT_MODEL,
                    "live": settings.ai_live,
                },
            ],
        }

    def _public_user(user: Any) -> dict[str, Any]:
        return {
            "id": user.id,
            "username": user.username,
            "roles": list(user.roles),
            "enabled": user.enabled,
            "auth_source": user.auth_source,
            "totp_enabled": user.totp_enabled,
            "last_login_at": user.last_login_at,
        }

    def _require_admin(request: Request) -> Identity:
        identity = _identify(request)
        if not identity.allows("admin"):
            raise ProblemError(403, "Forbidden", f"User '{identity.username}' lacks 'admin'")
        return identity

    def _last_admin_guard(target_id: str, make_non_admin: bool) -> None:
        """Refuse changes that would leave zero enabled admins."""
        if not make_non_admin:
            return
        admins = [
            u
            for u in deps.users.list_users()
            if u.enabled and "admin" in u.roles and u.id != target_id
        ]
        if not admins:
            raise ProblemError(409, "Conflict", "Cannot remove the last admin")

    @router.post("/api/v1/auth/login")
    async def login(body: LoginBody, request: Request, response: Response) -> dict[str, Any]:
        from opsai.auth.totp import verify_code

        username = body.username.strip().lower()
        locked = deps.users.locked_until(username)
        if locked is not None:
            raise ProblemError(429, "Locked out", "Too many failures, try again later")
        user = deps.users.verify(username, body.password)
        if user is None or not user.enabled:
            deps.users.record_failure(username)
            deps.audit.append(
                "auth.login_failed", actor=username, details={"reason": "bad-credentials"}
            )
            raise ProblemError(401, "Unauthorized", "Invalid username or password")
        if user.totp_enabled and not verify_code(deps.users.get_totp_secret(user.id), body.totp):
            deps.users.record_failure(username)
            deps.audit.append("auth.login_failed", actor=username, details={"reason": "bad-totp"})
            raise ProblemError(401, "Unauthorized", "Invalid second factor")
        deps.users.record_success(user.id)
        ip = request.client.host if request.client else ""
        token, _csrf = deps.web_sessions.create(user.id, ip)
        response.set_cookie(
            COOKIE_NAME,
            token,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="lax",
            max_age=settings.session_absolute_hours * 3600,
            path="/",
        )
        deps.audit.append("auth.login", actor=user.username, actor_ip=ip)
        return {"username": user.username, "roles": list(user.roles)}

    @router.post("/api/v1/auth/logout")
    async def logout(request: Request, response: Response) -> dict[str, str]:
        token = request.cookies.get(COOKIE_NAME, "")
        session = deps.web_sessions.get(token) if token else None
        actor = ""
        if session is not None:
            owner = deps.users.get_by_id(session.user_id)
            actor = owner.username if owner else ""
            deps.web_sessions.drop(token)
        response.delete_cookie(COOKIE_NAME, path="/")
        deps.audit.append("auth.logout", actor=actor)
        return {"status": "logged-out"}

    @router.get("/api/v1/auth/me")
    async def auth_me(request: Request) -> dict[str, Any]:
        return describe_identity(_identify(request))

    @router.get("/api/v1/auth/csrf")
    async def auth_csrf(request: Request) -> dict[str, str]:
        identity = _identify(request)
        if identity.method != "session":
            raise ProblemError(403, "Forbidden", "CSRF token requires a web session")
        session = deps.web_sessions.get(request.cookies.get(COOKIE_NAME, ""))
        if session is None:
            raise ProblemError(401, "Unauthorized", "Invalid or expired session")
        return {"csrf_token": session.csrf_token}

    @router.post("/api/v1/users")
    async def create_user(body: UserCreate, request: Request) -> dict[str, Any]:
        from opsai.auth.users import DuplicateUserError, UserValidationError

        if deps.users.count() == 0:
            # Setup mode: the first account is admin and needs no auth.
            actor, roles = "setup", ["admin"]
        else:
            actor = _require_admin(request).username
            roles = body.roles
        try:
            user = deps.users.create(body.username, body.password, roles)
        except DuplicateUserError as exc:
            raise ProblemError(409, "Conflict", str(exc)) from exc
        except UserValidationError as exc:
            raise ProblemError(400, "Invalid user", str(exc)) from exc
        deps.audit.append(
            "users.create",
            actor=actor,
            object_type="user",
            object_id=user.id,
            details={"username": user.username, "roles": list(user.roles)},
        )
        return _public_user(user)

    @router.get("/api/v1/users")
    async def list_users(request: Request) -> dict[str, Any]:
        _require_admin(request)
        return {"items": [_public_user(u) for u in deps.users.list_users()]}

    @router.get("/api/v1/users/{user_id}")
    async def get_user(user_id: str, request: Request) -> dict[str, Any]:
        identity = _require_admin(request)
        _ = identity
        user = deps.users.get_by_id(user_id)
        if user is None:
            raise ProblemError(404, "Not found", f"Unknown user {user_id!r}")
        return _public_user(user)

    @router.patch("/api/v1/users/{user_id}")
    async def update_user(user_id: str, body: UserUpdate, request: Request) -> dict[str, Any]:
        from opsai.auth.users import UserValidationError

        identity = _require_admin(request)
        user = deps.users.get_by_id(user_id)
        if user is None:
            raise ProblemError(404, "Not found", f"Unknown user {user_id!r}")
        try:
            if body.roles is not None:
                _last_admin_guard(user_id, "admin" not in body.roles)
                user = deps.users.set_roles(user_id, body.roles)
            if body.enabled is not None:
                _last_admin_guard(user_id, not body.enabled and "admin" in user.roles)
                user = deps.users.set_enabled(user_id, body.enabled)
            if body.password is not None:
                deps.users.set_password(user_id, body.password)
                deps.web_sessions.drop_for_user(user_id)
                user = deps.users.get_by_id(user_id)
                assert user is not None
        except UserValidationError as exc:
            raise ProblemError(400, "Invalid user", str(exc)) from exc
        deps.audit.append(
            "users.update",
            actor=identity.username,
            object_type="user",
            object_id=user_id,
            details={"username": user.username},
        )
        return _public_user(user)

    @router.delete("/api/v1/users/{user_id}")
    async def delete_user(user_id: str, request: Request) -> dict[str, str]:
        identity = _require_admin(request)
        user = deps.users.get_by_id(user_id)
        if user is None:
            raise ProblemError(404, "Not found", f"Unknown user {user_id!r}")
        _last_admin_guard(user_id, "admin" in user.roles)
        deps.users.delete(user_id)
        deps.audit.append(
            "users.delete",
            actor=identity.username,
            object_type="user",
            object_id=user_id,
            details={"username": user.username},
        )
        return {"status": "deleted"}

    @router.post("/api/v1/users/me/password")
    async def change_own_password(body: PasswordChange, request: Request) -> dict[str, str]:
        from opsai.auth.users import UserValidationError

        identity = _identify(request)
        if not identity.user_id:
            raise ProblemError(400, "No local account", "Password change needs a local account")
        user = deps.users.get_by_id(identity.user_id)
        if user is None or deps.users.verify(user.username, body.current) is None:
            raise ProblemError(401, "Unauthorized", "Current password is wrong")
        try:
            deps.users.set_password(user.id, body.new)
        except UserValidationError as exc:
            raise ProblemError(400, "Invalid password", str(exc)) from exc
        deps.web_sessions.drop_for_user(user.id)
        deps.audit.append(
            "users.password_change", actor=user.username, object_type="user", object_id=user.id
        )
        return {"status": "changed"}

    @router.post("/api/v1/users/me/totp/setup")
    async def totp_setup(request: Request) -> dict[str, str]:
        from opsai.auth.totp import generate_secret, provisioning_uri

        identity = _identify(request)
        if not identity.user_id:
            raise ProblemError(400, "No local account", "TOTP needs a local account")
        secret = generate_secret()
        # Stored only on confirm, so an abandoned setup cannot lock anyone out.
        return {"secret": secret, "uri": provisioning_uri(secret, identity.username)}

    @router.post("/api/v1/users/me/totp/confirm")
    async def totp_confirm(body: TotpConfirm, request: Request) -> dict[str, str]:
        from opsai.auth.totp import verify_code

        identity = _identify(request)
        if not identity.user_id:
            raise ProblemError(400, "No local account", "TOTP needs a local account")
        if not verify_code(body.secret, body.code):
            raise ProblemError(401, "Unauthorized", "Invalid TOTP code")
        deps.users.set_totp_secret(identity.user_id, body.secret)
        deps.audit.append(
            "users.totp_enabled",
            actor=identity.username,
            object_type="user",
            object_id=identity.user_id,
        )
        return {"status": "enabled"}

    @router.post("/api/v1/users/me/totp/disable")
    async def totp_disable(body: TotpDisable, request: Request) -> dict[str, str]:
        identity = _identify(request)
        if not identity.user_id:
            raise ProblemError(400, "No local account", "TOTP needs a local account")
        user = deps.users.get_by_id(identity.user_id)
        if user is None or deps.users.verify(user.username, body.password) is None:
            raise ProblemError(401, "Unauthorized", "Password is wrong")
        deps.users.set_totp_secret(identity.user_id, "")
        deps.audit.append(
            "users.totp_disabled",
            actor=identity.username,
            object_type="user",
            object_id=identity.user_id,
        )
        return {"status": "disabled"}

    @router.post("/api/v1/pats")
    async def create_pat(body: PatCreate, request: Request) -> dict[str, Any]:
        identity = _identify(request)
        if not identity.user_id:
            raise ProblemError(400, "No local account", "PATs need a local account")
        if not identity.allows("read"):
            raise ProblemError(403, "Forbidden", "PAT creation requires 'read'")
        try:
            info, token = deps.tokens.create(
                identity.user_id, body.name, body.scopes, body.ttl_days
            )
        except ValueError as exc:
            raise ProblemError(400, "Invalid token", str(exc)) from exc
        deps.audit.append(
            "pats.create",
            actor=identity.username,
            object_type="pat",
            object_id=info.id,
            details={"name": info.name, "scopes": info.scopes},
        )
        return {
            "id": info.id,
            "name": info.name,
            "prefix": info.prefix,
            "scopes": info.scopes,
            "expires_at": info.expires_at,
            "token": token,
        }

    @router.get("/api/v1/pats")
    async def list_pats(request: Request, all_users: bool = Query(default=False)) -> dict[str, Any]:
        identity = _identify(request)
        if not identity.user_id:
            raise ProblemError(400, "No local account", "PATs need a local account")
        if all_users:
            if not identity.allows("admin"):
                raise ProblemError(403, "Forbidden", "Listing all PATs requires 'admin'")
            infos = deps.tokens.list_all()
        else:
            infos = deps.tokens.list_for_user(identity.user_id)
        return {
            "items": [
                {
                    "id": info.id,
                    "user_id": info.user_id,
                    "name": info.name,
                    "prefix": info.prefix,
                    "scopes": info.scopes,
                    "created_at": info.created_at,
                    "expires_at": info.expires_at,
                    "last_used_at": info.last_used_at,
                    "revoked": info.revoked,
                }
                for info in infos
            ]
        }

    @router.delete("/api/v1/pats/{token_id}")
    async def revoke_pat(token_id: str, request: Request) -> dict[str, str]:
        identity = _identify(request)
        if not identity.user_id:
            raise ProblemError(400, "No local account", "PATs need a local account")
        owner_scoped = None if identity.allows("admin") else identity.user_id
        if not deps.tokens.revoke(token_id, owner_scoped):
            raise ProblemError(404, "Not found", f"Unknown token {token_id!r}")
        deps.audit.append(
            "pats.revoke", actor=identity.username, object_type="pat", object_id=token_id
        )
        return {"status": "revoked"}

    @router.post("/api/v1/sessions")
    async def create_session(
        body: SessionCreate, identity: Identity = Depends(_require("create_session"))
    ) -> dict[str, str]:
        _ = identity
        session_id = deps.sessions.create_session(body.name)
        return {"id": session_id, "name": body.name}

    @router.get("/api/v1/sessions")
    async def get_sessions(identity: Identity = Depends(_require("read"))) -> dict[str, Any]:
        _ = identity
        return {"items": deps.sessions.list_sessions()}

    @router.delete("/api/v1/sessions/{session_id}")
    async def delete_session(
        session_id: str, identity: Identity = Depends(_require("create_session"))
    ) -> dict[str, str]:
        _ = identity
        deps.sessions.delete_session(session_id)
        deps.engines.pop(session_id, None)
        return {"status": "deleted"}

    @router.post("/api/v1/sessions/{session_id}/ingest-file")
    async def ingest_file(
        session_id: str, body: IngestFile, identity: Identity = Depends(_require("create_session"))
    ) -> dict[str, Any]:
        _ = identity
        connector = FileConnector()
        profile = ConnectionProfile(
            id="adhoc", name="adhoc", connector_type="file", config={"path": body.path}
        )
        query = ReadQuery(limit_records=body.limit_records, tail_lines=body.tail_lines)
        added_total = 0
        status = "OPEN"
        async for batch in connector.read(profile, query):
            records = [to_log_record(raw, "file", None) for raw in batch.records]
            result = deps.sessions.add_records(session_id, records)
            added_total += int(result["added"])
            status = str(result["status"])
            if batch.truncated or status == "TRUNCATED":
                status = "TRUNCATED"
                break
        return {"added": added_total, "status": status}

    @router.post("/api/v1/sessions/{session_id}/ingest")
    async def ingest_batch(
        session_id: str, body: IngestBatch, identity: Identity = Depends(_require("create_session"))
    ) -> dict[str, Any]:
        _ = identity
        from dateutil.parser import isoparse

        from opsai.connectors.base import RawRecord

        records = []
        for item in body.records:
            ts = None
            if item.ts:
                try:
                    ts = isoparse(item.ts)
                except ValueError as exc:
                    raise ProblemError(
                        422, "Invalid timestamp", f"Unparsable ts: {item.ts[:100]}"
                    ) from exc
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
            raw = RawRecord(
                message=item.message,
                ts=ts,
                ts_raw=item.ts or None,
                level_raw=item.level or None,
                origin_host=item.host or None,
                service=item.service or None,
                fields=dict(item.fields),
                raw=item.message,
            )
            records.append(to_log_record(raw, body.source, None))
        try:
            result = deps.sessions.add_records(session_id, records)
        except ValueError as exc:
            raise ProblemError(404, "Not found", str(exc)) from exc
        return {"added": int(result["added"]), "status": str(result["status"])}

    @router.get("/api/v1/sessions/{session_id}/records")
    async def get_records(
        session_id: str,
        oql: str = Query(default=""),
        limit: int = Query(default=500, ge=1, le=5000),
        cursor: int = Query(default=0, ge=0),
        identity: Identity = Depends(_require("read")),
    ) -> dict[str, Any]:
        _ = identity
        return deps.sessions.query_records(session_id, oql=oql, limit=limit, cursor=cursor)

    @router.get("/api/v1/sessions/{session_id}/records/{rid}")
    async def get_record(
        session_id: str, rid: int, identity: Identity = Depends(_require("read"))
    ) -> dict[str, Any]:
        _ = identity
        record = deps.sessions.get_record(session_id, rid)
        if record is None:
            raise ProblemError(404, "Not found", f"Record {rid} not found")
        return record

    @router.get("/api/v1/sessions/{session_id}/stats")
    async def get_stats(
        session_id: str,
        oql: str = Query(default=""),
        identity: Identity = Depends(_require("read")),
    ) -> dict[str, Any]:
        _ = identity
        return deps.sessions.stats(session_id, oql=oql)

    @router.get("/api/v1/sessions/{session_id}/templates")
    async def get_templates(
        session_id: str,
        oql: str = Query(default=""),
        limit: int = Query(default=2000, ge=1, le=20000),
        backend: str = Query(default="auto"),
        identity: Identity = Depends(_require("read")),
    ) -> dict[str, Any]:
        _ = identity
        try:
            used = resolve_backend(backend)
        except ValueError as exc:
            raise ProblemError(400, "Invalid backend", str(exc)) from exc
        except DrainUnavailableError as exc:
            raise ProblemError(501, "Backend unavailable", str(exc)) from exc
        page = deps.sessions.query_records(session_id, oql=oql, limit=limit, cursor=0)
        messages = [str(item["message"]) for item in page["items"]]
        templates = compute_templates(messages, used)
        return {
            "templates": [
                {"template": t.template, "count": t.count, "hash": t.hash} for t in templates[:100]
            ],
            "sampled": len(messages),
            "backend": used,
        }

    @router.post("/api/v1/analyses/preview")
    async def analysis_preview(
        body: AnalysisPreview, identity: Identity = Depends(_require("analyze"))
    ) -> dict[str, Any]:
        _ = identity
        page = deps.sessions.query_records(
            body.session_id, oql=body.oql, limit=body.limit, cursor=0
        )
        records = page["items"]
        if not records:
            raise ProblemError(400, "Empty selection", "No records match the query")
        text, _meta = build_payload(records, body.mode)
        engine = deps.engine_for(body.session_id)
        masked = engine.mask_text(text)
        payload_sha = hashlib.sha256(masked.masked.encode("utf-8")).hexdigest()
        provider, _live = _provider_for(body.provider, settings)
        token_estimate = provider.estimate_tokens(masked.masked)
        stage_id = secrets.token_urlsafe(24)
        deps.stages[stage_id] = {
            "session_id": body.session_id,
            "masked": masked.masked,
            "sha256": payload_sha,
            "counts": masked.counts,
            "provider": body.provider,
            "model": body.model,
            "mode": body.mode,
            "mapping": engine.pseudonyms.as_dict(),
            "record_ids": [r["rid"] for r in records],
            "expires_at": time.time() + STAGE_TTL_SECONDS,
        }
        return {
            "stage_id": stage_id,
            "payload": masked.masked,
            "payload_sha256": payload_sha,
            "masking_counts": masked.counts,
            "token_estimate": token_estimate,
            "records": len(records),
            "provider": body.provider,
            "model": body.model,
            "mode": body.mode,
        }

    @router.post("/api/v1/analyses")
    async def analysis_send(
        body: AnalysisSend, identity: Identity = Depends(_require("analyze"))
    ) -> dict[str, Any]:
        _ = identity
        stage = deps.stages.get(body.stage_id)
        if stage is None or float(stage["expires_at"]) < time.time():
            deps.stages.pop(body.stage_id, None)
            raise ProblemError(410, "Stage expired", "Preview expired; create a new preview")
        if stage["sha256"] != body.payload_sha256:
            raise ProblemError(409, "Payload mismatch", "Hash does not match the approved preview")
        engine = deps.engine_for(str(stage["session_id"]))
        residual = engine.verify_masked(str(stage["masked"]))
        if residual and settings.restricted_mode:
            raise ProblemError(
                403, "Restricted mode", f"Post-mask verification found {len(residual)} finding(s)"
            )
        if residual and not body.confirm_findings:
            raise ProblemError(
                409,
                "Confirmation required",
                f"Post-mask verification found {len(residual)} finding(s); confirm explicitly",
            )
        provider, live = _provider_for(str(stage["provider"]), settings)
        system = _load_system_prompt(settings.language)
        llm_request = LLMRequest(
            system=system,
            messages=[LLMMessage(role="user", content=f"<<<LOGS\n{stage['masked']}\nLOGS>>>")],
            response_schema=ANALYSIS_JSON_SCHEMA,
            # Reasoning models spend part of the budget on hidden reasoning.
            max_output_tokens=8192,
        )
        try:
            response = provider.generate(llm_request, str(stage["model"]))
        except (PermissionError, RuntimeError) as exc:
            raise ProblemError(400, "Provider error", str(exc)) from exc
        except ProblemError:
            raise
        except Exception as exc:  # noqa: BLE001 - provider failures become 502
            raise ProblemError(502, "Provider failed", str(exc)[:500]) from exc
        data = response.data
        errors = validate_analysis(data)
        if errors:
            raise ProblemError(502, "Invalid AI output", "; ".join(errors[:10]))
        assert isinstance(data, dict)
        mapping: dict[str, str] = stage["mapping"]
        display, unknown_tokens = _deep_depseudonymize(data, mapping, engine)
        steps = display.get("remediation_plan", {}).get("steps", [])
        masked_steps = data.get("remediation_plan", {}).get("steps", [])
        for disp_step, masked_step in zip(steps, masked_steps, strict=True):
            combined = combine_risk(
                str(masked_step.get("risk", "change")), str(masked_step.get("command", ""))
            )
            disp_step["risk_local"] = combined
            disp_step["risk"] = combined
            allowed, reason = check_policy(str(masked_step.get("command", "")))
            disp_step["policy_allowed"] = allowed
            if not allowed:
                disp_step["policy_reason"] = reason
        analysis_id = uuid.uuid4().hex
        created = datetime.now(UTC).isoformat()
        with sqlite3.connect(get_app_db_path(settings)) as conn:
            conn.execute(
                "INSERT INTO analyses (id, session_id, provider, model, payload_mode,"
                " payload_sha256, status, prompt_version, created_at, response_json)"
                " VALUES (?, ?, ?, ?, ?, ?, 'DONE', ?, ?, ?)",
                (
                    analysis_id,
                    stage["session_id"],
                    stage["provider"],
                    stage["model"],
                    stage["mode"],
                    stage["sha256"],
                    PROMPT_VERSION,
                    created,
                    json.dumps(data, ensure_ascii=False),
                ),
            )
            conn.commit()
        payload_ref, _sha = deps.audit.store_payload(str(stage["masked"]), analysis_id)
        deps.audit.append(
            "ai.dispatch",
            actor=identity.username,
            object_type="analysis",
            object_id=analysis_id,
            details={
                "provider": stage["provider"],
                "model": stage["model"],
                "mode": stage["mode"],
                "payload_sha256": stage["sha256"],
                "payload_ref": payload_ref,
                "masking_counts": stage["counts"],
                "residual_findings": len(residual),
                "confirmed": bool(body.confirm_findings),
                "confirm_reason": body.confirm_reason,
                "live": live,
                "tokens_in": response.tokens_in,
                "tokens_out": response.tokens_out,
            },
        )
        deps.stages.pop(body.stage_id, None)
        return {
            "id": analysis_id,
            "provider": stage["provider"],
            "model": stage["model"],
            "live": live,
            "masked": data,
            "display": display,
            "unknown_tokens": unknown_tokens,
            "residual_findings": len(residual),
        }

    @router.get("/api/v1/analyses")
    async def list_analyses(identity: Identity = Depends(_require("read"))) -> dict[str, Any]:
        _ = identity
        with sqlite3.connect(get_app_db_path(settings)) as conn:
            rows = conn.execute(
                "SELECT id, session_id, provider, model, payload_mode, status, created_at"
                " FROM analyses ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
        return {
            "items": [
                {
                    "id": row[0],
                    "session_id": row[1],
                    "provider": row[2],
                    "model": row[3],
                    "payload_mode": row[4],
                    "status": row[5],
                    "created_at": row[6],
                }
                for row in rows
            ]
        }

    @router.get("/api/v1/analyses/{analysis_id}")
    async def get_analysis(
        analysis_id: str, identity: Identity = Depends(_require("read"))
    ) -> dict[str, Any]:
        _ = identity
        with sqlite3.connect(get_app_db_path(settings)) as conn:
            row = conn.execute(
                "SELECT id, session_id, provider, model, payload_mode, payload_sha256,"
                " status, prompt_version, created_at, response_json"
                " FROM analyses WHERE id = ?",
                (analysis_id,),
            ).fetchone()
        if row is None:
            raise ProblemError(404, "Not found", f"Analysis {analysis_id} not found")
        return {
            "id": row[0],
            "session_id": row[1],
            "provider": row[2],
            "model": row[3],
            "payload_mode": row[4],
            "payload_sha256": row[5],
            "status": row[6],
            "prompt_version": row[7],
            "created_at": row[8],
            "masked": json.loads(row[9]),
        }

    def _saved_to_dict(saved: Any) -> dict[str, Any]:
        return {
            "id": saved.id,
            "owner_id": saved.owner_id,
            "name": saved.name,
            "oql": saved.oql,
            "shared": saved.shared,
            "created_at": saved.created_at,
            "updated_at": saved.updated_at,
        }

    @router.post("/api/v1/queries/saved", status_code=201)
    async def create_saved_query(
        body: SavedQueryCreate,
        identity: Identity = Depends(_require("read")),
    ) -> dict[str, Any]:
        try:
            saved = deps.queries.save(identity.user_id, body.name, body.oql, body.shared)
        except ValueError as exc:
            raise ProblemError(400, "Invalid query", str(exc)) from exc
        return _saved_to_dict(saved)

    @router.get("/api/v1/queries/saved")
    async def list_saved_queries(
        identity: Identity = Depends(_require("read")),
    ) -> dict[str, Any]:
        return {"items": [_saved_to_dict(s) for s in deps.queries.list_saved(identity.user_id)]}

    @router.patch("/api/v1/queries/saved/{query_id}")
    async def update_saved_query(
        query_id: str,
        body: SavedQueryPatch,
        identity: Identity = Depends(_require("read")),
    ) -> dict[str, Any]:
        try:
            saved = deps.queries.update(
                query_id,
                identity.user_id,
                Role.ADMIN in identity.roles,
                name=body.name,
                oql=body.oql,
                shared=body.shared,
            )
        except KeyError as exc:
            raise ProblemError(404, "Not found", str(exc)) from exc
        except PermissionError as exc:
            raise ProblemError(403, "Forbidden", str(exc)) from exc
        except ValueError as exc:
            raise ProblemError(400, "Invalid query", str(exc)) from exc
        return _saved_to_dict(saved)

    @router.delete("/api/v1/queries/saved/{query_id}", status_code=204)
    async def delete_saved_query(
        query_id: str,
        identity: Identity = Depends(_require("read")),
    ) -> Response:
        try:
            deps.queries.delete(query_id, identity.user_id, Role.ADMIN in identity.roles)
        except KeyError as exc:
            raise ProblemError(404, "Not found", str(exc)) from exc
        except PermissionError as exc:
            raise ProblemError(403, "Forbidden", str(exc)) from exc
        return Response(status_code=204)

    @router.post("/api/v1/queries/history", status_code=201)
    async def add_query_history(
        body: QueryHistoryAdd,
        identity: Identity = Depends(_require("read")),
    ) -> dict[str, Any]:
        try:
            entry = deps.queries.record_history(identity.user_id, body.oql)
        except ValueError as exc:
            raise ProblemError(400, "Invalid query", str(exc)) from exc
        return {"id": entry.id, "oql": entry.oql, "created_at": entry.created_at}

    @router.get("/api/v1/queries/history")
    async def list_query_history(
        identity: Identity = Depends(_require("read")),
    ) -> dict[str, Any]:
        return {
            "items": [
                {"id": e.id, "oql": e.oql, "created_at": e.created_at}
                for e in deps.queries.history(identity.user_id)
            ]
        }

    @router.get("/api/v1/audit/events")
    async def audit_events(
        limit: int = Query(default=100, ge=1, le=1000),
        identity: Identity = Depends(_require("read_audit")),
    ) -> dict[str, Any]:
        _ = identity
        return {"items": deps.audit.list_events(limit=limit)}

    @router.get("/api/v1/audit/verify")
    async def audit_verify(identity: Identity = Depends(_require("read_audit"))) -> dict[str, Any]:
        _ = identity
        ok, checked = deps.audit.verify()
        return {"ok": ok, "checked": checked}

    def _mapping_for_analysis(analysis_id: str) -> dict[str, str]:
        with sqlite3.connect(get_app_db_path(settings)) as conn:
            row = conn.execute(
                "SELECT session_id FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
        if row is None:
            raise ProblemError(404, "Not found", f"Analysis {analysis_id} not found")
        return deps.engine_for(str(row[0])).pseudonyms.as_dict()

    def _require_execution() -> None:
        if not settings.execution_enabled:
            raise ProblemError(
                403, "Execution disabled", "Execution module is off (OPSAI_EXECUTION_ENABLED=false)"
            )

    @router.post("/api/v1/runs")
    async def create_run_legacy(
        identity: Identity = Depends(_require("execute")),
    ) -> dict[str, Any]:
        _ = identity
        _require_execution()
        raise ProblemError(
            400, "Plan required", "Create runs via POST /api/v1/plans/{analysis_id}/runs"
        )

    @router.post("/api/v1/plans/{analysis_id}/runs")
    async def create_plan_run(
        analysis_id: str,
        body: RunCreate,
        request: Request,
        identity: Identity = Depends(_require("execute")),
    ) -> dict[str, Any]:
        _ = identity
        _require_execution()
        user = _current_user(request)
        mapping = _mapping_for_analysis(analysis_id)
        if body.dry_run:
            return deps.execution.dry_run(analysis_id, mapping, body.target_overrides)
        return deps.execution.create_run(
            analysis_id,
            user,
            mapping,
            run_all=body.run_all,
            target_overrides=body.target_overrides,
        )

    @router.get("/api/v1/runs/{run_id}")
    async def get_run(
        run_id: str, identity: Identity = Depends(_require("read"))
    ) -> dict[str, Any]:
        _ = identity
        return deps.execution.get_run(run_id)

    @router.post("/api/v1/runs/{run_id}/abort")
    async def abort_run(
        run_id: str,
        request: Request,
        identity: Identity = Depends(_require("execute")),
    ) -> dict[str, Any]:
        _ = identity
        _require_execution()
        return deps.execution.abort_run(run_id, _current_user(request))

    @router.post("/api/v1/runs/{run_id}/run-all")
    async def run_all_steps(
        run_id: str,
        request: Request,
        identity: Identity = Depends(_require("execute")),
    ) -> dict[str, Any]:
        _ = identity
        _require_execution()
        return deps.execution.run_remaining(run_id, _current_user(request))

    @router.post("/api/v1/runs/{run_id}/steps/{order}/run")
    async def run_step(
        run_id: str,
        order: int,
        body: StepRun,
        request: Request,
        identity: Identity = Depends(_require("execute")),
    ) -> dict[str, Any]:
        _ = identity
        _require_execution()
        return deps.execution.run_step(
            run_id,
            order,
            _current_user(request),
            command=body.command,
            target_host_id=body.target_host_id,
            ai_check=body.ai_check,
        )

    @router.post("/api/v1/runs/{run_id}/steps/{order}/approve")
    async def approve_step(
        run_id: str,
        order: int,
        body: StepApprove,
        request: Request,
        identity: Identity = Depends(_require("approve")),
    ) -> dict[str, Any]:
        _ = identity
        _require_execution()
        return deps.execution.approve_step(run_id, order, _current_user(request), body.note)

    @router.post("/api/v1/runs/{run_id}/steps/{order}/skip")
    async def skip_step(
        run_id: str,
        order: int,
        body: StepSkip,
        request: Request,
        identity: Identity = Depends(_require("execute")),
    ) -> dict[str, Any]:
        _ = identity
        _require_execution()
        return deps.execution.skip_step(run_id, order, _current_user(request), body.reason)

    @router.post("/api/v1/runs/{run_id}/steps/{order}/abort")
    async def abort_step(
        run_id: str,
        order: int,
        request: Request,
        identity: Identity = Depends(_require("execute")),
    ) -> dict[str, Any]:
        _ = identity
        _require_execution()
        return deps.execution.abort_step(run_id, order, _current_user(request))

    @router.post("/api/v1/runs/{run_id}/rollback")
    async def start_rollback(
        run_id: str,
        request: Request,
        identity: Identity = Depends(_require("execute")),
    ) -> dict[str, Any]:
        _ = identity
        _require_execution()
        return deps.execution.start_rollback(run_id, _current_user(request))

    @router.get("/api/v1/inventory")
    async def list_inventory(identity: Identity = Depends(_require("read"))) -> dict[str, Any]:
        _ = identity
        return {"items": [_host_to_dict(h) for h in deps.execution.inventory.list_hosts()]}

    @router.post("/api/v1/inventory")
    async def add_host(
        body: HostIn,
        request: Request,
        identity: Identity = Depends(_require("admin")),
    ) -> dict[str, Any]:
        _ = identity
        host = deps.execution.inventory.add(
            HostRecord(
                id="",
                hostname=body.hostname,
                aliases=body.aliases,
                fqdn=body.fqdn,
                ip_addresses=body.ip_addresses,
                environment=body.environment,
                os=body.os,
                executor_type=body.executor_type,
                connection_profile_id=body.connection_profile_id,
            )
        )
        deps.audit.append(
            "inventory.added",
            actor=_current_user(request),
            object_type="host",
            object_id=host.id,
            details={"hostname": host.hostname, "environment": host.environment},
        )
        return _host_to_dict(host)

    @router.get("/api/v1/inventory/{host_id}")
    async def get_host(
        host_id: str, identity: Identity = Depends(_require("read"))
    ) -> dict[str, Any]:
        _ = identity
        host = deps.execution.inventory.get(host_id)
        if host is None:
            raise ProblemError(404, "Not found", f"Host {host_id} not found")
        return _host_to_dict(host)

    @router.put("/api/v1/inventory/{host_id}")
    async def update_host(
        host_id: str,
        body: HostIn,
        request: Request,
        identity: Identity = Depends(_require("admin")),
    ) -> dict[str, Any]:
        _ = identity
        host = deps.execution.inventory.get(host_id)
        if host is None:
            raise ProblemError(404, "Not found", f"Host {host_id} not found")
        updated = deps.execution.inventory.update(
            HostRecord(
                id=host_id,
                hostname=body.hostname,
                aliases=body.aliases,
                fqdn=body.fqdn,
                ip_addresses=body.ip_addresses,
                environment=body.environment,
                os=body.os,
                executor_type=body.executor_type,
                connection_profile_id=body.connection_profile_id,
            )
        )
        deps.audit.append(
            "inventory.updated",
            actor=_current_user(request),
            object_type="host",
            object_id=host_id,
            details={"hostname": updated.hostname},
        )
        return _host_to_dict(updated)

    @router.delete("/api/v1/inventory/{host_id}")
    async def delete_host(
        host_id: str,
        request: Request,
        identity: Identity = Depends(_require("admin")),
    ) -> dict[str, str]:
        _ = identity
        deps.execution.inventory.remove(host_id)
        deps.audit.append(
            "inventory.removed",
            actor=_current_user(request),
            object_type="host",
            object_id=host_id,
            details={},
        )
        return {"status": "deleted"}

    @router.post("/api/v1/inventory/resolve")
    async def resolve_target(
        body: ResolveIn, identity: Identity = Depends(_require("read"))
    ) -> dict[str, Any]:
        _ = identity
        resolution = deps.execution.inventory.resolve(body.target)
        return {
            "decision": resolution.decision,
            "environments_mixed": resolution.environments_mixed,
            "candidates": [
                {
                    "host_id": c.host.id,
                    "hostname": c.host.hostname,
                    "environment": c.host.environment,
                    "rule": c.rule,
                }
                for c in resolution.candidates
            ],
        }

    @router.get("/api/v1/policies/execution")
    async def get_policy(identity: Identity = Depends(_require("admin"))) -> dict[str, Any]:
        _ = identity
        return deps.execution.policies.get_execution().to_dict()

    @router.put("/api/v1/policies/execution")
    async def put_policy(
        body: dict[str, Any],
        request: Request,
        identity: Identity = Depends(_require("admin")),
    ) -> dict[str, Any]:
        _ = identity
        try:
            policy = ExecutionPolicy.from_dict(body)
        except (ValueError, re.error) as exc:
            raise ProblemError(400, "Invalid policy", str(exc)) from exc
        before = deps.execution.policies.get_execution().to_dict()
        stored = deps.execution.policies.save_execution(policy)
        deps.audit.append(
            "policy.updated",
            actor=_current_user(request),
            object_type="policy",
            object_id="execution-default",
            details={"before": before, "after": stored.to_dict()},
        )
        return stored.to_dict()

    return router


def _host_to_dict(host: HostRecord) -> dict[str, Any]:
    return {
        "id": host.id,
        "hostname": host.hostname,
        "aliases": host.aliases,
        "fqdn": host.fqdn,
        "ip_addresses": host.ip_addresses,
        "environment": host.environment,
        "os": host.os,
        "executor_type": host.executor_type,
        "connection_profile_id": host.connection_profile_id,
    }


def register_exception_handlers(app: FastAPI) -> None:
    """Register RFC 9457 problem-details handlers on any FastAPI app."""
    app.add_exception_handler(ProblemError, _problem_handler)  # type: ignore[arg-type]
    app.add_exception_handler(OQLSyntaxError, _oql_handler)  # type: ignore[arg-type]
    app.add_exception_handler(ExecutionError, _execution_handler)  # type: ignore[arg-type]
    app.add_exception_handler(TransitionError, _transition_handler)  # type: ignore[arg-type]
    app.add_exception_handler(ValueError, _value_handler)  # type: ignore[arg-type]


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the standalone FastAPI application."""
    import hmac

    deps = create_deps(settings or Settings.from_env())
    app = FastAPI(title="OpsAI", version=__version__, openapi_url="/api/v1/openapi.json")
    app.state.settings = deps.settings
    app.state.deps = deps
    app.include_router(build_api_router(deps))
    register_exception_handlers(app)

    @app.middleware("http")
    async def _csrf_protect(request: Request, call_next: Any) -> Any:
        # Cookie-authenticated mutations need the session CSRF token (FR-603).
        # Bearer PATs are exempt (not ambient); login has no session yet.
        if (
            request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and request.url.path.startswith("/api/")
            and request.url.path != "/api/v1/auth/login"
            and not request.headers.get("authorization")
        ):
            cookie = request.cookies.get(COOKIE_NAME, "")
            if cookie:
                session = deps.web_sessions.get(cookie)
                presented = request.headers.get(CSRF_HEADER, "")
                if (
                    session is None
                    or not presented
                    or not hmac.compare_digest(session.csrf_token, presented)
                ):
                    return JSONResponse(
                        status_code=403,
                        media_type="application/problem+json",
                        content={
                            "title": "Forbidden",
                            "status": 403,
                            "detail": "Missing or invalid CSRF token",
                        },
                    )
        return await call_next(request)

    return app
