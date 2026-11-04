"""Baseline schema: app tables in final shape plus audit tables.

Revision ID: 0001
Revises: None
Create Date: 2026-10-28
"""

from __future__ import annotations

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_UPGRADE = [
    """CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    record_count INTEGER NOT NULL DEFAULT 0,
    backend TEXT NOT NULL DEFAULT 'sqlite'
)""",
    """CREATE TABLE analyses (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    payload_mode TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'DONE',
    prompt_version TEXT NOT NULL DEFAULT 'v1',
    created_at TEXT NOT NULL,
    response_json TEXT NOT NULL DEFAULT '{}'
)""",
    """CREATE TABLE kb_entries (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    problem TEXT NOT NULL DEFAULT '',
    root_cause TEXT NOT NULL DEFAULT '',
    resolution TEXT NOT NULL DEFAULT '',
    commands TEXT NOT NULL DEFAULT '[]',
    tags TEXT NOT NULL DEFAULT '[]',
    source_types TEXT NOT NULL DEFAULT '[]',
    template_hashes TEXT NOT NULL DEFAULT '[]',
    analysis_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
)""",
    """CREATE TABLE connection_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    credential_ids TEXT NOT NULL DEFAULT '[]',
    owner TEXT NOT NULL DEFAULT 'local',
    enabled INTEGER NOT NULL DEFAULT 1
)""",
    """CREATE TABLE host_inventory (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    aliases TEXT NOT NULL DEFAULT '[]',
    fqdn TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT 'other',
    os TEXT NOT NULL DEFAULT 'linux',
    executor_type TEXT NOT NULL DEFAULT 'ssh',
    connection_profile_id TEXT NOT NULL DEFAULT '',
    ip_addresses TEXT NOT NULL DEFAULT '[]'
)""",
    """CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL DEFAULT '',
    roles TEXT NOT NULL DEFAULT '["admin"]',
    enabled INTEGER NOT NULL DEFAULT 1,
    auth_source TEXT NOT NULL DEFAULT 'local',
    totp_secret TEXT NOT NULL DEFAULT '',
    failed_count INTEGER NOT NULL DEFAULT 0,
    first_failed_at TEXT NOT NULL DEFAULT '',
    locked_until TEXT NOT NULL DEFAULT '',
    last_login_at TEXT NOT NULL DEFAULT ''
)""",
    """CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '["read"]',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL DEFAULT '',
    revoked INTEGER NOT NULL DEFAULT 0
)""",
    "CREATE INDEX idx_tokens_hash ON api_tokens(token_hash)",
    """CREATE TABLE web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT ''
)""",
    "CREATE INDEX idx_sessions_user ON web_sessions(user_id)",
    """CREATE TABLE policies (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    definition TEXT NOT NULL DEFAULT '{}',
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT ''
)""",
    """CREATE TABLE execution_runs (
    id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL,
    requested_by TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'DRAFT',
    dry_run INTEGER NOT NULL DEFAULT 0,
    run_all INTEGER NOT NULL DEFAULT 0,
    parent_run_id TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT ''
)""",
    """CREATE TABLE execution_steps (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    ord INTEGER NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    phase TEXT NOT NULL DEFAULT 'fix',
    target TEXT NOT NULL DEFAULT '',
    target_host_id TEXT NOT NULL DEFAULT '',
    shell TEXT NOT NULL DEFAULT 'bash',
    command_original TEXT NOT NULL DEFAULT '',
    command_final TEXT NOT NULL DEFAULT '',
    revisions TEXT NOT NULL DEFAULT '[]',
    risk TEXT NOT NULL DEFAULT 'change',
    status TEXT NOT NULL DEFAULT 'PENDING',
    exit_code INTEGER,
    stdout_text TEXT NOT NULL DEFAULT '',
    stderr_text TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    approvals TEXT NOT NULL DEFAULT '[]',
    verify_command TEXT NOT NULL DEFAULT '',
    rollback_command TEXT NOT NULL DEFAULT '',
    policy_reason TEXT NOT NULL DEFAULT ''
)""",
    "CREATE INDEX idx_steps_run ON execution_steps(run_id)",
    """CREATE TABLE audit_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    actor_ip TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    object_type TEXT NOT NULL DEFAULT '',
    object_id TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
)""",
    """CREATE TABLE analysis_payload (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL DEFAULT '',
    payload_sha256 TEXT NOT NULL,
    payload_text TEXT NOT NULL,
    created_at TEXT NOT NULL
)""",
    """CREATE TRIGGER audit_no_update
BEFORE UPDATE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event is append-only');
END""",
    """CREATE TRIGGER audit_no_delete
BEFORE DELETE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event is append-only');
END""",
    "CREATE INDEX idx_audit_type ON audit_event(event_type)",
    "CREATE INDEX idx_audit_actor ON audit_event(actor)",
    "CREATE INDEX idx_audit_ts ON audit_event(ts)",
]

_DOWNGRADE = [
    "DROP TRIGGER audit_no_delete",
    "DROP TRIGGER audit_no_update",
    "DROP TABLE analysis_payload",
    "DROP TABLE audit_event",
    "DROP TABLE execution_steps",
    "DROP TABLE execution_runs",
    "DROP TABLE policies",
    "DROP TABLE web_sessions",
    "DROP TABLE api_tokens",
    "DROP TABLE users",
    "DROP TABLE host_inventory",
    "DROP TABLE connection_profiles",
    "DROP TABLE kb_entries",
    "DROP TABLE analyses",
    "DROP TABLE sessions",
]


def upgrade() -> None:
    for statement in _UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in _DOWNGRADE:
        op.execute(statement)
