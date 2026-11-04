"""Bootstrap: directories and application database (TZ 2.2, FR-140).

Schema changes ship as Alembic revisions in :mod:`opsai.db.migrations`;
:func:`init_app_db` upgrades managed databases and stamps pre-Alembic ones
after a one-time legacy catch-up.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config

from opsai.app.config import Settings

APP_DB_NAME = "app.db"
SESSIONS_DIR_NAME = "sessions"
UPLOADS_DIR_NAME = "uploads"
STAGE_DIR_NAME = "stage"
MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "db" / "migrations"

# Legacy full schema: used only to catch up pre-Alembic databases before
# stamping them. New changes go to opsai/db/migrations/versions/.
SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    record_count INTEGER NOT NULL DEFAULT 0,
    backend TEXT NOT NULL DEFAULT 'sqlite'
);
CREATE TABLE IF NOT EXISTS analyses (
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
);
CREATE TABLE IF NOT EXISTS kb_entries (
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
);
CREATE TABLE IF NOT EXISTS connection_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    credential_ids TEXT NOT NULL DEFAULT '[]',
    owner TEXT NOT NULL DEFAULT 'local',
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS host_inventory (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    aliases TEXT NOT NULL DEFAULT '[]',
    fqdn TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT 'other',
    os TEXT NOT NULL DEFAULT 'linux',
    executor_type TEXT NOT NULL DEFAULT 'ssh',
    connection_profile_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL DEFAULT '',
    roles TEXT NOT NULL DEFAULT '["admin"]',
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS api_tokens (
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
);
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON api_tokens(token_hash);
CREATE TABLE IF NOT EXISTS web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON web_sessions(user_id);
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    definition TEXT NOT NULL DEFAULT '{}',
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS execution_runs (
    id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL,
    requested_by TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'DRAFT',
    dry_run INTEGER NOT NULL DEFAULT 0,
    run_all INTEGER NOT NULL DEFAULT 0,
    parent_run_id TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS execution_steps (
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
);
CREATE INDEX IF NOT EXISTS idx_steps_run ON execution_steps(run_id);
CREATE TABLE IF NOT EXISTS saved_queries (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    oql TEXT NOT NULL,
    shared INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS query_history (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT '',
    oql TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_query_history_user ON query_history(user_id);
"""

# Additive column migrations for tables created by older versions.
_COLUMNS = [
    ("sessions", "backend", "TEXT NOT NULL DEFAULT 'sqlite'"),
    ("host_inventory", "ip_addresses", "TEXT NOT NULL DEFAULT '[]'"),
    ("users", "auth_source", "TEXT NOT NULL DEFAULT 'local'"),
    ("users", "totp_secret", "TEXT NOT NULL DEFAULT ''"),
    ("users", "failed_count", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "first_failed_at", "TEXT NOT NULL DEFAULT ''"),
    ("users", "locked_until", "TEXT NOT NULL DEFAULT ''"),
    ("users", "last_login_at", "TEXT NOT NULL DEFAULT ''"),
]


def _ensure_columns(conn: sqlite3.Connection) -> None:
    for table, column, ddl in _COLUMNS:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def ensure_dirs(settings: Settings) -> dict[str, Path]:
    """Create data directories and return their paths."""
    data = settings.data_dir
    paths = {
        "data": data,
        "sessions": data / SESSIONS_DIR_NAME,
        "uploads": data / UPLOADS_DIR_NAME,
        "stage": data / STAGE_DIR_NAME,
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def get_app_db_path(settings: Settings) -> Path:
    """Return the path of the application database file."""
    return settings.data_dir / APP_DB_NAME


def _migration_config(db_path: Path) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def migrate_app_db(db_path: Path, revision: str = "head") -> None:
    """Upgrade a managed database to the given revision (default head)."""
    command.upgrade(_migration_config(db_path), revision)


def stamp_app_db(db_path: Path, revision: str = "head") -> None:
    """Mark a database at the given revision without running migrations."""
    command.stamp(_migration_config(db_path), revision)


def downgrade_app_db(db_path: Path, revision: str) -> None:
    """Downgrade a managed database to the given revision."""
    command.downgrade(_migration_config(db_path), revision)


def current_revision(db_path: Path) -> str | None:
    """Return the Alembic revision of the database (None = unmanaged)."""
    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "alembic_version" not in tables:
            return None
        row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        return str(row[0]) if row else None


def init_app_db(settings: Settings) -> Path:
    """Create data dirs and migrate application tables (idempotent)."""
    ensure_dirs(settings)
    db_path = get_app_db_path(settings)
    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    if "alembic_version" in tables:
        migrate_app_db(db_path)
    elif tables:
        # Pre-Alembic database: one-time legacy catch-up, then stamp.
        with sqlite3.connect(db_path) as conn:
            conn.executescript(SCHEMA)
            _ensure_columns(conn)
            conn.commit()
        stamp_app_db(db_path)
    else:
        migrate_app_db(db_path)
    # Audit tables live in the same app DB; AuditWriter also self-heals them.
    from opsai.core.audit import AuditWriter

    AuditWriter(db_path).close()
    return db_path
