"""Tests for Alembic application-database migrations."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from opsai.app.bootstrap import (
    current_revision,
    downgrade_app_db,
    init_app_db,
    migrate_app_db,
)
from opsai.app.config import Settings

EXPECTED_TABLES = {
    "sessions",
    "analyses",
    "kb_entries",
    "connection_profiles",
    "host_inventory",
    "users",
    "api_tokens",
    "web_sessions",
    "policies",
    "execution_runs",
    "execution_steps",
    "saved_queries",
    "query_history",
    "audit_event",
    "analysis_payload",
    "alembic_version",
}


def _settings(tmp_path: Path, name: str) -> Settings:
    return replace(Settings.from_env(), data_dir=tmp_path / name)


def _tables(db_path: Path) -> set[str]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {row[0] for row in rows} - {"sqlite_sequence"}


def test_fresh_init_upgrades_to_head(tmp_path: Path) -> None:
    db_path = init_app_db(_settings(tmp_path, "fresh"))
    assert current_revision(db_path) == "0002"
    assert _tables(db_path) == EXPECTED_TABLES
    with sqlite3.connect(db_path) as conn:
        triggers = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        }
    assert triggers == {"audit_no_update", "audit_no_delete"}
    indexes = {
        row[0]
        for row in sqlite3.connect(db_path).execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx\\_%' ESCAPE '\\'"
        )
    }
    assert indexes == {
        "idx_tokens_hash",
        "idx_sessions_user",
        "idx_steps_run",
        "idx_query_history_user",
        "idx_audit_type",
        "idx_audit_actor",
        "idx_audit_ts",
    }


def test_init_is_idempotent(tmp_path: Path) -> None:
    settings = _settings(tmp_path, "idem")
    first = init_app_db(settings)
    second = init_app_db(settings)
    assert first == second
    assert current_revision(first) == "0002"


def test_legacy_database_caught_up_and_stamped(tmp_path: Path) -> None:
    data_dir = tmp_path / "legacy"
    data_dir.mkdir()
    db_path = data_dir / "app.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            "CREATE TABLE sessions (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
            " created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN',"
            " size_bytes INTEGER NOT NULL DEFAULT 0, record_count INTEGER NOT NULL DEFAULT 0);"
            "CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,"
            " password_hash TEXT NOT NULL DEFAULT '',"
            " roles TEXT NOT NULL DEFAULT '[\"admin\"]', enabled INTEGER NOT NULL DEFAULT 1);"
            "INSERT INTO sessions VALUES ('s1', 'old', '2026-01-01', 'OPEN', 0, 0);"
        )
        conn.commit()
    assert current_revision(db_path) is None
    init_app_db(replace(Settings.from_env(), data_dir=data_dir))
    assert current_revision(db_path) == "0002"
    assert _tables(db_path) == EXPECTED_TABLES
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT id, name FROM sessions").fetchall() == [("s1", "old")]
        columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    assert {"totp_secret", "failed_count", "locked_until"} <= columns


def test_managed_database_behind_head_upgrades(tmp_path: Path) -> None:
    db_path = init_app_db(_settings(tmp_path, "behind"))
    downgrade_app_db(db_path, "0001")
    assert current_revision(db_path) == "0001"
    assert "saved_queries" not in _tables(db_path)
    init_app_db(_settings(tmp_path, "behind"))
    assert current_revision(db_path) == "0002"
    assert "saved_queries" in _tables(db_path)


def test_downgrade_to_base_and_back(tmp_path: Path) -> None:
    db_path = init_app_db(_settings(tmp_path, "cycle"))
    downgrade_app_db(db_path, "base")
    assert _tables(db_path) == {"alembic_version"}
    migrate_app_db(db_path, "head")
    assert current_revision(db_path) == "0002"
    assert _tables(db_path) == EXPECTED_TABLES


def test_audit_append_only_survives_migration(tmp_path: Path) -> None:
    db_path = init_app_db(_settings(tmp_path, "audit"))
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO audit_event (ts, event_type, prev_hash, hash)"
            " VALUES ('t', 'test', 'p', 'h')"
        )
        conn.commit()
        with pytest.raises(Exception, match="append-only"):
            conn.execute("UPDATE audit_event SET ts = 'x'")
