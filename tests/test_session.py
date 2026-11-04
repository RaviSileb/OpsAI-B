"""Tests for sessions: ingest, OQL query, stats, size limit (FR-006)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from opsai.core.normalize import ERROR, INFO, LogRecord
from opsai.core.session import SessionManager


@pytest.fixture
def manager(data_dir: Path) -> SessionManager:
    """Return a session manager over the isolated data directory."""
    from dataclasses import replace

    from opsai.api.main import create_deps
    from opsai.app.config import Settings

    deps = create_deps(replace(Settings.from_env(), data_dir=data_dir))
    return deps.sessions


def _record(message: str, level: int | None = INFO, host: str = "h1") -> LogRecord:
    return LogRecord(
        ts=datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC),
        message=message,
        origin_host=host,
        service="webapp",
        level=level,
    )


def test_create_query_stats_and_delete(manager: SessionManager) -> None:
    session_id = manager.create_session("demo")
    result = manager.add_records(
        session_id, [_record("all good"), _record("boom failed", ERROR, "h2")]
    )
    assert result["added"] == 2
    assert result["status"] == "OPEN"
    page = manager.query_records(session_id, oql="level>=ERROR", limit=10, cursor=0)
    assert page["total"] == 1
    assert page["items"][0]["origin_host"] == "h2"
    stats = manager.stats(session_id)
    assert stats["total"] == 2
    assert stats["by_level"] == {str(INFO): 1, str(ERROR): 1}
    full = manager.get_record(session_id, page["items"][0]["rid"])
    assert full is not None
    assert full["message"] == "boom failed"
    manager.delete_session(session_id)
    assert manager.list_sessions() == []


def test_size_limit_truncates(manager: SessionManager, data_dir: Path) -> None:
    tiny = SessionManager(data_dir, session_limit_bytes=10)
    session_id = tiny.create_session("tiny")
    result = tiny.add_records(session_id, [_record("x" * 100)])
    assert result["added"] == 0
    assert result["status"] == "TRUNCATED"
    again = tiny.add_records(session_id, [_record("y")])
    assert again["added"] == 0


def test_unknown_session_raises(manager: SessionManager) -> None:
    with pytest.raises(ValueError):
        manager.add_records("0" * 32, [_record("x")])
