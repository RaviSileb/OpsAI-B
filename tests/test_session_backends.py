"""Session backend conformance: sqlite + duckdb always, postgres via Docker."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from opsai.app.bootstrap import get_app_db_path, init_app_db
from opsai.app.config import Settings
from opsai.core.normalize import ERROR, INFO, WARN, LogRecord
from opsai.core.session import SessionManager
from tests.containers import Container, docker_available

PG_PORT = 15432
PG_DSN = f"host=127.0.0.1 port={PG_PORT} dbname=postgres user=postgres password=opsai-pw"


def _settings(tmp_path: Path, name: str) -> Settings:
    return replace(Settings.from_env(), data_dir=tmp_path / name)


def _manager(tmp_path: Path, backend: str, name: str, **kwargs: Any) -> SessionManager:
    settings = _settings(tmp_path, name)
    init_app_db(settings)
    return SessionManager(settings.data_dir, backend=backend, **kwargs)


def _records() -> list[LogRecord]:
    base = datetime(2026, 10, 28, 10, 0, tzinfo=UTC)
    return [
        LogRecord(
            ts=base,
            message="err5 disk failure",
            source_type="file",
            origin_host="h1",
            service="webapp",
            level=ERROR,
            level_raw="ERROR",
            fields={"request_id": "abc", "code": 500},
            src_meta={"host": "h1"},
        ),
        LogRecord(
            ts=base + timedelta(minutes=1),
            message="Slow query 1234ms",
            source_type="file",
            origin_host="h1",
            service="webapp",
            level=WARN,
            level_raw="WARN",
            fields={"request_id": "def"},
        ),
        LogRecord(
            ts=base + timedelta(minutes=2),
            message="User login ok",
            source_type="syslog",
            origin_host="h2",
            service="auth",
            level=INFO,
            level_raw="INFO",
        ),
        LogRecord(
            ts=base + timedelta(minutes=3),
            message="payment processed",
            source_type="kafka",
            origin_host="h3",
            service="shop",
            level=INFO,
            fields={"order": {"id": 42}},
        ),
        LogRecord(
            ts=base + timedelta(minutes=4),
            message="health check pass",
            source_type="file",
            origin_host=None,
            service=None,
            level=None,
        ),
    ]


def _conformance(manager: SessionManager, backend_name: str) -> None:
    session_id = manager.create_session("conf")
    listed = manager.list_sessions()
    assert listed[0]["backend"] == backend_name
    result = manager.add_records(session_id, _records())
    assert result == {"added": 5, "status": "OPEN", "size_bytes": result["size_bytes"]}

    assert manager.query_records(session_id)["total"] == 5
    assert manager.query_records(session_id, "disk")["total"] == 1
    assert manager.query_records(session_id, "level>=WARN")["total"] == 2
    assert manager.query_records(session_id, "service:auth")["total"] == 1
    assert manager.query_records(session_id, "origin_host:h1")["total"] == 2
    assert manager.query_records(session_id, "source_type:kafka")["total"] == 1
    assert manager.query_records(session_id, "message:/err\\d+/")["total"] == 1
    assert manager.query_records(session_id, "fields.request_id:abc")["total"] == 1
    assert manager.query_records(session_id, "exists:fields.request_id")["total"] == 2
    assert manager.query_records(session_id, "src_meta.host:h1")["total"] == 1
    assert manager.query_records(session_id, 'ts>"2026-10-28T10:02:30+00:00"')["total"] == 2
    page = manager.query_records(session_id, "", limit=2)
    assert [i["rid"] for i in page["items"]] == [1, 2]
    assert page["next_cursor"] == 2
    page2 = manager.query_records(session_id, "", limit=2, cursor=page["next_cursor"])
    assert [i["rid"] for i in page2["items"]] == [3, 4]

    full = manager.get_record(session_id, 1)
    assert full is not None
    assert full["fields"] == {"request_id": "abc", "code": 500}
    assert full["src_meta"] == {"host": "h1"}
    assert full["message"] == "err5 disk failure"
    assert manager.get_record(session_id, 999) is None

    stats = manager.stats(session_id)
    assert stats["total"] == 5
    assert stats["by_level"] == {"5": 1, "4": 1, "2": 2, "None": 1}
    assert stats["by_host"]["h1"] == 2
    assert stats["by_service"]["webapp"] == 2

    manager.delete_session(session_id)
    assert manager.list_sessions() == []
    assert manager.query_records(session_id)["total"] == 0


def test_sqlite_backend(tmp_path: Path) -> None:
    _conformance(_manager(tmp_path, "sqlite", "lite"), "sqlite")


def test_duckdb_backend(tmp_path: Path) -> None:
    _conformance(_manager(tmp_path, "duckdb", "duck"), "duckdb")


def test_unknown_session_behavior(tmp_path: Path) -> None:
    manager = _manager(tmp_path, "duckdb", "duck")
    bogus = "0" * 32
    with pytest.raises(ValueError, match="Unknown session"):
        manager.add_records(bogus, _records())
    assert manager.query_records(bogus) == {"items": [], "next_cursor": 0, "total": 0}
    assert manager.get_record(bogus, 1) is None
    assert manager.stats(bogus)["total"] == 0
    with pytest.raises(ValueError, match="Invalid session id"):
        manager.query_records("not-hex", "")


def test_size_limit_truncates(tmp_path: Path) -> None:
    settings = _settings(tmp_path, "tiny")
    init_app_db(settings)
    manager = SessionManager(settings.data_dir, session_limit_bytes=30, backend="duckdb")
    session_id = manager.create_session("tiny")
    result = manager.add_records(session_id, _records())
    assert result["status"] == "TRUNCATED"
    assert result["added"] < 5
    again = manager.add_records(session_id, _records())
    assert again["added"] == 0


def test_mixed_backends_coexist(tmp_path: Path) -> None:
    settings = _settings(tmp_path, "mixed")
    init_app_db(settings)
    lite = SessionManager(settings.data_dir, backend="sqlite")
    duck = SessionManager(settings.data_dir, backend="duckdb")
    lite_id = lite.create_session("old")
    duck_id = duck.create_session("new")
    lite.add_records(lite_id, _records()[:1])
    duck.add_records(duck_id, _records()[:2])
    backends = {s["id"]: s["backend"] for s in duck.list_sessions()}
    assert backends == {lite_id: "sqlite", duck_id: "duckdb"}
    assert duck.query_records(lite_id)["total"] == 1
    assert lite.query_records(duck_id)["total"] == 2
    duck.delete_session(lite_id)
    duck.delete_session(duck_id)
    assert list((settings.data_dir / "sessions").glob("*.sqlite")) == []
    assert list((settings.data_dir / "sessions").glob("*.duckdb")) == []


def test_invalid_backend_rejected(tmp_path: Path) -> None:
    settings = _settings(tmp_path, "bad")
    init_app_db(settings)
    with pytest.raises(ValueError, match="Unknown session backend"):
        SessionManager(settings.data_dir, backend="mysql")
    with pytest.raises(ValueError, match="postgres_dsn"):
        SessionManager(settings.data_dir, backend="postgres")


def test_duckdb_concurrent_writes(tmp_path: Path) -> None:
    manager = _manager(tmp_path, "duckdb", "conc")
    session_id = manager.create_session("conc")
    errors: list[str] = []

    def worker(n: int) -> None:
        try:
            base = datetime(2026, 10, 28, 10, tzinfo=UTC)
            records = [LogRecord(ts=base, message=f"worker {n} line {i}") for i in range(10)]
            manager.add_records(session_id, records)
        except Exception as exc:  # noqa: BLE001 - collected, asserted below
            errors.append(str(exc))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert manager.query_records(session_id)["total"] == 40


@pytest.fixture(scope="module")
def pg_dsn() -> Iterator[str]:
    """Run PostgreSQL 16 in Docker; skip the module without docker."""
    if not docker_available():
        pytest.skip("docker unavailable")
    container = Container(
        "postgres:16", ports={PG_PORT: 5432}, env={"POSTGRES_PASSWORD": "opsai-pw"}
    )
    container.start()
    try:

        def ready() -> bool:
            import psycopg

            with psycopg.connect(PG_DSN, connect_timeout=5) as conn:
                conn.execute("SELECT 1")
            return True

        container.wait_for(ready, timeout=120)
        yield PG_DSN
    finally:
        container.stop()


def test_postgres_backend(tmp_path: Path, pg_dsn: str) -> None:
    _conformance(_manager(tmp_path, "postgres", "pg", postgres_dsn=pg_dsn), "postgres")


def test_postgres_indexes(tmp_path: Path, pg_dsn: str) -> None:
    import psycopg

    manager = _manager(tmp_path, "postgres", "pgidx", postgres_dsn=pg_dsn)
    session_id = manager.create_session("idx")
    manager.add_records(session_id, _records()[:1])
    table = f"session_records_{session_id}"
    with psycopg.connect(pg_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT indexname FROM pg_indexes WHERE tablename = %s ORDER BY 1", (table,))
        names = {row[0] for row in cur.fetchall()}
    assert f"{table}_ts" in names
    assert f"{table}_msg" in names
    with psycopg.connect(pg_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT indexdef FROM pg_indexes WHERE indexname = %s", (f"{table}_msg",))
        assert "gin_trgm_ops" in cur.fetchone()[0].lower()
    manager.delete_session(session_id)
    assert get_app_db_path(_settings(tmp_path, "pgidx")).exists()


def test_postgres_unreachable_dsn(tmp_path: Path) -> None:
    manager = _manager(
        tmp_path,
        "postgres",
        "pgdead",
        postgres_dsn="host=127.0.0.1 port=1 dbname=x user=x password=x connect_timeout=2",
    )
    with pytest.raises(Exception, match="connection|connect"):
        manager.create_session("dead")
