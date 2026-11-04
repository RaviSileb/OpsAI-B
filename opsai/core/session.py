"""Session manager: metadata in app.db, records in a pluggable backend.

Backends (TZ FR-140): ``sqlite`` (legacy, one file per session),
``duckdb`` (desktop default, one file per session) and ``postgres``
(server, one table per session). Every session remembers its backend,
so a backend switch never orphans existing sessions.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opsai.core.normalize import LogRecord
from opsai.core.query import compile_oql
from opsai.core.store_backends import (
    DuckDBBackend,
    PostgresBackend,
    SessionBackend,
    SQLiteBackend,
)

BACKENDS = ("sqlite", "duckdb", "postgres")


class SessionManager:
    """Create sessions, ingest records and run OQL queries."""

    def __init__(
        self,
        data_dir: Path,
        session_limit_bytes: int = 1_000_000_000,
        backend: str = "duckdb",
        postgres_dsn: str = "",
    ) -> None:
        if backend not in BACKENDS:
            msg = f"Unknown session backend {backend!r}"
            raise ValueError(msg)
        if backend == "postgres" and not postgres_dsn:
            msg = "PostgreSQL backend requires postgres_dsn (OPSAI_POSTGRES_DSN)"
            raise ValueError(msg)
        self.data_dir = data_dir
        self.sessions_dir = data_dir / "sessions"
        self.app_db = data_dir / "app.db"
        self.session_limit_bytes = session_limit_bytes
        self.default_backend = backend
        self.postgres_dsn = postgres_dsn
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self._backends: dict[str, SessionBackend] = {
            "sqlite": SQLiteBackend(self.sessions_dir),
            "duckdb": DuckDBBackend(self.sessions_dir),
        }

    def _backend(self, name: str) -> SessionBackend:
        if name == "postgres" and name not in self._backends:
            self._backends[name] = PostgresBackend(self.postgres_dsn)
        try:
            return self._backends[name]
        except KeyError:
            msg = f"Unknown session backend {name!r}"
            raise ValueError(msg) from None

    def _backend_name(self, session_id: str) -> str:
        with sqlite3.connect(self.app_db) as conn:
            try:
                row = conn.execute(
                    "SELECT backend FROM sessions WHERE id = ?", (session_id,)
                ).fetchone()
            except sqlite3.OperationalError:
                return self.default_backend  # table predates the backend column
        if row is None or not row[0]:
            return self.default_backend
        return str(row[0])

    def create_session(self, name: str) -> str:
        """Create a session and return its id."""
        session_id = uuid.uuid4().hex
        self._backend(self.default_backend).create_store(session_id)
        created = datetime.now(UTC).isoformat()
        with sqlite3.connect(self.app_db) as conn:
            try:
                conn.execute(
                    "INSERT INTO sessions (id, name, created_at, status, backend)"
                    " VALUES (?, ?, ?, 'OPEN', ?)",
                    (session_id, name, created, self.default_backend),
                )
            except sqlite3.OperationalError:
                conn.execute(
                    "INSERT INTO sessions (id, name, created_at, status) VALUES (?, ?, ?, 'OPEN')",
                    (session_id, name, created),
                )
            conn.commit()
        return session_id

    def list_sessions(self) -> list[dict[str, Any]]:
        """List sessions newest first."""
        with sqlite3.connect(self.app_db) as conn:
            try:
                rows = conn.execute(
                    "SELECT id, name, created_at, status, size_bytes, record_count, backend"
                    " FROM sessions ORDER BY created_at DESC"
                ).fetchall()
                with_backend = True
            except sqlite3.OperationalError:
                rows = conn.execute(
                    "SELECT id, name, created_at, status, size_bytes, record_count"
                    " FROM sessions ORDER BY created_at DESC"
                ).fetchall()
                with_backend = False
        items = []
        for row in rows:
            items.append(
                {
                    "id": row[0],
                    "name": row[1],
                    "created_at": row[2],
                    "status": row[3],
                    "size_bytes": row[4],
                    "record_count": row[5],
                    "backend": row[6] if with_backend else "sqlite",
                }
            )
        return items

    def rename_session(self, session_id: str, name: str) -> None:
        """Rename a session."""
        with sqlite3.connect(self.app_db) as conn:
            conn.execute("UPDATE sessions SET name = ? WHERE id = ?", (name, session_id))
            conn.commit()

    def delete_session(self, session_id: str) -> None:
        """Delete a session including its record store."""
        backend = self._backend(self._backend_name(session_id))
        backend.delete_store(session_id)
        # Best effort: drop stray files left by an earlier backend switch.
        for name in ("sqlite", "duckdb"):
            if name != backend.name:
                self._backends[name].delete_store(session_id)
        with sqlite3.connect(self.app_db) as conn:
            conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            conn.commit()

    def add_records(self, session_id: str, records: list[LogRecord]) -> dict[str, Any]:
        """Append records; enforce the session size limit (FR-006)."""
        backend = self._backend(self._backend_name(session_id))
        if not backend.store_exists(session_id):
            msg = f"Unknown session {session_id!r}"
            raise ValueError(msg)
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT size_bytes, record_count, status FROM sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            msg = f"Unknown session {session_id!r}"
            raise ValueError(msg)
        size_bytes, record_count, status = int(row[0]), int(row[1]), str(row[2])
        if status == "TRUNCATED":
            return {"added": 0, "status": status, "size_bytes": size_bytes}
        ingest_ts = datetime.now(UTC).isoformat()
        rows_to_add: list[tuple[Any, ...]] = []
        added_bytes = 0
        truncated = False
        for record in records:
            need = record.size_bytes()
            if size_bytes + added_bytes + need > self.session_limit_bytes:
                truncated = True
                break
            rows_to_add.append(
                (
                    record.ts.isoformat(),
                    record.ts_raw or "",
                    record.ts_quality,
                    ingest_ts,
                    record.source_type,
                    record.origin_host,
                    record.origin_host_rule,
                    record.service,
                    record.level,
                    record.level_raw,
                    record.message,
                    record.message.lower(),
                    record.raw,
                    json.dumps(record.fields, ensure_ascii=False),
                    json.dumps(record.src_meta, ensure_ascii=False),
                    record.template_id,
                )
            )
            added_bytes += need
        backend.insert(session_id, rows_to_add)
        new_status = "TRUNCATED" if truncated else status
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "UPDATE sessions SET size_bytes = ?, record_count = ?, status = ? WHERE id = ?",
                (size_bytes + added_bytes, record_count + len(rows_to_add), new_status, session_id),
            )
            conn.commit()
        return {
            "added": len(rows_to_add),
            "status": new_status,
            "size_bytes": size_bytes + added_bytes,
        }

    def query_records(
        self, session_id: str, oql: str = "", limit: int = 500, cursor: int = 0
    ) -> dict[str, Any]:
        """Query records with OQL; cursor is the last seen rid."""
        backend = self._backend(self._backend_name(session_id))
        if not backend.store_exists(session_id):
            return {"items": [], "next_cursor": cursor, "total": 0}
        where, params = compile_oql(oql, backend.dialect)
        total = backend.count(session_id, where, params, cursor)
        rows = backend.select(session_id, where, params, cursor, limit)
        items = [
            {
                "rid": row[0],
                "ts": row[1],
                "source_type": row[2],
                "origin_host": row[3],
                "service": row[4],
                "level": row[5],
                "message": row[6],
            }
            for row in rows
        ]
        next_cursor = items[-1]["rid"] if items else cursor
        return {"items": items, "next_cursor": next_cursor, "total": total}

    def get_record(self, session_id: str, rid: int) -> dict[str, Any] | None:
        """Return one full record by rid."""
        backend = self._backend(self._backend_name(session_id))
        if not backend.store_exists(session_id):
            return None
        row = backend.get(session_id, rid)
        if row is None:
            return None
        return {
            "rid": row[0],
            "ts": row[1],
            "ts_raw": row[2],
            "source_type": row[3],
            "origin_host": row[4],
            "origin_host_rule": row[5],
            "service": row[6],
            "level": row[7],
            "level_raw": row[8],
            "message": row[9],
            "raw": row[10],
            "fields": json.loads(row[11]),
            "src_meta": json.loads(row[12]),
            "template_id": row[13],
        }

    def stats(self, session_id: str, oql: str = "") -> dict[str, Any]:
        """Count records by level, host, service and source (FR-207)."""
        backend = self._backend(self._backend_name(session_id))
        if not backend.store_exists(session_id):
            return {"total": 0, "by_level": {}, "by_host": {}, "by_service": {}}
        where, params = compile_oql(oql, backend.dialect)
        total, by_level, by_host, by_service = backend.stats(session_id, where, params)
        return {
            "total": total,
            "by_level": {str(row[0]): row[1] for row in by_level},
            "by_host": {row[0]: row[1] for row in by_host},
            "by_service": {row[0]: row[1] for row in by_service},
        }
