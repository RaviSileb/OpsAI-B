"""Saved OQL queries and per-user filter history (TZ FR-163)."""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opsai.core.query import OQLSyntaxError, compile_oql

HISTORY_LIMIT = 50


@dataclass
class SavedQuery:
    """One named query (personal or shared)."""

    id: str
    owner_id: str
    name: str
    oql: str
    shared: bool
    created_at: str
    updated_at: str


@dataclass
class HistoryEntry:
    """One filter from the user's history."""

    id: str
    oql: str
    created_at: str


class QueryStore:
    """CRUD for saved queries plus a capped per-user history."""

    def __init__(self, app_db: Path) -> None:
        self.app_db = app_db

    @staticmethod
    def _check_oql(oql: str) -> str:
        text = (oql or "").strip()
        if not text:
            msg = "Query text must not be empty"
            raise ValueError(msg)
        if len(text) > 4000:
            msg = "Query text must be at most 4000 characters"
            raise ValueError(msg)
        try:
            compile_oql(text)
        except OQLSyntaxError as exc:
            msg = f"Invalid OQL: {exc}"
            raise ValueError(msg) from exc
        return text

    @staticmethod
    def _row_to_saved(row: tuple[Any, ...]) -> SavedQuery:
        return SavedQuery(
            id=row[0],
            owner_id=row[1],
            name=row[2],
            oql=row[3],
            shared=bool(row[4]),
            created_at=row[5],
            updated_at=row[6],
        )

    def save(self, owner_id: str, name: str, oql: str, shared: bool = False) -> SavedQuery:
        """Store a named query after OQL validation."""
        clean_name = name.strip()
        if not 1 <= len(clean_name) <= 100:
            msg = "Query name must be 1-100 characters"
            raise ValueError(msg)
        text = self._check_oql(oql)
        query_id = uuid.uuid4().hex
        now = datetime.now(UTC).isoformat()
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "INSERT INTO saved_queries (id, owner_id, name, oql, shared,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (query_id, owner_id, clean_name, text, int(shared), now, now),
            )
            conn.commit()
        saved = self.get(query_id)
        assert saved is not None
        return saved

    def get(self, query_id: str) -> SavedQuery | None:
        """Return a saved query by id, or None."""
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT id, owner_id, name, oql, shared, created_at, updated_at"
                " FROM saved_queries WHERE id = ?",
                (query_id,),
            ).fetchone()
        return self._row_to_saved(row) if row else None

    def list_saved(self, owner_id: str) -> list[SavedQuery]:
        """List own plus shared queries, newest first."""
        with sqlite3.connect(self.app_db) as conn:
            rows = conn.execute(
                "SELECT id, owner_id, name, oql, shared, created_at, updated_at"
                " FROM saved_queries WHERE owner_id = ? OR shared = 1"
                " ORDER BY updated_at DESC",
                (owner_id,),
            ).fetchall()
        return [self._row_to_saved(row) for row in rows]

    def update(
        self,
        query_id: str,
        owner_id: str,
        is_admin: bool,
        name: str | None = None,
        oql: str | None = None,
        shared: bool | None = None,
    ) -> SavedQuery:
        """Update a query owned by the caller (or any, for admins)."""
        saved = self.get(query_id)
        if saved is None:
            msg = f"Unknown query {query_id!r}"
            raise KeyError(msg)
        if saved.owner_id != owner_id and not is_admin:
            msg = f"Query {query_id!r} belongs to another user"
            raise PermissionError(msg)
        new_name = saved.name if name is None else name.strip()
        if not 1 <= len(new_name) <= 100:
            msg = "Query name must be 1-100 characters"
            raise ValueError(msg)
        new_oql = saved.oql if oql is None else self._check_oql(oql)
        new_shared = saved.shared if shared is None else shared
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "UPDATE saved_queries SET name = ?, oql = ?, shared = ?, updated_at = ?"
                " WHERE id = ?",
                (new_name, new_oql, int(new_shared), datetime.now(UTC).isoformat(), query_id),
            )
            conn.commit()
        updated = self.get(query_id)
        assert updated is not None
        return updated

    def delete(self, query_id: str, owner_id: str, is_admin: bool) -> None:
        """Delete a query owned by the caller (or any, for admins)."""
        saved = self.get(query_id)
        if saved is None:
            msg = f"Unknown query {query_id!r}"
            raise KeyError(msg)
        if saved.owner_id != owner_id and not is_admin:
            msg = f"Query {query_id!r} belongs to another user"
            raise PermissionError(msg)
        with sqlite3.connect(self.app_db) as conn:
            conn.execute("DELETE FROM saved_queries WHERE id = ?", (query_id,))
            conn.commit()

    def record_history(self, user_id: str, oql: str) -> HistoryEntry:
        """Append a filter to the history, keeping the last 50 per user."""
        text = self._check_oql(oql)
        entry_id = uuid.uuid4().hex
        now = datetime.now(UTC).isoformat()
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "INSERT INTO query_history (id, user_id, oql, created_at) VALUES (?, ?, ?, ?)",
                (entry_id, user_id, text, now),
            )
            conn.execute(
                "DELETE FROM query_history WHERE user_id = ? AND id NOT IN ("
                "SELECT id FROM query_history WHERE user_id = ?"
                " ORDER BY created_at DESC, rowid DESC LIMIT ?)",
                (user_id, user_id, HISTORY_LIMIT),
            )
            conn.commit()
        return HistoryEntry(id=entry_id, oql=text, created_at=now)

    def history(self, user_id: str) -> list[HistoryEntry]:
        """Return the user's history, newest first."""
        with sqlite3.connect(self.app_db) as conn:
            rows = conn.execute(
                "SELECT id, oql, created_at FROM query_history WHERE user_id = ?"
                " ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (user_id, HISTORY_LIMIT),
            ).fetchall()
        return [HistoryEntry(id=row[0], oql=row[1], created_at=row[2]) for row in rows]
