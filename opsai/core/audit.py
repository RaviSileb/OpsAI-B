"""Append-only audit log with hash chain (TZ FR-650..652).

Audit can never be disabled; a failed audit write must fail the operation
(fail-closed for AI dispatch and execution). Full payload text lives in the
``analysis_payload`` table, the audit row carries its hash and reference.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_event (
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
);
CREATE TABLE IF NOT EXISTS analysis_payload (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL DEFAULT '',
    payload_sha256 TEXT NOT NULL,
    payload_text TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event is append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event is append-only');
END;
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_event(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_event(actor);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_event(ts);
"""

GENESIS_HASH = "0" * 64


def canonical_json(data: dict[str, Any]) -> str:
    """Serialize details deterministically for hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditWriter:
    """Append-only audit writer backed by SQLite."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        # FastAPI runs sync endpoints in a worker thread pool, so the single
        # connection is shared across threads behind a lock.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._conn.close()

    def append(
        self,
        event_type: str,
        actor: str = "",
        object_type: str = "",
        object_id: str = "",
        details: dict[str, Any] | None = None,
        actor_ip: str = "",
    ) -> int:
        """Append one audit event and return its id."""
        payload = details or {}
        ts = datetime.now(UTC).isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT hash FROM audit_event ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = row[0] if row else GENESIS_HASH
            body = canonical_json(
                {
                    "ts": ts,
                    "actor": actor,
                    "actor_ip": actor_ip,
                    "event_type": event_type,
                    "object_type": object_type,
                    "object_id": object_id,
                    "details": payload,
                }
            )
            digest = hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()
            cursor = self._conn.execute(
                "INSERT INTO audit_event "
                "(ts, actor, actor_ip, event_type, object_type, object_id, details,"
                " prev_hash, hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    actor,
                    actor_ip,
                    event_type,
                    object_type,
                    object_id,
                    canonical_json(payload),
                    prev_hash,
                    digest,
                ),
            )
            self._conn.commit()
            row_id = cursor.lastrowid
            assert row_id is not None
            return row_id

    def store_payload(self, payload_text: str, analysis_id: str = "") -> tuple[int, str]:
        """Store full payload text and return ``(row_id, sha256)``."""
        sha = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
        created = datetime.now(UTC).isoformat()
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO analysis_payload (analysis_id, payload_sha256, payload_text,"
                " created_at) VALUES (?, ?, ?, ?)",
                (analysis_id, sha, payload_text, created),
            )
            self._conn.commit()
            row_id = cursor.lastrowid
            assert row_id is not None
            return row_id, sha

    def verify(self) -> tuple[bool, int]:
        """Verify the hash chain; return ``(ok, checked_count)``."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, actor, actor_ip, event_type, object_type, object_id,"
                " details, prev_hash, hash FROM audit_event ORDER BY id ASC"
            ).fetchall()
        expected_prev = GENESIS_HASH
        for row in rows:
            ts, actor, actor_ip, event_type, obj_type, obj_id, details, prev_hash, digest = row
            if prev_hash != expected_prev:
                return False, 0
            try:
                payload = json.loads(details)
            except json.JSONDecodeError:
                return False, 0
            body = canonical_json(
                {
                    "ts": ts,
                    "actor": actor,
                    "actor_ip": actor_ip,
                    "event_type": event_type,
                    "object_type": obj_type,
                    "object_id": obj_id,
                    "details": payload,
                }
            )
            recomputed = hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()
            if recomputed != digest:
                return False, 0
            expected_prev = digest
        return True, len(rows)

    def list_events(
        self,
        limit: int = 100,
        cursor: int = 0,
        event_type: str | None = None,
        actor: str | None = None,
    ) -> list[dict[str, Any]]:
        """List audit events newest first."""
        query = (
            "SELECT id, ts, actor, event_type, object_type, object_id, details"
            " FROM audit_event WHERE id > ?"
        )
        params: list[Any] = [cursor]
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if actor:
            query += " AND actor = ?"
            params.append(actor)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [
            {
                "id": row[0],
                "ts": row[1],
                "actor": row[2],
                "event_type": row[3],
                "object_type": row[4],
                "object_id": row[5],
                "details": json.loads(row[6]),
            }
            for row in rows
        ]
