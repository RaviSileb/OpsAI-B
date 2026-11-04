"""Tests for the append-only audit log (FR-650..652)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from opsai.core.audit import AuditWriter


@pytest.fixture
def audit_db(tmp_path: Path) -> Path:
    """Return a fresh audit database path."""
    return tmp_path / "audit.sqlite"


def test_append_and_verify_chain(audit_db: Path) -> None:
    writer = AuditWriter(audit_db)
    try:
        first = writer.append("login", actor="alice", details={"ip": "10.0.0.1"})
        second = writer.append(
            "ai.dispatch",
            actor="alice",
            object_type="analysis",
            object_id="a1",
            details={"model": "m"},
        )
        assert (first, second) == (1, 2)
        ok, checked = writer.verify()
        assert (ok, checked) == (True, 2)
        events = writer.list_events()
        assert [e["event_type"] for e in events] == ["ai.dispatch", "login"]
    finally:
        writer.close()


def test_audit_table_rejects_updates(audit_db: Path) -> None:
    writer = AuditWriter(audit_db)
    try:
        writer.append("login", actor="alice")
        with pytest.raises(sqlite3.IntegrityError):
            writer._conn.execute("UPDATE audit_event SET actor='mallory' WHERE id=1")
    finally:
        writer.close()


def test_verify_detects_tampering(audit_db: Path) -> None:
    writer = AuditWriter(audit_db)
    try:
        writer.append("login", actor="alice", details={"ip": "10.0.0.1"})
        writer.append("login", actor="bob", details={"ip": "10.0.0.2"})
        assert writer.verify() == (True, 2)
    finally:
        writer.close()
    raw = sqlite3.connect(audit_db)
    try:
        raw.execute("DROP TRIGGER audit_no_update")
        raw.execute("UPDATE audit_event SET details='{}' WHERE id=1")
        raw.commit()
    finally:
        raw.close()
    writer2 = AuditWriter(audit_db)
    try:
        assert writer2.verify()[0] is False
    finally:
        writer2.close()


def test_store_payload_returns_sha(audit_db: Path) -> None:
    writer = AuditWriter(audit_db)
    try:
        ref, sha = writer.store_payload("masked payload", "a1")
        assert ref == 1
        assert len(sha) == 64
    finally:
        writer.close()
