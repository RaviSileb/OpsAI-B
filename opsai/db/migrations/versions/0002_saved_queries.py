"""Saved queries and filter history (FR-163).

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-28
"""

from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE saved_queries (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    oql TEXT NOT NULL,
    shared INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)"""
    )
    op.execute(
        """CREATE TABLE query_history (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT '',
    oql TEXT NOT NULL,
    created_at TEXT NOT NULL
)"""
    )
    op.execute("CREATE INDEX idx_query_history_user ON query_history(user_id)")


def downgrade() -> None:
    op.execute("DROP TABLE query_history")
    op.execute("DROP TABLE saved_queries")
