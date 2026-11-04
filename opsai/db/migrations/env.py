"""Alembic environment: sqlite app.db, URL injected by the caller."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def run_migrations_online(db_url: str) -> None:
    """Run migrations against the configured database."""
    engine = create_engine(db_url)
    with engine.connect() as connection:
        context.configure(connection=connection, render_as_batch=False)
        with context.begin_transaction():
            context.run_migrations()


url = config.get_main_option("sqlalchemy.url")
if url is None:
    msg = "sqlalchemy.url is not configured for migrations"
    raise ValueError(msg)
run_migrations_online(url)
