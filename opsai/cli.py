"""Command line interface: ``opsai desktop|server|audit|ingest|users``."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from opsai import __version__
from opsai.app.bootstrap import get_app_db_path, init_app_db
from opsai.app.config import Settings
from opsai.connectors.base import ConnectionProfile, ReadQuery
from opsai.connectors.file import FileConnector, to_log_record
from opsai.connectors.registry import ensure_builtin_connectors
from opsai.core.audit import AuditWriter
from opsai.core.session import SessionManager
from opsai.secrets.store import SecretRedactor

ensure_builtin_connectors()


def _settings_from_args(args: argparse.Namespace) -> Settings:
    settings = Settings.from_env()
    if getattr(args, "data_dir", None):
        from dataclasses import replace

        settings = replace(settings, data_dir=args.data_dir)
    return settings


def cmd_desktop(args: argparse.Namespace) -> int:
    """Run the Linux/Windows desktop UI (FR-811)."""
    from opsai.ui.main import run_desktop

    run_desktop(_settings_from_args(args))
    return 0


def cmd_server(args: argparse.Namespace) -> int:
    """Run the server UI + API in one process (Docker form)."""
    settings = _settings_from_args(args)
    if getattr(args, "api_only", False):
        import uvicorn

        from opsai.api.main import create_app

        uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
        return 0
    from opsai.ui.main import run_server_ui

    run_server_ui(settings)
    return 0


def cmd_users_create(args: argparse.Namespace) -> int:
    """Create a local user (server bootstrap, FR-600)."""
    import getpass

    from opsai.auth.users import (
        DuplicateUserError,
        UserStore,
        UserValidationError,
    )

    settings = _settings_from_args(args)
    init_app_db(settings)
    if args.password_file:
        password = args.password_file.read_text(encoding="utf-8").strip()
    elif args.password:
        password = args.password
    else:
        password = getpass.getpass("Password: ")
    try:
        user = UserStore(get_app_db_path(settings)).create(args.username, password, args.roles)
    except (DuplicateUserError, UserValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"created user {user.username} with roles {','.join(user.roles)}")
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify the audit hash chain (FR-651)."""
    settings = _settings_from_args(args)
    init_app_db(settings)
    writer = AuditWriter(get_app_db_path(settings))
    try:
        ok, checked = writer.verify()
    finally:
        writer.close()
    print(f"audit chain valid: {ok} ({checked} events)")
    return 0 if ok else 1


def cmd_ingest(args: argparse.Namespace) -> int:
    """Ingest a file into a session and print the record count."""
    settings = _settings_from_args(args)
    init_app_db(settings)
    sessions = SessionManager(
        settings.data_dir,
        settings.session_limit_bytes,
        backend=settings.session_backend,
        postgres_dsn=settings.postgres_dsn,
    )
    session_id = args.session or sessions.create_session(args.name)
    connector = FileConnector()
    profile = ConnectionProfile(
        id="cli", name="cli", connector_type="file", config={"path": args.path}
    )
    added_total = 0

    async def run() -> None:
        nonlocal added_total
        async for batch in connector.read(profile, ReadQuery()):
            records = [to_log_record(raw, "file", None) for raw in batch.records]
            result = sessions.add_records(session_id, records)
            added_total += int(result["added"])

    asyncio.run(run())
    print(f"session={session_id} added={added_total}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(prog="opsai", description="OpsAI variant B (Linux MVP)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--data-dir", dest="data_dir", default=None, help="Data directory")
    sub = parser.add_subparsers(dest="command", required=True)
    desktop = sub.add_parser("desktop", help="Run the desktop UI")
    desktop.set_defaults(func=cmd_desktop)
    server = sub.add_parser("server", help="Run the server UI + API")
    server.add_argument("--api-only", action="store_true", help="Serve only the REST API")
    server.set_defaults(func=cmd_server)
    audit = sub.add_parser("audit", help="Audit tools")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    verify = audit_sub.add_parser("verify", help="Verify the audit hash chain")
    verify.set_defaults(func=cmd_audit_verify)
    users = sub.add_parser("users", help="Local user administration")
    users_sub = users.add_subparsers(dest="users_command", required=True)
    create = users_sub.add_parser("create", help="Create a local user")
    create.add_argument("--username", required=True, help="Login name")
    create.add_argument("--password", default="", help="Password (prefer --password-file)")
    create.add_argument("--password-file", type=Path, default=None, help="File with the password")
    create.add_argument("--roles", nargs="+", default=["admin"], help="Roles")
    create.set_defaults(func=cmd_users_create)
    ingest = sub.add_parser("ingest", help="Ingest a log file into a session")
    ingest.add_argument("--path", required=True, help="File, directory or glob")
    ingest.add_argument("--session", default="", help="Existing session id")
    ingest.add_argument("--name", default="CLI session", help="Name for a new session")
    ingest.set_defaults(func=cmd_ingest)
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    logging.basicConfig(level=logging.INFO)
    logging.getLogger().addFilter(SecretRedactor())
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
