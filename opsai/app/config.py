"""Application configuration loaded from environment (TZ FR-801)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def default_data_dir() -> Path:
    """Return the default data directory for the current platform."""
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "opsai"
    return Path.home() / ".local" / "share" / "opsai"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return int(raw.strip())


@dataclass(frozen=True)
class Settings:
    """Runtime settings. Desktop and server share the code, mode picks behavior."""

    mode: str = "desktop"
    data_dir: Path = Path.home() / ".local" / "share" / "opsai"
    host: str = "127.0.0.1"
    port: int = 8080
    execution_enabled: bool = False
    local_exec_enabled: bool = False
    restricted_mode: bool = False
    secret_backend: str = "keyring"
    log_level: str = "INFO"
    language: str = "cs"
    session_limit_bytes: int = 1_000_000_000
    session_backend: str = "duckdb"
    postgres_dsn: str = ""
    default_tz: str = "UTC"
    ai_live: bool = False
    dev_auth: bool = False
    desktop_lock: bool = False
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    cookie_secure: bool = True
    presidio_mode: str = "auto"

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from environment variables."""
        mode = os.environ.get("OPSAI_MODE", "desktop").strip().lower()
        if mode not in {"desktop", "server"}:
            msg = f"Invalid OPSAI_MODE={mode!r}, expected 'desktop' or 'server'"
            raise ValueError(msg)
        data_dir_raw = os.environ.get("OPSAI_DATA_DIR", "").strip()
        data_dir = Path(data_dir_raw) if data_dir_raw else default_data_dir()
        language = os.environ.get("OPSAI_LANGUAGE", "cs").strip().lower()
        if language not in {"cs", "en"}:
            language = "cs"
        return cls(
            mode=mode,
            data_dir=data_dir,
            host=os.environ.get("OPSAI_HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=_env_int("OPSAI_PORT", 8080),
            execution_enabled=_env_bool("OPSAI_EXECUTION_ENABLED", False),
            local_exec_enabled=_env_bool("OPSAI_LOCAL_EXEC_ENABLED", False),
            restricted_mode=_env_bool("OPSAI_RESTRICTED_MODE", False),
            secret_backend=os.environ.get("OPSAI_SECRET_BACKEND", "keyring").strip() or "keyring",
            log_level=os.environ.get("OPSAI_LOG_LEVEL", "INFO").strip().upper() or "INFO",
            language=language,
            session_limit_bytes=_env_int("OPSAI_SESSION_LIMIT_BYTES", 1_000_000_000),
            session_backend=os.environ.get("OPSAI_SESSION_BACKEND", "duckdb").strip() or "duckdb",
            postgres_dsn=os.environ.get("OPSAI_POSTGRES_DSN", "").strip(),
            default_tz=os.environ.get("OPSAI_DEFAULT_TZ", "UTC").strip() or "UTC",
            ai_live=_env_bool("OPSAI_AI_LIVE", False),
            dev_auth=_env_bool("OPSAI_DEV_AUTH", False),
            desktop_lock=_env_bool("OPSAI_DESKTOP_LOCK", False),
            session_idle_minutes=_env_int("OPSAI_SESSION_IDLE_MINUTES", 30),
            session_absolute_hours=_env_int("OPSAI_SESSION_ABSOLUTE_HOURS", 12),
            cookie_secure=_env_bool("OPSAI_COOKIE_SECURE", True),
            presidio_mode=os.environ.get("OPSAI_PRESIDIO_MODE", "auto").strip() or "auto",
        )
