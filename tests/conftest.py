"""Shared pytest fixtures: isolated data dir, services, sample logs."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from opsai.api.main import ApiDeps, create_deps
from opsai.app.config import Settings

SAMPLE_LOG = """\
2026-10-27T10:00:01Z INFO app-srv-12 webapp Started on port 8080
2026-10-27T10:00:02Z WARN app-srv-12 webapp Slow query 1234ms user=alice
2026-10-27T10:00:03Z ERROR app-srv-12 webapp Failed password for bob from 10.1.2.3
Traceback (most recent call last):
  File "app.py", line 10, in main
    raise ValueError('boom')
ValueError: boom
2026-10-27T10:00:04Z INFO app-srv-12 webapp password=hunter2 login attempt
"""


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """Return an isolated data directory."""
    path = tmp_path / "opsai-data"
    path.mkdir()
    return path


@pytest.fixture
def settings(data_dir: Path) -> Settings:
    """Return test settings bound to the isolated data directory."""
    return replace(Settings.from_env(), data_dir=data_dir)


@pytest.fixture
def deps(settings: Settings) -> ApiDeps:
    """Return API services over the isolated data directory."""
    return create_deps(settings)


@pytest.fixture
def sample_log(tmp_path: Path) -> Path:
    """Write the sample log file and return its path."""
    path = tmp_path / "sample.log"
    path.write_text(SAMPLE_LOG, encoding="utf-8")
    return path
