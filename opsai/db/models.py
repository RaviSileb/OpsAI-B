"""Application entity shapes (TZ 3.1).

The MVP persists these with plain SQL in ``bootstrap``/``session``/``audit``.
A SQLAlchemy + Alembic mapping keeps these field names when it lands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Analysis:
    """One AI analysis over session records."""

    id: str
    session_id: str
    provider: str
    model: str
    payload_mode: str
    payload_sha256: str
    status: str = "DONE"
    prompt_version: str = "v1"
    created_at: str = ""
    response: dict[str, Any] = field(default_factory=dict)


@dataclass
class KBEntry:
    """One knowledge-base record (FR-220)."""

    id: str
    title: str
    problem: str = ""
    root_cause: str = ""
    resolution: str = ""
    commands: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source_types: list[str] = field(default_factory=list)
    template_hashes: list[str] = field(default_factory=list)
    analysis_id: str = ""
    created_at: str = ""


@dataclass
class HostRecord:
    """One host inventory record (FR-512)."""

    id: str
    hostname: str
    aliases: list[str] = field(default_factory=list)
    fqdn: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    environment: str = "other"
    os: str = "linux"
    executor_type: str = "ssh"
    connection_profile_id: str = ""


@dataclass
class UsageRecord:
    """One AI usage record for cost evidence (FR-304)."""

    user: str
    provider: str
    model: str
    tokens_in: int
    tokens_out: int
    cost: float = 0.0
    ts: str = ""
