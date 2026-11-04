"""Connector interface: every source is read-only (TZ FR-001, FR-002)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ConnectionProfile:
    """Connection definition without secrets (FR-156)."""

    id: str
    name: str
    connector_type: str
    config: dict[str, Any] = field(default_factory=dict)
    credential_ids: list[str] = field(default_factory=list)


@dataclass
class ReadQuery:
    """Read request with pushdown filters and load limits (FR-003, FR-005)."""

    time_from: datetime | None = None
    time_to: datetime | None = None
    limit_records: int = 100_000
    limit_bytes: int = 256_000_000
    filters: dict[str, Any] = field(default_factory=dict)
    tail_lines: int | None = None


@dataclass
class RawRecord:
    """One raw record before normalization."""

    message: str
    ts: datetime | None = None
    ts_raw: str | None = None
    level_raw: str | None = None
    origin_host: str | None = None
    service: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    src_meta: dict[str, Any] = field(default_factory=dict)
    raw: str | None = None


@dataclass
class RawBatch:
    """Batch of raw records plus a truncation flag."""

    records: list[RawRecord]
    truncated: bool = False


@dataclass
class StepResult:
    """One step of a connectivity test (FR-208)."""

    name: str
    ok: bool
    message: str = ""


@dataclass
class TestResult:
    """Connectivity test outcome."""

    ok: bool
    message: str = ""
    steps: list[StepResult] = field(default_factory=list)


class Connector(ABC):
    """Read-only log source (FR-002). Mutating calls are forbidden."""

    name: str = "base"

    @abstractmethod
    def describe(self) -> dict[str, Any]:
        """Return the config schema and supported auth methods."""

    @abstractmethod
    async def test(self, profile: ConnectionProfile) -> TestResult:
        """Test connectivity without changing source state."""

    @abstractmethod
    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        """List selectable objects (files, units, containers, ...)."""

    @abstractmethod
    def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        """Yield raw batches; must never mutate the source."""

    def capabilities(self) -> dict[str, Any]:
        """Return connector capabilities (tail support, filters, ...)."""
        return {"tail": False, "time_pushdown": False}
