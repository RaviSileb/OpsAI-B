"""Host inventory with target resolution (TZ FR-510, FR-512).

Resolution order: exact ``hostname``, ``aliases``, ``fqdn``, short name,
``ip_addresses``. Zero or ambiguous matches force an explicit choice;
candidates from mixed environments always force one too.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opsai.db.models import HostRecord


@dataclass
class HostCandidate:
    """One inventory candidate for a target string."""

    host: HostRecord
    rule: str


@dataclass
class TargetResolution:
    """Outcome of resolving one target string."""

    candidates: list[HostCandidate] = field(default_factory=list)
    environments_mixed: bool = False

    @property
    def decision(self) -> str:
        """Return ``single``, ``none`` or ``choose``."""
        if len(self.candidates) == 1 and not self.environments_mixed:
            return "single"
        if not self.candidates:
            return "none"
        return "choose"

    @property
    def single(self) -> HostRecord | None:
        """Return the host when the decision is ``single``."""
        if self.decision == "single":
            return self.candidates[0].host
        return None


def _row_to_host(row: Any) -> HostRecord:
    return HostRecord(
        id=row[0],
        hostname=row[1],
        aliases=json.loads(row[2] or "[]"),
        fqdn=row[3] or "",
        ip_addresses=json.loads(row[4] or "[]"),
        environment=row[5] or "other",
        os=row[6] or "linux",
        executor_type=row[7] or "ssh",
        connection_profile_id=row[8] or "",
    )


class InventoryStore:
    """CRUD and resolution over the host inventory table."""

    def __init__(self, app_db: Path) -> None:
        self.app_db = app_db

    def add(self, host: HostRecord) -> HostRecord:
        """Insert a host, generating an id when empty."""
        host_id = host.id or uuid.uuid4().hex
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "INSERT INTO host_inventory (id, hostname, aliases, fqdn, ip_addresses,"
                " environment, os, executor_type, connection_profile_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    host_id,
                    host.hostname,
                    json.dumps(host.aliases),
                    host.fqdn,
                    json.dumps(host.ip_addresses),
                    host.environment,
                    host.os,
                    host.executor_type,
                    host.connection_profile_id,
                ),
            )
            conn.commit()
        host.id = host_id
        return host

    def get(self, host_id: str) -> HostRecord | None:
        """Return one host by id."""
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT id, hostname, aliases, fqdn, ip_addresses, environment, os,"
                " executor_type, connection_profile_id FROM host_inventory WHERE id = ?",
                (host_id,),
            ).fetchone()
        return _row_to_host(row) if row else None

    def update(self, host: HostRecord) -> HostRecord:
        """Replace a host record entirely."""
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "UPDATE host_inventory SET hostname = ?, aliases = ?, fqdn = ?,"
                " ip_addresses = ?, environment = ?, os = ?, executor_type = ?,"
                " connection_profile_id = ? WHERE id = ?",
                (
                    host.hostname,
                    json.dumps(host.aliases),
                    host.fqdn,
                    json.dumps(host.ip_addresses),
                    host.environment,
                    host.os,
                    host.executor_type,
                    host.connection_profile_id,
                    host.id,
                ),
            )
            conn.commit()
        return host

    def remove(self, host_id: str) -> None:
        """Delete a host record."""
        with sqlite3.connect(self.app_db) as conn:
            conn.execute("DELETE FROM host_inventory WHERE id = ?", (host_id,))
            conn.commit()

    def list_hosts(self) -> list[HostRecord]:
        """List all hosts ordered by hostname."""
        with sqlite3.connect(self.app_db) as conn:
            rows = conn.execute(
                "SELECT id, hostname, aliases, fqdn, ip_addresses, environment, os,"
                " executor_type, connection_profile_id FROM host_inventory"
                " ORDER BY hostname ASC"
            ).fetchall()
        return [_row_to_host(row) for row in rows]

    def resolve(self, target: str) -> TargetResolution:
        """Resolve a target string to inventory candidates (FR-510)."""
        needle = target.strip().lower()
        if not needle:
            return TargetResolution()
        short = needle.split(".", 1)[0]
        candidates: list[HostCandidate] = []
        for host in self.list_hosts():
            rule = self._match_rule(host, needle, short)
            if rule:
                candidates.append(HostCandidate(host=host, rule=rule))
        envs = {c.host.environment for c in candidates}
        return TargetResolution(candidates=candidates, environments_mixed=len(envs) > 1)

    @staticmethod
    def _match_rule(host: HostRecord, needle: str, short: str) -> str:
        if host.hostname.lower() == needle:
            return "hostname"
        if needle in {a.lower() for a in host.aliases}:
            return "alias"
        if host.fqdn and host.fqdn.lower() == needle:
            return "fqdn"
        host_short = host.hostname.lower().split(".", 1)[0]
        if host_short and host_short == short:
            return "short-name"
        if host.fqdn:
            fqdn_short = host.fqdn.lower().split(".", 1)[0]
            if fqdn_short and fqdn_short == short:
                return "short-name"
        if needle in {ip.lower() for ip in host.ip_addresses}:
            return "ip"
        return ""
