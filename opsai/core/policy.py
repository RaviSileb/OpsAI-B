"""Execution policy: deny list, environments, four-eyes, time windows (FR-540..544).

Policies are versioned (admin-only edits, every change audited with a diff).
Deny patterns are best-effort; human approval and local risk classification
stay the primary defense.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from croniter import croniter

_RISK_ORDER = {"read_only": 0, "change": 1, "destructive": 2}

DEFAULT_DENY_PATTERNS = [
    r"rm\s+-rf\s+/(\s|$)",
    r"\bmkfs\b",
    r"\bdd\s+if=.*of=/dev/",
    r":\(\)\s*\{",
    r"shutdown|reboot|halt|poweroff",
    r"iptables\s+-F",
    r"kubectl\s+delete\s+(ns|namespace|node|pv|crd)",
    r"kafka-topics.*--delete",
    r"kafka-delete-records",
    r"Remove-Item.*-Recurse.*[A-Z]:\\\s*$",
    r"Format-Volume",
    r"Stop-Computer|Restart-Computer",
    r"DROP\s+(DATABASE|TABLE)",
    r"\bTRUNCATE\b",
]

_CHAIN_PATTERNS = [r";", r"&&", r"\|\|", r"\$\(", r"`", r"\n"]


@dataclass
class PolicyDecision:
    """Result of evaluating one command against the policy."""

    allowed: bool
    reasons: list[str] = field(default_factory=list)
    requires_approval: bool = False


@dataclass
class ExecutionPolicy:
    """Versioned execution policy (FR-540)."""

    deny_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_DENY_PATTERNS))
    allow_only: list[str] | None = None
    env_max_risk: dict[str, str] = field(default_factory=dict)
    four_eyes_envs: list[str] = field(default_factory=lambda: ["prod"])
    four_eyes_risks: list[str] = field(default_factory=lambda: ["change", "destructive"])
    time_windows: list[str] = field(default_factory=list)
    timezone: str = "UTC"
    default_timeout_s: int = 300
    max_timeout_s: int = 3600
    allowed_executors: list[str] = field(default_factory=lambda: ["local", "ssh"])
    chain_allowlist: list[str] = field(default_factory=list)
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Serialize the policy to plain data."""
        return {
            "deny_patterns": list(self.deny_patterns),
            "allow_only": list(self.allow_only) if self.allow_only is not None else None,
            "env_max_risk": dict(self.env_max_risk),
            "four_eyes_envs": list(self.four_eyes_envs),
            "four_eyes_risks": list(self.four_eyes_risks),
            "time_windows": list(self.time_windows),
            "timezone": self.timezone,
            "default_timeout_s": self.default_timeout_s,
            "max_timeout_s": self.max_timeout_s,
            "allowed_executors": list(self.allowed_executors),
            "chain_allowlist": list(self.chain_allowlist),
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionPolicy:
        """Build a policy from plain data, validating patterns."""
        deny = [str(p) for p in data.get("deny_patterns", DEFAULT_DENY_PATTERNS)]
        allow = data.get("allow_only")
        chains = [str(p) for p in data.get("chain_allowlist", [])]
        for pattern in [*deny, *(allow or []), *chains]:
            try:
                re.compile(pattern)
            except re.error as exc:
                msg = f"Invalid regex {pattern!r}: {exc}"
                raise ValueError(msg) from exc
        max_risk = {str(k): str(v) for k, v in data.get("env_max_risk", {}).items()}
        for risk in max_risk.values():
            if risk not in _RISK_ORDER:
                msg = f"Unknown risk level {risk!r} in env_max_risk"
                raise ValueError(msg)
        windows = [str(w) for w in data.get("time_windows", [])]
        for window in windows:
            if not croniter.is_valid(window):
                msg = f"Invalid cron window {window!r}"
                raise ValueError(msg)
        return cls(
            deny_patterns=deny,
            allow_only=[str(p) for p in allow] if allow is not None else None,
            env_max_risk=max_risk,
            four_eyes_envs=[str(e) for e in data.get("four_eyes_envs", ["prod"])],
            four_eyes_risks=[
                str(r) for r in data.get("four_eyes_risks", ["change", "destructive"])
            ],
            time_windows=windows,
            timezone=str(data.get("timezone", "UTC")),
            default_timeout_s=int(data.get("default_timeout_s", 300)),
            max_timeout_s=int(data.get("max_timeout_s", 3600)),
            allowed_executors=[str(e) for e in data.get("allowed_executors", ["local", "ssh"])],
            chain_allowlist=chains,
            version=int(data.get("version", 1)),
        )

    def evaluate(
        self,
        command: str,
        risk: str,
        environment: str,
        executor: str,
        now: datetime | None = None,
    ) -> PolicyDecision:
        """Evaluate one command; unknown risks fail up to ``change``."""
        reasons: list[str] = []
        ranked = _RISK_ORDER.get(risk, 1)
        if executor not in self.allowed_executors:
            reasons.append(f"Executor {executor!r} is not allowed")
        for pattern in self.deny_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                reasons.append(f"Blocked by deny pattern: {pattern}")
        if self.allow_only is not None and not any(
            re.search(pattern, command) for pattern in self.allow_only
        ):
            reasons.append("Command is not on the allow-only list")
        cap = self.env_max_risk.get(environment)
        if cap is not None and ranked > _RISK_ORDER[cap]:
            reasons.append(f"Risk {risk!r} exceeds {cap!r} allowed in {environment!r}")
        chain_reason = self._check_chaining(command)
        if chain_reason:
            reasons.append(chain_reason)
        if self.time_windows and not self._inside_window(now):
            reasons.append("Outside execution time windows")
        requires_approval = risk in self.four_eyes_risks and environment in self.four_eyes_envs
        return PolicyDecision(
            allowed=not reasons, reasons=reasons, requires_approval=requires_approval
        )

    def _check_chaining(self, command: str) -> str:
        for pattern in _CHAIN_PATTERNS:
            if not re.search(pattern, command):
                continue
            if any(re.search(allowed, command) for allowed in self.chain_allowlist):
                continue
            return f"Blocked command chaining: {pattern!r}"
        return ""

    def _inside_window(self, now: datetime | None) -> bool:
        moment = now or datetime.now(ZoneInfo(self.timezone))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=ZoneInfo(self.timezone))
        floored = moment.replace(second=0, microsecond=0, tzinfo=None)
        for window in self.time_windows:
            # A window matches when the schedule fires in the current minute.
            probe = croniter(window, floored - timedelta(minutes=1)).get_next(datetime)
            if probe == floored:
                return True
        return False


class PolicyStore:
    """Versioned policy persistence (admin-only writes, audited by callers)."""

    def __init__(self, app_db: Path) -> None:
        self.app_db = app_db

    def get_execution(self) -> ExecutionPolicy:
        """Return the execution policy, default when never saved."""
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT definition, version FROM policies WHERE id = 'execution-default'"
            ).fetchone()
        if row is None:
            return ExecutionPolicy()
        data = json.loads(row[0])
        data["version"] = int(row[1])
        return ExecutionPolicy.from_dict(data)

    def save_execution(self, policy: ExecutionPolicy) -> ExecutionPolicy:
        """Save the policy with a bumped version; return the stored policy."""
        stored = self.get_execution()
        policy.version = stored.version + 1 if self._exists() else 1
        updated = datetime.now(UTC).isoformat()
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "INSERT INTO policies (id, type, definition, version, updated_at)"
                " VALUES ('execution-default', 'execution', ?, ?, ?)"
                " ON CONFLICT(id) DO UPDATE SET definition = excluded.definition,"
                " version = excluded.version, updated_at = excluded.updated_at",
                (json.dumps(policy.to_dict()), policy.version, updated),
            )
            conn.commit()
        return policy

    def _exists(self) -> bool:
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute("SELECT 1 FROM policies WHERE id = 'execution-default'").fetchone()
        return row is not None
