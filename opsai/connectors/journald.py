"""systemd journal connector via ``journalctl -o json`` (TZ FR-060..FR-061)."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from opsai.connectors.base import (
    ConnectionProfile,
    Connector,
    RawBatch,
    RawRecord,
    ReadQuery,
    StepResult,
    TestResult,
)
from opsai.connectors.registry import register

_JOURNAL_FIELDS = (
    "__REALTIME_TIMESTAMP,_HOSTNAME,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,PRIORITY,MESSAGE,"
    "_PID,_BOOT_ID,_COMM"
)


def _journalctl_binary() -> str:
    binary = shutil.which("journalctl")
    if binary is None:
        msg = "journalctl not found (Linux with systemd required)"
        raise RuntimeError(msg)
    return binary


def _build_command(config: dict[str, Any], query: ReadQuery) -> list[str]:
    cmd = [
        _journalctl_binary(),
        "-o",
        "json",
        f"--output-fields={_JOURNAL_FIELDS}",
        "--no-pager",
    ]
    unit = str(config.get("unit", "") or "").strip()
    if unit:
        cmd.extend(["-u", unit])
    priority = str(config.get("priority", "") or "").strip()
    if priority:
        cmd.extend(["-p", priority])
    if query.time_from:
        cmd.extend(["--since", query.time_from.isoformat()])
    if query.time_to:
        cmd.extend(["--until", query.time_to.isoformat()])
    if query.tail_lines is not None:
        cmd.extend(["-n", str(query.tail_lines)])
    return cmd


def _map_entry(entry: dict[str, Any]) -> RawRecord:
    ts: datetime | None = None
    raw_ts = entry.get("__REALTIME_TIMESTAMP")
    try:
        if raw_ts is not None:
            ts = datetime.fromtimestamp(int(raw_ts) / 1_000_000, tz=UTC)
    except (ValueError, TypeError, OverflowError, OSError):
        ts = None
    priority = entry.get("PRIORITY")
    try:
        level = int(priority) if priority is not None else None
    except (ValueError, TypeError):
        level = None
    message = str(entry.get("MESSAGE", ""))
    unit = entry.get("_SYSTEMD_UNIT") or entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")
    return RawRecord(
        message=message,
        ts=ts,
        ts_raw=str(raw_ts) if raw_ts is not None else None,
        level_raw=str(level) if level is not None else None,
        origin_host=entry.get("_HOSTNAME"),
        service=str(unit) if unit else None,
        fields={"pid": entry.get("_PID"), "boot_id": entry.get("_BOOT_ID")},
        src_meta={"unit": unit, "priority": level},
        raw=json.dumps(entry, ensure_ascii=False),
    )


@register
class JournaldConnector(Connector):
    """Read the local systemd journal (Linux only, read-only)."""

    name = "journald"

    def describe(self) -> dict[str, Any]:
        return {
            "config_schema": {
                "unit": "systemd unit filter, e.g. kafka.service (optional)",
                "priority": "priority filter, e.g. err (optional)",
            },
            "auth": [],
        }

    async def test(self, profile: ConnectionProfile) -> TestResult:
        binary = shutil.which("journalctl")
        steps = [StepResult("journalctl-present", binary is not None, binary or "not found")]
        if binary is None:
            return TestResult(False, "journalctl not found (Linux with systemd required)", steps)
        try:
            proc = subprocess.run(
                [binary, "-n", "1", "--no-pager", "-o", "cat"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            steps.append(StepResult("read-probe", False, str(exc)))
            return TestResult(False, str(exc), steps)
        ok = proc.returncode == 0
        steps.append(StepResult("read-probe", ok, proc.stderr.strip()[:300]))
        return TestResult(ok, "OK" if ok else proc.stderr.strip()[:300], steps)

    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        return [{"name": "system journal", "path": "journal"}]

    async def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        cmd = _build_command(profile.config, query)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"journalctl failed: {exc}") from exc
        if proc.returncode != 0:
            raise RuntimeError(f"journalctl failed: {proc.stderr.strip()[:500]}")
        batch: list[RawRecord] = []
        emitted = 0
        emitted_bytes = 0
        for line in proc.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            record = _map_entry(entry)
            cost = len(record.message.encode("utf-8", "replace"))
            if emitted >= query.limit_records or emitted_bytes + cost > query.limit_bytes:
                yield RawBatch(records=batch, truncated=True)
                return
            batch.append(record)
            emitted += 1
            emitted_bytes += cost
            if len(batch) >= 1000:
                yield RawBatch(records=batch)
                batch = []
        yield RawBatch(records=batch)

    def capabilities(self) -> dict[str, Any]:
        return {"tail": False, "time_pushdown": True}
