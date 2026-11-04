"""Docker/Podman connector via container CLI (TZ FR-070..FR-072, MVP form).

Uses the ``docker`` (or ``podman``) CLI over the local socket. Remote access
over SSH and TLS stays a documented next step.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
from collections.abc import AsyncIterator
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
from opsai.core.normalize import parse_timestamp

_TS_LINE_RE = re.compile(r"^(\S+)\s(.*)$", re.DOTALL)


def _cli_binary(config: dict[str, Any]) -> str:
    preferred = str(config.get("cli", "docker") or "docker")
    if preferred not in {"docker", "podman"}:
        preferred = "docker"
    for candidate in (preferred, "podman" if preferred == "docker" else "docker"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    msg = "Neither docker nor podman CLI was found in PATH"
    raise RuntimeError(msg)


def _cli_label(config: dict[str, Any]) -> str:
    preferred = str(config.get("cli", "docker") or "docker")
    return preferred if preferred in {"docker", "podman"} else "docker"


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


@register
class DockerConnector(Connector):
    """Read container logs locally (read-only ``logs``/``ps``/``info`` only)."""

    name = "docker"

    def describe(self) -> dict[str, Any]:
        return {
            "config_schema": {
                "cli": "docker|podman (default docker)",
                "container": "container name or id (required for read)",
            },
            "auth": [],
        }

    async def test(self, profile: ConnectionProfile) -> TestResult:
        label = _cli_label(profile.config)
        try:
            binary = _cli_binary(profile.config)
        except RuntimeError:
            steps = [StepResult(f"{label}-present", False, "not found")]
            return TestResult(False, f"{label} CLI not found", steps)
        steps = [StepResult(f"{label}-present", True, binary)]
        try:
            proc = _run([binary, "info", "--format", "{{.Name}}"], timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            steps.append(StepResult("daemon-probe", False, str(exc)))
            return TestResult(False, str(exc), steps)
        ok = proc.returncode == 0
        steps.append(StepResult("daemon-probe", ok, (proc.stdout or proc.stderr).strip()[:300]))
        return TestResult(ok, "OK" if ok else proc.stderr.strip()[:300], steps)

    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        label = _cli_label(profile.config)
        binary = _cli_binary(profile.config)
        proc = _run([binary, "ps", "-a", "--format", "{{json .}}"], timeout=30)
        if proc.returncode != 0:
            raise RuntimeError(f"{label} ps failed: {proc.stderr.strip()[:300]}")
        items: list[dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            items.append(
                {
                    "name": entry.get("Names", entry.get("ID", "?")),
                    "path": entry.get("ID", ""),
                    "size": 0,
                    "image": entry.get("Image", ""),
                    "state": entry.get("State", ""),
                }
            )
        return items

    async def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        label = _cli_label(profile.config)
        binary = _cli_binary(profile.config)
        container = str(profile.config.get("container", "") or "").strip()
        if not container:
            msg = "Docker connector requires config.container"
            raise ValueError(msg)
        cmd = [binary, "logs", "--timestamps"]
        if query.time_from:
            cmd.extend(["--since", query.time_from.isoformat()])
        if query.time_to:
            cmd.extend(["--until", query.time_to.isoformat()])
        cmd.extend(["--tail", str(query.tail_lines or "all"), container])
        try:
            proc = _run(cmd, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"{label} logs failed: {exc}") from exc
        if proc.returncode != 0:
            raise RuntimeError(f"{label} logs failed: {proc.stderr.strip()[:500]}")
        try:
            host = socket.gethostname()
        except OSError:
            host = "docker-host"
        batch: list[RawRecord] = []
        emitted = 0
        emitted_bytes = 0
        for line in (proc.stdout + "\n" + proc.stderr).splitlines():
            if not line.strip():
                continue
            match = _TS_LINE_RE.match(line)
            ts_raw, message = (match.group(1), match.group(2)) if match else (None, line)
            ts = parse_timestamp(ts_raw) if ts_raw else None
            cost = len(message.encode("utf-8", "replace"))
            if emitted >= query.limit_records or emitted_bytes + cost > query.limit_bytes:
                yield RawBatch(records=batch, truncated=True)
                return
            batch.append(
                RawRecord(
                    message=message,
                    ts=ts,
                    ts_raw=ts_raw,
                    origin_host=host,
                    service=container,
                    src_meta={"container": container, "cli": label},
                    raw=line,
                )
            )
            emitted += 1
            emitted_bytes += cost
            if len(batch) >= 1000:
                yield RawBatch(records=batch)
                batch = []
        yield RawBatch(records=batch)

    def capabilities(self) -> dict[str, Any]:
        return {"tail": False, "time_pushdown": True}
