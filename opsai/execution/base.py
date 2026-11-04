"""Executor interface: one command, one result, no interaction (TZ 11.1)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

MAX_STREAM_BYTES = 1_000_000


@dataclass
class ExecOptions:
    """Execution options for one step."""

    timeout_s: int = 300
    run_as: str = ""
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class ExecResult:
    """Completed command outcome (FR-529: streams capped at 1 MB)."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False


def truncate_stream(text: str, limit: int = MAX_STREAM_BYTES) -> tuple[str, bool]:
    """Cap a stream at ``limit`` bytes, keeping head and tail."""
    raw = text.encode("utf-8", "replace")
    if len(raw) <= limit:
        return text, False
    head = raw[: limit * 3 // 4].decode("utf-8", "replace")
    tail = raw[-limit // 4 :].decode("utf-8", "replace")
    note = f"\n...[truncated {len(raw)} bytes total]...\n"
    return head + note + tail, True


class Executor(ABC):
    """One transport executing single commands without a PTY (CON-106)."""

    name: str = "base"
    shells: set[str] = set()

    @abstractmethod
    def run(
        self, command: str, shell: str, target: dict[str, Any], options: ExecOptions
    ) -> ExecResult:
        """Run one command on the target and return its result."""
