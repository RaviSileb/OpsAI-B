"""Tests for the local executor (subprocess, no PTY, no stdin)."""

from __future__ import annotations

from opsai.execution.base import ExecOptions
from opsai.execution.local_exec import LocalExecutor


def test_echo_succeeds() -> None:
    result = LocalExecutor().run("echo hello", "bash", {"host": "localhost"}, ExecOptions())
    assert result.exit_code == 0
    assert result.stdout.strip() == "hello"
    assert not result.timed_out


def test_exit_code_and_stderr() -> None:
    result = LocalExecutor().run(
        "echo oops >&2; exit 3", "bash", {"host": "localhost"}, ExecOptions()
    )
    assert result.exit_code == 3
    assert "oops" in result.stderr


def test_timeout_kills_and_flags() -> None:
    result = LocalExecutor().run("sleep 5", "bash", {"host": "localhost"}, ExecOptions(timeout_s=1))
    assert result.timed_out
    assert result.exit_code == 124


def test_big_output_truncated() -> None:
    result = LocalExecutor().run(
        "head -c 2000000 /dev/zero | tr '\\0' 'x'",
        "bash",
        {"host": "localhost"},
        ExecOptions(),
    )
    assert result.truncated
    assert "truncated" in result.stdout
