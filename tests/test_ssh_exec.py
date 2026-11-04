"""Tests for the SSH executor argv (OpenSSH CLI, stubbed binary)."""

from __future__ import annotations

from pathlib import Path

from opsai.execution.base import ExecOptions
from opsai.execution.ssh_exec import SshExecutor, build_ssh_argv


def _stub_ssh(tmp_path: Path, body: str) -> str:
    script = tmp_path / "ssh"
    script.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def test_argv_hardening_and_quoting(tmp_path: Path) -> None:
    stub = _stub_ssh(tmp_path, "exit 0")
    argv = build_ssh_argv(
        "echo 'a  b' && id",
        "bash",
        {
            "host": "db-01",
            "user": "ops",
            "port": 2222,
            "key_file": "/tmp/k",
            "jump": ["ops@jump-1"],
            "known_hosts": "/tmp/kh",
        },
        ExecOptions(timeout_s=60),
        ssh_binary=stub,
    )
    assert argv[0] == stub
    assert "-o" in argv and "BatchMode=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "UserKnownHostsFile=/tmp/kh" in argv
    assert argv[argv.index("-J") + 1] == "ops@jump-1"
    assert argv[argv.index("-p") + 1] == "2222"
    assert argv[argv.index("-i") + 1] == "/tmp/k"
    assert argv[-3:] == ["bash", "-c", "'echo '\"'\"'a  b'\"'\"' && id'"]
    assert "ops@db-01" in argv


def test_missing_host_rejected(tmp_path: Path) -> None:
    stub = _stub_ssh(tmp_path, "exit 0")
    try:
        build_ssh_argv("id", "bash", {}, ExecOptions(), ssh_binary=stub)
    except ValueError as exc:
        assert "host" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_run_uses_stub_and_reports_exit(tmp_path: Path) -> None:
    stub = _stub_ssh(tmp_path, 'echo "stub-out"; echo "stub-err" >&2; exit 7')
    result = SshExecutor(ssh_binary=stub).run("id", "bash", {"host": "h"}, ExecOptions())
    assert result.exit_code == 7
    assert "stub-out" in result.stdout
    assert "stub-err" in result.stderr
    assert not result.timed_out


def test_run_as_adds_sudo(tmp_path: Path) -> None:
    stub = _stub_ssh(tmp_path, "exit 0")
    argv = build_ssh_argv("id", "bash", {"host": "h"}, ExecOptions(run_as="app"), ssh_binary=stub)
    assert "sudo" in argv
    assert argv[argv.index("sudo") + 1 : argv.index("sudo") + 3] == ["-n", "-u"]
