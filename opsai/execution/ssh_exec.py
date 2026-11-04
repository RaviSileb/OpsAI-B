"""SSH executor via the OpenSSH CLI (key auth, jump hosts, strict host keys).

MVP transport decision: the CLI instead of asyncssh, so host-key handling and
jump chains reuse the operator's existing OpenSSH setup. Batch mode forbids
password prompts; insecure host-key modes are not offered.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from opsai.execution.base import ExecOptions, ExecResult, Executor, truncate_stream


def build_ssh_argv(
    command: str,
    shell: str,
    target: dict[str, Any],
    options: ExecOptions,
    ssh_binary: str | None = None,
) -> list[str]:
    """Build the ``ssh`` argument vector (no shell, no password prompts)."""
    binary = ssh_binary or shutil.which("ssh")
    if binary is None:
        msg = "OpenSSH client (ssh) not found in PATH"
        raise RuntimeError(msg)
    host = str(target.get("host", "") or "").strip()
    if not host:
        msg = "SSH target needs 'host'"
        raise ValueError(msg)
    user = str(target.get("user", "") or "").strip()
    port = target.get("port")
    key_file = str(target.get("key_file", "") or "").strip()
    known_hosts = str(target.get("known_hosts", "") or "").strip() or str(
        Path.home() / ".ssh" / "known_hosts"
    )
    jumps = [str(j).strip() for j in target.get("jump", []) if str(j).strip()]
    connect_timeout = min(30, max(5, options.timeout_s))
    argv = [
        binary,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-p",
        str(port or 22),
    ]
    if key_file:
        argv.extend(["-i", key_file])
    if jumps:
        argv.extend(["-J", ",".join(jumps)])
    destination = f"{user}@{host}" if user else host
    shell_word = "bash" if shell == "bash" else "sh"
    if options.run_as:
        argv.extend([destination, "sudo", "-n", "-u", options.run_as, shell_word, "-c", command])
    else:
        argv.extend([destination, shell_word, "-c", command])
    # Quote the remote command so the remote shell gets exactly one script.
    argv[-1] = shlex.quote(command)
    return argv


class SshExecutor(Executor):
    """Run commands over SSH with the system OpenSSH client."""

    name = "ssh"
    shells = {"bash", "sh"}

    def __init__(self, ssh_binary: str | None = None) -> None:
        self.ssh_binary = ssh_binary

    def run(
        self, command: str, shell: str, target: dict[str, Any], options: ExecOptions
    ) -> ExecResult:
        argv = build_ssh_argv(command, shell, target, options, self.ssh_binary)
        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=options.timeout_s,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            stdout, _ = truncate_stream(stdout or "")
            stderr, _ = truncate_stream(stderr or "")
            return ExecResult(
                exit_code=124, stdout=stdout, stderr=stderr, duration_ms=duration_ms, timed_out=True
            )
        except OSError as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            return ExecResult(exit_code=127, stdout="", stderr=str(exc), duration_ms=duration_ms)
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout, cut_out = truncate_stream(proc.stdout)
        stderr, cut_err = truncate_stream(proc.stderr)
        return ExecResult(
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            truncated=cut_out or cut_err,
        )
