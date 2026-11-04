"""Local executor: subprocess on the OpsAI host (desktop only).

Enabled only with ``OPSAI_LOCAL_EXEC_ENABLED=true``. Commands run without a
PTY and without stdin; ``run_as`` other than the current user needs
non-interactive ``sudo -n``.
"""

from __future__ import annotations

import getpass
import os
import subprocess
import time
from typing import Any

from opsai.execution.base import ExecOptions, ExecResult, Executor, truncate_stream


class LocalExecutor(Executor):
    """Run commands in a local subprocess."""

    name = "local"
    shells = {"bash", "sh"}

    def run(
        self, command: str, shell: str, target: dict[str, Any], options: ExecOptions
    ) -> ExecResult:
        _ = target
        shell_bin = "/bin/bash" if shell == "bash" else "/bin/sh"
        argv = [shell_bin, "-c", command]
        if options.run_as and options.run_as != getpass.getuser():
            argv = ["sudo", "-n", "-u", options.run_as, *argv]
        env = {"LANG": "C.UTF-8", "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        env.update(options.env)
        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=options.timeout_s,
                stdin=subprocess.DEVNULL,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            stdout, _ = truncate_stream(
                exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            )
            stderr, _ = truncate_stream(
                exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            )
            return ExecResult(
                exit_code=124, stdout=stdout, stderr=stderr, duration_ms=duration_ms, timed_out=True
            )
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
