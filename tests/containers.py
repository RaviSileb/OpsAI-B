"""Docker test-container helpers (tests skip when docker is missing)."""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from collections.abc import Callable


def docker_available() -> bool:
    """Return True when the docker CLI exists and the daemon answers."""
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


class Container:
    """One throwaway container with explicit cleanup."""

    def __init__(
        self,
        image: str,
        ports: dict[int, int] | None = None,
        env: dict[str, str] | None = None,
        args: list[str] | None = None,
        volumes: dict[str, str] | None = None,
    ) -> None:
        self.image = image
        self.ports = ports or {}
        self.env = env or {}
        self.args = args or []
        self.volumes = volumes or {}
        self.name = f"opsai-test-{uuid.uuid4().hex[:12]}"
        self.started = False

    def start(self) -> Container:
        """Start the container detached."""
        cmd = ["docker", "run", "-d", "--name", self.name]
        for host_port, container_port in self.ports.items():
            cmd.extend(["-p", f"127.0.0.1:{host_port}:{container_port}"])
        for key, value in self.env.items():
            cmd.extend(["-e", f"{key}={value}"])
        for host_path, container_path in self.volumes.items():
            cmd.extend(["-v", f"{host_path}:{container_path}:ro"])
        cmd.append(self.image)
        # Container command args go after the image (docker flags would
        # misparse them, e.g. -config.file as -c cpu-shares).
        cmd.extend(self.args)
        subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=True)
        self.started = True
        return self

    def stop(self) -> None:
        """Force-remove the container (missing containers are ignored)."""
        if not self.started:
            return
        subprocess.run(
            ["docker", "rm", "-f", self.name],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.started = False

    def wait_for(self, ready: Callable[[], bool], timeout: float = 120.0) -> None:
        """Poll ``ready`` until True or the timeout expires."""
        deadline = time.monotonic() + timeout
        last_error = ""
        while time.monotonic() < deadline:
            try:
                if ready():
                    return
            except Exception as exc:
                last_error = str(exc)
            time.sleep(1.0)
        msg = f"Container {self.name} ({self.image}) not ready in time: {last_error}"
        raise TimeoutError(msg)

    def logs(self) -> str:
        """Return recent container logs for failure diagnosis."""
        proc = subprocess.run(
            ["docker", "logs", "--tail", "50", self.name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return proc.stdout + proc.stderr
