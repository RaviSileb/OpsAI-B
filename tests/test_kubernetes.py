"""Kubernetes connector tests: unit + live minikube (skipped without cluster)."""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from opsai.connectors.base import ConnectionProfile, ReadQuery
from opsai.connectors.kubernetes import (
    KubernetesConnector,
    load_kubeconfig,
    parse_log_line,
    resolve_target,
)

NAMESPACE = "opsai-test"
POD = "opsai-loggen"
LABEL = "app=opsai-loggen"

POD_MANIFEST = """\
apiVersion: v1
kind: Pod
metadata:
  name: opsai-loggen
  namespace: opsai-test
  labels:
    app: opsai-loggen
spec:
  restartPolicy: Never
  containers:
    - name: gen
      image: busybox:1.36
      command:
        - sh
        - -c
        - >-
          i=1;
          while [ $i -le 20 ]; do
            echo "event $i";
            i=$((i+1));
            sleep 0.2;
          done;
          sleep 600
"""


def _kubectl(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["kubectl", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def cluster_available() -> bool:
    """Return True when kubectl talks to a cluster."""
    if shutil.which("kubectl") is None:
        return False
    try:
        proc = _kubectl("cluster-info", "--request-timeout=5s", timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _profile(**overrides: Any) -> ConnectionProfile:
    config: dict[str, Any] = {"namespace": NAMESPACE, "selector": LABEL}
    config.update(overrides)
    return ConnectionProfile(id="k8s", name="k8s", connector_type="kubernetes", config=config)


@pytest.fixture(scope="module")
def loggen() -> Iterator[None]:
    """Deploy the log-generator pod; skip everything without a cluster."""
    if not cluster_available():
        pytest.skip("no kubernetes cluster")
    _kubectl("create", "namespace", NAMESPACE, timeout=30)
    proc = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=POD_MANIFEST,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    proc = _kubectl(
        "wait",
        "--for=condition=Ready",
        "-n",
        NAMESPACE,
        f"pod/{POD}",
        "--timeout=180s",
        timeout=200,
    )
    assert proc.returncode == 0, proc.stderr
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        proc = _kubectl("logs", "-n", NAMESPACE, POD, "--tail=25", timeout=30)
        if proc.returncode == 0 and "event 20" in proc.stdout:
            break
        time.sleep(2)
    else:
        raise TimeoutError("loggen pod did not finish logging")
    yield None
    _kubectl("delete", "namespace", NAMESPACE, "--wait=true", timeout=120)


async def test_test_and_browse(loggen: None) -> None:
    _ = loggen
    connector = KubernetesConnector()
    result = await connector.test(_profile())
    assert result.ok, result.message
    namespaces = await connector.browse(_profile())
    assert any(item["name"] == NAMESPACE for item in namespaces)
    pods = await connector.browse(_profile(), NAMESPACE)
    assert any(item["name"] == POD for item in pods)
    containers = await connector.browse(_profile(), f"{NAMESPACE}/{POD}")
    assert [c["name"] for c in containers] == ["gen"]


async def test_read_pod_logs(loggen: None) -> None:
    _ = loggen
    connector = KubernetesConnector()
    records = []
    async for batch in connector.read(_profile(), ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 20
    first = records[0]
    assert first.service == "gen"
    assert first.fields["pod"] == POD
    assert first.fields["namespace"] == NAMESPACE
    assert first.fields["container"] == "gen"
    assert first.fields["labels"]["app"] == "opsai-loggen"
    assert first.origin_host == "minikube"
    assert first.ts is not None
    assert any("event 1" in r.message for r in records)


async def test_read_respects_record_limit(loggen: None) -> None:
    _ = loggen
    connector = KubernetesConnector()
    batches = [b async for b in connector.read(_profile(), ReadQuery(limit_records=3))]
    assert sum(len(b.records) for b in batches) == 3
    assert batches[-1].truncated


async def test_read_single_pod_and_time_range(loggen: None) -> None:
    _ = loggen
    connector = KubernetesConnector()
    profile = _profile(pod=POD)
    probe = []
    async for batch in connector.read(profile, ReadQuery(limit_records=20)):
        probe.extend(batch.records)
    assert probe, "expected log lines from the single pod"
    newest = max(r.ts for r in probe if r.ts is not None)
    assert newest is not None
    from datetime import timedelta

    since = newest - timedelta(minutes=5)
    records = []
    async for batch in connector.read(profile, ReadQuery(time_from=since, limit_records=100)):
        records.extend(batch.records)
    assert records
    assert all(r.ts is None or r.ts >= since for r in records)


def test_parse_log_line_unit() -> None:
    ts, message = parse_log_line("2026-10-27T10:00:00.123456789Z hello world")
    assert ts == datetime(2026, 10, 27, 10, 0, 0, 123456, tzinfo=UTC)
    assert message == "hello world"
    ts, message = parse_log_line("no timestamp here")
    assert ts is None
    assert message == "no timestamp here"


def test_kubeconfig_token_user(tmp_path: Path) -> None:
    kubeconfig = {
        "current-context": "ctx",
        "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "u"}}],
        "clusters": [{"name": "c", "cluster": {"server": "https://k8s:6443"}}],
        "users": [{"name": "u", "user": {"token": "s3cret"}}],
    }
    path = tmp_path / "kubeconfig"
    path.write_text(yaml.safe_dump(kubeconfig))
    target = load_kubeconfig(path)
    assert target.api_url == "https://k8s:6443"
    assert target.token == "s3cret"
    assert target.verify is True


def test_kubeconfig_exec_rejected(tmp_path: Path) -> None:
    kubeconfig = {
        "current-context": "ctx",
        "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "u"}}],
        "clusters": [{"name": "c", "cluster": {"server": "https://k8s:6443"}}],
        "users": [{"name": "u", "user": {"exec": {"command": "aws"}}}],
    }
    path = tmp_path / "kubeconfig"
    path.write_text(yaml.safe_dump(kubeconfig))
    with pytest.raises(ValueError, match="exec plugin"):
        load_kubeconfig(path)


def test_kubeconfig_missing_context(tmp_path: Path) -> None:
    path = tmp_path / "kubeconfig"
    path.write_text(yaml.safe_dump({"current-context": "nope", "contexts": []}))
    with pytest.raises(ValueError, match="not found"):
        load_kubeconfig(path)


def test_resolve_explicit_target(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("file-token\n")
    profile = ConnectionProfile(
        id="k",
        name="k",
        connector_type="kubernetes",
        config={
            "api_url": "https://k8s:6443/",
            "token_file": str(token_file),
            "verify_tls": False,
        },
    )
    target = resolve_target(profile)
    assert target.api_url == "https://k8s:6443"
    assert target.token == "file-token"
    assert target.verify is False
