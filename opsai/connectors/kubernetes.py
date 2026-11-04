"""Kubernetes connector: read-only pod logs over the REST API (no watch)."""

from __future__ import annotations

import base64
import os
import ssl
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml
from dateutil.parser import isoparse

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

_DEFAULT_TIMEOUT = 30.0
_DEFAULT_TAIL_LINES = 5000


@dataclass
class KubeTarget:
    """Resolved cluster endpoint plus auth material."""

    api_url: str
    token: str | None = None
    ca_cert: str | Path | None = None
    verify: bool | str = True
    client_cert: str | None = None
    client_key: str | None = None


def load_kubeconfig(path: str | Path, context_name: str | None = None) -> KubeTarget:
    """Resolve api_url/token/CA from a kubeconfig file (no exec plugins)."""
    kube_path = Path(path).expanduser()
    if not kube_path.is_file():
        msg = f"kubeconfig not found: {kube_path}"
        raise ValueError(msg)
    with kube_path.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict):
        msg = f"invalid kubeconfig: {kube_path}"
        raise ValueError(msg)
    current = context_name or config.get("current-context")
    contexts = {c["name"]: c["context"] for c in config.get("contexts", []) if "name" in c}
    if current not in contexts:
        msg = f"kubeconfig context {current!r} not found in {kube_path}"
        raise ValueError(msg)
    context = contexts[current]
    clusters = {c["name"]: c["cluster"] for c in config.get("clusters", []) if "name" in c}
    users = {u["name"]: u["user"] for u in config.get("users", []) if "name" in u}
    cluster = clusters.get(context.get("cluster", ""))
    user = users.get(context.get("user", ""), {})
    if not cluster or not cluster.get("server"):
        msg = f"kubeconfig context {current!r} has no cluster server"
        raise ValueError(msg)
    if user.get("exec"):
        msg = (
            f"kubeconfig user for context {current!r} uses an exec plugin, "
            "which OpsAI does not run; use a static token instead"
        )
        raise ValueError(msg)
    verify: bool | str = True
    ca_cert: str | Path | None = None
    if cluster.get("certificate-authority-data"):
        ca_cert = _write_temp_ca(cluster["certificate-authority-data"], kube_path)
        verify = str(ca_cert)
    elif cluster.get("certificate-authority"):
        ca_path = Path(cluster["certificate-authority"])
        if not ca_path.is_absolute():
            ca_path = kube_path.parent / ca_path
        ca_cert = ca_path
        verify = str(ca_path)
    elif cluster.get("insecure-skip-tls-verify"):
        verify = False
    token = user.get("token")
    if not token and user.get("tokenFile"):
        token_path = Path(user["tokenFile"]).expanduser()
        token = token_path.read_text(encoding="utf-8").strip()
    client_cert: str | None = None
    client_key: str | None = None
    if user.get("client-certificate-data") and user.get("client-key-data"):
        client_cert = str(_write_temp_pem(user["client-certificate-data"], kube_path, "client.crt"))
        client_key = str(_write_temp_pem(user["client-key-data"], kube_path, "client.key"))
    elif user.get("client-certificate") or user.get("client-key"):
        client_cert = str(_resolve_kube_path(user.get("client-certificate", ""), kube_path))
        client_key = str(_resolve_kube_path(user.get("client-key", ""), kube_path))
    return KubeTarget(
        api_url=str(cluster["server"]).rstrip("/"),
        token=str(token) if token else None,
        ca_cert=ca_cert,
        verify=verify,
        client_cert=client_cert,
        client_key=client_key,
    )


def _write_temp_ca(data_b64: str, kube_path: Path) -> Path:
    """Materialize embedded CA bytes next to the kubeconfig (0600)."""
    raw = base64.b64decode(data_b64)
    ca_path = kube_path.parent / f".{kube_path.stem}-ca.crt"
    if not ca_path.exists() or ca_path.read_bytes() != raw:
        ca_path.write_bytes(raw)
        os.chmod(ca_path, 0o600)
    return ca_path


def resolve_target(profile: ConnectionProfile) -> KubeTarget:
    """Resolve the API target from explicit config or kubeconfig."""
    config = profile.config
    if config.get("api_url"):
        verify_cfg = config.get("verify_tls", True)
        verify: bool | str = verify_cfg if isinstance(verify_cfg, str) else bool(verify_cfg)
        ca = config.get("ca_cert")
        if ca:
            verify = str(ca)
        token = config.get("token")
        if not token and config.get("token_file"):
            token = Path(str(config["token_file"])).expanduser().read_text(encoding="utf-8").strip()
        client_cert = config.get("client_cert")
        client_key = config.get("client_key")
        return KubeTarget(
            api_url=str(config["api_url"]).rstrip("/"),
            token=str(token) if token else None,
            ca_cert=str(ca) if ca else None,
            verify=verify,
            client_cert=str(client_cert) if client_cert else None,
            client_key=str(client_key) if client_key else None,
        )
    kube_path = config.get("kubeconfig", "~/.kube/config")
    return load_kubeconfig(str(kube_path), config.get("context"))


def _write_temp_pem(data_b64: str, kube_path: Path, suffix: str) -> Path:
    """Materialize embedded PEM bytes next to the kubeconfig (0600)."""
    raw = base64.b64decode(data_b64)
    pem_path = kube_path.parent / f".{kube_path.stem}-{suffix}"
    if not pem_path.exists() or pem_path.read_bytes() != raw:
        pem_path.write_bytes(raw)
        os.chmod(pem_path, 0o600)
    return pem_path


def _resolve_kube_path(value: str, kube_path: Path) -> Path:
    """Resolve a kubeconfig-relative file reference."""
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = kube_path.parent / candidate
    return candidate


def _ssl_context(target: KubeTarget) -> ssl.SSLContext:
    """Build the TLS context (httpx ignores cert when verify is a path)."""
    if target.verify is False:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif isinstance(target.verify, str):
        context = ssl.create_default_context(cafile=target.verify)
    else:
        context = ssl.create_default_context()
    if target.client_cert and target.client_key:
        context.load_cert_chain(target.client_cert, target.client_key)
    return context


def _client(target: KubeTarget, timeout: float) -> httpx.AsyncClient:
    headers: dict[str, str] = {"Accept": "application/json"}
    if target.token:
        headers["Authorization"] = f"Bearer {target.token}"
    return httpx.AsyncClient(
        base_url=target.api_url,
        headers=headers,
        verify=_ssl_context(target),
        timeout=timeout,
    )


def parse_log_line(line: str) -> tuple[datetime | None, str]:
    """Split a `timestamps=true` log line into (ts, message)."""
    text = line.rstrip("\n")
    head, _, rest = text.partition(" ")
    try:
        ts = isoparse(head)
    except ValueError:
        return None, text
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts, rest


@register
class KubernetesConnector(Connector):
    """Read pod logs via GET only (list pods, fetch /log); nothing is created."""

    name = "kubernetes"

    def describe(self) -> dict[str, Any]:
        return {
            "config_schema": {
                "api_url": "API server URL (or kubeconfig + context)",
                "kubeconfig": "kubeconfig path (default ~/.kube/config)",
                "context": "kubeconfig context (default current-context)",
                "token": "bearer token (prefer credential store / token_file)",  # nosec B105 - config key name, not a secret
                "token_file": "path to file with the bearer token",  # nosec B105 - config key name, not a secret
                "ca_cert": "CA bundle path (default from kubeconfig)",
                "client_cert": "client certificate path (mTLS users)",
                "client_key": "client key path (mTLS users)",
                "verify_tls": "verify TLS certificates (default true)",
                "namespace": "namespace (default: all the token can list)",
                "selector": "label selector, e.g. app=api",
                "pod": "single pod name (skips listing)",
                "container": "container name (default: first container)",
                "previous": "read previous container logs (default false)",
                "tail_lines": f"lines per pod (default {_DEFAULT_TAIL_LINES})",
                "timeout": "request timeout in seconds (default 30)",
            },
            "auth": ["bearer", "client-cert", "kubeconfig"],
        }

    async def _pods(
        self, client: httpx.AsyncClient, profile: ConnectionProfile
    ) -> list[dict[str, Any]]:
        namespace = str(profile.config.get("namespace", "") or "").strip()
        selector = str(profile.config.get("selector", "") or "").strip()
        pod = str(profile.config.get("pod", "") or "").strip()
        if pod:
            path = f"/api/v1/namespaces/{namespace or 'default'}/pods/{pod}"
            response = await client.get(path)
            response.raise_for_status()
            return [response.json()]
        path = f"/api/v1/namespaces/{namespace}/pods" if namespace else "/api/v1/pods"
        params = {"labelSelector": selector} if selector else {}
        response = await client.get(path, params=params)
        response.raise_for_status()
        items = response.json().get("items", [])
        return list(items)

    async def test(self, profile: ConnectionProfile) -> TestResult:
        steps: list[StepResult] = []
        try:
            target = resolve_target(profile)
        except (ValueError, OSError) as exc:
            return TestResult(False, str(exc), [StepResult("config", False, str(exc))])
        timeout = float(profile.config.get("timeout", _DEFAULT_TIMEOUT))
        try:
            async with _client(target, timeout) as client:
                version = await client.get("/version")
                if version.status_code != 200:
                    steps.append(StepResult("version", False, f"HTTP {version.status_code}"))
                    return TestResult(False, f"HTTP {version.status_code}", steps)
                git = version.json().get("gitVersion", "?")
                steps.append(StepResult("version", True, git))
                pods = await self._pods(client, profile)
                steps.append(StepResult("pods", True, f"{len(pods)} pod(s) listed"))
        except (httpx.HTTPError, ValueError) as exc:
            steps.append(StepResult("connect", False, str(exc)[:300]))
            return TestResult(False, str(exc)[:300], steps)
        return TestResult(True, "OK", steps)

    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        target = resolve_target(profile)
        timeout = float(profile.config.get("timeout", _DEFAULT_TIMEOUT))
        async with _client(target, timeout) as client:
            if not path:
                response = await client.get("/api/v1/namespaces")
                response.raise_for_status()
                names = [i["metadata"]["name"] for i in response.json().get("items", [])]
                return [{"name": n, "path": n, "size": 0} for n in sorted(names)]
            namespace, _, pod = path.partition("/")
            if not pod:
                response = await client.get(f"/api/v1/namespaces/{namespace}/pods")
                response.raise_for_status()
                names = [i["metadata"]["name"] for i in response.json().get("items", [])]
                return [{"name": n, "path": f"{namespace}/{n}", "size": 0} for n in sorted(names)]
            response = await client.get(f"/api/v1/namespaces/{namespace}/pods/{pod}")
            response.raise_for_status()
            containers = response.json()["spec"].get("containers", [])
            return [
                {"name": c["name"], "path": f"{path}/{c['name']}", "size": 0} for c in containers
            ]

    async def _container_lines(
        self,
        client: httpx.AsyncClient,
        namespace: str,
        pod_name: str,
        container_name: str,
        previous: bool,
        tail_lines: int,
    ) -> list[str]:
        """Fetch one container log; unreadable pods yield no lines."""
        params: dict[str, Any] = {
            "container": container_name,
            "timestamps": "true",
            "tailLines": str(max(tail_lines, 1)),
        }
        if previous:
            params["previous"] = "true"
        try:
            # NOTE: no Accept override - the API server answers 406 to
            # text/plain here, but returns the raw log anyway.
            response = await client.get(
                f"/api/v1/namespaces/{namespace}/pods/{pod_name}/log",
                params=params,
            )
        except httpx.HTTPError:
            return []
        if response.status_code != 200:
            return []
        return [line for line in response.text.splitlines() if line.strip()]

    async def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        target = resolve_target(profile)
        timeout = float(profile.config.get("timeout", _DEFAULT_TIMEOUT))
        container = str(profile.config.get("container", "") or "")
        previous = bool(profile.config.get("previous", False))
        tail_lines = int(profile.config.get("tail_lines", _DEFAULT_TAIL_LINES))
        async with _client(target, timeout) as client:
            pods = await self._pods(client, profile)
            emitted = 0
            emitted_bytes = 0
            truncated = False
            for pod in pods:
                meta = pod.get("metadata", {})
                spec = pod.get("spec", {})
                pod_name = meta.get("name", "")
                namespace = meta.get("namespace", "")
                containers = [c.get("name", "") for c in spec.get("containers", [])]
                if container:
                    wanted = [container]
                else:
                    wanted = containers[:1]
                for container_name in wanted:
                    lines = await self._container_lines(
                        client, namespace, pod_name, container_name, previous, tail_lines
                    )
                    batch: list[RawRecord] = []
                    for line in lines:
                        ts, message = parse_log_line(line)
                        if query.time_from and ts and ts < query.time_from:
                            continue
                        if query.time_to and ts and ts > query.time_to:
                            continue
                        cost = len(message.encode("utf-8", "replace"))
                        if (
                            emitted >= query.limit_records
                            or emitted_bytes + cost > query.limit_bytes
                        ):
                            truncated = True
                            break
                        batch.append(
                            RawRecord(
                                message=message,
                                ts=ts,
                                ts_raw=line.split(" ", 1)[0] if ts else None,
                                origin_host=pod.get("spec", {}).get("nodeName"),
                                service=container_name,
                                fields={
                                    "pod": pod_name,
                                    "namespace": namespace,
                                    "container": container_name,
                                    "labels": meta.get("labels", {}),
                                },
                                src_meta={
                                    "pod": pod_name,
                                    "namespace": namespace,
                                    "container": container_name,
                                },
                                raw=line,
                            )
                        )
                        emitted += 1
                        emitted_bytes += cost
                    if batch:
                        # Sort ascending: tailLines returns oldest-first already,
                        # but multi-pod output stays grouped per pod.
                        yield RawBatch(records=batch, truncated=False)
                    if truncated:
                        break
                if truncated:
                    break
            if truncated:
                yield RawBatch(records=[], truncated=True)

    def capabilities(self) -> dict[str, Any]:
        return {"tail": False, "time_pushdown": True}
