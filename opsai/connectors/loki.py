"""Loki connector: read-only LogQL queries over the HTTP API."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

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

_DEFAULT_PAGE_SIZE = 1000
_MAX_PAGE_SIZE = 5000
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_LOOKBACK = timedelta(hours=24)
_MAX_PAGES = 100


def _base_url(profile: ConnectionProfile) -> str:
    url = str(profile.config.get("url", "") or "").strip().rstrip("/")
    if not url:
        msg = "Loki connector requires config.url (e.g. http://127.0.0.1:3100)"
        raise ValueError(msg)
    if not url.startswith(("http://", "https://")):
        msg = f"Loki url must start with http:// or https://, got {url!r}"
        raise ValueError(msg)
    return url


def _logql_query(profile: ConnectionProfile, filters: dict[str, Any]) -> str:
    """Return the effective LogQL range query for a read."""
    query = str(profile.config.get("query", "") or "").strip()
    if not query:
        selector = str(profile.config.get("selector", "") or "").strip()
        if not selector:
            msg = "Loki connector requires config.query or config.selector"
            raise ValueError(msg)
        if not selector.startswith("{"):
            msg = f'Loki selector must be a stream selector like {{job="x"}}, got {selector!r}'
            raise ValueError(msg)
        query = selector
    extra = str(filters.get("logql", "") or "").strip()
    if extra:
        query = f"{query} {extra}"
    return query


def _client(profile: ConnectionProfile) -> httpx.AsyncClient:
    config = profile.config
    headers: dict[str, str] = {}
    if config.get("org_id"):
        headers["X-Scope-OrgID"] = str(config["org_id"])
    if config.get("bearer_token"):
        headers["Authorization"] = f"Bearer {config['bearer_token']}"
    auth = None
    if config.get("username"):
        auth = (str(config["username"]), str(config.get("password", "")))
    verify = config.get("verify_tls", True)
    if isinstance(verify, str):
        verify_any: Any = verify  # CA bundle path
    else:
        verify_any = bool(verify)
    timeout = float(config.get("timeout", _DEFAULT_TIMEOUT))
    return httpx.AsyncClient(
        base_url=_base_url(profile),
        headers=headers,
        auth=auth,
        verify=verify_any,
        timeout=timeout,
    )


def _to_nano(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return str(int(value.timestamp() * 1_000_000_000))


def stream_to_record(stream: dict[str, Any], ts_ns: str, line: str) -> RawRecord:
    """Map one Loki entry (stream labels + timestamp + line) to a raw record."""
    labels = stream.get("stream", {}) if isinstance(stream, dict) else {}
    if not isinstance(labels, dict):
        labels = {}
    ts: datetime | None = None
    try:
        ts = datetime.fromtimestamp(int(ts_ns) / 1_000_000_000, tz=UTC)
    except (ValueError, OverflowError, OSError):
        ts = None
    fields: dict[str, Any] = {f"label_{k}": v for k, v in labels.items()}
    level_raw = labels.get("level") or labels.get("severity")
    service = labels.get("job") or labels.get("app") or labels.get("service")
    host = labels.get("host") or labels.get("hostname")
    instance = str(labels.get("instance", "") or "")
    if host is None and instance and ":" in instance:
        host = instance.rsplit(":", 1)[0]
    return RawRecord(
        message=line,
        ts=ts,
        ts_raw=ts_ns,
        level_raw=str(level_raw) if level_raw is not None else None,
        origin_host=str(host) if host is not None else None,
        service=str(service) if service is not None else None,
        fields=fields,
        src_meta={"labels": dict(labels)},
        raw=line,
    )


@register
class LokiConnector(Connector):
    """Query Loki with LogQL; only read endpoints are used."""

    name = "loki"

    def describe(self) -> dict[str, Any]:
        return {
            "config_schema": {
                "url": "Loki base URL, e.g. http://127.0.0.1:3100 (required)",
                "query": "full LogQL range query (or selector)",
                "selector": 'stream selector, e.g. {job="api"}',
                "direction": "BACKWARD (default) or FORWARD",
                "page_size": f"entries per request (default {_DEFAULT_PAGE_SIZE})",
                "timeout": "request timeout in seconds (default 30)",
                "org_id": "X-Scope-OrgID tenant header",
                "username": "basic-auth username",
                "password": "basic-auth secret (prefer credential store)",  # nosec B105 - config key name, not a secret
                "bearer_token": "bearer token (prefer credential store)",  # nosec B105 - config key name, not a secret
                "verify_tls": "verify TLS certificates (default true)",
            },
            "auth": ["none", "basic", "bearer", "org-id"],
        }

    async def test(self, profile: ConnectionProfile) -> TestResult:
        steps: list[StepResult] = []
        try:
            query = _logql_query(profile, {})
        except ValueError as exc:
            return TestResult(False, str(exc), [StepResult("config", False, str(exc))])
        try:
            async with _client(profile) as client:
                ready = await client.get("/ready")
                steps.append(StepResult("ready", ready.status_code == 200, ready.text[:200]))
                if ready.status_code != 200:
                    return TestResult(False, f"Loki not ready: HTTP {ready.status_code}", steps)
                probe = await client.get(
                    "/loki/api/v1/query_range",
                    params={"query": query, "limit": 1},
                )
                if probe.status_code != 200:
                    detail = probe.text[:300]
                    steps.append(StepResult("query", False, detail))
                    return TestResult(False, f"query rejected: {detail}", steps)
                steps.append(StepResult("query", True, "LogQL accepted"))
        except (httpx.HTTPError, ValueError) as exc:
            steps.append(StepResult("connect", False, str(exc)[:300]))
            return TestResult(False, str(exc)[:300], steps)
        return TestResult(True, "OK", steps)

    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        async with _client(profile) as client:
            if not path:
                response = await client.get("/loki/api/v1/labels")
                response.raise_for_status()
                names = response.json().get("data", [])
                return [{"name": n, "path": n, "size": 0} for n in sorted(names)]
            response = await client.get(f"/loki/api/v1/label/{quote(path, safe='')}/values")
            response.raise_for_status()
            values = response.json().get("data", [])
            return [{"name": v, "path": f"{path}={v}", "size": 0} for v in sorted(values)]

    async def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        logql = _logql_query(profile, query.filters)
        direction = str(profile.config.get("direction", "BACKWARD") or "BACKWARD").upper()
        if direction not in {"BACKWARD", "FORWARD"}:
            msg = f"Loki direction must be BACKWARD or FORWARD, got {direction!r}"
            raise ValueError(msg)
        page_size = min(int(profile.config.get("page_size", _DEFAULT_PAGE_SIZE)), _MAX_PAGE_SIZE)
        page_size = max(page_size, 1)
        max_pages = int(profile.config.get("max_pages", _MAX_PAGES))
        end = query.time_to or datetime.now(UTC)
        start = query.time_from or (end - _DEFAULT_LOOKBACK)

        emitted = 0
        emitted_bytes = 0
        truncated = False
        seen: set[tuple[str, str]] = set()
        params: dict[str, Any] = {
            "query": logql,
            "start": _to_nano(start),
            "end": _to_nano(end),
            "limit": page_size,
            "direction": direction,
        }
        async with _client(profile) as client:
            for _ in range(max(1, max_pages)):
                response = await client.get("/loki/api/v1/query_range", params=params)
                response.raise_for_status()
                entries: list[tuple[str, str, dict[str, Any]]] = []
                for stream in response.json().get("data", {}).get("result", []):
                    for ts_ns, line in stream.get("values", []):
                        entries.append((ts_ns, line, stream))
                if direction == "FORWARD":
                    entries.sort(key=lambda item: item[0])
                else:
                    entries.sort(key=lambda item: item[0], reverse=True)
                fresh = [e for e in entries if (e[0], e[1]) not in seen]
                if not fresh:
                    break
                batch: list[RawRecord] = []
                for ts_ns, line, stream in fresh:
                    record = stream_to_record(stream, ts_ns, line)
                    if query.time_from and record.ts and record.ts < query.time_from:
                        continue
                    if query.time_to and record.ts and record.ts > query.time_to:
                        continue
                    cost = len(line.encode("utf-8", "replace"))
                    if emitted >= query.limit_records or emitted_bytes + cost > query.limit_bytes:
                        truncated = True
                        break
                    batch.append(record)
                    seen.add((ts_ns, line))
                    emitted += 1
                    emitted_bytes += cost
                if batch:
                    yield RawBatch(records=batch, truncated=False)
                if truncated or len(fresh) < page_size:
                    break
                edge = fresh[-1][0]
                if direction == "BACKWARD":
                    params["end"] = edge
                else:
                    params["start"] = edge
            if truncated:
                yield RawBatch(records=[], truncated=True)

    def capabilities(self) -> dict[str, Any]:
        return {"tail": False, "time_pushdown": True}
