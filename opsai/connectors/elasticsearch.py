"""Elasticsearch connector: read-only _search with search_after paging."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
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

_DEFAULT_PAGE_SIZE = 1000
_MAX_PAGE_SIZE = 5000
_DEFAULT_TIMEOUT = 30.0
_MAX_PAGES = 100


def _base_url(profile: ConnectionProfile) -> str:
    url = str(profile.config.get("url", "") or "").strip().rstrip("/")
    if not url:
        msg = "Elasticsearch connector requires config.url (e.g. http://127.0.0.1:9200)"
        raise ValueError(msg)
    if not url.startswith(("http://", "https://")):
        msg = f"Elasticsearch url must start with http:// or https://, got {url!r}"
        raise ValueError(msg)
    return url


def _index(profile: ConnectionProfile) -> str:
    index = str(profile.config.get("index", "") or "").strip()
    if not index:
        msg = "Elasticsearch connector requires config.index (name or pattern)"
        raise ValueError(msg)
    return index


def _client(profile: ConnectionProfile) -> httpx.AsyncClient:
    config = profile.config
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if config.get("api_key"):
        headers["Authorization"] = f"ApiKey {config['api_key']}"
    elif config.get("bearer_token"):
        headers["Authorization"] = f"Bearer {config['bearer_token']}"
    auth = None
    if config.get("username"):
        auth = (str(config["username"]), str(config.get("password", "")))
    verify = config.get("verify_tls", True)
    verify_any: Any = verify if isinstance(verify, str) else bool(verify)
    timeout = float(config.get("timeout", _DEFAULT_TIMEOUT))
    return httpx.AsyncClient(
        base_url=_base_url(profile),
        headers=headers,
        auth=auth,
        verify=verify_any,
        timeout=timeout,
    )


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            stamp = float(value)
            if stamp > 1e12:  # epoch millis
                stamp /= 1000
            parsed = datetime.fromtimestamp(stamp, tz=UTC)
        else:
            parsed = isoparse(str(value))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
    except (ValueError, OverflowError, OSError):
        return None
    return parsed


def _first_present(source: dict[str, Any], *paths: str) -> Any:
    """Return the first dotted-path value found in the source document."""
    for path in paths:
        current: Any = source
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current is not None:
            return current
    return None


def hit_to_record(
    hit: dict[str, Any],
    timestamp_field: str = "@timestamp",
    message_field: str = "message",
) -> RawRecord:
    """Map one search hit to a raw record."""
    source = hit.get("_source", {})
    if not isinstance(source, dict):
        source = {}
    ts_raw = _first_present(source, timestamp_field)
    ts = _parse_ts(ts_raw)
    message = _first_present(source, message_field)
    if message is None:
        message = ""
    level_raw = _first_present(source, "log.level", "level", "severity", "loglevel")
    service = _first_present(source, "service.name", "service", "app", "application")
    host = _first_present(source, "host.name", "host", "hostname")
    fields = {k: v for k, v in source.items() if k != message_field}
    return RawRecord(
        message=str(message),
        ts=ts,
        ts_raw=str(ts_raw) if ts_raw is not None else None,
        level_raw=str(level_raw) if level_raw is not None else None,
        origin_host=str(host) if host is not None else None,
        service=str(service) if service is not None else None,
        fields=fields,
        src_meta={
            "index": hit.get("_index"),
            "doc_id": hit.get("_id"),
            "sort": hit.get("sort"),
        },
        raw=str(message),
    )


def _build_query(profile: ConnectionProfile, query: ReadQuery) -> dict[str, Any]:
    """Build the Query DSL body: time range plus optional user query."""
    config = profile.config
    timestamp_field = str(config.get("timestamp_field", "@timestamp"))
    must: list[dict[str, Any]] = []
    user_query = config.get("query")
    if isinstance(user_query, dict) and user_query:
        must.append(user_query)
    elif isinstance(user_query, str) and user_query.strip():
        must.append({"query_string": {"query": user_query}})
    extra = str(query.filters.get("query_string", "") or "").strip()
    if extra:
        must.append({"query_string": {"query": extra}})
    range_filter: dict[str, Any] = {}
    if query.time_from:
        range_filter["gte"] = query.time_from.isoformat()
    if query.time_to:
        range_filter["lte"] = query.time_to.isoformat()
    if range_filter:
        must.append({"range": {timestamp_field: range_filter}})
    if not must:
        return {"match_all": {}}
    if len(must) == 1:
        return must[0]
    return {"bool": {"filter": must}}


@register
class ElasticsearchConnector(Connector):
    """Search Elasticsearch read-only; paging uses search_after (no scroll)."""

    name = "elasticsearch"

    def describe(self) -> dict[str, Any]:
        return {
            "config_schema": {
                "url": "base URL, e.g. http://127.0.0.1:9200 (required)",
                "index": "index name or pattern, e.g. logs-* (required)",
                "query": "Query DSL dict or query_string (optional)",
                "timestamp_field": "time field for range/sort (default @timestamp)",
                "message_field": "message field (default message)",
                "sort_order": "desc (default) or asc",
                "page_size": f"hits per request (default {_DEFAULT_PAGE_SIZE})",
                "timeout": "request timeout in seconds (default 30)",
                "username": "basic-auth username",
                "password": "basic-auth secret (prefer credential store)",  # nosec B105 - config key name, not a secret
                "api_key": "base64 API key (prefer credential store)",
                "bearer_token": "bearer token (prefer credential store)",  # nosec B105 - config key name, not a secret
                "verify_tls": "verify TLS certificates (default true)",
            },
            "auth": ["none", "basic", "api-key", "bearer"],
        }

    async def test(self, profile: ConnectionProfile) -> TestResult:
        steps: list[StepResult] = []
        try:
            index = _index(profile)
        except ValueError as exc:
            return TestResult(False, str(exc), [StepResult("config", False, str(exc))])
        try:
            async with _client(profile) as client:
                info = await client.get("/")
                if info.status_code != 200:
                    steps.append(StepResult("connect", False, f"HTTP {info.status_code}"))
                    return TestResult(False, f"HTTP {info.status_code}", steps)
                version = info.json().get("version", {}).get("number", "?")
                steps.append(StepResult("connect", True, f"v{version}"))
                mapping = await client.get(f"/{index}/_mapping")
                if mapping.status_code == 404:
                    steps.append(StepResult("index", False, f"{index} not found"))
                    return TestResult(False, f"index {index} not found", steps)
                mapping.raise_for_status()
                steps.append(StepResult("index", True, index))
        except (httpx.HTTPError, ValueError) as exc:
            steps.append(StepResult("connect", False, str(exc)[:300]))
            return TestResult(False, str(exc)[:300], steps)
        return TestResult(True, "OK", steps)

    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        async with _client(profile) as client:
            if not path:
                response = await client.get("/_cat/indices", params={"format": "json"})
                response.raise_for_status()
                indices = response.json()
                return [
                    {"name": i["index"], "path": i["index"], "size": 0}
                    for i in sorted(indices, key=lambda x: x.get("index", ""))
                    if not str(i.get("index", "")).startswith(".")
                ]
            response = await client.get(f"/{path}/_mapping")
            response.raise_for_status()
            fields: list[dict[str, Any]] = []
            for index_mapping in response.json().values():
                props = index_mapping.get("mappings", {}).get("properties", {})
                fields.extend({"name": k, "path": f"{path}.{k}", "size": 0} for k in sorted(props))
            return fields

    async def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        index = _index(profile)
        timestamp_field = str(profile.config.get("timestamp_field", "@timestamp"))
        message_field = str(profile.config.get("message_field", "message"))
        sort_order = str(profile.config.get("sort_order", "desc") or "desc").lower()
        if sort_order not in {"asc", "desc"}:
            msg = f"Elasticsearch sort_order must be asc or desc, got {sort_order!r}"
            raise ValueError(msg)
        page_size = min(int(profile.config.get("page_size", _DEFAULT_PAGE_SIZE)), _MAX_PAGE_SIZE)
        page_size = max(page_size, 1)
        max_pages = int(profile.config.get("max_pages", _MAX_PAGES))
        body: dict[str, Any] = {
            "query": _build_query(profile, query),
            "size": page_size,
            # Tie-breaker keeps search_after stable without a point in
            # time (_shard_doc needs PIT, _id needs fielddata).
            "sort": [
                {timestamp_field: {"order": sort_order}},
                {"_doc": {"order": sort_order}},
            ],
            "track_total_hits": False,
        }
        emitted = 0
        emitted_bytes = 0
        truncated = False
        async with _client(profile) as client:
            for _ in range(max(1, max_pages)):
                response = await client.post(f"/{index}/_search", json=body)
                response.raise_for_status()
                hits = response.json().get("hits", {}).get("hits", [])
                if not hits:
                    break
                batch: list[RawRecord] = []
                for hit in hits:
                    record = hit_to_record(hit, timestamp_field, message_field)
                    cost = len(record.message.encode("utf-8", "replace"))
                    if emitted >= query.limit_records or emitted_bytes + cost > query.limit_bytes:
                        truncated = True
                        break
                    batch.append(record)
                    emitted += 1
                    emitted_bytes += cost
                if batch:
                    yield RawBatch(records=batch, truncated=False)
                if truncated or len(hits) < page_size:
                    break
                last_sort = hits[-1].get("sort")
                if not last_sort:
                    break
                body["search_after"] = last_sort
            if truncated:
                yield RawBatch(records=[], truncated=True)

    def capabilities(self) -> dict[str, Any]:
        return {"tail": False, "time_pushdown": True}
