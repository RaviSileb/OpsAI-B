"""Elasticsearch connector tests: live single-node in Docker (search only)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from opsai.connectors.base import ConnectionProfile, ReadQuery
from opsai.connectors.elasticsearch import ElasticsearchConnector, hit_to_record
from tests.containers import Container, docker_available

ES_URL = "http://127.0.0.1:19200"
INDEX = "opsai-test-logs"


def _profile(**overrides: Any) -> ConnectionProfile:
    config: dict[str, Any] = {"url": ES_URL, "index": INDEX}
    config.update(overrides)
    return ConnectionProfile(id="e", name="e", connector_type="elasticsearch", config=config)


@pytest.fixture(scope="module")
def es() -> Iterator[str]:
    """Start single-node Elasticsearch without security and seed 10 docs."""
    if not docker_available():
        pytest.skip("docker unavailable")
    container = Container(
        "docker.elastic.co/elasticsearch/elasticsearch:8.15.0",
        ports={19200: 9200},
        env={
            "discovery.type": "single-node",
            "xpack.security.enabled": "false",
            "ES_JAVA_OPTS": "-Xms512m -Xmx512m",
        },
    )
    container.start()
    try:

        def ready() -> bool:
            response = httpx.get(ES_URL, timeout=5)
            return response.status_code == 200

        container.wait_for(ready, timeout=180)
        now = datetime.now(UTC)
        old = now - timedelta(hours=1)
        docs = [
            {
                "@timestamp": (old + timedelta(seconds=i)).isoformat(),
                "message": f"old event {i}",
                "log": {"level": "info"},
                "service": {"name": "webapp"},
                "host": {"name": "h1"},
            }
            for i in range(5)
        ]
        docs += [
            {
                "@timestamp": (now + timedelta(seconds=i)).isoformat(),
                "message": f"new event {i}",
                "log": {"level": "error" if i == 0 else "info"},
                "service": {"name": "webapp"},
                "host": {"name": "h2"},
            }
            for i in range(5)
        ]
        bulk_lines: list[str] = []
        for doc in docs:
            bulk_lines.append('{"index": {}}')
            bulk_lines.append(json.dumps(doc))
        response = httpx.post(
            f"{ES_URL}/{INDEX}/_bulk?refresh=true",
            content="\n".join(bulk_lines) + "\n",
            headers={"Content-Type": "application/x-ndjson"},
            timeout=60,
        )
        response.raise_for_status()
        assert not response.json().get("errors"), response.text[:500]
        yield ES_URL
    finally:
        container.stop()


async def test_test_and_browse(es: str) -> None:
    _ = es
    connector = ElasticsearchConnector()
    result = await connector.test(_profile())
    assert result.ok, result.message
    indices = await connector.browse(_profile())
    assert any(item["name"] == INDEX for item in indices)
    fields = await connector.browse(_profile(), INDEX)
    assert any(item["name"] == "message" for item in fields)
    missing = await connector.test(_profile(index="no-such-index"))
    assert not missing.ok


async def test_read_all(es: str) -> None:
    _ = es
    connector = ElasticsearchConnector()
    records = []
    async for batch in connector.read(_profile(), ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 10
    first = records[0]
    assert first.service == "webapp"
    # Descending sort: newest first, error event exists exactly once.
    assert first.message == "new event 4"
    assert first.origin_host == "h2"
    assert [r.level_raw for r in records].count("error") == 1
    assert first.ts is not None
    assert first.src_meta["index"] == INDEX


async def test_read_time_range(es: str) -> None:
    _ = es
    connector = ElasticsearchConnector()
    since = datetime.now(UTC) - timedelta(minutes=30)
    records = []
    async for batch in connector.read(_profile(), ReadQuery(time_from=since, limit_records=100)):
        records.extend(batch.records)
    assert len(records) == 5
    assert all("new event" in r.message for r in records)


async def test_read_respects_record_limit(es: str) -> None:
    _ = es
    connector = ElasticsearchConnector()
    batches = [b async for b in connector.read(_profile(), ReadQuery(limit_records=3))]
    assert sum(len(b.records) for b in batches) == 3
    assert batches[-1].truncated


async def test_read_paginates(es: str) -> None:
    _ = es
    connector = ElasticsearchConnector()
    profile = _profile(page_size=4)
    records = []
    async for batch in connector.read(profile, ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 10
    assert len({r.message for r in records}) == 10


async def test_read_query_string_filter(es: str) -> None:
    _ = es
    connector = ElasticsearchConnector()
    query = ReadQuery(filters={"query_string": '"new event 1"'})
    records = []
    async for batch in connector.read(_profile(), query):
        records.extend(batch.records)
    assert len(records) == 1
    assert records[0].message == "new event 1"


def test_hit_to_record_unit() -> None:
    record = hit_to_record(
        {
            "_index": "i",
            "_id": "1",
            "_source": {
                "@timestamp": "2024-07-03T09:46:40Z",
                "message": "boom",
                "level": "ERROR",
                "service": "api",
                "hostname": "h9",
            },
        }
    )
    assert record.message == "boom"
    assert record.level_raw == "ERROR"
    assert record.service == "api"
    assert record.origin_host == "h9"
    assert record.ts == datetime(2024, 7, 3, 9, 46, 40, tzinfo=UTC)
    epoch = hit_to_record({"_source": {"@timestamp": 1720000000000, "message": "m"}})
    assert epoch.ts == datetime(2024, 7, 3, 9, 46, 40, tzinfo=UTC)
    broken = hit_to_record({"_source": {"@timestamp": "nonsense"}})
    assert broken.ts is None
    assert broken.message == ""
