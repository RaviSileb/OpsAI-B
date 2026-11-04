"""Loki connector tests: live single-binary Loki in Docker (read-only API)."""

from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from opsai.connectors.base import ConnectionProfile, ReadQuery
from opsai.connectors.loki import LokiConnector, stream_to_record
from tests.containers import Container, docker_available

LOKI_URL = "http://127.0.0.1:13100"

LOKI_CONFIG = """\
auth_enabled: false
server:
  http_listen_port: 3100
common:
  instance_addr: 127.0.0.1
  path_prefix: /tmp/loki
  storage:
    filesystem:
      chunks_directory: /tmp/loki/chunks
      rules_directory: /tmp/loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2020-10-24
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
"""


def _profile(**overrides: Any) -> ConnectionProfile:
    config: dict[str, Any] = {
        "url": LOKI_URL,
        "selector": '{job="opsai-test"}',
    }
    config.update(overrides)
    return ConnectionProfile(id="l", name="l", connector_type="loki", config=config)


def _push(lines: list[tuple[int, str, dict[str, str]]]) -> None:
    streams: dict[str, dict[str, Any]] = {}
    for ts_ns, line, labels in lines:
        key = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        entry = streams.setdefault(key, {"stream": labels, "values": []})
        entry["values"].append([str(ts_ns), line])
    response = httpx.post(
        f"{LOKI_URL}/loki/api/v1/push",
        json={"streams": list(streams.values())},
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    response.raise_for_status()


@pytest.fixture(scope="module")
def loki(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Start Loki and seed two streams (old + new entries)."""
    if not docker_available():
        pytest.skip("docker unavailable")
    config_path = tmp_path_factory.mktemp("loki") / "loki.yaml"
    config_path.write_text(LOKI_CONFIG)
    container = Container(
        "grafana/loki:3.3.0",
        ports={13100: 3100},
        args=["-config.file=/etc/loki/loki.yaml"],
        volumes={str(config_path): "/etc/loki/loki.yaml"},
    )
    container.start()
    try:

        def ready() -> bool:
            response = httpx.get(f"{LOKI_URL}/ready", timeout=5)
            return response.status_code == 200

        container.wait_for(ready, timeout=120)
        now_ns = time.time_ns()
        old_ns = now_ns - 3_600_000_000_000
        seed = [
            (old_ns + i, f"old event {i}", {"job": "opsai-test", "level": "info"}) for i in range(5)
        ]
        seed += [
            (
                now_ns + i,
                f"new event {i}",
                {"job": "opsai-test", "level": "error" if i == 0 else "info"},
            )
            for i in range(5)
        ]
        _push(seed)
        yield LOKI_URL
    finally:
        container.stop()


async def test_test_and_browse(loki: str) -> None:
    _ = loki
    connector = LokiConnector()
    result = await connector.test(_profile())
    assert result.ok, result.message
    labels = await connector.browse(_profile())
    names = {item["name"] for item in labels}
    assert "job" in names
    values = await connector.browse(_profile(), "job")
    assert any(item["name"] == "opsai-test" for item in values)
    bad = await connector.test(_profile(selector="{broken"))
    assert not bad.ok


async def test_read_all(loki: str) -> None:
    _ = loki
    connector = LokiConnector()
    records = []
    async for batch in connector.read(_profile(), ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 10
    first = records[0]
    assert first.service == "opsai-test"
    assert first.fields["label_job"] == "opsai-test"
    assert first.ts is not None
    assert any(r.level_raw == "error" for r in records)
    assert first.src_meta["labels"]["job"] == "opsai-test"


async def test_read_time_range(loki: str) -> None:
    _ = loki
    connector = LokiConnector()
    since = datetime.now(UTC) - timedelta(minutes=30)
    records = []
    async for batch in connector.read(_profile(), ReadQuery(time_from=since, limit_records=100)):
        records.extend(batch.records)
    assert len(records) == 5
    assert all("new event" in r.message for r in records)


async def test_read_respects_record_limit(loki: str) -> None:
    _ = loki
    connector = LokiConnector()
    batches = [b async for b in connector.read(_profile(), ReadQuery(limit_records=3))]
    assert sum(len(b.records) for b in batches) == 3
    assert batches[-1].truncated


async def test_read_paginates(loki: str) -> None:
    _ = loki
    connector = LokiConnector()
    profile = _profile(page_size=4)
    records = []
    async for batch in connector.read(profile, ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 10


def test_stream_to_record_unit() -> None:
    record = stream_to_record(
        {"stream": {"job": "api", "level": "warn", "instance": "h1:9100"}},
        "1720000000000000000",
        "hello",
    )
    assert record.message == "hello"
    assert record.level_raw == "warn"
    assert record.service == "api"
    assert record.origin_host == "h1"
    assert record.ts == datetime(2024, 7, 3, 9, 46, 40, tzinfo=UTC)
    broken = stream_to_record({"stream": {}}, "not-a-number", "x")
    assert broken.ts is None
    assert broken.service is None


def test_profile_validation() -> None:
    connector = LokiConnector()
    assert "selector" in connector.describe()["config_schema"]
    assert connector.capabilities()["time_pushdown"] is True
