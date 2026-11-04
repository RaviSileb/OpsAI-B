"""Kafka connector tests: live broker in Docker, never commits (FR-020..024)."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from opsai.connectors.base import ConnectionProfile, ReadQuery
from opsai.connectors.kafka import KafkaConnector, build_consumer_config
from tests.containers import Container, docker_available

pytestmark = pytest.mark.skipif(not docker_available(), reason="docker unavailable")

BOOTSTRAP = "127.0.0.1:19092"
TOPIC = "opsai-test-logs"


def _profile(**overrides: Any) -> ConnectionProfile:
    config: dict[str, Any] = {"bootstrap_servers": BOOTSTRAP, "topic": TOPIC}
    config.update(overrides)
    return ConnectionProfile(id="k", name="k", connector_type="kafka", config=config)


@pytest.fixture(scope="module")
def broker() -> Iterator[str]:
    """Start a single-node KRaft broker and seed one topic."""
    from confluent_kafka.admin import AdminClient, NewTopic

    container = Container(
        "apache/kafka:3.8.0",
        ports={19092: 19092},
        env={
            "KAFKA_NODE_ID": "1",
            "KAFKA_PROCESS_ROLES": "broker,controller",
            "KAFKA_LISTENERS": "PLAINTEXT://:9092,CONTROLLER://:9093,PLAINTEXT_HOST://:19092",
            "KAFKA_ADVERTISED_LISTENERS": "PLAINTEXT://kafka:9092,PLAINTEXT_HOST://127.0.0.1:19092",
            "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": "CONTROLLER:PLAINTEXT,"
            "PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT",
            "KAFKA_CONTROLLER_QUORUM_VOTERS": "1@127.0.0.1:9093",
            "KAFKA_CONTROLLER_LISTENER_NAMES": "CONTROLLER",
            "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR": "1",
            "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR": "1",
            "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR": "1",
            "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS": "0",
            "KAFKA_NUM_PARTITIONS": "1",
            "CLUSTER_ID": "MkU3OEVDQ05EBk2QwoUhT3qg",
        },
    )
    container.start()
    try:
        admin = AdminClient({"bootstrap.servers": BOOTSTRAP, "socket.timeout.ms": 5000})

        def ready() -> bool:
            metadata = admin.list_topics(timeout=5)
            return metadata.brokers is not None and len(metadata.brokers) >= 1

        container.wait_for(ready, timeout=120)
        futures = admin.create_topics([NewTopic(TOPIC, num_partitions=1)])
        futures[TOPIC].result(timeout=30)
        _seed()
        _wait_for_records()
        yield BOOTSTRAP
    finally:
        container.stop()


def _seed() -> None:
    from confluent_kafka import Producer

    producer = Producer({"bootstrap.servers": BOOTSTRAP, "enable.idempotence": True})
    now_ms = int(time.time() * 1000)
    old_ms = now_ms - 3600_000
    for i in range(5):
        payload = json.dumps({"message": f"old event {i}", "level": "INFO", "request_id": f"r{i}"})
        producer.produce(
            TOPIC,
            payload.encode(),
            key=f"k{i}".encode(),
            timestamp=old_ms,
            headers={"source": "seed"},
        )
    for i in range(5):
        payload = json.dumps({"message": f"new event {i}", "level": "ERROR" if i == 0 else "INFO"})
        producer.produce(
            TOPIC,
            payload.encode(),
            key=f"n{i}".encode(),
            timestamp=now_ms,
            headers={"source": "seed"},
        )
    left = producer.flush(30)
    assert left == 0, f"{left} seed messages undelivered"


def _wait_for_records(expected: int = 10, timeout: float = 60.0) -> None:
    """Block until the seeded records are visible (query only, no group offsets)."""
    from confluent_kafka import Consumer, TopicPartition

    consumer = Consumer(
        {
            "bootstrap.servers": BOOTSTRAP,
            "group.id": "opsai-test-seedwait",
            "enable.auto.commit": False,
        }
    )
    try:
        deadline = time.monotonic() + timeout
        high = -1
        while time.monotonic() < deadline:
            _low, high = consumer.get_watermark_offsets(TopicPartition(TOPIC, 0), timeout=10)
            if high >= expected:
                return
            time.sleep(1.0)
        raise TimeoutError(f"seed records not visible, high watermark {high}")
    finally:
        consumer.close()


async def test_test_and_browse(broker: str) -> None:
    _ = broker
    connector = KafkaConnector()
    result = await connector.test(_profile())
    assert result.ok, result.message
    assert any(t["name"] == TOPIC for t in await connector.browse(_profile()))
    missing = await connector.test(_profile(topic="no-such-topic"))
    assert not missing.ok


async def test_read_all_without_commits(broker: str) -> None:
    from confluent_kafka import ConsumerGroupTopicPartitions
    from confluent_kafka.admin import AdminClient

    _ = broker
    connector = KafkaConnector()
    records = []
    async for batch in connector.read(_profile(), ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 10
    first = records[0]
    assert first.service == TOPIC
    assert first.fields["kafka_topic"] == TOPIC
    assert first.fields["partition"] == 0
    assert first.fields["header_source"] == "seed"
    assert first.fields["kafka_key"] == "k0"
    assert first.src_meta["offset"] == 0
    assert first.ts is not None
    assert any(r.level_raw == "ERROR" for r in records)
    # Prove no offsets were committed by any opsai group: assign-based
    # readers never even register a group, but if one shows up it must
    # hold no committed offsets.
    admin = AdminClient({"bootstrap.servers": BOOTSTRAP})
    groups = admin.list_consumer_groups(request_timeout=10).result().valid
    ours = [g.group_id for g in groups if g.group_id.startswith("opsai-")]
    if ours:
        listed = admin.list_consumer_group_offsets([ConsumerGroupTopicPartitions(g) for g in ours])
        for group_id, future in listed.items():
            offsets = future.result(timeout=10)
            assert offsets.topic_partitions == [], f"group {group_id} committed offsets"


async def test_read_time_range(broker: str) -> None:
    _ = broker
    connector = KafkaConnector()
    since = datetime.now(UTC) - timedelta(minutes=30)
    records = []
    async for batch in connector.read(_profile(), ReadQuery(time_from=since, limit_records=100)):
        records.extend(batch.records)
    assert len(records) == 5
    assert all("new event" in r.message for r in records)


async def test_read_respects_record_limit(broker: str) -> None:
    _ = broker
    connector = KafkaConnector()
    batches = [b async for b in connector.read(_profile(), ReadQuery(limit_records=3))]
    assert sum(len(b.records) for b in batches) == 3
    assert batches[-1].truncated


def test_consumer_config_never_commits() -> None:
    config = build_consumer_config(
        _profile(
            security_protocol="SASL_SSL",
            sasl_mechanism="SCRAM-SHA-512",
            sasl_username="u",
            sasl_password="p",
            ssl_ca="/tmp/ca",
        )
    )
    assert config["enable.auto.commit"] is False
    assert config["group.id"].startswith("opsai-")
    assert config["security.protocol"] == "SASL_SSL"
    assert config["sasl.mechanism"] == "SCRAM-SHA-512"
    assert config["ssl.ca.location"] == "/tmp/ca"
    other = build_consumer_config(_profile())
    assert other["group.id"] != config["group.id"]
