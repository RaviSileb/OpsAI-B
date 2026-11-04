"""Kafka connector: read-only consumer that never commits (TZ FR-020..FR-024)."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

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

_BATCH_SIZE = 1000
_EMPTY_POLL_LIMIT = 5
_POLL_TIMEOUT = 1.0


def build_consumer_config(profile: ConnectionProfile) -> dict[str, Any]:
    """Build the consumer config; commits are always disabled (FR-022)."""
    config = profile.config
    bootstrap = config.get("bootstrap_servers", "")
    if isinstance(bootstrap, list):
        bootstrap = ",".join(str(b) for b in bootstrap)
    bootstrap = str(bootstrap or "").strip()
    if not bootstrap:
        msg = "Kafka connector requires config.bootstrap_servers"
        raise ValueError(msg)
    group_prefix = str(config.get("group_prefix", "opsai") or "opsai")
    consumer: dict[str, Any] = {
        "bootstrap.servers": bootstrap,
        # Unique group per read: we never join the target consumer group,
        # and with auto-commit off we never commit offsets anywhere.
        "group.id": f"{group_prefix}-{uuid.uuid4().hex[:8]}",
        "enable.auto.commit": False,
        "auto.offset.reset": str(config.get("auto_offset_reset", "earliest")),
        "session.timeout.ms": 10000,
        "socket.timeout.ms": 10000,
        "message.timeout.ms": 10000,
        "fetch.wait.max.ms": 500,
    }
    security = str(config.get("security_protocol", "PLAINTEXT") or "PLAINTEXT").upper()
    consumer["security.protocol"] = security
    if security.startswith("SASL_"):
        consumer["sasl.mechanism"] = str(config.get("sasl_mechanism", "PLAIN"))
        if config.get("sasl_username"):
            consumer["sasl.username"] = str(config.get("sasl_username"))
        if config.get("sasl_password"):
            consumer["sasl.password"] = str(config.get("sasl_password"))
    if security in {"SSL", "SASL_SSL"}:
        for key, option in (
            ("ssl_ca", "ssl.ca.location"),
            ("ssl_cert", "ssl.certificate.location"),
            ("ssl_key", "ssl.key.location"),
        ):
            if config.get(key):
                consumer[option] = str(config.get(key))
    return consumer


def decode_payload(data: bytes | None) -> tuple[str, bool]:
    """Decode key/value bytes; return ``(text, was_json)``."""
    if data is None:
        return "", False
    stripped = data.strip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        try:
            parsed = json.loads(stripped.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        else:
            return json.dumps(parsed, ensure_ascii=False), True
    return data.decode("utf-8", errors="replace"), False


def message_to_record(message: Any) -> RawRecord:
    """Map a consumed message to a raw record (FR-024)."""
    from confluent_kafka import TIMESTAMP_LOG_APPEND_TIME

    value_text, value_json = decode_payload(message.value())
    key_text, _ = decode_payload(message.key())
    ts_type, ts_ms = message.timestamp()
    ts = None
    if ts_ms is not None and ts_ms >= 0:
        try:
            ts = datetime.fromtimestamp(ts_ms / 1000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            ts = None
    level_raw: str | None = None
    fields: dict[str, Any] = {
        "kafka_topic": message.topic(),
        "partition": message.partition(),
        "offset": message.offset(),
    }
    if value_json:
        try:
            payload = json.loads(value_text)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            level_raw = payload.get("level") or payload.get("severity")
            level_raw = str(level_raw) if level_raw is not None else None
            fields.update({k: v for k, v in payload.items() if k != "message"})
            message_text = str(payload.get("message", value_text))
        else:
            message_text = value_text
    else:
        message_text = value_text
    if key_text:
        fields["kafka_key"] = key_text
    headers = message.headers() or []
    for name, value in headers:
        fields[f"header_{name}"] = value.decode("utf-8", errors="replace") if value else ""
    return RawRecord(
        message=message_text,
        ts=ts,
        ts_raw=str(ts_ms) if ts_ms is not None else None,
        level_raw=level_raw,
        service=message.topic(),
        fields=fields,
        src_meta={
            "topic": message.topic(),
            "partition": message.partition(),
            "offset": message.offset(),
            "timestamp_type": ts_type,
            "log_append_time": ts_type == TIMESTAMP_LOG_APPEND_TIME,
        },
        raw=value_text,
    )


def _topic_list(profile: ConnectionProfile, available: set[str] | None = None) -> list[str]:
    config = profile.config
    topics = config.get("topics") or ([config["topic"]] if config.get("topic") else [])
    topics = [str(t) for t in topics]
    pattern = str(config.get("topic_pattern", "") or "").strip()
    if pattern and available is not None:
        import re

        try:
            regex = re.compile(pattern)
        except re.error as exc:
            msg = f"Invalid topic_pattern {pattern!r}: {exc}"
            raise ValueError(msg) from exc
        topics.extend(sorted(t for t in available if regex.search(t)))
    topics = sorted(set(topics))
    if not topics:
        msg = "Kafka connector requires config.topic(s) or config.topic_pattern"
        raise ValueError(msg)
    return topics


@register
class KafkaConnector(Connector):
    """Consume Kafka topics read-only without offset commits."""

    name = "kafka"

    def describe(self) -> dict[str, Any]:
        return {
            "config_schema": {
                "bootstrap_servers": "host:port list (required)",
                "topic": "single topic (or topics list / topic_pattern regex)",
                "topics": "topic list",
                "topic_pattern": "regex over topic names",
                "security_protocol": "PLAINTEXT|SSL|SASL_PLAINTEXT|SASL_SSL",
                "sasl_mechanism": "PLAIN|SCRAM-SHA-256|SCRAM-SHA-512|OAUTHBEARER",
                "sasl_username": "SASL username",
                "sasl_password": "SASL secret (prefer credential store)",  # nosec B105 - config key name, not a secret
                "ssl_ca": "CA file path",
                "ssl_cert": "client cert path",
                "ssl_key": "client key path",
                "max_poll_seconds": "read budget in seconds (default 60)",
            },
            "auth": ["none", "sasl", "ssl", "sasl-ssl"],
        }

    async def test(self, profile: ConnectionProfile) -> TestResult:
        from confluent_kafka.admin import AdminClient

        steps: list[StepResult] = []
        try:
            consumer_config = build_consumer_config(profile)
        except ValueError as exc:
            return TestResult(False, str(exc), [StepResult("config", False, str(exc))])
        admin_config = {
            k: v
            for k, v in consumer_config.items()
            if k
            in {
                "bootstrap.servers",
                "security.protocol",
                "sasl.mechanism",
                "sasl.username",
                "sasl.password",
                "ssl.ca.location",
                "ssl.certificate.location",
                "ssl.key.location",
                "socket.timeout.ms",
            }
        }
        try:
            metadata = AdminClient(admin_config).list_topics(timeout=10)
        except Exception as exc:
            steps.append(StepResult("metadata", False, str(exc)[:300]))
            return TestResult(False, str(exc)[:300], steps)
        available = set(metadata.topics)
        steps.append(StepResult("metadata", True, f"{len(available)} topic(s)"))
        try:
            topics = _topic_list(profile, available)
        except ValueError as exc:
            steps.append(StepResult("topics", False, str(exc)))
            return TestResult(False, str(exc), steps)
        missing = [t for t in topics if t not in available]
        if missing:
            steps.append(StepResult("topics", False, f"missing: {missing}"))
            return TestResult(False, f"missing topics: {missing}", steps)
        steps.append(StepResult("topics", True, ", ".join(topics)))
        return TestResult(True, "OK", steps)

    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        from confluent_kafka.admin import AdminClient

        _ = path
        consumer_config = build_consumer_config(profile)
        admin_config = {k: v for k, v in consumer_config.items() if k != "group.id"}
        metadata = AdminClient(admin_config).list_topics(timeout=10)
        return [{"name": name, "path": name, "size": 0} for name in sorted(metadata.topics)]

    async def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        from confluent_kafka import OFFSET_BEGINNING, Consumer, TopicPartition

        consumer_config = build_consumer_config(profile)
        consumer = Consumer(consumer_config)
        try:
            metadata = consumer.list_topics(timeout=10)
            available = set(metadata.topics)
            topics = _topic_list(profile, available)
            assignment: list[TopicPartition] = []
            for topic in topics:
                partitions = metadata.topics[topic].partitions
                for partition_id in partitions:
                    # Explicit start offset: an unset offset makes the
                    # consumer query committed offsets first, which stalls
                    # reads when the group coordinator is not ready yet.
                    assignment.append(TopicPartition(topic, partition_id, OFFSET_BEGINNING))
            if query.time_from:
                from confluent_kafka import OFFSET_INVALID

                stamp_ms = int(query.time_from.timestamp() * 1000)
                for tp in assignment:
                    tp.offset = stamp_ms
                resolved = consumer.offsets_for_times(assignment, timeout=10)
                assignment = [tp for tp in resolved if tp.offset != OFFSET_INVALID]
            consumer.assign(assignment)
            budget = float(profile.config.get("max_poll_seconds", 60))
            import time as time_module

            deadline = time_module.monotonic() + budget
            batch: list[RawRecord] = []
            emitted = 0
            emitted_bytes = 0
            empty_polls = 0
            truncated = False
            while time_module.monotonic() < deadline:
                message = consumer.poll(_POLL_TIMEOUT)
                if message is None:
                    empty_polls += 1
                    if empty_polls >= _EMPTY_POLL_LIMIT:
                        break
                    continue
                empty_polls = 0
                if message.error():
                    continue
                record = message_to_record(message)
                if query.time_from and record.ts and record.ts < query.time_from:
                    continue
                if query.time_to and record.ts and record.ts > query.time_to:
                    continue
                cost = len(record.message.encode("utf-8", "replace"))
                if emitted >= query.limit_records or emitted_bytes + cost > query.limit_bytes:
                    truncated = True
                    break
                batch.append(record)
                emitted += 1
                emitted_bytes += cost
                if len(batch) >= _BATCH_SIZE:
                    yield RawBatch(records=batch)
                    batch = []
            if batch or truncated:
                yield RawBatch(records=batch, truncated=truncated)
        finally:
            # Never commit: with auto-commit off, close stores nothing.
            consumer.close()

    def capabilities(self) -> dict[str, Any]:
        return {"tail": False, "time_pushdown": True}
