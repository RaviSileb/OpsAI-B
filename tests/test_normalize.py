"""Tests for log normalization (FR-120..122, FR-130)."""

from __future__ import annotations

from datetime import UTC

from opsai.core.normalize import (
    ALERT,
    CRITICAL,
    DEBUG,
    EMERGENCY,
    ERROR,
    INFO,
    NOTICE,
    TRACE,
    WARN,
    detect_origin_host,
    group_multiline,
    level_from_value,
    level_name,
    parse_timestamp,
)


def test_level_from_syslog_int() -> None:
    assert level_from_value(3) == NOTICE
    assert level_from_value(9) is None


def test_level_from_windows_source() -> None:
    assert level_from_value(1, "windows") == CRITICAL
    assert level_from_value(2, "windows") == ERROR
    assert level_from_value(3, "windows") == WARN
    assert level_from_value(4, "windows") == INFO
    assert level_from_value(5, "windows") == DEBUG


def test_level_from_text_variants() -> None:
    assert level_from_value("error") == ERROR
    assert level_from_value("  WARNING ") == WARN
    assert level_from_value("FATAL") == ALERT
    assert level_from_value("EMERG") == EMERGENCY
    assert level_from_value("trace") == TRACE
    assert level_from_value("nonsense") is None
    assert level_from_value(None) is None
    assert level_from_value(True) is None


def test_level_from_http_status() -> None:
    assert level_from_value("500") == ERROR
    assert level_from_value("404") == WARN
    assert level_from_value("200") == INFO


def test_level_name_roundtrip() -> None:
    assert level_name(ERROR) == "ERROR"
    assert level_name(None) == "UNKNOWN"


def test_parse_iso_timestamp() -> None:
    parsed = parse_timestamp("2026-10-27T10:00:01Z")
    assert parsed is not None
    assert parsed.tzinfo == UTC
    assert parsed.hour == 10


def test_parse_naive_uses_default_tz() -> None:
    parsed = parse_timestamp("2026-07-27 10:00:01", "Europe/Prague")
    assert parsed is not None
    assert parsed.tzinfo == UTC
    assert parsed.hour == 8  # CEST -> UTC


def test_parse_epoch_variants() -> None:
    assert parse_timestamp(1761559201) is not None
    assert parse_timestamp(1761559201000) is not None
    assert parse_timestamp("not a date") is None


def test_group_multiline_keeps_traceback_together() -> None:
    lines = [
        "2026-10-27 ERROR app boom",
        "Traceback (most recent call last):",
        '  File "app.py", line 1, in main',
        "ValueError: boom",
        "2026-10-27 INFO app next event",
    ]
    events = group_multiline(lines)
    assert len(events) == 2
    assert "Traceback" in events[0]
    assert events[1].endswith("next event")


def test_detect_origin_host_order() -> None:
    host, rule = detect_origin_host("x", {"host": {"name": "App-Srv-12"}}, explicit="manual-1")
    assert (host, rule) == ("manual-1", "explicit")
    host, rule = detect_origin_host("x", {"host": {"name": "App-Srv-12"}})
    assert (host, rule) == ("app-srv-12", "field:host.name")
    host, rule = detect_origin_host("failed on db-Primary.internal today")
    assert host == "db-primary.internal"
    assert rule == "message-pattern"
    host, rule = detect_origin_host("nothing here", fallback="Kafka-Broker")
    assert (host, rule) == ("kafka-broker", "source")
    host, rule = detect_origin_host("nothing here")
    assert (host, rule) == (None, None)
