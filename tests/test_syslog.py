"""Syslog listener tests: UDP/TCP receive, parsing, spool (no docker needed)."""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from opsai.connectors.base import ConnectionProfile, ReadQuery
from opsai.connectors.syslog import (
    SyslogConnector,
    parse_syslog_line,
    split_tcp_stream,
)

UDP_PORT = 15514
TCP_PORT = 15514


def _profile(tmp_path: Any, **overrides: Any) -> ConnectionProfile:
    config: dict[str, Any] = {
        "bind": "127.0.0.1",
        "port": UDP_PORT,
        "spool_path": str(tmp_path / "syslog.db"),
    }
    config.update(overrides)
    return ConnectionProfile(id="s", name="s", connector_type="syslog", config=config)


@pytest.fixture
async def listener(tmp_path: Any) -> Any:
    """Run a listener on test ports with an isolated spool."""
    connector = SyslogConnector()
    profile = _profile(tmp_path)
    await connector.start_listener(profile)
    try:
        yield profile
    finally:
        await connector.stop_listener(profile)


def _send_udp(payload: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload.encode(), ("127.0.0.1", UDP_PORT))
    finally:
        sock.close()


async def _send_tcp(payload: bytes) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", TCP_PORT)
    _ = reader
    writer.write(payload)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def _wait_for(connector: SyslogConnector, profile: ConnectionProfile, count: int) -> None:
    for _ in range(100):
        items = await connector.browse(profile)
        total = next(i["size"] for i in items if i["path"] == "")
        if total >= count:
            return
        await asyncio.sleep(0.05)
    raise TimeoutError(f"spool did not reach {count} messages")


async def test_udp_rfc5424_and_rfc3164(listener: ConnectionProfile) -> None:
    connector = SyslogConnector()
    _send_udp('<165>1 2026-10-27T10:00:00Z web1 nginx 123 ID47 [ex i="1"] accepted conn')
    _send_udp("<34>Oct 27 10:01:00 db1 postgres[456]: checkpoint done")
    await _wait_for(connector, listener, 2)
    records = []
    async for batch in connector.read(listener, ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 2
    first, second = records
    assert first.service == "nginx"
    assert first.origin_host == "web1"
    assert first.fields["facility"] == "local4"
    assert first.level_raw == "notice"
    assert first.fields["procid"] == "123"
    assert first.fields["msgid"] == "ID47"
    assert first.fields["protocol"] == "udp"
    assert first.message == "accepted conn"
    assert second.service == "postgres"
    assert second.origin_host == "db1"
    assert second.fields["procid"] == "456"
    assert second.level_raw == "crit"


async def test_tcp_newline_and_octet_framing(listener: ConnectionProfile) -> None:
    connector = SyslogConnector()
    await _send_tcp(b"<165>1 2026-10-27T10:00:00Z a app - - - line one\n<13>line two\n")
    msg = "<165>1 2026-10-27T10:00:00Z b app - - - octet counted"
    await _send_tcp(f"{len(msg)} {msg}".encode())
    await asyncio.sleep(0.2)
    await _wait_for(connector, listener, 3)
    records = []
    async for batch in connector.read(listener, ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 3
    assert [r.fields["protocol"] for r in records] == ["tcp"] * 3
    assert records[2].message == "octet counted"


async def test_test_and_browse(listener: ConnectionProfile, tmp_path: Any) -> None:
    connector = SyslogConnector()
    assert (await connector.test(listener)).ok
    _send_udp("<165>1 2026-10-27T10:00:00Z web1 nginx - - - hi")
    await _wait_for(connector, listener, 1)
    items = await connector.browse(listener)
    assert items[0]["size"] == 1
    # A profile with an unusable address fails the bind probe.
    bad = _profile(tmp_path, bind="192.0.2.1")
    assert not (await connector.test(bad)).ok


async def test_read_time_range_and_limit(listener: ConnectionProfile) -> None:
    connector = SyslogConnector()
    _send_udp("<165>1 2020-01-01T00:00:00Z h app - - - ancient")
    _send_udp("<165>1 2026-10-27T10:00:00Z h app - - - fresh")
    await _wait_for(connector, listener, 2)
    since = datetime.now(UTC) - timedelta(days=30)
    records = []
    async for batch in connector.read(listener, ReadQuery(time_from=since)):
        records.extend(batch.records)
    assert [r.message for r in records] == ["fresh"]
    batches = [b async for b in connector.read(listener, ReadQuery(limit_records=1))]
    assert sum(len(b.records) for b in batches) == 1
    assert batches[-1].truncated


async def test_spool_survives_restart(tmp_path: Any) -> None:
    connector = SyslogConnector()
    profile = _profile(tmp_path)
    await connector.start_listener(profile)
    _send_udp("<165>1 2026-10-27T10:00:00Z h app - - - kept")
    await _wait_for(connector, profile, 1)
    await connector.stop_listener(profile)
    # Read with no listener running: straight from the spool file.
    records = []
    async for batch in connector.read(profile, ReadQuery()):
        records.extend(batch.records)
    assert [r.message for r in records] == ["kept"]
    await connector.start_listener(profile)
    try:
        records = []
        async for batch in connector.read(profile, ReadQuery()):
            records.extend(batch.records)
        assert len(records) == 1
    finally:
        await connector.stop_listener(profile)


def test_parse_fallback_and_year_boundary() -> None:
    received = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    plain = parse_syslog_line("just a line", received)
    assert plain.message == "just a line"
    assert plain.pri is None
    assert plain.ts == received
    dec = parse_syslog_line("<13>Dec 31 23:59:59 h app: year end", received)
    assert dec.ts is not None and dec.ts.year == 2025
    bad_ts = parse_syslog_line("<165>1 not-a-date h app - - - m", received)
    assert bad_ts.ts == received


def test_split_tcp_stream_partial() -> None:
    assert split_tcp_stream(b"") == ([], b"")
    assert split_tcp_stream(b"half") == ([], b"half")
    assert split_tcp_stream(b"a\nb\n") == (["a", "b"], b"")
    assert split_tcp_stream(b"9 <13>hellonext") == (["<13>hello"], b"next")
    assert split_tcp_stream(b"20 <165>short") == ([], b"20 <165>short")
