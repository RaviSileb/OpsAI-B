"""Syslog listener: accept UDP/TCP syslog (RFC3164/RFC5424) into a spool."""

from __future__ import annotations

import asyncio
import re
import socket
import sqlite3
import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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

_FACILITY_NAMES = (
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "authpriv",
    "ftp",
    "ntp",
    "audit",
    "alert",
    "clock",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
)
_SEVERITY_NAMES = (
    "emerg",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug",
)

_PRI_RE = re.compile(r"\A<(\d{1,3})>")
_RFC5424_RE = re.compile(
    r"\A<(\d{1,3})>(\d{1,3}) (\S+) (\S+) (\S+) (\S+) (\S+)"
    r" (?:-|\[(?:[^\]\\]|\\.)*\]) ?(.*)\Z",
    re.DOTALL,
)
_RFC3164_RE = re.compile(
    r"\A<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([^:]+): ?(.*)\Z",
    re.DOTALL,
)
_OCTET_RE = re.compile(r"\A(\d{1,7}) ")
_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@dataclass
class SyslogMessage:
    """One parsed syslog message."""

    pri: int | None
    facility: str | None
    severity: str | None
    ts: datetime | None
    host: str | None
    app: str | None
    procid: str | None
    msgid: str | None
    message: str
    raw: str
    protocol: str = "udp"


def _pri_parts(pri: int) -> tuple[str, str]:
    facility = _FACILITY_NAMES[pri // 8] if 0 <= pri // 8 < len(_FACILITY_NAMES) else f"f{pri // 8}"
    severity = _SEVERITY_NAMES[pri % 8] if 0 <= pri % 8 < len(_SEVERITY_NAMES) else f"s{pri % 8}"
    return facility, severity


def _parse_3164_ts(stamp: str, received: datetime) -> datetime | None:
    match = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})", stamp)
    if not match:
        return None
    month = _MONTHS.get(match.group(1))
    if month is None:
        return None
    year = received.year
    candidate = received.replace(
        year=year,
        month=month,
        day=int(match.group(2)),
        hour=int(match.group(3)),
        minute=int(match.group(4)),
        second=int(match.group(5)),
        microsecond=0,
    )
    if candidate > received:
        # Year boundary: a December stamp received in January is last year.
        try:
            candidate = candidate.replace(year=year - 1)
        except ValueError:
            return None
    return candidate


def parse_syslog_line(line: str, received: datetime, protocol: str = "udp") -> SyslogMessage:
    """Parse one syslog line (RFC5424, RFC3164, or plain fallback)."""
    text = line.strip("\r\n")
    match5424 = _RFC5424_RE.match(text)
    if match5424:
        pri = int(match5424.group(1))
        facility, severity = _pri_parts(pri)
        stamp = match5424.group(3)
        try:
            ts = isoparse(stamp) if stamp != "-" else None
        except ValueError:
            ts = None
        if ts is not None and ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        host = match5424.group(4)
        app = match5424.group(5)
        procid = match5424.group(6)
        msgid = match5424.group(7)
        return SyslogMessage(
            pri=pri,
            facility=facility,
            severity=severity,
            ts=ts or received,
            host=None if host == "-" else host,
            app=None if app == "-" else app,
            procid=None if procid == "-" else procid,
            msgid=None if msgid == "-" else msgid,
            message=match5424.group(8),
            raw=text,
            protocol=protocol,
        )
    match3164 = _RFC3164_RE.match(text)
    if match3164:
        pri = int(match3164.group(1))
        facility, severity = _pri_parts(pri)
        tag = match3164.group(4).strip()
        app, _, pid = tag.partition("[")
        procid = pid.rstrip("]") or None if pid else None
        return SyslogMessage(
            pri=pri,
            facility=facility,
            severity=severity,
            ts=_parse_3164_ts(match3164.group(2), received) or received,
            host=match3164.group(3),
            app=app.strip() or None,
            procid=procid,
            msgid=None,
            message=match3164.group(5),
            raw=text,
            protocol=protocol,
        )
    pri_match = _PRI_RE.match(text)
    fallback_pri = int(pri_match.group(1)) if pri_match else None
    fallback_facility: str | None = None
    fallback_severity: str | None = None
    if fallback_pri is not None:
        fallback_facility, fallback_severity = _pri_parts(fallback_pri)
    return SyslogMessage(
        pri=fallback_pri,
        facility=fallback_facility,
        severity=fallback_severity,
        ts=received,
        host=None,
        app=None,
        procid=None,
        msgid=None,
        message=text,
        raw=text,
        protocol=protocol,
    )


class SyslogSpool:
    """Thread-safe SQLite spool of received messages."""

    def __init__(self, path: str | Path, max_messages: int = 100_000) -> None:
        self.path = Path(path)
        self.max_messages = max(1000, max_messages)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        with self._lock:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS syslog (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received TEXT NOT NULL,
                    pri INTEGER,
                    facility TEXT,
                    severity TEXT,
                    ts TEXT,
                    host TEXT,
                    app TEXT,
                    procid TEXT,
                    msgid TEXT,
                    message TEXT NOT NULL,
                    raw TEXT NOT NULL,
                    protocol TEXT NOT NULL
                )"""
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_syslog_ts ON syslog(ts)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_syslog_host ON syslog(host)")
            self._conn.commit()

    def close(self) -> None:
        """Close the spool database."""
        with self._lock:
            self._conn.close()

    def store(self, message: SyslogMessage, received: datetime) -> int:
        """Store one message, trimming the spool past the cap. Returns row id."""
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO syslog (received, pri, facility, severity, ts, host, app,"
                " procid, msgid, message, raw, protocol)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    received.isoformat(),
                    message.pri,
                    message.facility,
                    message.severity,
                    message.ts.isoformat() if message.ts else None,
                    message.host,
                    message.app,
                    message.procid,
                    message.msgid,
                    message.message,
                    message.raw,
                    message.protocol,
                ),
            )
            row_id = int(cursor.lastrowid or 0)
            self._conn.execute(
                "DELETE FROM syslog WHERE id <= (SELECT MAX(id) - ? FROM syslog)",
                (self.max_messages,),
            )
            self._conn.commit()
            return row_id

    def fetch(
        self,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        limit: int = 100_000,
        after_id: int = 0,
    ) -> list[dict[str, Any]]:
        """Fetch messages ordered by id with optional time bounds."""
        from_iso = time_from.isoformat() if time_from else None
        to_iso = time_to.isoformat() if time_to else None
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, received, pri, facility, severity, ts, host, app,"
                " procid, msgid, message, raw, protocol FROM syslog"
                " WHERE id > ? AND (? IS NULL OR ts >= ?)"
                " AND (? IS NULL OR ts <= ?) ORDER BY id LIMIT ?",
                (after_id, from_iso, from_iso, to_iso, to_iso, limit),
            ).fetchall()
        names = (
            "id",
            "received",
            "pri",
            "facility",
            "severity",
            "ts",
            "host",
            "app",
            "procid",
            "msgid",
            "message",
            "raw",
            "protocol",
        )
        return [dict(zip(names, row, strict=True)) for row in rows]

    def stats(self) -> dict[str, Any]:
        """Return spool counters grouped by host, app, and severity."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM syslog").fetchone()[0]
            by_host = self._conn.execute(
                "SELECT COALESCE(host, '?'), COUNT(*) FROM syslog GROUP BY host"
            ).fetchall()
            by_app = self._conn.execute(
                "SELECT COALESCE(app, '?'), COUNT(*) FROM syslog GROUP BY app"
            ).fetchall()
            by_sev = self._conn.execute(
                "SELECT COALESCE(severity, '?'), COUNT(*) FROM syslog GROUP BY severity"
            ).fetchall()
        return {
            "total": total,
            "by_host": dict(by_host),
            "by_app": dict(by_app),
            "by_severity": dict(by_sev),
        }


def split_tcp_stream(buffer: bytes) -> tuple[list[str], bytes]:
    """Split buffered TCP bytes into complete messages (both framings).

    Supports RFC6587 octet-counting (``<len> <message>``) and
    non-transparent newline framing. Returns messages and the remainder.
    """
    messages: list[str] = []
    rest = buffer
    while rest:
        octet = _OCTET_RE.match(rest.decode("ascii", errors="ignore")[:16])
        if octet and rest[len(octet.group(0)) : len(octet.group(0)) + 1] == b"<":
            length = int(octet.group(1))
            start = len(octet.group(0))
            if len(rest) < start + length:
                break
            chunk = rest[start : start + length]
            messages.append(chunk.decode("utf-8", errors="replace"))
            rest = rest[start + length :]
            continue
        newline = rest.find(b"\n")
        if newline < 0:
            break
        chunk = rest[:newline]
        messages.append(chunk.decode("utf-8", errors="replace"))
        rest = rest[newline + 1 :]
    return messages, rest


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, listener: SyslogListener) -> None:
        self.listener = listener

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        _ = addr
        received = datetime.now(UTC)
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines() or [text]:
            if line.strip():
                self.listener.spool.store(parse_syslog_line(line, received, "udp"), received)


class SyslogListener:
    """Asyncio UDP/TCP syslog listener writing to a spool."""

    def __init__(
        self,
        spool: SyslogSpool,
        bind: str = "127.0.0.1",
        udp_port: int = 5514,
        tcp_port: int = 5514,
        protocols: str = "both",
    ) -> None:
        self.spool = spool
        self.bind = bind
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.protocols = protocols
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.Server | None = None

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            buffer = b""
            while True:
                try:
                    chunk = await reader.read(65536)
                except (asyncio.IncompleteReadError, ConnectionError, OSError):
                    break
                if not chunk:
                    break
                buffer += chunk
                if len(buffer) > 10_000_000:
                    buffer = b""  # drop runaway framing garbage
                    continue
                messages, buffer = split_tcp_stream(buffer)
                received = datetime.now(UTC)
                for line in messages:
                    if line.strip():
                        self.spool.store(parse_syslog_line(line, received, "tcp"), received)
        finally:
            # Always close our side: Server.wait_closed() waits for it.
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def start(self) -> None:
        """Bind sockets and start serving."""
        loop = asyncio.get_running_loop()
        if self.protocols in {"udp", "both"}:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UdpProtocol(self), local_addr=(self.bind, self.udp_port)
            )
            self._udp_transport = transport
        if self.protocols in {"tcp", "both"}:
            self._tcp_server = await asyncio.start_server(
                self._handle_tcp, self.bind, self.tcp_port
            )

    async def stop(self) -> None:
        """Close sockets (spool stays open for reads)."""
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
            # Datagram close is lazy: let the loop release the socket so a
            # restart on the same port does not hit EADDRINUSE.
            await asyncio.sleep(0)
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None

    @property
    def running(self) -> bool:
        """Return True while any socket is bound."""
        tcp_open = self._tcp_server is not None and self._tcp_server.is_serving()
        return self._udp_transport is not None or tcp_open


_LISTENERS: dict[str, SyslogListener] = {}
_LISTENERS_LOCK = threading.Lock()


def listener_key(bind: str, udp_port: int, tcp_port: int) -> str:
    """Return the registry key for a listener address set."""
    return f"{bind}:{udp_port}/{tcp_port}"


def get_listener(key: str) -> SyslogListener | None:
    """Return a running listener by key, if any."""
    with _LISTENERS_LOCK:
        return _LISTENERS.get(key)


def register_listener(key: str, listener: SyslogListener) -> None:
    """Register a running listener."""
    with _LISTENERS_LOCK:
        _LISTENERS[key] = listener


def unregister_listener(key: str) -> None:
    """Drop a listener registration."""
    with _LISTENERS_LOCK:
        _LISTENERS.pop(key, None)


def can_bind(bind: str, port: int, sock_type: int) -> bool:
    """Return True when a socket can be bound (connectivity probe)."""
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    sock = socket.socket(family, sock_type)
    try:
        sock.bind((bind, port))
    except OSError:
        return False
    finally:
        sock.close()
    return True


def _listener_config(profile: ConnectionProfile) -> tuple[str, int, int, str, str, int]:
    config = profile.config
    bind = str(config.get("bind", "127.0.0.1") or "127.0.0.1")
    udp_port = int(config.get("udp_port", config.get("port", 5514)))
    tcp_port = int(config.get("tcp_port", config.get("port", 5514)))
    protocols = str(config.get("protocols", "both") or "both").lower()
    if protocols not in {"udp", "tcp", "both"}:
        msg = f"syslog protocols must be udp, tcp, or both, got {protocols!r}"
        raise ValueError(msg)
    # Default spool is a documented fallback; deployments set spool_path.
    default_spool = f"/tmp/opsai-syslog-{udp_port}-{tcp_port}.db"  # nosec B108
    spool_path = str(config.get("spool_path", default_spool))
    max_messages = int(config.get("max_messages", 100_000))
    return bind, udp_port, tcp_port, protocols, spool_path, max_messages


def row_to_record(row: dict[str, Any]) -> RawRecord:
    """Map one spool row to a raw record."""
    ts_raw = row.get("ts")
    try:
        ts = isoparse(str(ts_raw)) if ts_raw else None
    except ValueError:
        ts = None
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return RawRecord(
        message=str(row.get("message", "")),
        ts=ts,
        ts_raw=str(ts_raw) if ts_raw else None,
        level_raw=row.get("severity"),
        origin_host=row.get("host"),
        service=row.get("app"),
        fields={
            "pri": row.get("pri"),
            "facility": row.get("facility"),
            "procid": row.get("procid"),
            "msgid": row.get("msgid"),
            "protocol": row.get("protocol"),
        },
        src_meta={"spool_id": row.get("id"), "received": row.get("received")},
        raw=row.get("raw"),
    )


@register
class SyslogConnector(Connector):
    """Read messages received by the built-in syslog listener."""

    name = "syslog"

    def describe(self) -> dict[str, Any]:
        return {
            "config_schema": {
                "bind": "listen address (default 127.0.0.1)",
                "port": "UDP+TCP port when both share one (default 5514)",
                "udp_port": "UDP port (default 5514)",
                "tcp_port": "TCP port (default 5514)",
                "protocols": "udp, tcp, or both (default both)",
                "spool_path": "SQLite spool file (default /tmp/opsai-syslog-*.db)",
                "max_messages": "spool ring cap (default 100000)",
            },
            "auth": ["none"],
        }

    async def start_listener(self, profile: ConnectionProfile) -> SyslogListener:
        """Start (or reuse) the listener for this profile."""
        bind, udp_port, tcp_port, protocols, spool_path, max_messages = _listener_config(profile)
        key = listener_key(bind, udp_port, tcp_port)
        existing = get_listener(key)
        if existing is not None and existing.running:
            return existing
        spool = SyslogSpool(spool_path, max_messages)
        listener = SyslogListener(
            spool,
            bind=bind,
            udp_port=udp_port,
            tcp_port=tcp_port,
            protocols=protocols,
        )
        await listener.start()
        register_listener(key, listener)
        return listener

    async def stop_listener(self, profile: ConnectionProfile) -> None:
        """Stop the listener for this profile (spool file is kept)."""
        bind, udp_port, tcp_port, _protocols, _spool, _max = _listener_config(profile)
        key = listener_key(bind, udp_port, tcp_port)
        listener = get_listener(key)
        if listener is None:
            return
        await listener.stop()
        listener.spool.close()
        unregister_listener(key)

    async def test(self, profile: ConnectionProfile) -> TestResult:
        steps: list[StepResult] = []
        try:
            bind, udp_port, tcp_port, protocols, _spool, _max = _listener_config(profile)
        except ValueError as exc:
            return TestResult(False, str(exc), [StepResult("config", False, str(exc))])
        key = listener_key(bind, udp_port, tcp_port)
        listener = get_listener(key)
        if listener is not None and listener.running:
            steps.append(StepResult("listener", True, f"running on {key}"))
            return TestResult(True, "OK", steps)
        if protocols in {"udp", "both"} and not can_bind(bind, udp_port, socket.SOCK_DGRAM):
            steps.append(StepResult("bind-udp", False, f"{bind}:{udp_port} busy"))
            return TestResult(False, f"UDP {bind}:{udp_port} unavailable", steps)
        steps.append(StepResult("bind-udp", True, f"{bind}:{udp_port} free"))
        if protocols in {"tcp", "both"} and not can_bind(bind, tcp_port, socket.SOCK_STREAM):
            steps.append(StepResult("bind-tcp", False, f"{bind}:{tcp_port} busy"))
            return TestResult(False, f"TCP {bind}:{tcp_port} unavailable", steps)
        steps.append(StepResult("bind-tcp", True, f"{bind}:{tcp_port} free"))
        return TestResult(True, "OK", steps)

    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        _ = path
        bind, udp_port, tcp_port, _protocols, spool_path, _max = _listener_config(profile)
        key = listener_key(bind, udp_port, tcp_port)
        listener = get_listener(key)
        if listener is not None:
            stats = listener.spool.stats()
        elif Path(spool_path).exists():
            spool = SyslogSpool(spool_path)
            try:
                stats = spool.stats()
            finally:
                spool.close()
        else:
            stats = {"total": 0, "by_host": {}, "by_app": {}, "by_severity": {}}
        items = [{"name": f"total: {stats['total']}", "path": "", "size": stats["total"]}]
        for group in ("by_host", "by_app", "by_severity"):
            for name, count in sorted(stats[group].items()):
                items.append({"name": f"{group[3:]} {name}: {count}", "path": name, "size": count})
        return items

    async def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        bind, udp_port, tcp_port, _protocols, spool_path, _max = _listener_config(profile)
        key = listener_key(bind, udp_port, tcp_port)
        listener = get_listener(key)
        own_spool = None
        if listener is not None:
            spool = listener.spool
        else:
            own_spool = SyslogSpool(spool_path)
            spool = own_spool
        try:
            after_id = 0
            emitted = 0
            emitted_bytes = 0
            truncated = False
            while True:
                rows = spool.fetch(query.time_from, query.time_to, 1000, after_id)
                if not rows:
                    break
                batch: list[RawRecord] = []
                for row in rows:
                    after_id = max(after_id, int(row["id"]))
                    record = row_to_record(row)
                    cost = len(record.message.encode("utf-8", "replace"))
                    if emitted >= query.limit_records or emitted_bytes + cost > query.limit_bytes:
                        truncated = True
                        break
                    batch.append(record)
                    emitted += 1
                    emitted_bytes += cost
                if batch:
                    yield RawBatch(records=batch, truncated=False)
                if truncated:
                    break
            if truncated:
                yield RawBatch(records=[], truncated=True)
        finally:
            if own_spool is not None:
                own_spool.close()

    def capabilities(self) -> dict[str, Any]:
        return {"tail": False, "time_pushdown": True}
