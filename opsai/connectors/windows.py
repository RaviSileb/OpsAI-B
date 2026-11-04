"""Windows Event Log connector: local EvtQuery or remote WinRM (read-only)."""

from __future__ import annotations

import re
import sys
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from xml.etree import ElementTree  # nosec B405 - local EvtRender XML only

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

WELL_KNOWN_CHANNELS = ("System", "Application", "Security", "Setup", "ForwardedEvents")
_WIN_LEVEL_NAMES = {1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}
_CHANNEL_RE = re.compile(r"^[\w][\w\-/ ']*$")
_PROVIDER_RE = re.compile(r"^[\w][\w\-. ']*$")
_DEFAULT_PAGE_SIZE = 1000
_MAX_PAGE_SIZE = 5000
_DEFAULT_TIMEOUT = 60.0
_DEFAULT_LOOKBACK = timedelta(hours=24)

ACCESS_DENIED_HINTS = (
    "access is denied",
    "access denied",
    "accessdenied",
    "0x80070005",
    "e_accessdenied",
)


@dataclass
class WinEventFilter:
    """Typed event filter; the only input to script/XPath builders."""

    channel: str
    start: datetime | None = None
    end: datetime | None = None
    levels: tuple[int, ...] = ()
    event_ids: tuple[int, ...] = ()
    provider: str | None = None

    def validate(self) -> None:
        """Reject values that cannot be represented safely."""
        if not _CHANNEL_RE.match(self.channel):
            msg = f"Invalid channel name: {self.channel!r}"
            raise ValueError(msg)
        if self.provider is not None and not _PROVIDER_RE.match(self.provider):
            msg = f"Invalid provider name: {self.provider!r}"
            raise ValueError(msg)
        for level in self.levels:
            if level not in (1, 2, 3, 4, 5):
                msg = f"Invalid level (must be 1-5): {level!r}"
                raise ValueError(msg)
        for event_id in self.event_ids:
            if not 0 <= event_id <= 0xFFFFFFFF:
                msg = f"Invalid event id: {event_id!r}"
                raise ValueError(msg)


def _ps_quote(value: str) -> str:
    """Quote a string for a PowerShell single-quoted literal."""
    return "'" + value.replace("'", "''") + "'"


def build_filter_hashtable(flt: WinEventFilter, max_events: int, oldest: bool) -> str:
    """Build the Get-WinEvent call from typed values only (FR-041)."""
    flt.validate()
    if not 1 <= max_events <= 100_000:
        msg = f"max_events out of range 1-100000: {max_events!r}"
        raise ValueError(msg)
    parts = [f"LogName={_ps_quote(flt.channel)}"]
    if flt.start is not None:
        parts.append(f"StartTime=[datetime]{_ps_quote(flt.start.isoformat())}")
    if flt.end is not None:
        parts.append(f"EndTime=[datetime]{_ps_quote(flt.end.isoformat())}")
    if flt.levels:
        parts.append(f"Level={','.join(str(level) for level in flt.levels)}")
    if flt.event_ids:
        parts.append(f"Id={','.join(str(eid) for eid in flt.event_ids)}")
    if flt.provider:
        parts.append(f"ProviderName={_ps_quote(flt.provider)}")
    direction = "-Oldest" if oldest else ""
    return (
        f"Get-WinEvent -FilterHashtable @{{{';'.join(parts)}}} "
        f"-MaxEvents {max_events} {direction}".rstrip()
    )


PROJECTION_SCRIPT = """\
ForEach-Object {
  [pscustomobject]@{
    RecordId = $_.RecordId
    TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
    Level = $_.Level
    LevelName = $_.LevelDisplayName
    EventId = $_.Id
    Provider = $_.ProviderName
    Channel = $_.LogName
    Computer = $_.MachineName
    Audit = @($_.KeywordsDisplayNames) -join ';'
    Message = $_.Message
    EventData = @($_.Properties | ForEach-Object { $_.Value }) -join '|'
  }
}"""


def build_query_script(flt: WinEventFilter, max_events: int, oldest: bool) -> str:
    """Build the full remote script: Get-WinEvent, project, JSON output."""
    getter = build_filter_hashtable(flt, max_events, oldest)
    return f"{getter} | {PROJECTION_SCRIPT} | ConvertTo-Json -Depth 4 -Compress"


def build_xpath(flt: WinEventFilter) -> str:
    """Build the EvtQuery XPath for the local path (FR-040)."""
    flt.validate()
    channel = flt.channel.replace("'", "&apos;")
    conditions = [f"Event/System/Channel='{channel}'"]
    if flt.start is not None:
        start_ms = int(flt.start.timestamp() * 1000)
        conditions.append(f"Event/System/TimeCreated/@SystemTime&gt;={start_ms}")
    if flt.end is not None:
        end_ms = int(flt.end.timestamp() * 1000)
        conditions.append(f"Event/System/TimeCreated/@SystemTime&lt;={end_ms}")
    if flt.levels:
        conditions.append(" or ".join(f"Event/System/Level={level}" for level in flt.levels))
    if flt.event_ids:
        conditions.append(" or ".join(f"Event/System/EventID={eid}" for eid in flt.event_ids))
    if flt.provider:
        provider = flt.provider.replace("'", "&apos;")
        conditions.append(f"Event/System/Provider/@Name='{provider}'")
    joined = " and ".join(f"({c})" for c in conditions)
    return f"Event/System[{joined}]"


def is_access_denied(text: str) -> bool:
    """Detect permission errors for a clear report (FR-044)."""
    folded = text.lower().replace(" ", "").replace("_", "")
    compact_hints = tuple(h.replace(" ", "").replace("_", "") for h in ACCESS_DENIED_HINTS)
    return any(h in folded for h in compact_hints)


def _evtx_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _to_int(value: Any) -> int | None:
    """Coerce an event field to int (bool is never a valid level/id)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def parse_event_xml(xml: str) -> dict[str, Any]:
    """Parse one rendered event XML (local path) into plain fields."""
    # Local EvtRender output only; never parses remote/untrusted XML.
    root = ElementTree.fromstring(xml)  # nosec B314 - local trusted EvtRender output
    system = root.find("./{http://schemas.microsoft.com/win/2004/08/events/event}System")
    out: dict[str, Any] = {}
    if system is not None:
        for child in system:
            name = _evtx_ns(child.tag)
            if name == "TimeCreated":
                out["TimeCreated"] = child.attrib.get("SystemTime", "")
            elif name == "Provider":
                out["Provider"] = child.attrib.get("Name", "")
            elif name in {"EventID", "Level", "Channel", "Computer"}:
                out[name] = (child.text or "").strip()
            elif name == "EventRecordID":
                out["RecordId"] = (child.text or "").strip()
    data: list[str] = []
    for elem in root.iter():
        if _evtx_ns(elem.tag) == "Data" and elem.text:
            data.append(elem.text.strip())
    if data:
        out["EventData"] = "|".join(data)
    return out


def event_to_record(event: dict[str, Any]) -> RawRecord:
    """Map a projected event (remote JSON or local XML fields) to a record."""
    from dateutil.parser import isoparse

    ts_raw = str(event.get("TimeCreated", "") or "")
    try:
        ts = isoparse(ts_raw) if ts_raw else None
    except ValueError:
        ts = None
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    level_int = _to_int(event.get("Level"))
    level_name = str(event.get("LevelName", "") or "")
    if not level_name and level_int in _WIN_LEVEL_NAMES:
        # Local XML carries only the numeric level.
        level_name = _WIN_LEVEL_NAMES[level_int or 0]
    audit = str(event.get("Audit", "") or "")
    if "Audit Failure" in audit:
        level_name = "Audit Failure"
    elif "Audit Success" in audit and level_int in (None, 0):
        level_name = "Audit Success"
    message = str(event.get("Message", "") or "").strip()
    if not message:
        # FR-043 fallback: EventData when no rendered message exists.
        message = str(event.get("EventData", "") or "").strip()
    record_id = _to_int(event.get("RecordId"))
    fields: dict[str, Any] = {
        "win.channel": event.get("Channel"),
        "win.event_id": event.get("EventId"),
        "win.provider": event.get("Provider"),
        "win.level": level_int,
        "win.record_id": record_id,
        "win.audit": audit or None,
    }
    return RawRecord(
        message=message,
        ts=ts,
        ts_raw=ts_raw or None,
        level_raw=level_name or (str(level_int) if level_int is not None else None),
        origin_host=str(event.get("Computer", "") or "") or None,
        service=str(event.get("Channel", "") or "") or None,
        fields={k: v for k, v in fields.items() if v is not None},
        src_meta={"record_id": record_id, "channel": event.get("Channel")},
        raw=str(event.get("Message", "") or message),
    )


@dataclass
class WinRMSettings:
    """Validated WinRM connection settings (FR-041 transport rules)."""

    host: str
    port: int
    use_ssl: bool
    auth: str
    username: str
    message_encryption: bool
    cert_validation: bool

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> WinRMSettings:
        """Validate transport rules: 5986/SSL default, 5985 needs encryption."""
        host = str(config.get("host", "") or "").strip()
        if not host:
            msg = "Windows connector (remote) requires config.host"
            raise ValueError(msg)
        use_ssl = bool(config.get("ssl", True))
        port = int(config.get("port", 5986 if use_ssl else 5985))
        auth = str(config.get("auth", "ntlm") or "ntlm").lower()
        if auth not in {"kerberos", "ntlm", "credssp", "certificate", "basic"}:
            msg = f"Unsupported WinRM auth {auth!r}"
            raise ValueError(msg)
        if auth == "basic" and not use_ssl:
            msg = "Basic auth is allowed over HTTPS only"
            raise ValueError(msg)
        message_encryption = bool(config.get("message_encryption", not use_ssl))
        if not use_ssl and not message_encryption and auth in {"ntlm", "kerberos"}:
            msg = "HTTP transport requires message encryption"
            raise ValueError(msg)
        username = str(config.get("username", "") or "")
        if auth != "certificate" and not username:
            msg = f"WinRM auth {auth!r} requires config.username"
            raise ValueError(msg)
        return cls(
            host=host,
            port=port,
            use_ssl=use_ssl,
            auth=auth,
            username=username,
            message_encryption=message_encryption,
            cert_validation=bool(config.get("cert_validation", True)),
        )


class WinRMTransport:
    """Thin pypsrp wrapper; stub this class in tests (no Windows needed)."""

    def __init__(self, settings: WinRMSettings, password: str | None) -> None:
        self.settings = settings
        self.password = password

    def run_ps(self, script: str, timeout: float) -> tuple[str, str, bool]:
        """Run a script; return (output, error_text, had_errors)."""
        from pypsrp.client import Client

        client = Client(
            self.settings.host,
            username=self.settings.username,
            password=self.password,
            port=self.settings.port,
            ssl=self.settings.use_ssl,
            auth=self.settings.auth,
            cert_validation=self.settings.cert_validation,
            connection_timeout=int(timeout),
        )
        output, streams, had_errors = client.execute_ps(script)
        errors = "\n".join(str(e) for e in streams.error)
        return output, errors, had_errors


def parse_ps_json(output: str) -> list[dict[str, Any]]:
    """Parse ConvertTo-Json output (object, array, or empty) into events."""
    import json

    text = output.strip()
    if not text:
        return []
    decoded = json.loads(text)
    if isinstance(decoded, dict):
        return [decoded]
    if isinstance(decoded, list):
        return [item for item in decoded if isinstance(item, dict)]
    return []


@register
class WindowsConnector(Connector):
    """Read Windows Event Log locally (EvtQuery) or remotely (WinRM)."""

    name = "windows"

    def describe(self) -> dict[str, Any]:
        return {
            "config_schema": {
                "mode": "local (Windows only) or remote via WinRM (default remote)",
                "channel": "event channel, e.g. System (required)",
                "levels": "levels 1-5 filter, e.g. [1, 2]",
                "event_ids": "event id filter, e.g. [4625]",
                "provider": "provider name filter",
                "order": "newest (default) or oldest",
                "page_size": f"events per batch (default {_DEFAULT_PAGE_SIZE})",
                "timeout": "WinRM timeout in seconds (default 60)",
                "host": "WinRM host (remote mode, required)",
                "port": "WinRM port (default 5986 HTTPS / 5985 HTTP)",
                "ssl": "use HTTPS transport (default true)",
                "auth": "kerberos|ntlm|credssp|certificate|basic (default ntlm)",
                "username": "WinRM username (DOMAIN\\user or user@domain)",
                "password": "WinRM secret (prefer credential store)",  # nosec B105 - config key name, not a secret
                "message_encryption": "encrypt HTTP messages (default !ssl)",
                "cert_validation": "validate server TLS cert (default true)",
            },
            "auth": ["kerberos", "ntlm", "credssp", "certificate", "basic"],
        }

    def _filter(self, profile: ConnectionProfile, query: ReadQuery) -> WinEventFilter:
        config = profile.config
        channel = str(config.get("channel", "") or "").strip()
        if not channel:
            msg = "Windows connector requires config.channel"
            raise ValueError(msg)
        end = query.time_to or datetime.now(UTC)
        start = query.time_from or (end - _DEFAULT_LOOKBACK)
        levels = tuple(int(v) for v in (config.get("levels") or []))
        event_ids = tuple(int(v) for v in (config.get("event_ids") or []))
        provider = config.get("provider")
        flt = WinEventFilter(
            channel=channel,
            start=start,
            end=end,
            levels=levels,
            event_ids=event_ids,
            provider=str(provider) if provider else None,
        )
        flt.validate()
        return flt

    async def test(self, profile: ConnectionProfile) -> TestResult:
        mode = str(profile.config.get("mode", "remote") or "remote").lower()
        steps: list[StepResult] = []
        try:
            flt = self._filter(profile, ReadQuery(limit_records=1))
        except ValueError as exc:
            return TestResult(False, str(exc), [StepResult("config", False, str(exc))])
        if mode == "local":
            return self._test_local(flt, steps)
        return await self._test_remote(profile, flt, steps)

    def _test_local(self, flt: WinEventFilter, steps: list[StepResult]) -> TestResult:
        if sys.platform != "win32":
            steps.append(StepResult("platform", False, "local mode needs Windows"))
            return TestResult(False, "local mode is Windows-only", steps)
        try:
            import win32evtlog  # noqa: F401
        except ImportError:
            steps.append(StepResult("pywin32", False, "pip install opsai[windows]"))
            return TestResult(False, "pywin32 is not installed", steps)
        steps.append(StepResult("channel", True, flt.channel))
        return TestResult(True, "OK", steps)

    async def _test_remote(
        self, profile: ConnectionProfile, flt: WinEventFilter, steps: list[StepResult]
    ) -> TestResult:
        import asyncio

        try:
            settings = WinRMSettings.from_config(profile.config)
        except ValueError as exc:
            steps.append(StepResult("transport", False, str(exc)))
            return TestResult(False, str(exc), steps)
        steps.append(
            StepResult("transport", True, f"{settings.host}:{settings.port} {settings.auth}")
        )
        password = profile.config.get("password")
        transport = WinRMTransport(settings, str(password) if password else None)
        script = build_query_script(flt, 1, oldest=True)
        timeout = float(profile.config.get("timeout", _DEFAULT_TIMEOUT))
        try:
            output, errors, had_errors = await asyncio.to_thread(transport.run_ps, script, timeout)
        except Exception as exc:  # noqa: BLE001 - mapped to steps below
            detail = str(exc)[:300]
            if is_access_denied(detail):
                steps.append(StepResult("channel", False, f"Access denied: {flt.channel}"))
                return TestResult(False, f"Access denied: {flt.channel}", steps)
            steps.append(StepResult("connect", False, detail))
            return TestResult(False, detail, steps)
        if had_errors:
            detail = (errors or output)[:300]
            if is_access_denied(detail):
                steps.append(StepResult("channel", False, f"Access denied: {flt.channel}"))
                return TestResult(False, f"Access denied: {flt.channel}", steps)
            steps.append(StepResult("query", False, detail))
            return TestResult(False, detail, steps)
        steps.append(StepResult("query", True, "Get-WinEvent accepted"))
        return TestResult(True, "OK", steps)

    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        _ = profile
        if not path:
            return [
                {"name": name, "path": name, "size": 0}
                for name in (*WELL_KNOWN_CHANNELS, "Microsoft-Windows-Sysmon/Operational")
            ]
        return [{"name": path, "path": path, "size": 0}]

    def _transport_factory(self, profile: ConnectionProfile) -> Callable[[], WinRMTransport]:
        """Return a transport factory (overridable seam for tests)."""
        settings = WinRMSettings.from_config(profile.config)
        password = profile.config.get("password")
        secret = str(password) if password else None
        return lambda: WinRMTransport(settings, secret)

    async def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        mode = str(profile.config.get("mode", "remote") or "remote").lower()
        flt = self._filter(profile, query)
        if mode == "local":
            async for batch in self._read_local(profile, flt, query):
                yield batch
            return
        async for batch in self._read_remote(profile, flt, query):
            yield batch

    async def _read_local(
        self, profile: ConnectionProfile, flt: WinEventFilter, query: ReadQuery
    ) -> AsyncIterator[RawBatch]:
        import asyncio

        _ = profile
        if sys.platform != "win32":
            msg = "local mode is Windows-only; use mode=remote from this host"
            raise RuntimeError(msg)
        xpath = build_xpath(flt)
        page_size = min(int(profile.config.get("page_size", _DEFAULT_PAGE_SIZE)), _MAX_PAGE_SIZE)

        def fetch() -> list[dict[str, Any]]:
            import win32evtlog

            handle = win32evtlog.EvtQuery(flt.channel, win32evtlog.EvtQueryChannelPath, xpath)
            events: list[dict[str, Any]] = []
            while len(events) < query.limit_records:
                batch = win32evtlog.EvtNext(handle, page_size, 1000)
                if not batch:
                    break
                for item in batch:
                    xml = win32evtlog.EvtRender(item, win32evtlog.EvtRenderEventXml)
                    events.append(parse_event_xml(xml))
                    if len(events) >= query.limit_records:
                        break
            win32evtlog.EvtClose(handle)
            return events

        events = await asyncio.to_thread(fetch)
        records = [event_to_record(e) for e in events[: query.limit_records]]
        truncated = len(events) >= query.limit_records
        if records:
            yield RawBatch(records=records, truncated=False)
        if truncated:
            yield RawBatch(records=[], truncated=True)

    async def _read_remote(
        self, profile: ConnectionProfile, flt: WinEventFilter, query: ReadQuery
    ) -> AsyncIterator[RawBatch]:
        import asyncio

        make_transport = self._transport_factory(profile)
        order = str(profile.config.get("order", "newest") or "newest").lower()
        if order not in {"newest", "oldest"}:
            msg = f"order must be newest or oldest, got {order!r}"
            raise ValueError(msg)
        oldest = order == "oldest"
        page_size = min(int(profile.config.get("page_size", _DEFAULT_PAGE_SIZE)), _MAX_PAGE_SIZE)
        page_size = max(page_size, 1)
        timeout = float(profile.config.get("timeout", _DEFAULT_TIMEOUT))
        max_pages = int(profile.config.get("max_pages", 100))
        emitted = 0
        emitted_bytes = 0
        truncated = False
        # Paging (FR-041): shift the time window to the previous edge and
        # drop already-seen (timestamp, RecordId) pairs at the boundary.
        window_start = flt.start
        window_end = flt.end
        seen: set[tuple[str, int]] = set()
        for _ in range(max(1, max_pages)):
            page_filter = WinEventFilter(
                channel=flt.channel,
                start=window_start,
                end=window_end,
                levels=flt.levels,
                event_ids=flt.event_ids,
                provider=flt.provider,
            )
            script = build_query_script(page_filter, page_size, oldest)
            transport = make_transport()
            output, errors, had_errors = await asyncio.to_thread(transport.run_ps, script, timeout)
            if had_errors:
                detail = (errors or output)[:300]
                if is_access_denied(detail):
                    msg = f"Access denied: {flt.channel}"
                    raise PermissionError(msg)
                msg = f"Get-WinEvent failed: {detail}"
                raise RuntimeError(msg)
            events = parse_ps_json(output)
            fresh = [e for e in events if self._event_key(e) not in seen]
            if not fresh:
                break
            batch: list[RawRecord] = []
            for event in fresh:
                key = self._event_key(event)
                record = event_to_record(event)
                cost = len(record.message.encode("utf-8", "replace"))
                if emitted >= query.limit_records or emitted_bytes + cost > query.limit_bytes:
                    truncated = True
                    break
                batch.append(record)
                seen.add(key)
                emitted += 1
                emitted_bytes += cost
            if batch:
                yield RawBatch(records=batch, truncated=False)
            if truncated or len(events) < page_size:
                break
            edge_ts = self._edge_time(fresh, oldest)
            if edge_ts is None:
                break
            if oldest:
                window_start = edge_ts
            else:
                window_end = edge_ts
        if truncated:
            yield RawBatch(records=[], truncated=True)

    @staticmethod
    def _event_key(event: dict[str, Any]) -> tuple[str, int]:
        return (str(event.get("TimeCreated", "")), _to_int(event.get("RecordId")) or 0)

    @staticmethod
    def _edge_time(events: list[dict[str, Any]], oldest: bool) -> datetime | None:
        from dateutil.parser import isoparse

        stamps: list[datetime] = []
        for event in events:
            try:
                stamp = isoparse(str(event.get("TimeCreated", "")))
            except ValueError:
                continue
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=UTC)
            stamps.append(stamp)
        if not stamps:
            return None
        return max(stamps) if oldest else min(stamps)

    def capabilities(self) -> dict[str, Any]:
        return {"tail": False, "time_pushdown": True}
