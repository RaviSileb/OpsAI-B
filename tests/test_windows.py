"""Windows connector tests: builders, parsing, paging with stub WinRM.

Live WinRM tests run only when OPSAI_TEST_WINRM_HOST is set (a real
Windows target with WinRM enabled is required).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from opsai.connectors.base import ConnectionProfile, ReadQuery
from opsai.connectors.windows import (
    WindowsConnector,
    WinEventFilter,
    WinRMSettings,
    WinRMTransport,
    build_filter_hashtable,
    build_query_script,
    build_xpath,
    event_to_record,
    is_access_denied,
    parse_event_xml,
    parse_ps_json,
)

WINRM_HOST = os.environ.get("OPSAI_TEST_WINRM_HOST", "")
needs_winrm = pytest.mark.skipif(not WINRM_HOST, reason="OPSAI_TEST_WINRM_HOST not set")


def _profile(**overrides: Any) -> ConnectionProfile:
    config: dict[str, Any] = {
        "mode": "remote",
        "host": "win-test.local",
        "username": "tester",
        "password": "secret",
        "channel": "System",
    }
    config.update(overrides)
    return ConnectionProfile(id="w", name="w", connector_type="windows", config=config)


def _filter(**overrides: Any) -> WinEventFilter:
    params: dict[str, Any] = {"channel": "System"}
    params.update(overrides)
    return WinEventFilter(**params)


class StubTransport(WinRMTransport):
    """WinRM stub replaying canned Get-WinEvent pages."""

    def __init__(self, pages: list[list[dict[str, Any]]]) -> None:
        super().__init__(
            WinRMSettings(
                host="stub",
                port=5986,
                use_ssl=True,
                auth="ntlm",
                username="stub",
                message_encryption=False,
                cert_validation=True,
            ),
            None,
        )
        self.pages = pages
        self.scripts: list[str] = []

    def run_ps(self, script: str, timeout: float) -> tuple[str, str, bool]:
        _ = timeout
        self.scripts.append(script)
        if ";" in script.split("Get-WinEvent", 1)[0]:
            raise AssertionError("script prefix must stay a single pipeline")
        page = self.pages.pop(0) if self.pages else []
        return json.dumps(page), "", False


def _event(record_id: int, minute: int, **over: Any) -> dict[str, Any]:
    base = datetime(2026, 10, 27, 10, 0, tzinfo=UTC) + timedelta(minutes=minute)
    event: dict[str, Any] = {
        "RecordId": record_id,
        "TimeCreated": base.isoformat(),
        "Level": 2,
        "LevelName": "Error",
        "EventId": 1001,
        "Provider": "Test-Provider",
        "Channel": "System",
        "Computer": "WIN-TEST",
        "Audit": "",
        "Message": f"failure {record_id}",
        "EventData": "",
    }
    event.update(over)
    return event


def test_build_filter_hashtable() -> None:
    flt = _filter(
        channel="Security",
        start=datetime(2026, 10, 26, 10, tzinfo=UTC),
        end=datetime(2026, 10, 27, 10, tzinfo=UTC),
        levels=(1, 2),
        event_ids=(4625,),
        provider="Microsoft-Windows-Security-Auditing",
    )
    script = build_filter_hashtable(flt, 100, oldest=True)
    assert "LogName='Security'" in script
    assert "Level=1,2" in script
    assert "Id=4625" in script
    assert "ProviderName='Microsoft-Windows-Security-Auditing'" in script
    assert "-MaxEvents 100 -Oldest" in script
    newest = build_filter_hashtable(_filter(), 10, oldest=False)
    assert "-Oldest" not in newest


def test_builders_reject_injection() -> None:
    evil_channel = WinEventFilter(channel="System'; Remove-Item C:\\ -Recurse; '")
    with pytest.raises(ValueError, match="Invalid channel"):
        build_query_script(evil_channel, 10, oldest=True)
    with pytest.raises(ValueError, match="Invalid channel"):
        build_xpath(evil_channel)
    evil_provider = _filter(provider="x'; Invoke-Expression $env:PWN; '")
    with pytest.raises(ValueError, match="Invalid provider"):
        build_query_script(evil_provider, 10, oldest=True)
    with pytest.raises(ValueError, match="Invalid level"):
        build_query_script(_filter(levels=(9,)), 10, oldest=True)
    with pytest.raises(ValueError, match="max_events"):
        build_query_script(_filter(), 0, oldest=True)
    quoted = build_filter_hashtable(_filter(provider="O'Brien"), 5, oldest=True)
    assert "ProviderName='O''Brien'" in quoted


def test_build_xpath() -> None:
    flt = _filter(
        start=datetime(2026, 10, 26, 10, tzinfo=UTC),
        levels=(2,),
        event_ids=(1001,),
    )
    xpath = build_xpath(flt)
    assert "Channel='System'" in xpath
    assert "SystemTime&gt;=" in xpath
    assert "Level=2" in xpath
    assert "EventID=1001" in xpath


def test_winrm_transport_rules() -> None:
    ssl_default = WinRMSettings.from_config({"host": "h", "username": "u"})
    assert (ssl_default.port, ssl_default.use_ssl) == (5986, True)
    plain = WinRMSettings.from_config(
        {"host": "h", "username": "u", "ssl": False, "message_encryption": True}
    )
    assert (plain.port, plain.message_encryption) == (5985, True)
    with pytest.raises(ValueError, match="HTTPS only"):
        WinRMSettings.from_config(
            {
                "host": "h",
                "username": "u",
                "ssl": False,
                "auth": "basic",
                "message_encryption": True,
            }
        )
    with pytest.raises(ValueError, match="message encryption"):
        WinRMSettings.from_config(
            {"host": "h", "username": "u", "ssl": False, "message_encryption": False}
        )
    with pytest.raises(ValueError, match="username"):
        WinRMSettings.from_config({"host": "h"})
    with pytest.raises(ValueError, match="Unsupported WinRM auth"):
        WinRMSettings.from_config({"host": "h", "username": "u", "auth": "digest"})


def test_is_access_denied() -> None:
    assert is_access_denied("Get-WinEvent: Access is denied")
    assert is_access_denied("HRESULT 0x80070005 (E_ACCESSDENIED)")
    assert not is_access_denied("The specified channel was not found")


def test_parse_ps_json_shapes() -> None:
    assert parse_ps_json("") == []
    assert parse_ps_json("  \n") == []
    single = parse_ps_json(json.dumps({"RecordId": 1}))
    assert single == [{"RecordId": 1}]
    multi = parse_ps_json(json.dumps([{"RecordId": 1}, {"RecordId": 2}, 42]))
    assert [e["RecordId"] for e in multi] == [1, 2]


def test_parse_event_xml() -> None:
    xml = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager"/>
    <EventID>7036</EventID>
    <Level>4</Level>
    <Channel>System</Channel>
    <Computer>WIN-TEST</Computer>
    <EventRecordID>42</EventRecordID>
    <TimeCreated SystemTime="2026-10-27T10:00:00.0000000Z"/>
  </System>
  <EventData>
    <Data>wuauserv</Data>
    <Data>running</Data>
  </EventData>
</Event>"""
    fields = parse_event_xml(xml)
    assert fields["EventID"] == "7036"
    assert fields["Level"] == "4"
    assert fields["RecordId"] == "42"
    assert fields["EventData"] == "wuauserv|running"
    record = event_to_record({**fields, "LevelName": "", "Message": "", "Audit": ""})
    assert record.level_raw == "Information"
    assert record.origin_host == "WIN-TEST"
    assert record.message == "wuauserv|running"
    assert record.fields["win.record_id"] == 42


def test_event_to_record_levels_and_audit() -> None:
    from opsai.core.normalize import level_from_value

    assert level_from_value(event_to_record(_event(1, 0)).level_raw) == 5
    verbose = event_to_record(_event(2, 1, Level=5, LevelName="Verbose"))
    assert level_from_value(verbose.level_raw) == 1
    failure = event_to_record(
        _event(3, 2, Level=0, LevelName="", Audit="Audit Failure;Classic", EventId=4625, Message="")
    )
    assert failure.level_raw == "Audit Failure"
    assert level_from_value(failure.level_raw) == 5
    success = event_to_record(_event(4, 3, Level=0, LevelName="", Audit="Audit Success"))
    assert level_from_value(success.level_raw) == 2
    record = event_to_record(_event(5, 4))
    assert record.service == "System"
    assert record.fields["win.event_id"] == 1001
    assert record.fields["win.provider"] == "Test-Provider"
    assert record.src_meta["record_id"] == 5


async def test_read_remote_pages_without_gaps_or_dupes() -> None:
    pages = [
        [_event(1, 0), _event(2, 1)],
        [_event(2, 1), _event(3, 2)],  # boundary re-sent, must be dropped
        [_event(4, 3)],
    ]
    stub = StubTransport(pages)
    connector = WindowsConnector()
    connector._transport_factory = lambda profile: lambda: stub  # type: ignore[method-assign]
    profile = _profile(page_size=2, order="oldest")
    records = []
    async for batch in connector.read(profile, ReadQuery()):
        records.extend(batch.records)
    assert [r.src_meta["record_id"] for r in records] == [1, 2, 3, 4]
    assert len(stub.scripts) == 3
    assert "-Oldest" in stub.scripts[0]
    # Window shifts forward to the previous edge.
    assert "2026-10-27T10:01:00" in stub.scripts[1]


async def test_read_remote_newest_and_limit() -> None:
    stub = StubTransport([[_event(9, 9), _event(8, 8)]])
    connector = WindowsConnector()
    connector._transport_factory = lambda profile: lambda: stub  # type: ignore[method-assign]
    batches = [b async for b in connector.read(_profile(page_size=10), ReadQuery(limit_records=1))]
    assert sum(len(b.records) for b in batches) == 1
    assert batches[-1].truncated
    assert "-Oldest" not in stub.scripts[0]


async def test_read_remote_access_denied() -> None:
    class Denied(StubTransport):
        def run_ps(self, script: str, timeout: float) -> tuple[str, str, bool]:
            return "", "Get-WinEvent: Access is denied", True

    connector = WindowsConnector()
    denied = Denied([])
    connector._transport_factory = lambda profile: lambda: denied  # type: ignore[method-assign]
    with pytest.raises(PermissionError, match="Access denied: System"):
        async for _ in connector.read(_profile(), ReadQuery()):
            pass


async def test_test_reports_access_denied_clearly() -> None:
    class Denied(StubTransport):
        def run_ps(self, script: str, timeout: float) -> tuple[str, str, bool]:
            return "", "Access is denied", True

    connector = WindowsConnector()
    real_transport = WinRMTransport
    denied = Denied([])
    try:
        import opsai.connectors.windows as winmod

        winmod.WinRMTransport = lambda settings, password: denied  # type: ignore[assignment]
        result = await connector.test(_profile(channel="Security"))
    finally:
        winmod.WinRMTransport = real_transport  # type: ignore[assignment]
    assert not result.ok
    assert result.message == "Access denied: Security"


async def test_local_mode_reports_platform() -> None:
    connector = WindowsConnector()
    result = await connector.test(_profile(mode="local"))
    assert not result.ok
    assert "Windows" in result.message
    items = await connector.browse(_profile())
    assert any(i["name"] == "Security" for i in items)


@needs_winrm
async def test_live_winrm_system_channel() -> None:
    """Live test: read System channel from OPSAI_TEST_WINRM_HOST."""
    profile = ConnectionProfile(
        id="w",
        name="w",
        connector_type="windows",
        config={
            "mode": "remote",
            "host": WINRM_HOST,
            "username": os.environ["OPSAI_TEST_WINRM_USER"],
            "password": os.environ["OPSAI_TEST_WINRM_PASSWORD"],
            "ssl": os.environ.get("OPSAI_TEST_WINRM_SSL", "true") == "true",
            "auth": os.environ.get("OPSAI_TEST_WINRM_AUTH", "ntlm"),
            "cert_validation": False,
            "channel": "System",
            "page_size": 10,
        },
    )
    connector = WindowsConnector()
    assert (await connector.test(profile)).ok
    records = []
    async for batch in connector.read(profile, ReadQuery(limit_records=10)):
        records.extend(batch.records)
    assert records
    assert all(r.service == "System" for r in records)
