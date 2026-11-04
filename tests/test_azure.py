"""Azure connector tests: mock Log Analytics API + stub credentials.

Live tests run only when OPSAI_TEST_AZURE_WORKSPACE_ID and a service
principal are provided via environment.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from opsai.connectors.azure import (
    _TOKEN_CACHE,
    AzureAuth,
    AzureConnector,
    DeviceCodeRequiredError,
    acquire_token,
    build_credential,
    detect_level,
    format_timespan,
    parse_query_response,
    row_to_record,
)
from opsai.connectors.base import ConnectionProfile, ReadQuery

WORKSPACE = os.environ.get("OPSAI_TEST_AZURE_WORKSPACE_ID", "")
needs_azure = pytest.mark.skipif(not WORKSPACE, reason="OPSAI_TEST_AZURE_WORKSPACE_ID not set")

SYSLOG_COLUMNS = [
    {"name": "TimeGenerated", "type": "datetime"},
    {"name": "Computer", "type": "string"},
    {"name": "SeverityLevel", "type": "string"},
    {"name": "SyslogMessage", "type": "string"},
    {"name": "ProcessName", "type": "string"},
]

SYSLOG_ROWS = [
    ["2026-10-27T10:00:00Z", "web-1", "err", "disk full", "kernel"],
    ["2026-10-27T10:01:00Z", "web-1", "info", "cron ran", "cron"],
    ["2026-10-27T10:02:00Z", "web-2", "warning", "slow query", "postgres"],
]


def _response(rows: list[list[Any]], partial: bool = False) -> dict[str, Any]:
    body: dict[str, Any] = {
        "tables": [{"name": "PrimaryResult", "columns": SYSLOG_COLUMNS, "rows": rows}]
    }
    if partial:
        body["partialTables"] = [{"id": "sr0001"}]
    return body


class StubToken:
    """Minimal azure-core AccessToken shape."""

    def __init__(self) -> None:
        self.token = "stub-token"
        self.expires_on = time.time() + 3600


class StubCredential:
    """Credential stub recording scopes."""

    def __init__(self) -> None:
        self.scopes: list[str] = []

    def get_token(self, *scopes: str, **kwargs: Any) -> StubToken:
        _ = kwargs
        self.scopes.extend(scopes)
        return StubToken()


@pytest.fixture
def azure_mock() -> Iterator[dict[str, Any]]:
    """Install stub credential + mock API, capturing requests."""
    _TOKEN_CACHE.clear()
    credential = StubCredential()
    captured: dict[str, Any] = {"requests": [], "credential": credential}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured["requests"].append(request)
        assert request.headers.get("Authorization") == "Bearer stub-token"
        body = json.loads(request.content.decode())
        timespan = body.get("timespan", "")
        # Full 2h window is partial; halves return their rows.
        if "T10:00:00" in timespan and "T12:00:00" in timespan:
            payload: dict[str, Any] = _response([SYSLOG_ROWS[0]], partial=True)
        elif "T10:00:00" in timespan:
            payload = _response(SYSLOG_ROWS[:2])
        elif "T11:00:00" in timespan:
            payload = _response(SYSLOG_ROWS[2:])
        else:
            payload = _response(SYSLOG_ROWS)
        return httpx.Response(200, json=payload)

    AzureConnector.credential_factory = staticmethod(lambda auth: credential)  # type: ignore[method-assign]
    AzureConnector.http_transport = httpx.MockTransport(handler)
    try:
        yield captured
    finally:
        AzureConnector.credential_factory = None
        AzureConnector.http_transport = None
        _TOKEN_CACHE.clear()


def _profile(**overrides: Any) -> ConnectionProfile:
    config: dict[str, Any] = {
        "workspace_id": "ws-1",
        "table": "Syslog",
        "auth": "client_secret",
        "tenant_id": "tenant",
        "client_id": "app",
        "client_secret": "secret",
    }
    config.update(overrides)
    return ConnectionProfile(id="a", name="a", connector_type="azure", config=config)


def test_auth_validation() -> None:
    good = AzureAuth.from_config({"auth": "client_secret", "tenant_id": "t", "client_secret": "s"})
    assert good.scope() == "https://api.loganalytics.io/.default"
    with pytest.raises(ValueError, match="Unsupported Azure auth"):
        AzureAuth.from_config({"auth": "password"})
    with pytest.raises(ValueError, match="Unknown cloud"):
        AzureAuth.from_config({"cloud": "mars"})
    with pytest.raises(ValueError, match="authority_host and endpoint"):
        AzureAuth.from_config({"cloud": "custom"})
    with pytest.raises(ValueError, match="tenant_id"):
        AzureAuth.from_config({"auth": "client_secret"})
    with pytest.raises(ValueError, match="client_secret"):
        AzureAuth.from_config({"auth": "client_secret", "tenant_id": "t"})
    custom = AzureAuth.from_config(
        {
            "auth": "azure_cli",
            "cloud": "custom",
            "authority_host": "https://login.custom",
            "endpoint": "https://logs.custom/",
        }
    )
    assert custom.resolved_endpoint() == "https://logs.custom"
    gov = AzureAuth.from_config({"auth": "managed_identity", "cloud": "government"})
    assert gov.resolved_endpoint() == "https://api.loganalytics.us"


def test_build_credential_types() -> None:
    from azure.identity import (
        AzureCliCredential,
        ClientSecretCredential,
        ManagedIdentityCredential,
    )

    assert isinstance(
        build_credential(
            AzureAuth.from_config(
                {"auth": "client_secret", "tenant_id": "t", "client_id": "c", "client_secret": "s"}
            )
        ),
        ClientSecretCredential,
    )
    assert isinstance(
        build_credential(AzureAuth.from_config({"auth": "managed_identity"})),
        ManagedIdentityCredential,
    )
    assert isinstance(
        build_credential(AzureAuth.from_config({"auth": "azure_cli"})),
        AzureCliCredential,
    )


def test_format_timespan() -> None:
    start = datetime(2026, 10, 27, 10, tzinfo=UTC)
    end = datetime(2026, 10, 27, 12, tzinfo=UTC)
    assert format_timespan(start, end) == f"{start.isoformat()}/{end.isoformat()}"
    assert format_timespan(None, None) == "PT24H"
    open_ended = format_timespan(start, None)
    assert open_ended.startswith(start.isoformat())


def test_parse_query_response_partial() -> None:
    rows, partial = parse_query_response(_response(SYSLOG_ROWS))
    assert not partial
    assert rows[0] == {
        "TimeGenerated": "2026-10-27T10:00:00Z",
        "Computer": "web-1",
        "SeverityLevel": "err",
        "SyslogMessage": "disk full",
        "ProcessName": "kernel",
    }
    _rows, partial = parse_query_response(_response([], partial=True))
    assert partial
    _rows, partial = parse_query_response({"tables": [], "error": {"code": "PartialError"}})
    assert partial


def test_detect_level() -> None:
    assert detect_level({"SeverityLevel": 3, "AppRoleName": "api"}, None) == "Error"
    assert detect_level({"SeverityLevel": "warning"}, None) == "warning"
    assert detect_level({"EventLevelName": "Error"}, None) == "Error"
    assert detect_level({"EventLevel": 2}, None) == "Error"
    assert detect_level({"Computer": "x"}, None) is None
    assert detect_level({"custom": "crit"}, "custom") == "crit"


def test_row_to_record_mapping() -> None:
    from opsai.core.normalize import level_from_value

    row = {
        "TimeGenerated": "2026-10-27T10:00:00Z",
        "Computer": "web-1",
        "SeverityLevel": "err",
        "SyslogMessage": "disk full",
        "ProcessName": "kernel",
    }
    record = row_to_record(row, "Syslog")
    assert record.ts == datetime(2026, 10, 27, 10, tzinfo=UTC)
    assert record.origin_host == "web-1"
    assert record.service == "kernel"
    assert record.message == "disk full"
    assert level_from_value(record.level_raw) == 5
    assert record.src_meta == {"azure.table": "Syslog"}
    fallback = row_to_record({"TimeGenerated": "x", "A": 1}, "custom")
    assert fallback.ts is None
    assert "A=1" in fallback.message


async def test_test_browse_and_read(azure_mock: dict[str, Any]) -> None:
    connector = AzureConnector()
    result = await connector.test(_profile())
    assert result.ok, result.message
    tables = await connector.browse(_profile())
    assert {t["name"] for t in tables} >= {"Syslog", "ContainerLogV2", "KubeEvents"}
    columns = await connector.browse(_profile(), "Syslog")
    assert any(c["name"] == "SeverityLevel" for c in columns)
    records = []
    async for batch in connector.read(_profile(), ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 3
    assert records[0].fields["Computer"] == "web-1"
    credential: StubCredential = azure_mock["credential"]
    assert credential.scopes == ["https://api.loganalytics.io/.default"]


async def test_timespan_pushdown(azure_mock: dict[str, Any]) -> None:
    _ = azure_mock
    connector = AzureConnector()
    start = datetime(2026, 10, 27, 8, tzinfo=UTC)
    end = datetime(2026, 10, 27, 9, tzinfo=UTC)
    records = []
    async for batch in connector.read(
        _profile(), ReadQuery(time_from=start, time_to=end, limit_records=10)
    ):
        records.extend(batch.records)
    import json

    bodies = [json.loads(r.content.decode()) for r in azure_mock["requests"]]
    assert bodies
    assert all(
        start.isoformat() in b["timespan"] and end.isoformat() in b["timespan"] for b in bodies
    )


async def test_partial_result_splits_window(azure_mock: dict[str, Any]) -> None:
    _ = azure_mock
    connector = AzureConnector()
    start = datetime(2026, 10, 27, 10, tzinfo=UTC)
    end = datetime(2026, 10, 27, 12, tzinfo=UTC)
    records = []
    async for batch in connector.read(
        _profile(), ReadQuery(time_from=start, time_to=end, limit_records=100)
    ):
        records.extend(batch.records)
    # Full window was partial (its rows dropped); halves re-queried.
    assert [r.message for r in records] == ["disk full", "cron ran", "slow query"]
    assert len(azure_mock["requests"]) == 3


async def test_read_respects_record_limit(azure_mock: dict[str, Any]) -> None:
    _ = azure_mock
    connector = AzureConnector()
    batches = [b async for b in connector.read(_profile(), ReadQuery(limit_records=2))]
    assert sum(len(b.records) for b in batches) == 2
    assert batches[-1].truncated


def test_device_code_raises_instructions() -> None:
    class BlockingCredential:
        def get_token(self, *scopes: str, **kwargs: Any) -> Any:
            prompt = kwargs.get("prompt_callback")
            if prompt is not None:

                class Info:
                    message = "Visit https://microsoft.com/devicelogin code ABCD"

                prompt(Info())
            threading.Event().wait(30)
            raise AssertionError("must time out first")

    auth = AzureAuth.from_config({"auth": "device_code", "tenant_id": "t"})
    with pytest.raises(DeviceCodeRequiredError, match="devicelogin"):
        acquire_token(auth, BlockingCredential(), device_code_timeout=0.2)


def test_unknown_table_rejected() -> None:
    connector = AzureConnector()
    with pytest.raises(ValueError, match="Unknown table"):
        connector._query_text(_profile(table="Nope", kql=""))
    with pytest.raises(ValueError, match="requires config"):
        connector._query_text(_profile(table="", kql=""))


@needs_azure
async def test_live_syslog_query() -> None:
    """Live test: KQL over a real workspace (needs SP credentials)."""
    profile = ConnectionProfile(
        id="a",
        name="a",
        connector_type="azure",
        config={
            "workspace_id": WORKSPACE,
            "table": "Syslog",
            "auth": "client_secret",
            "tenant_id": os.environ["OPSAI_TEST_AZURE_TENANT_ID"],
            "client_id": os.environ["OPSAI_TEST_AZURE_CLIENT_ID"],
            "client_secret": os.environ["OPSAI_TEST_AZURE_CLIENT_SECRET"],
        },
    )
    connector = AzureConnector()
    assert (await connector.test(profile)).ok
    records = []
    async for batch in connector.read(profile, ReadQuery(limit_records=5)):
        records.extend(batch.records)
    assert records
