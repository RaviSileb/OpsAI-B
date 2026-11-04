"""Azure Monitor connector: KQL over the Log Analytics Query API."""

from __future__ import annotations

import threading
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
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

_DEFAULT_TIMEOUT = 60.0
_DEFAULT_LOOKBACK = timedelta(hours=24)
_MIN_SLICE = timedelta(minutes=5)
_MAX_SPLIT_DEPTH = 6

CLOUDS: dict[str, dict[str, str]] = {
    "public": {
        "authority": "https://login.microsoftonline.com",
        "endpoint": "https://api.loganalytics.io",
    },
    "government": {
        "authority": "https://login.microsoftonline.us",
        "endpoint": "https://api.loganalytics.us",
    },
    "china": {
        "authority": "https://login.chinacloudapi.cn",
        "endpoint": "https://api.loganalytics.azure.cn",
    },
}

TABLE_QUERIES: dict[str, str] = {
    "Syslog": "Syslog | project TimeGenerated, Computer, HostName, Facility,"
    " SeverityLevel, ProcessName, ProcessID, SyslogMessage",
    "Event": "Event | project TimeGenerated, Computer, EventLog, EventLevel,"
    " EventLevelName, EventID, Source, RenderedDescription",
    "ContainerLogV2": "ContainerLogV2 | project TimeGenerated, Computer,"
    " PodName, PodNamespace, ContainerName, ContainerId, LogMessage, LogSource",
    "AppTraces": "AppTraces | project TimeGenerated, AppRoleName, SeverityLevel,"
    " Message, OperationName, OperationId",
    "AppExceptions": "AppExceptions | project TimeGenerated, AppRoleName,"
    " SeverityLevel, ExceptionType, OuterMessage, InnermostMessage, OperationId",
    "AzureDiagnostics": "AzureDiagnostics | project TimeGenerated, Resource,"
    " ResourceGroup, Category, OperationName, ResultType, Message",
    "KubeEvents": "KubeEvents | project TimeGenerated, Computer, NameSpace,"
    " Name, Reason, Message, Count, FirstSeen, LastSeen",
}

TABLE_COLUMNS: dict[str, list[str]] = {}
for _table, _query in TABLE_QUERIES.items():
    _cols = _query.split("project", 1)[1].split(",")
    TABLE_COLUMNS[_table] = [col.strip() for col in _cols]

APPINSIGHTS_SEVERITY = {
    0: "Verbose",
    1: "Information",
    2: "Warning",
    3: "Error",
    4: "Critical",
}
WIN_EVENT_LEVEL = {1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}

_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_TOKEN_LOCK = threading.Lock()


class DeviceCodeRequiredError(Exception):
    """Raised when the user must complete a device-code flow in a browser."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class AzureAuth:
    """Validated authentication settings (FR-110)."""

    method: str
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    client_cert_path: str | None = None
    cloud: str = "public"
    authority_host: str | None = None
    endpoint: str | None = None

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> AzureAuth:
        """Validate auth settings and cloud selection."""
        method = str(config.get("auth", "client_secret") or "client_secret").lower()
        if method not in {
            "client_secret",
            "client_certificate",
            "managed_identity",
            "workload_identity",
            "azure_cli",
            "device_code",
        }:
            msg = f"Unsupported Azure auth method {method!r}"
            raise ValueError(msg)
        cloud = str(config.get("cloud", "public") or "public").lower()
        if cloud not in {*CLOUDS, "custom"}:
            msg = f"Unknown cloud {cloud!r} (public/government/china/custom)"
            raise ValueError(msg)
        authority_host = config.get("authority_host")
        endpoint = config.get("endpoint")
        if cloud == "custom" and not (authority_host and endpoint):
            msg = "custom cloud requires authority_host and endpoint"
            raise ValueError(msg)
        if method in {"client_secret", "client_certificate", "device_code"} and not config.get(
            "tenant_id"
        ):
            msg = f"auth {method!r} requires tenant_id"
            raise ValueError(msg)
        if method == "client_secret" and not config.get("client_secret"):
            msg = "client_secret auth requires client_secret (prefer credential store)"
            raise ValueError(msg)
        if method == "client_certificate" and not config.get("client_cert_path"):
            msg = "client_certificate auth requires client_cert_path (PEM file)"
            raise ValueError(msg)
        return cls(
            method=method,
            tenant_id=config.get("tenant_id"),
            client_id=config.get("client_id"),
            client_secret=config.get("client_secret"),
            client_cert_path=config.get("client_cert_path"),
            cloud=cloud,
            authority_host=str(authority_host) if authority_host else None,
            endpoint=str(endpoint).rstrip("/") if endpoint else None,
        )

    def resolved_endpoint(self) -> str:
        """Return the Log Analytics query endpoint for the cloud."""
        if self.endpoint:
            return self.endpoint
        return CLOUDS[self.cloud]["endpoint"]

    def resolved_authority(self) -> str:
        """Return the Entra authority host for the cloud."""
        if self.authority_host:
            return self.authority_host
        return CLOUDS[self.cloud]["authority"]

    def scope(self) -> str:
        """Return the token scope for the query endpoint."""
        return f"{self.resolved_endpoint()}/.default"

    def cache_key(self) -> str:
        """Return the token-cache key for these settings."""
        return "|".join([self.method, self.tenant_id or "", self.client_id or "", self.scope()])


def build_credential(auth: AzureAuth) -> Any:
    """Build the azure-identity credential for the method (FR-110)."""
    from azure.identity import (
        AzureCliCredential,
        CertificateCredential,
        ClientSecretCredential,
        DeviceCodeCredential,
        ManagedIdentityCredential,
        WorkloadIdentityCredential,
    )

    if auth.method == "client_secret":
        return ClientSecretCredential(
            str(auth.tenant_id),
            str(auth.client_id),
            str(auth.client_secret),
            authority=auth.resolved_authority(),
        )
    if auth.method == "client_certificate":
        return CertificateCredential(
            str(auth.tenant_id),
            str(auth.client_id),
            certificate_path=str(auth.client_cert_path),
            authority=auth.resolved_authority(),
        )
    if auth.method == "managed_identity":
        return ManagedIdentityCredential(client_id=auth.client_id)
    if auth.method == "workload_identity":
        return WorkloadIdentityCredential()
    if auth.method == "azure_cli":
        return AzureCliCredential()
    return DeviceCodeCredential(
        client_id=auth.client_id or "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        tenant_id=str(auth.tenant_id),
        authority=auth.resolved_authority(),
    )


def acquire_token(
    auth: AzureAuth,
    credential: Any,
    device_code_timeout: float = 30.0,
) -> str:
    """Return a cached or fresh token; device code raises with instructions."""
    key = auth.cache_key()
    with _TOKEN_LOCK:
        cached = _TOKEN_CACHE.get(key)
        if cached and cached[1] > time.time() + 60:
            return cached[0]
    if auth.method == "device_code":
        token = _device_code_token(credential, auth.scope(), device_code_timeout)
    else:
        token = credential.get_token(auth.scope())
    with _TOKEN_LOCK:
        _TOKEN_CACHE[key] = (token.token, float(token.expires_on))
    return str(token.token)


def _device_code_token(credential: Any, scope: str, timeout: float) -> Any:
    """Run the device flow briefly; raise instructions when input is needed."""
    import concurrent.futures

    captured: dict[str, str] = {}

    def prompt(info: Any) -> None:
        captured["message"] = str(getattr(info, "message", info))

    original = credential.get_token

    def patched(*args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("prompt_callback", prompt)
        return original(*args, **kwargs)

    credential.get_token = patched  # type: ignore[method-assign]
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        future = pool.submit(credential.get_token, scope)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            message = captured.get(
                "message", "Complete the device-code flow in a browser, then retry."
            )
            raise DeviceCodeRequiredError(message) from exc
    finally:
        # Do not wait for the polling worker; it ends on its own.
        pool.shutdown(wait=False, cancel_futures=True)
        credential.get_token = original  # type: ignore[method-assign]


def format_timespan(start: datetime | None, end: datetime | None) -> str:
    """Format the API timespan: absolute range or a lookback duration."""
    if start is not None and end is not None:
        return f"{start.isoformat()}/{end.isoformat()}"
    if start is not None:
        now = datetime.now(UTC)
        return f"{start.isoformat()}/{now.isoformat()}"
    return "PT24H"


def _row_value(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return None


def detect_level(row: dict[str, Any], level_field: str | None) -> str | None:
    """Map the row severity to a display name (FR-113)."""
    if level_field:
        value = row.get(level_field)
        return str(value) if value is not None else None
    app_sev = row.get("SeverityLevel")
    if isinstance(app_sev, bool):
        pass
    elif isinstance(app_sev, (int, float)) and "AppRoleName" in row:
        return APPINSIGHTS_SEVERITY.get(int(app_sev))
    elif isinstance(app_sev, str) and app_sev:
        # Syslog table: textual severity (err, warning, ...).
        return app_sev
    event_name = row.get("EventLevelName")
    if isinstance(event_name, str) and event_name:
        return event_name
    event_level = row.get("EventLevel")
    if isinstance(event_level, (int, float)) and not isinstance(event_level, bool):
        return WIN_EVENT_LEVEL.get(int(event_level))
    return None


def row_to_record(
    row: dict[str, Any],
    table: str,
    time_field: str = "TimeGenerated",
    host_fields: tuple[str, ...] = ("Computer",),
    service_field: str | None = None,
    level_field: str | None = None,
    message_fields: tuple[str, ...] = (
        "SyslogMessage",
        "RenderedDescription",
        "LogMessage",
        "Message",
        "OuterMessage",
    ),
) -> RawRecord:
    """Map one Log Analytics row to a raw record."""
    ts_raw = row.get(time_field)
    try:
        ts = isoparse(str(ts_raw)) if ts_raw else None
    except ValueError:
        ts = None
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    host = _row_value(row, *host_fields)
    service = row.get(service_field) if service_field else None
    if service is None:
        service = _row_value(row, "ProcessName", "ContainerName", "Source", "AppRoleName", "Name")
    message = _row_value(row, *message_fields)
    if message is None:
        message = " | ".join(f"{k}={v}" for k, v in row.items() if v is not None)
    return RawRecord(
        message=str(message),
        ts=ts,
        ts_raw=str(ts_raw) if ts_raw else None,
        level_raw=detect_level(row, level_field),
        origin_host=str(host) if host is not None else None,
        service=str(service) if service is not None else None,
        fields={k: v for k, v in row.items()},
        src_meta={"azure.table": table},
        raw=str(message),
    )


def parse_query_response(data: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """Return (rows, is_partial) from a query API response."""
    tables = data.get("tables", [])
    rows: list[dict[str, Any]] = []
    if tables:
        columns = [c.get("name", f"col{i}") for i, c in enumerate(tables[0].get("columns", []))]
        for values in tables[0].get("rows", []):
            rows.append(dict(zip(columns, values, strict=False)))
    partial = bool(data.get("partialTables"))
    error = data.get("error")
    if error and "partial" in str(error).lower():
        partial = True
    return rows, partial


@register
class AzureConnector(Connector):
    """Query Azure Log Analytics with KQL (read-only POST /query)."""

    name = "azure"

    # Test seams (unit tests inject fakes; production leaves them None).
    credential_factory: Callable[[AzureAuth], Any] | None = None
    http_transport: httpx.AsyncBaseTransport | None = None

    def describe(self) -> dict[str, Any]:
        return {
            "config_schema": {
                "workspace_id": "Log Analytics workspace id (required)",
                "kql": "KQL query (or table template below)",
                "table": f"template table: {', '.join(sorted(TABLE_QUERIES))}",
                "auth": "client_secret|client_certificate|managed_identity|"
                "workload_identity|azure_cli|device_code",
                "tenant_id": "Entra tenant id",
                "client_id": "service principal / app id",
                "client_secret": "SP secret (prefer credential store)",  # nosec B105 - config key name, not a secret
                "client_cert_path": "PEM certificate path (client_certificate)",
                "cloud": "public|government|china|custom (default public)",
                "authority_host": "custom Entra authority (cloud=custom)",
                "endpoint": "custom query endpoint (cloud=custom)",
                "time_field": "timestamp column (default TimeGenerated)",
                "level_field": "explicit severity column (default auto-detect)",
                "service_field": "explicit service column (default auto-detect)",
                "timeout": "request timeout in seconds (default 60)",
            },
            "auth": [
                "client-secret",
                "client-certificate",
                "managed-identity",
                "workload-identity",
                "azure-cli",
                "device-code",
            ],
        }

    def _query_text(self, profile: ConnectionProfile) -> tuple[str, str]:
        config = profile.config
        kql = str(config.get("kql", "") or "").strip()
        table = str(config.get("table", "") or "").strip()
        if kql:
            return kql, table or "custom"
        if table in TABLE_QUERIES:
            return TABLE_QUERIES[table], table
        if table:
            msg = f"Unknown table {table!r}; pass raw kql instead"
            raise ValueError(msg)
        msg = "Azure connector requires config.kql or config.table"
        raise ValueError(msg)

    def _workspace(self, profile: ConnectionProfile) -> str:
        workspace = str(profile.config.get("workspace_id", "") or "").strip()
        if not workspace:
            msg = "Azure connector requires config.workspace_id"
            raise ValueError(msg)
        return workspace

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout, transport=self.http_transport)

    async def _run_query(
        self,
        profile: ConnectionProfile,
        kql: str,
        start: datetime | None,
        end: datetime | None,
    ) -> dict[str, Any]:
        import asyncio

        auth = AzureAuth.from_config(profile.config)
        factory = self.credential_factory or build_credential
        credential = factory(auth)
        # azure-identity credentials are blocking; keep the loop free.
        token = await asyncio.to_thread(
            acquire_token,
            auth,
            credential,
            float(profile.config.get("device_code_timeout", 30.0)),
        )
        timeout = float(profile.config.get("timeout", _DEFAULT_TIMEOUT))
        body: dict[str, Any] = {"query": kql, "timespan": format_timespan(start, end)}
        extra = profile.config.get("additional_workspaces")
        if extra:
            body["workspaces"] = [self._workspace(profile), *[str(w) for w in extra]]
        async with self._client(timeout) as client:
            response = await client.post(
                f"{auth.resolved_endpoint()}/v1/workspaces/{self._workspace(profile)}/query",
                json=body,
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
            return dict(response.json())

    async def test(self, profile: ConnectionProfile) -> TestResult:
        steps: list[StepResult] = []
        try:
            kql, _table = self._query_text(profile)
            self._workspace(profile)
            AzureAuth.from_config(profile.config)
        except ValueError as exc:
            return TestResult(False, str(exc), [StepResult("config", False, str(exc))])
        try:
            data = await self._run_query(profile, f"{kql} | take 1", None, None)
        except DeviceCodeRequiredError as exc:
            steps.append(StepResult("device-code", False, exc.message[:300]))
            return TestResult(False, f"device code required: {exc.message[:200]}", steps)
        except (httpx.HTTPError, ValueError) as exc:
            steps.append(StepResult("query", False, str(exc)[:300]))
            return TestResult(False, str(exc)[:300], steps)
        rows, _partial = parse_query_response(data)
        steps.append(StepResult("auth", True, "token acquired"))
        steps.append(StepResult("query", True, f"KQL accepted ({len(rows)} probe row(s))"))
        return TestResult(True, "OK", steps)

    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        _ = profile
        if not path:
            return [{"name": name, "path": name, "size": 0} for name in sorted(TABLE_QUERIES)]
        columns = TABLE_COLUMNS.get(path, [])
        return [{"name": col, "path": f"{path}.{col}", "size": 0} for col in columns]

    async def _slices(
        self, profile: ConnectionProfile, kql: str, query: ReadQuery
    ) -> AsyncIterator[tuple[list[dict[str, Any]], str]]:
        """Yield (rows, table) per window, splitting on partial results (FR-112)."""
        _kql, table = self._query_text(profile)
        end = query.time_to or datetime.now(UTC)
        start = query.time_from or (end - _DEFAULT_LOOKBACK)
        pending: list[tuple[datetime, datetime, int]] = [(start, end, 0)]
        while pending:
            window_start, window_end, depth = pending.pop(0)
            data = await self._run_query(profile, kql, window_start, window_end)
            rows, partial = parse_query_response(data)
            width = (window_end - window_start).total_seconds()
            if partial and depth < _MAX_SPLIT_DEPTH and width > _MIN_SLICE.total_seconds() * 2:
                midpoint = window_start + (window_end - window_start) / 2
                pending.insert(0, (window_start, midpoint, depth + 1))
                pending.insert(1, (midpoint, window_end, depth + 1))
                continue
            yield rows, table

    async def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        kql, _table = self._query_text(profile)
        time_field = str(profile.config.get("time_field", "TimeGenerated"))
        level_field = profile.config.get("level_field")
        service_field = profile.config.get("service_field")
        emitted = 0
        emitted_bytes = 0
        truncated = False
        async for rows, table in self._slices(profile, kql, query):
            batch: list[RawRecord] = []
            for row in rows:
                record = row_to_record(
                    row,
                    table,
                    time_field=time_field,
                    level_field=str(level_field) if level_field else None,
                    service_field=str(service_field) if service_field else None,
                )
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

    def capabilities(self) -> dict[str, Any]:
        return {"tail": False, "time_pushdown": True}
