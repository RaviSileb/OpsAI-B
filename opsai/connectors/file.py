"""File connector: local paths, archives, JSON lines (TZ FR-010..FR-014)."""

from __future__ import annotations

import bz2
import gzip
import json
import lzma
import re
import zipfile
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from charset_normalizer import from_bytes

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
from opsai.core.normalize import (
    TS_PREFIX_RES,
    detect_origin_host,
    group_multiline,
    level_from_value,
    parse_timestamp,
)

_LEVEL_TOKEN_RE = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|CRITICAL|CRIT|FATAL|ALERT)\b",
    re.IGNORECASE,
)
_HOST_TOKEN_RE = re.compile(r"^(?=.*[A-Za-z-])[A-Za-z0-9_.-]+$")

_BATCH_SIZE = 1000
_PROBE_BYTES = 65536


def detect_encoding(path: Path) -> str:
    """Detect file encoding from the first 64 kB (default UTF-8)."""
    with path.open("rb") as handle:
        sample = handle.read(_PROBE_BYTES)
    if not sample:
        return "utf-8"
    if sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff"):
        return "utf-16"
    result = from_bytes(sample).best()
    if result is None or result.encoding is None:
        return "utf-8"
    return str(result.encoding)


def iter_files(pattern: str) -> list[Path]:
    """Expand a file path, directory or glob into a sorted file list."""
    candidate = Path(pattern).expanduser()
    if candidate.is_file():
        return [candidate]
    if candidate.is_dir():
        return sorted(p for p in candidate.iterdir() if p.is_file())
    parent = candidate.parent
    matches = sorted(parent.glob(candidate.name)) if parent.exists() else []
    return [p for p in matches if p.is_file()]


def open_text_lines(path: Path, encoding: str) -> Iterator[str]:
    """Yield decoded lines, transparently decompressing archives."""
    suffix = path.suffix.lower()
    if suffix == ".gz":
        handle = gzip.open(path, "rt", encoding=encoding, errors="replace")
        with handle:
            yield from handle
    elif suffix == ".bz2":
        handle = bz2.open(path, "rt", encoding=encoding, errors="replace")
        with handle:
            yield from handle
    elif suffix in {".xz", ".lzma"}:
        handle = lzma.open(path, "rt", encoding=encoding, errors="replace")
        with handle:
            yield from handle
    elif suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if not info.filename.lower().endswith((".log", ".txt", ".json", ".jsonl", ".out")):
                    continue
                with archive.open(info) as member:
                    text = member.read().decode(encoding, errors="replace")
                    yield from text.splitlines()
    else:
        with path.open("r", encoding=encoding, errors="replace") as handle:
            yield from handle


def _extract_ts_prefix(line: str) -> str | None:
    for pattern in TS_PREFIX_RES:
        match = pattern.match(line)
        if match:
            return match.group(1)
    return None


def parse_text_event(event: str, default_tz: str) -> RawRecord:
    """Parse one text event: timestamp prefix, level token, origin host."""
    first_line = event.split("\n", 1)[0]
    ts_raw = _extract_ts_prefix(first_line)
    ts = parse_timestamp(ts_raw, default_tz) if ts_raw else None
    level_match = _LEVEL_TOKEN_RE.search(first_line)
    level_raw = level_match.group(1).upper() if level_match else None
    host, _rule = detect_origin_host(event)
    service: str | None = None
    if host is None and ts is not None and level_raw is not None:
        # Common syslog layout: "<ts> <LEVEL> <host> <service> <message>".
        tokens = first_line.split()
        if len(tokens) >= 4 and _HOST_TOKEN_RE.match(tokens[2]):
            host = tokens[2].lower()
            service = tokens[3]
    return RawRecord(
        message=event,
        ts=ts,
        ts_raw=ts_raw,
        level_raw=level_raw,
        origin_host=host,
        service=service,
        raw=event,
    )


def parse_json_event(payload: dict[str, Any], default_tz: str) -> RawRecord:
    """Map a JSON object to a raw record (ECS-ish field names first)."""
    message = (
        payload.get("message") or payload.get("msg") or json.dumps(payload, ensure_ascii=False)
    )
    ts_raw = payload.get("@timestamp") or payload.get("timestamp") or payload.get("time")
    ts = parse_timestamp(ts_raw, default_tz) if ts_raw is not None else None
    level_raw = (
        payload.get("log", {}).get("level") if isinstance(payload.get("log"), dict) else None
    )
    level_raw = level_raw or payload.get("level") or payload.get("severity")
    host, _rule = detect_origin_host(str(message), payload)
    service = (
        payload.get("service", {}).get("name") if isinstance(payload.get("service"), dict) else None
    )
    service = service or payload.get("service") or payload.get("app") or payload.get("unit")
    return RawRecord(
        message=str(message),
        ts=ts,
        ts_raw=str(ts_raw) if ts_raw is not None else None,
        level_raw=str(level_raw) if level_raw is not None else None,
        origin_host=host,
        service=str(service) if service is not None else None,
        fields={k: v for k, v in payload.items() if k not in {"message", "msg"}},
        raw=json.dumps(payload, ensure_ascii=False),
    )


@register
class FileConnector(Connector):
    """Read local log files, directories and globs (read-only)."""

    name = "file"

    def describe(self) -> dict[str, Any]:
        return {
            "config_schema": {
                "path": "file, directory or glob (required)",
                "format": "auto|text|json (default auto)",
                "encoding": "auto-detected unless set",
                "tz": "default timezone for naive timestamps (default UTC)",
                "multiline": "group stack traces (default true)",
            },
            "auth": [],
        }

    async def test(self, profile: ConnectionProfile) -> TestResult:
        path = str(profile.config.get("path", ""))
        steps = [StepResult("resolve-path", False)]
        try:
            files = iter_files(path)
        except OSError as exc:
            steps[0].message = str(exc)
            return TestResult(False, f"Cannot resolve path: {exc}", steps)
        if not files:
            steps[0].message = "No files matched"
            return TestResult(False, "No files matched", steps)
        steps[0].ok = True
        steps[0].message = f"{len(files)} file(s)"
        unreadable = [str(p) for p in files if not _is_readable(p)][:5]
        steps.append(StepResult("read-access", not unreadable, "; ".join(unreadable)))
        ok = not unreadable
        return TestResult(ok, "OK" if ok else "Some files are not readable", steps)

    async def browse(self, profile: ConnectionProfile, path: str = "") -> list[dict[str, Any]]:
        base = path or str(profile.config.get("path", "."))
        return [
            {"name": p.name, "path": str(p), "size": p.stat().st_size} for p in iter_files(base)
        ]

    async def read(self, profile: ConnectionProfile, query: ReadQuery) -> AsyncIterator[RawBatch]:
        config = profile.config
        pattern = str(config.get("path", ""))
        fmt = str(config.get("format", "auto")).lower()
        encoding_cfg = str(config.get("encoding", "") or "").strip()
        default_tz = str(config.get("tz", "UTC") or "UTC")
        multiline = bool(config.get("multiline", True))
        emitted = 0
        emitted_bytes = 0
        truncated = False
        for path in iter_files(pattern):
            if path.suffix.lower() == ".evtx":
                continue  # python-evtx support is a documented next step
            encoding = encoding_cfg or detect_encoding(path)
            lines = list(open_text_lines(path, encoding))
            if query.tail_lines is not None:
                lines = lines[-query.tail_lines :]
            if fmt == "json" or (fmt == "auto" and _looks_like_json(lines)):
                events = _json_events(lines, default_tz)
            else:
                grouped = group_multiline(lines) if multiline else [ln.rstrip("\n") for ln in lines]
                events = [parse_text_event(event, default_tz) for event in grouped if event.strip()]
            batch: list[RawRecord] = []
            for event in events:
                if query.time_from and event.ts and event.ts < query.time_from:
                    continue
                if query.time_to and event.ts and event.ts > query.time_to:
                    continue
                cost = len(event.message.encode("utf-8", "replace"))
                if emitted >= query.limit_records or emitted_bytes + cost > query.limit_bytes:
                    truncated = True
                    break
                event.src_meta = {"file": str(path)}
                batch.append(event)
                emitted += 1
                emitted_bytes += cost
                if len(batch) >= _BATCH_SIZE:
                    yield RawBatch(records=batch)
                    batch = []
            if batch:
                yield RawBatch(records=batch, truncated=truncated)
            if truncated:
                break
        if truncated:
            yield RawBatch(records=[], truncated=True)

    def capabilities(self) -> dict[str, Any]:
        return {"tail": False, "time_pushdown": True}


def _is_readable(path: Path) -> bool:
    try:
        with path.open("rb"):
            return True
    except OSError:
        return False


def _looks_like_json(lines: list[str]) -> bool:
    checked = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("{"):
            return False
        checked += 1
        if checked >= 5:
            break
    return checked > 0


def _json_events(lines: list[str], default_tz: str) -> list[RawRecord]:
    events: list[RawRecord] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            events.append(parse_text_event(stripped, default_tz))
            continue
        if isinstance(payload, dict):
            events.append(parse_json_event(payload, default_tz))
        else:
            events.append(parse_text_event(stripped, default_tz))
    return events


def to_log_record(raw: RawRecord, source_type: str, fallback_host: str | None) -> Any:
    """Convert a raw record to a normalized LogRecord (shared helper)."""
    from opsai.core.normalize import LogRecord

    host = raw.origin_host
    rule = "connector" if host else None
    if not host:
        host, rule = detect_origin_host(raw.message, raw.fields, fallback=fallback_host)
    ts = raw.ts or datetime.now().astimezone()

    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return LogRecord(
        ts=ts,
        message=raw.message,
        source_type=source_type,
        origin_host=host,
        origin_host_rule=rule,
        service=raw.service,
        level=level_from_value(raw.level_raw),
        level_raw=raw.level_raw,
        ts_raw=raw.ts_raw,
        ts_quality=0 if raw.ts else 1,
        raw=raw.raw,
        fields=raw.fields,
        src_meta=raw.src_meta,
    )
