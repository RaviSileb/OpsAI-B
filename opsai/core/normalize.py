"""Log normalization: levels, timestamps, multiline grouping, origin host.

Implements TZ FR-120 (level mapping), FR-121 (multiline), FR-130 (origin host)
and the unified record shape from TZ 3.2.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

TRACE = 0
DEBUG = 1
INFO = 2
NOTICE = 3
WARN = 4
ERROR = 5
CRITICAL = 6
ALERT = 7
EMERGENCY = 8

LEVEL_NAMES = {
    TRACE: "TRACE",
    DEBUG: "DEBUG",
    INFO: "INFO",
    NOTICE: "NOTICE",
    WARN: "WARN",
    ERROR: "ERROR",
    CRITICAL: "CRITICAL",
    ALERT: "ALERT",
    EMERGENCY: "EMERGENCY",
}

_TEXT_LEVELS: dict[str, int] = {
    "TRACE": TRACE,
    "TRC": TRACE,
    "DEBUG": DEBUG,
    "DBG": DEBUG,
    "D": DEBUG,
    "FINE": DEBUG,
    "FINER": TRACE,
    "FINEST": TRACE,
    "INFO": INFO,
    "INF": INFO,
    "INFORMATION": INFO,
    "I": INFO,
    "NOTICE": NOTICE,
    "NOT": NOTICE,
    "WARN": WARN,
    "WARNING": WARN,
    "WRN": WARN,
    "W": WARN,
    "ERROR": ERROR,
    "ERR": ERROR,
    "ERRO": ERROR,
    "E": ERROR,
    "SEVERE": ERROR,
    "CRITICAL": CRITICAL,
    "CRIT": CRITICAL,
    "C": CRITICAL,
    "FATAL": ALERT,
    "ALERT": ALERT,
    "A": ALERT,
    "EMERG": EMERGENCY,
    "EMERGENCY": EMERGENCY,
    "VERBOSE": DEBUG,
    "AUDIT SUCCESS": INFO,
    "AUDIT FAILURE": ERROR,
}

_WINDOWS_LEVELS = {1: CRITICAL, 2: ERROR, 3: WARN, 4: INFO, 5: DEBUG}

_KNOWN_HOST_FIELDS = (
    "host.name",
    "hostname",
    "host",
    "_HOSTNAME",
    "Computer",
    "computer",
    "kubernetes.node_name",
    "node",
    "instance",
)

_HOST_MESSAGE_PATTERNS = (
    re.compile(r"\bhost\s*[:=]\s*([A-Za-z0-9_][A-Za-z0-9_.-]*)", re.IGNORECASE),
    re.compile(r"\bhostname\s*[:=]\s*([A-Za-z0-9_][A-Za-z0-9_.-]*)", re.IGNORECASE),
    re.compile(r"\bserver\s+([A-Za-z0-9_][A-Za-z0-9_.-]*)", re.IGNORECASE),
    re.compile(r"\bon\s+([a-z0-9][a-z0-9-]*\.[a-z0-9.-]+)", re.IGNORECASE),
)

_CONTINUATION_PREFIXES = (
    " ",
    "\t",
    "at ",
    "Caused by:",
    "Traceback",
    "... ",
    "--- ",
    "| ",
    "Suppressed:",
)

TS_PREFIX_RES = (
    re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d:?\d{2})?)"),
    re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})"),
    re.compile(r"^(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})"),
    re.compile(r"^(\d{10}(?:\.\d+)?)"),
    re.compile(r"^(\d{4}-\d{2}-\d{2})\b"),
)


def has_ts_prefix(line: str) -> bool:
    """Return True when the line starts with a known timestamp prefix."""
    return any(pattern.match(line) for pattern in TS_PREFIX_RES)


_EPOCH_RE = re.compile(r"^\d+(?:\.\d+)?$")


def level_from_value(value: Any, source: str = "syslog") -> int | None:
    """Map a raw level value to the unified 0-8 scale (None = unknown)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if source == "windows":
            return _WINDOWS_LEVELS.get(value)
        if 0 <= value <= 8:
            return value
        return None
    if isinstance(value, float):
        as_int = int(value)
        return level_from_value(as_int, source)
    text = str(value).strip().upper()
    if not text:
        return None
    if text in _TEXT_LEVELS:
        return _TEXT_LEVELS[text]
    if re.fullmatch(r"[1-5]\d\d", text):
        code = int(text)
        if code >= 500:
            return ERROR
        if code >= 400:
            return WARN
        return INFO
    return None


def level_name(level: int | None) -> str:
    """Return the display name for a unified level."""
    if level is None:
        return "UNKNOWN"
    return LEVEL_NAMES.get(level, "UNKNOWN")


def parse_timestamp(value: Any, default_tz: str = "UTC") -> datetime | None:
    """Parse a timestamp value into UTC datetime (None = unparsable)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))
    text = str(value).strip()
    if not text:
        return None
    if _EPOCH_RE.match(text):
        try:
            return _from_epoch(float(text))
        except (OverflowError, OSError, ValueError):
            return None
    try:
        from dateutil import parser as dateutil_parser

        parsed = dateutil_parser.parse(text)
    except (ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        try:
            tz = ZoneInfo(default_tz)
        except Exception:  # noqa: BLE001 - unknown zone falls back to UTC
            tz = UTC  # type: ignore[assignment]
        parsed = parsed.replace(tzinfo=tz)
    return parsed.astimezone(UTC)


def _from_epoch(value: float) -> datetime | None:
    magnitude = abs(value)
    if magnitude >= 1e17:  # nanoseconds
        value = value / 1e9
    elif magnitude >= 1e14:  # microseconds
        value = value / 1e6
    elif magnitude >= 1e11:  # milliseconds
        value = value / 1e3
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def is_continuation_line(line: str) -> bool:
    """Return True when the line belongs to the previous event (FR-121)."""
    if not line:
        return True
    for prefix in _CONTINUATION_PREFIXES:
        if line.startswith(prefix):
            return True
    if re.match(r'^\s*File "', line):
        return True
    return False


def group_multiline(
    lines: list[str],
    max_lines: int = 500,
    max_bytes: int = 65536,
) -> list[str]:
    """Group raw lines into events; stack traces stay a single event.

    A line without a timestamp joins the current event only when that event
    started with a timestamped line (FR-121); timestamp-less logs keep one
    event per line.
    """
    events: list[str] = []
    current: list[str] = []
    current_bytes = 0
    current_has_ts = False

    def flush() -> None:
        if current:
            events.append("\n".join(current))

    for line in lines:
        stripped_nl = line.rstrip("\n")
        continuation = is_continuation_line(stripped_nl) or (
            bool(current) and current_has_ts and not has_ts_prefix(stripped_nl)
        )
        starts_new = bool(current) and not continuation
        too_long = len(current) >= max_lines or current_bytes >= max_bytes
        if starts_new or too_long:
            flush()
            current = []
            current_bytes = 0
            current_has_ts = False
        if not current:
            current_has_ts = has_ts_prefix(stripped_nl)
        current.append(stripped_nl)
        current_bytes += len(stripped_nl.encode("utf-8", "replace"))
    flush()
    return events


def _lookup_dotted(data: dict[str, Any], dotted: str) -> Any:
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def detect_origin_host(
    message: str = "",
    fields: dict[str, Any] | None = None,
    explicit: str | None = None,
    fallback: str | None = None,
    short_name: bool = False,
) -> tuple[str | None, str | None]:
    """Determine the origin host and the rule used (FR-130).

    Order: explicit mapping, known fields, message patterns, source fallback.
    """
    if explicit:
        return _normalize_host(explicit, short_name), "explicit"
    if fields:
        for name in _KNOWN_HOST_FIELDS:
            found = _lookup_dotted(fields, name)
            if isinstance(found, str) and found.strip():
                return _normalize_host(found, short_name), f"field:{name}"
    if message:
        for pattern in _HOST_MESSAGE_PATTERNS:
            match = pattern.search(message)
            if match:
                return _normalize_host(match.group(1), short_name), "message-pattern"
    if fallback:
        return _normalize_host(fallback, short_name), "source"
    return None, None


def _normalize_host(host: str, short_name: bool) -> str:
    cleaned = host.strip().strip("\"'").rstrip(".").lower()
    if short_name and "." in cleaned:
        cleaned = cleaned.split(".", 1)[0]
    return cleaned


@dataclass
class LogRecord:
    """Unified log record (TZ 3.2 subset used by the MVP session store)."""

    ts: datetime
    message: str
    source_type: str = "file"
    origin_host: str | None = None
    origin_host_rule: str | None = None
    service: str | None = None
    level: int | None = None
    level_raw: str | None = None
    ts_raw: str | None = None
    ts_quality: int = 0
    raw: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    src_meta: dict[str, Any] = field(default_factory=dict)
    template_id: int | None = None
    rid: int | None = None

    def size_bytes(self) -> int:
        """Return the byte size counted against the session limit."""
        total = len(self.message.encode("utf-8", "replace"))
        if self.raw:
            total += len(self.raw.encode("utf-8", "replace"))
        return total
