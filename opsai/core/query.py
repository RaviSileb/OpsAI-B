"""OQL subset parser: OQL text -> parameterized SQL (TZ FR-160..161).

Supported subset: free text, ``field:value``, quoted values, ``field:/regex/``,
``level`` / ``ts`` / ``rid`` comparisons, numeric comparisons on JSON fields
(``fields.latency_ms>100``), ``ts:last 15m``, ``in(field, a, b)``,
``exists:field``, ``AND`` / ``OR`` / ``NOT``, ``-`` negation and parentheses.
Adjacent atoms mean ``AND``.

All values become bound parameters; column names come from a whitelist and
JSON paths are validated, so fuzz input cannot inject SQL. Values containing
spaces, ``:`` or ``,`` must be quoted (``field:"C:\\logs\\app.log"``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from opsai.core.normalize import level_from_value

_COLUMN_FIELDS = {"rid", "ts", "source_type", "origin_host", "service", "level", "message"}
_JSON_ROOTS = {"fields", "src_meta"}
_PATH_PART = re.compile(r"^[A-Za-z0-9_]+$")
_FIELD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*)(>=|<=|!=|>|<|=|:)(.*)$")
_DURATION_RE = re.compile(r"^(\d+)([smhd])$")
_DURATION_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
DIALECTS = ("sqlite", "duckdb", "postgres")
_MAX_DEPTH = 50
_MAX_QUERY_LEN = 8000

# Source-specific fields (FR-164): OQL name -> (JSON column, path segments).
# Segments with dots address flat connector keys (e.g. fields."win.channel").
_EXACT_ALIASES: dict[str, tuple[str, list[str]]] = {
    "kafka.topic": ("fields", ["kafka_topic"]),
    "kafka.partition": ("fields", ["partition"]),
    "kafka.offset": ("fields", ["offset"]),
    "kafka.key": ("fields", ["kafka_key"]),
    "win.channel": ("fields", ["win.channel"]),
    "win.event_id": ("fields", ["win.event_id"]),
    "win.provider": ("fields", ["win.provider"]),
    "k8s.namespace": ("fields", ["namespace"]),
    "k8s.pod": ("fields", ["pod"]),
    "k8s.container": ("fields", ["container"]),
    "win.record_id": ("fields", ["win.record_id"]),
    "es.index": ("src_meta", ["index"]),
    "es.doc_id": ("src_meta", ["doc_id"]),
    "syslog.pri": ("fields", ["pri"]),
    "syslog.facility": ("fields", ["facility"]),
    "syslog.procid": ("fields", ["procid"]),
    "syslog.msgid": ("fields", ["msgid"]),
    "azure.table": ("src_meta", ["azure.table"]),
}


class OQLSyntaxError(ValueError):
    """Raised when an OQL query cannot be parsed or compiled."""


@dataclass
class _Text:
    value: str


@dataclass
class _FieldQuery:
    field: str
    value: str
    is_regex: bool = False


@dataclass
class _Comparison:
    field: str
    op: str
    value: str


@dataclass
class _TsRelative:
    delta: timedelta


@dataclass
class _Not:
    child: Any


@dataclass
class _And:
    children: list[Any]


@dataclass
class _Or:
    children: list[Any]


def _tokenize(text: str) -> list[str]:
    """Split OQL into tokens, keeping quoted strings and regexes whole."""
    tokens: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "(),":
            tokens.append(ch)
            i += 1
            continue
        if ch == '"':
            end = i + 1
            buf = ['"']
            while end < length:
                c = text[end]
                buf.append(c)
                end += 1
                if c == "\\" and end < length:
                    buf.append(text[end])
                    end += 1
                elif c == '"':
                    break
            else:
                msg = "Unterminated quoted string in OQL query"
                raise OQLSyntaxError(msg)
            tokens.append("".join(buf))
            i = end
            continue
        buf = []
        while i < length and not text[i].isspace() and text[i] not in '()",':
            buf.append(text[i])
            i += 1
        tokens.append("".join(buf))
    return tokens


def _unquote(token: str) -> str:
    inner = token[1:-1]
    return inner.replace('\\"', '"').replace("\\\\", "\\")


def _split_regex(token: str) -> str | None:
    """Return the pattern when the token is exactly ``/pattern/``."""
    if len(token) >= 2 and token.startswith("/") and token.endswith("/") and token != "/":  # nosec B105
        return token[1:-1]
    return None


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.depth = 0

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > _MAX_DEPTH:
            msg = f"OQL query nesting exceeds {_MAX_DEPTH} levels"
            raise OQLSyntaxError(msg)

    def _leave(self) -> None:
        self.depth -= 1

    def peek(self) -> str | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def next(self) -> str:
        token = self.peek()
        if token is None:
            msg = "Unexpected end of OQL query"
            raise OQLSyntaxError(msg)
        self.pos += 1
        return token

    def parse(self) -> Any:
        node = self.parse_or()
        rest = self.peek()
        if rest is not None:
            msg = f"Unexpected token {rest!r} in OQL query"
            raise OQLSyntaxError(msg)
        return node

    def parse_or(self) -> Any:
        children = [self.parse_and()]
        while (token := self.peek()) is not None and token.upper() == "OR":
            self.next()
            children.append(self.parse_and())
        if len(children) == 1:
            return children[0]
        return _Or(children)

    def parse_and(self) -> Any:
        children = [self.parse_not()]
        while True:
            token = self.peek()
            if token is None or token == ")" or token.upper() == "OR":  # nosec B105
                break
            if token.upper() == "AND":
                self.next()
            children.append(self.parse_not())
        if len(children) == 1:
            return children[0]
        return _And(children)

    def parse_not(self) -> Any:
        token = self.peek()
        if token is not None and token.upper() == "NOT":
            self.next()
            return self._negate()
        if token is not None and token.startswith("-"):
            self.next()
            rest = token[1:]
            if rest:
                self.tokens.insert(self.pos, rest)
            return self._negate()
        return self.parse_atom()

    def _negate(self) -> Any:
        self._enter()
        try:
            return _Not(self.parse_not())
        finally:
            self._leave()

    def parse_atom(self) -> Any:
        token = self.next()
        if token == "(":  # nosec B105
            self._enter()
            try:
                node = self.parse_or()
            finally:
                self._leave()
            closing = self.next()
            if closing != ")":
                msg = f"Expected ')' in OQL query, got {closing!r}"
                raise OQLSyntaxError(msg)
            return node
        if token == ")":  # nosec B105
            msg = "Unexpected ')' in OQL query"
            raise OQLSyntaxError(msg)
        if token.startswith('"'):
            return _Text(_unquote(token))
        if token.lower() == "in" and self.peek() == "(":
            return self._parse_in_list()
        pattern = _split_regex(token)
        if pattern is not None:
            return _FieldQuery("message", pattern, True)
        match = _FIELD_RE.match(token)
        if match:
            name, sep, rest = match.group(1), match.group(2), match.group(3)
            if rest.startswith('"'):
                value = self._gather_quoted(rest)
            else:
                value = rest if rest else self._next_value_token()
            if sep == ":":
                if name == "ts" and value.lower() == "last":
                    return self._parse_relative_time()
                inner_pattern = _split_regex(value)
                if inner_pattern is not None:
                    return _FieldQuery(name, inner_pattern, True)
                return _FieldQuery(name, value)
            return _Comparison(name, sep, value)
        return _Text(token)

    def _parse_in_list(self) -> Any:
        self.next()  # consume '('
        field = self.next()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", field):
            msg = f"Expected a field name in in(...), got {field!r}"
            raise OQLSyntaxError(msg)
        first_sep = self.next()
        if first_sep != ",":
            msg = f"Expected ',' after the field in in(...), got {first_sep!r}"
            raise OQLSyntaxError(msg)
        values: list[str] = []
        while True:
            token = self.next()
            if token in ("(", ")", ","):
                msg = f"Expected a value in in(...), got {token!r}"
                raise OQLSyntaxError(msg)
            values.append(_unquote(token) if token.startswith('"') else token)
            sep = self.next()
            if sep == ")":
                break
            if sep != ",":
                msg = f"Expected ',' or ')' in in(...), got {sep!r}"
                raise OQLSyntaxError(msg)
        children = []
        for value in values:
            inner_pattern = _split_regex(value)
            if inner_pattern is not None:
                children.append(_FieldQuery(field, inner_pattern, True))
            else:
                children.append(_FieldQuery(field, value))
        if len(children) == 1:
            return children[0]
        return _Or(children)

    def _parse_relative_time(self) -> _TsRelative:
        token = self.peek()
        match = _DURATION_RE.match((token or "").lower())
        if match is None:
            msg = f"Expected a duration like 15m after 'ts:last', got {token!r}"
            raise OQLSyntaxError(msg)
        self.next()
        amount = int(match.group(1))
        if amount <= 0:
            msg = f"Duration must be positive, got {token!r}"
            raise OQLSyntaxError(msg)
        return _TsRelative(timedelta(**{_DURATION_UNITS[match.group(2)]: amount}))

    def _gather_quoted(self, first: str) -> str:
        parts = [first]
        while True:
            joined = " ".join(parts)
            if len(joined) >= 2 and joined.endswith('"') and not joined.endswith('\\"'):
                return _unquote(joined)
            nxt = self.peek()
            if nxt is None:
                msg = "Unterminated quoted string in OQL query"
                raise OQLSyntaxError(msg)
            parts.append(self.next())

    def _next_value_token(self) -> str:
        token = self.next()
        if token.startswith('"'):
            return _unquote(token)
        if token in ("(", ")"):
            msg = f"Expected a value in OQL query, got {token!r}"
            raise OQLSyntaxError(msg)
        return token


def _validate_json_path(root: str, dotted: str) -> list[str]:
    parts = dotted.split(".")[1:]
    if not parts:
        msg = f"Field '{dotted}' needs a JSON path after '{root}'"
        raise OQLSyntaxError(msg)
    for part in parts:
        if not _PATH_PART.match(part):
            msg = f"Invalid path segment {part!r} in field '{dotted}'"
            raise OQLSyntaxError(msg)
    return parts


def _resolve_field(field: str) -> tuple[str | None, list[str]]:
    """Resolve a field to (JSON column, path segments); column None = plain column."""
    if field in _COLUMN_FIELDS:
        return None, [field]
    if field in _EXACT_ALIASES:
        column, segments = _EXACT_ALIASES[field]
        return column, list(segments)
    for prefix, make in (
        ("kafka.header.", lambda name: ("fields", [f"header_{name}"])),
        ("k8s.label.", lambda name: ("fields", ["labels", name])),
        ("loki.label.", lambda name: ("fields", [f"label_{name}"])),
    ):
        if field.startswith(prefix):
            name = field[len(prefix) :]
            if not _PATH_PART.match(name):
                msg = f"Invalid name {name!r} in field '{field}'"
                raise OQLSyntaxError(msg)
            return make(name)
    root = field.split(".", 1)[0]
    if root in _JSON_ROOTS:
        column = "fields" if root == "fields" else "src_meta"
        return column, _validate_json_path(root, field)
    msg = f"Unknown field '{field}'"
    raise OQLSyntaxError(msg)


def _quote_segment(segment: str) -> str:
    if _PATH_PART.fullmatch(segment):
        return segment
    return f'"{segment}"'


def _json_sql(column: str, segments: list[str], dialect: str) -> str:
    if dialect == "postgres":
        # JSONB chain: all but the last step keep JSON, last extracts text.
        expr = f'"{column}"'
        for part in segments[:-1]:
            expr += f"->'{part}'"
        return expr + f"->>'{segments[-1]}'"
    path = "$." + ".".join(_quote_segment(part) for part in segments)
    if dialect == "duckdb":
        # json_extract returns quoted JSON; _string matches SQLite semantics.
        return f"json_extract_string({column}, '{path}')"
    return f"json_extract({column}, '{path}')"


def _column_sql(field: str, dialect: str) -> str:
    column, segments = _resolve_field(field)
    if column is None:
        return f'"{segments[0]}"'
    return _json_sql(column, segments, dialect)


def _text_sql(field: str, dialect: str) -> str:
    """Return the text-cast expression for value comparisons on JSON fields."""
    column, segments = _resolve_field(field)
    if column is None or dialect == "postgres":
        # Plain columns compare natively; PG ->> already yields text.
        return f'"{segments[0]}"' if column is None else _json_sql(column, segments, dialect)
    # Numbers stored in JSON would never equal string parameters otherwise.
    return f"CAST({_json_sql(column, segments, dialect)} AS TEXT)"


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _compile_node(node: Any, params: list[Any], dialect: str, now: datetime) -> str:
    if isinstance(node, _Text):
        params.append(f"%{_like_escape(node.value.lower())}%")
        return "\"message_lc\" LIKE ? ESCAPE '\\'"
    if isinstance(node, _Not):
        return f"(NOT {_compile_node(node.child, params, dialect, now)})"
    if isinstance(node, _And):
        parts = [_compile_node(child, params, dialect, now) for child in node.children]
        return "(" + " AND ".join(parts) + ")"
    if isinstance(node, _Or):
        parts = [_compile_node(child, params, dialect, now) for child in node.children]
        return "(" + " OR ".join(parts) + ")"
    if isinstance(node, _FieldQuery):
        return _compile_field_query(node, params, dialect)
    if isinstance(node, _Comparison):
        return _compile_comparison(node, params, dialect)
    if isinstance(node, _TsRelative):
        params.append((now - node.delta).isoformat())
        return '("ts" >= ?)'
    msg = f"Unsupported OQL node: {node!r}"
    raise OQLSyntaxError(msg)


def _compile_field_query(node: _FieldQuery, params: list[Any], dialect: str) -> str:
    if node.field == "exists":
        column = _column_sql(node.value, dialect)
        return f"({column} IS NOT NULL)"
    column = _column_sql(node.field, dialect)
    if node.is_regex:
        try:
            re.compile(node.value)
        except re.error as exc:
            msg = f"Invalid regex /{node.value}/: {exc}"
            raise OQLSyntaxError(msg) from exc
        params.append(node.value)
        if dialect == "duckdb":
            return f"regexp_matches({column}, ?)"
        if dialect == "postgres":
            return f"({column} ~ ?)"
        return f"({column} REGEXP ?)"
    if node.field == "level":
        level = level_from_value(node.value)
        if level is None:
            msg = f"Unknown level {node.value!r}"
            raise OQLSyntaxError(msg)
        params.append(level)
        return f"({column} = ?)"
    if node.field == "message":
        params.append(f"%{_like_escape(node.value.lower())}%")
        return "\"message_lc\" LIKE ? ESCAPE '\\'"
    text = _text_sql(node.field, dialect)
    if "*" in node.value:
        params.append(_like_escape(node.value).replace("*", "%"))
        return f"({text} LIKE ? ESCAPE '\\')"
    params.append(node.value)
    return f"({text} = ?)"


def _compile_comparison(node: _Comparison, params: list[Any], dialect: str) -> str:
    if node.field == "level":
        level = level_from_value(node.value)
        if level is None:
            msg = f"Unknown level {node.value!r}"
            raise OQLSyntaxError(msg)
        params.append(level)
        return f'("level" {node.op} ?)'
    if node.field == "rid":
        try:
            params.append(int(node.value))
        except ValueError as exc:
            msg = f"Invalid rid {node.value!r}"
            raise OQLSyntaxError(msg) from exc
        return f'("rid" {node.op} ?)'
    if node.field == "ts":
        params.append(node.value)
        return f'("ts" {node.op} ?)'
    column, segments = _resolve_field(node.field)
    if column is None:
        msg = f"Comparisons support only level, ts, rid and JSON fields (got '{node.field}')"
        raise OQLSyntaxError(msg)
    try:
        params.append(float(node.value))
    except ValueError as exc:
        msg = f"Comparison on '{node.field}' needs a numeric value (got {node.value!r})"
        raise OQLSyntaxError(msg) from exc
    return f"(CAST({_json_sql(column, segments, dialect)} AS REAL) {node.op} ?)"


def compile_oql(
    oql: str, dialect: str = "sqlite", now: datetime | None = None
) -> tuple[str, list[Any]]:
    """Compile OQL to ``(where_sql, params)`` for the given SQL dialect."""
    if dialect not in DIALECTS:
        msg = f"Unknown OQL dialect '{dialect}'"
        raise NotImplementedError(msg)
    text = (oql or "").strip()
    if not text:
        return "1=1", []
    if len(text) > _MAX_QUERY_LEN:
        msg = f"OQL query exceeds {_MAX_QUERY_LEN} characters"
        raise OQLSyntaxError(msg)
    node = _Parser(_tokenize(text)).parse()
    params: list[Any] = []
    where = _compile_node(node, params, dialect, now or datetime.now(UTC))
    if dialect == "postgres":
        # Safe: fragments never contain a literal '?' (paths are validated,
        # values are bound parameters).
        where = where.replace("?", "%s")
    return where, params
