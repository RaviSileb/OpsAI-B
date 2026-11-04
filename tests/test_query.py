"""Tests for the OQL subset parser (FR-160..161, FR-164)."""

from __future__ import annotations

import random
import re
import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from opsai.app.bootstrap import init_app_db
from opsai.app.config import Settings
from opsai.core.normalize import ERROR, INFO, WARN, LogRecord
from opsai.core.query import OQLSyntaxError, compile_oql
from opsai.core.session import SessionManager
from tests.containers import Container, docker_available

PG_OQL_PORT = 15433
PG_OQL_DSN = f"host=127.0.0.1 port={PG_OQL_PORT} dbname=postgres user=postgres password=opsai-pw"

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)

# (oql, expected WHERE, expected params) for the sqlite dialect.
SUITE: list[tuple[str, str, list[Any]]] = [
    # Free text.
    ("timeout", "\"message_lc\" LIKE ? ESCAPE '\\'", ["%timeout%"]),
    ("Timeout", "\"message_lc\" LIKE ? ESCAPE '\\'", ["%timeout%"]),
    (
        "foo bar",
        "(\"message_lc\" LIKE ? ESCAPE '\\' AND \"message_lc\" LIKE ? ESCAPE '\\')",
        ["%foo%", "%bar%"],
    ),
    # Level names map to the 0-8 scale.
    ("level:ERROR", '("level" = ?)', [5]),
    ("level:error", '("level" = ?)', [5]),
    ("level>=WARN", '("level" >= ?)', [4]),
    ("level!=INFO", '("level" != ?)', [2]),
    ("level<ERROR", '("level" < ?)', [5]),
    # Plain columns.
    ("origin_host:web-01", '("origin_host" = ?)', ["web-01"]),
    ("origin_host:web-*", "(\"origin_host\" LIKE ? ESCAPE '\\')", ["web-%"]),
    ("service:api", '("service" = ?)', ["api"]),
    ("service:app-*", "(\"service\" LIKE ? ESCAPE '\\')", ["app-%"]),
    ("source_type:kafka", '("source_type" = ?)', ["kafka"]),
    ("rid:42", '("rid" = ?)', ["42"]),
    ("rid>100", '("rid" > ?)', [100]),
    # Message field.
    ("message:timeout", "\"message_lc\" LIKE ? ESCAPE '\\'", ["%timeout%"]),
    (
        'message:"connection refused"',
        "\"message_lc\" LIKE ? ESCAPE '\\'",
        ["%connection refused%"],
    ),
    # Timestamps.
    ("ts:2026-10-28", '("ts" = ?)', ["2026-10-28"]),
    ("ts>=2026-10-28T10:00", '("ts" >= ?)', ["2026-10-28T10:00"]),
    ("ts<2026-10-28", '("ts" < ?)', ["2026-10-28"]),
    # Generic JSON fields.
    (
        "fields.request_id:abc",
        "(CAST(json_extract(fields, '$.request_id') AS TEXT) = ?)",
        ["abc"],
    ),
    (
        "fields.msg:fail*",
        "(CAST(json_extract(fields, '$.msg') AS TEXT) LIKE ? ESCAPE '\\')",
        ["fail%"],
    ),
    (
        "fields.http.status:500",
        "(CAST(json_extract(fields, '$.http.status') AS TEXT) = ?)",
        ["500"],
    ),
    (
        "fields.latency_ms>100",
        "(CAST(json_extract(fields, '$.latency_ms') AS REAL) > ?)",
        [100.0],
    ),
    ("fields.ok:true", "(CAST(json_extract(fields, '$.ok') AS TEXT) = ?)", ["true"]),
    (
        "fields.0x:y",
        "(CAST(json_extract(fields, '$.0x') AS TEXT) = ?)",
        ["y"],
    ),
    (
        "src_meta.index:logs",
        "(CAST(json_extract(src_meta, '$.index') AS TEXT) = ?)",
        ["logs"],
    ),
    (
        "exists:fields.request_id",
        "(json_extract(fields, '$.request_id') IS NOT NULL)",
        [],
    ),
    # Source aliases (FR-164).
    (
        "kafka.topic:orders",
        "(CAST(json_extract(fields, '$.kafka_topic') AS TEXT) = ?)",
        ["orders"],
    ),
    (
        "kafka.partition:3",
        "(CAST(json_extract(fields, '$.partition') AS TEXT) = ?)",
        ["3"],
    ),
    (
        "kafka.offset>=1000",
        "(CAST(json_extract(fields, '$.offset') AS REAL) >= ?)",
        [1000.0],
    ),
    (
        "kafka.header.trace_id:t-1",
        "(CAST(json_extract(fields, '$.header_trace_id') AS TEXT) = ?)",
        ["t-1"],
    ),
    (
        "win.channel:Security",
        "(CAST(json_extract(fields, '$.\"win.channel\"') AS TEXT) = ?)",
        ["Security"],
    ),
    (
        "win.event_id:4624",
        "(CAST(json_extract(fields, '$.\"win.event_id\"') AS TEXT) = ?)",
        ["4624"],
    ),
    (
        "win.record_id:99",
        "(CAST(json_extract(fields, '$.\"win.record_id\"') AS TEXT) = ?)",
        ["99"],
    ),
    (
        "k8s.namespace:prod",
        "(CAST(json_extract(fields, '$.namespace') AS TEXT) = ?)",
        ["prod"],
    ),
    (
        "k8s.pod:api-*",
        "(CAST(json_extract(fields, '$.pod') AS TEXT) LIKE ? ESCAPE '\\')",
        ["api-%"],
    ),
    (
        "k8s.label.app:api",
        "(CAST(json_extract(fields, '$.labels.app') AS TEXT) = ?)",
        ["api"],
    ),
    (
        "k8s.label.9lives:x",
        "(CAST(json_extract(fields, '$.labels.9lives') AS TEXT) = ?)",
        ["x"],
    ),
    (
        "loki.label.job:varlogs",
        "(CAST(json_extract(fields, '$.label_job') AS TEXT) = ?)",
        ["varlogs"],
    ),
    (
        "es.index:logs-1",
        "(CAST(json_extract(src_meta, '$.index') AS TEXT) = ?)",
        ["logs-1"],
    ),
    (
        "syslog.facility:daemon",
        "(CAST(json_extract(fields, '$.facility') AS TEXT) = ?)",
        ["daemon"],
    ),
    (
        "azure.table:Syslog",
        "(CAST(json_extract(src_meta, '$.\"azure.table\"') AS TEXT) = ?)",
        ["Syslog"],
    ),
    # Regex values.
    ("message:/time.?out/", '("message" REGEXP ?)', ["time.?out"]),
    ("service:/api-\\d+/", '("service" REGEXP ?)', ["api-\\d+"]),
    (
        "fields.code:/5\\d\\d/",
        "(json_extract(fields, '$.code') REGEXP ?)",
        ["5\\d\\d"],
    ),
    # in(...) lists.
    (
        "in(service, api, worker)",
        '(("service" = ?) OR ("service" = ?))',
        ["api", "worker"],
    ),
    ("in(level, ERROR, WARN)", '(("level" = ?) OR ("level" = ?))', [5, 4]),
    (
        "in(kafka.topic, a, b)",
        "((CAST(json_extract(fields, '$.kafka_topic') AS TEXT) = ?)"
        " OR (CAST(json_extract(fields, '$.kafka_topic') AS TEXT) = ?))",
        ["a", "b"],
    ),
    ('in(service, "a b", c)', '(("service" = ?) OR ("service" = ?))', ["a b", "c"]),
    ("NOT in(service, a)", '(NOT ("service" = ?))', ["a"]),
    # Relative time.
    ("ts:last 15m", '("ts" >= ?)', ["2026-10-28T11:45:00+00:00"]),
    ("ts:last 2h", '("ts" >= ?)', ["2026-10-28T10:00:00+00:00"]),
    # Boolean combinations.
    (
        "level:ERROR AND service:api",
        '(("level" = ?) AND ("service" = ?))',
        [5, "api"],
    ),
    (
        "level:ERROR OR level:WARN",
        '(("level" = ?) OR ("level" = ?))',
        [5, 4],
    ),
    ("NOT level:INFO", '(NOT ("level" = ?))', [2]),
    ("-service:health", '(NOT ("service" = ?))', ["health"]),
    (
        "NOT (service:api OR service:web)",
        '(NOT (("service" = ?) OR ("service" = ?)))',
        ["api", "web"],
    ),
    (
        "level:ERROR OR service:api AND NOT service:noise",
        '(("level" = ?) OR (("service" = ?) AND (NOT ("service" = ?))))',
        [5, "api", "noise"],
    ),
    (
        "level>=WARN AND ts:last 1h AND kafka.topic:orders",
        '(("level" >= ?) AND ("ts" >= ?)'
        " AND (CAST(json_extract(fields, '$.kafka_topic') AS TEXT) = ?))",
        [4, "2026-10-28T11:00:00+00:00", "orders"],
    ),
    # Injection attempts stay parameters.
    (
        "service:\"x' OR '1'='1\"",
        '("service" = ?)',
        ["x' OR '1'='1"],
    ),
]


@pytest.mark.parametrize(("oql", "want_where", "want_params"), SUITE)
def test_oql_suite(oql: str, want_where: str, want_params: list[Any]) -> None:
    """Each documented query compiles to the exact SQL and parameters."""
    where, params = compile_oql(oql, now=NOW)
    assert where == want_where
    assert params == want_params


def test_oql_suite_size() -> None:
    assert len(SUITE) >= 50, f"suite shrank to {len(SUITE)} queries"


ERRORS = [
    "level:",
    "ts>",
    "ts>=",
    "(level:ERROR",
    "level:ERROR)",
    "NOT",
    "level:ERROR AND",
    "()",
    "in(",
    "in()",
    "in(service)",
    "in(service,)",
    "in(service,,a)",
    "in(service,a",
    "in(service, a,)",
    "in(1x,a)",
    "level:UNKNOWN",
    "level:5",
    "level>BOGUS",
    "bogus:x",
    "service>api",
    "fields.a>xyz",
    "rid>abc",
    "ts:last",
    "ts:last xyz",
    "ts:last 0m",
    "ts:last 5x",
    "kafka.header.:x",
    '"unterminated',
    '"a\\"',
    "exists:",
    "exists:bogus",
    "(" * 5000,
    "NOT " * 1600 + "x",
    "x" * 9000,
]


@pytest.mark.parametrize("oql", ERRORS)
def test_oql_errors(oql: str) -> None:
    """Malformed queries fail with OQLSyntaxError, never a crash."""
    with pytest.raises(OQLSyntaxError):
        compile_oql(oql, now=NOW)


def test_ts_last_defaults_to_now() -> None:
    where, params = compile_oql("ts:last 1m")
    assert where == '("ts" >= ?)'
    delta = (datetime.now(UTC) - datetime.fromisoformat(params[0])).total_seconds()
    assert 55 <= delta <= 65


def _seeded_sqlite() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE records (rid INTEGER PRIMARY KEY, ts TEXT, source_type TEXT,"
        " origin_host TEXT, service TEXT, level INTEGER, message TEXT,"
        " message_lc TEXT, fields TEXT, src_meta TEXT)"
    )
    conn.execute(
        "INSERT INTO records VALUES"
        " (1, '2026-10-28T11:50:00+00:00', 'kafka', 'broker-1', 'orders', 3,"
        " 'order placed', 'order placed',"
        ' \'{"kafka_topic":"orders","partition":3,"offset":150'
        ' ,"header_trace_id":"t-1"}\', \'{}\'),'
        " (2, '2026-10-28T11:55:00+00:00', 'windows', 'DC01', 'winevt', 4,"
        " 'logon failure', 'logon failure',"
        ' \'{"win.channel":"Security","win.event_id":4625'
        " ,\"win.record_id\":99}', '{}'),"
        " (3, '2026-10-28T11:58:00+00:00', 'kubernetes', 'node-1', 'api', 5,"
        " 'panic in handler', 'panic in handler',"
        ' \'{"pod":"api-7d4","namespace":"prod","labels":{"app":"api"}}\', \'{}\'),'
        " (4, '2026-10-20T08:00:00+00:00', 'azure', 'law-1', 'syslog', 3,"
        " 'old entry', 'old entry', '{}', '{\"azure.table\":\"Syslog\"}')"
    )
    conn.create_function(
        "regexp", 2, lambda pattern, value: re.search(pattern, value or "") is not None
    )
    return conn


ALIAS_ROWS: list[tuple[str, list[int]]] = [
    ("kafka.topic:orders", [1]),
    ("kafka.partition:3", [1]),
    ("kafka.offset>=100", [1]),
    ("kafka.offset>=200", []),
    ("kafka.header.trace_id:t-1", [1]),
    ("win.channel:Security", [2]),
    ("win.event_id:4625", [2]),
    ("win.record_id:99", [2]),
    ("k8s.namespace:prod", [3]),
    ("k8s.pod:api-*", [3]),
    ("k8s.label.app:api", [3]),
    ("azure.table:Syslog", [4]),
    ("in(level, ERROR, WARN)", [2, 3]),
    ("ts:last 1h", [1, 2, 3]),
    ("level>=WARN AND ts:last 1h", [2, 3]),
]


@pytest.mark.parametrize(("oql", "want_rids"), ALIAS_ROWS)
def test_alias_queries_match_rows_sqlite(oql: str, want_rids: list[int]) -> None:
    """Alias SQL executes and matches the rows written by connectors."""
    where, params = compile_oql(oql, now=NOW)
    conn = _seeded_sqlite()
    rows = conn.execute(f"SELECT rid FROM records WHERE {where} ORDER BY rid", params).fetchall()
    assert [row[0] for row in rows] == want_rids


@pytest.mark.parametrize(("oql", "want_rids"), ALIAS_ROWS)
def test_alias_queries_match_rows_duckdb(oql: str, want_rids: list[int]) -> None:
    """Same alias coverage on the DuckDB dialect."""
    import duckdb

    where, params = compile_oql(oql, dialect="duckdb", now=NOW)
    conn = duckdb.connect(":memory:")
    conn.execute(
        "CREATE TABLE records (rid INTEGER, ts TEXT, source_type TEXT,"
        " origin_host TEXT, service TEXT, level INTEGER, message TEXT,"
        " message_lc TEXT, fields TEXT, src_meta TEXT)"
    )
    conn.execute(
        "INSERT INTO records VALUES"
        " (1, '2026-10-28T11:50:00+00:00', 'kafka', 'broker-1', 'orders', 3,"
        " 'order placed', 'order placed',"
        ' \'{"kafka_topic":"orders","partition":3,"offset":150'
        ' ,"header_trace_id":"t-1"}\', \'{}\'),'
        " (2, '2026-10-28T11:55:00+00:00', 'windows', 'DC01', 'winevt', 4,"
        " 'logon failure', 'logon failure',"
        ' \'{"win.channel":"Security","win.event_id":4625'
        " ,\"win.record_id\":99}', '{}'),"
        " (3, '2026-10-28T11:58:00+00:00', 'kubernetes', 'node-1', 'api', 5,"
        " 'panic in handler', 'panic in handler',"
        ' \'{"pod":"api-7d4","namespace":"prod","labels":{"app":"api"}}\', \'{}\'),'
        " (4, '2026-10-20T08:00:00+00:00', 'azure', 'law-1', 'syslog', 3,"
        " 'old entry', 'old entry', '{}', '{\"azure.table\":\"Syslog\"}')"
    )
    rows = conn.execute(f"SELECT rid FROM records WHERE {where} ORDER BY rid", params).fetchall()
    assert [row[0] for row in rows] == want_rids


def test_postgres_alias_placeholders() -> None:
    where, params = compile_oql("kafka.topic:orders AND win.event_id:4625", dialect="postgres")
    assert where == "((\"fields\"->>'kafka_topic' = %s) AND (\"fields\"->>'win.event_id' = %s))"
    assert params == ["orders", "4625"]
    where, _ = compile_oql("k8s.label.app:api", dialect="postgres")
    assert where == "(\"fields\"->'labels'->>'app' = %s)"
    where, _ = compile_oql("azure.table:Syslog", dialect="postgres")
    assert where == "(\"src_meta\"->>'azure.table' = %s)"
    where, _ = compile_oql("fields.latency_ms>100", dialect="postgres")
    assert where == "(CAST(\"fields\"->>'latency_ms' AS REAL) > %s)"


FUZZ_TOKENS = [
    "level",
    "ERROR",
    "service",
    "api",
    ":",
    ">=",
    "<",
    ">",
    "(",
    ")",
    "AND",
    "OR",
    "NOT",
    "in",
    ",",
    "ts",
    "last",
    "15m",
    "2h",
    "*",
    '"',
    "/",
    "\\",
    "fields",
    ".",
    "kafka",
    "topic",
    "win",
    "channel",
    "message",
    "origin_host",
    "5",
    "_",
    "-",
    " ",
    "1d",
    ";",
    "%",
    "'",
    "=",
    "exists",
    "!",
    "žluť",
    "a" * 200,
]


def test_oql_fuzz_never_crashes_and_sql_executes() -> None:
    """Seeded fuzz: only OQLSyntaxError escapes, valid SQL always executes."""
    rng = random.Random(20261028)
    conn = _seeded_sqlite()
    compiled = 0
    for _ in range(2000):
        query = "".join(rng.choice(FUZZ_TOKENS) for _ in range(rng.randint(1, 25)))
        try:
            where, params = compile_oql(query, now=NOW)
        except OQLSyntaxError:
            continue
        compiled += 1
        conn.execute(f"SELECT rid FROM records WHERE {where}", params).fetchall()
    assert compiled > 100  # sanity: fuzz reached plenty of valid queries


@pytest.fixture(scope="module")
def pg_oql_dsn() -> Iterator[str]:
    """Run PostgreSQL 16 in Docker; skip without docker."""
    if not docker_available():
        pytest.skip("docker unavailable")
    container = Container(
        "postgres:16", ports={PG_OQL_PORT: 5432}, env={"POSTGRES_PASSWORD": "opsai-pw"}
    )
    container.start()
    try:

        def ready() -> bool:
            import psycopg

            with psycopg.connect(PG_OQL_DSN, connect_timeout=5) as conn:
                conn.execute("SELECT 1")
            return True

        container.wait_for(ready, timeout=120)
        yield PG_OQL_DSN
    finally:
        container.stop()


def test_postgres_alias_end_to_end(tmp_path: Path, pg_oql_dsn: str) -> None:
    """Alias OQL filters JSONB rows through the postgres session backend."""
    settings = replace(Settings.from_env(), data_dir=tmp_path / "pg-oql")
    init_app_db(settings)
    manager = SessionManager(settings.data_dir, backend="postgres", postgres_dsn=pg_oql_dsn)
    session_id = manager.create_session("oql")
    base = datetime(2026, 10, 28, 10, 0, tzinfo=UTC)
    manager.add_records(
        session_id,
        [
            LogRecord(
                ts=base,
                message="order placed",
                source_type="kafka",
                service="orders",
                level=INFO,
                fields={
                    "kafka_topic": "orders",
                    "partition": 3,
                    "offset": 150,
                    "header_trace_id": "t-1",
                },
            ),
            LogRecord(
                ts=base,
                message="logon failure",
                source_type="windows",
                service="winevt",
                level=WARN,
                fields={
                    "win.channel": "Security",
                    "win.event_id": 4625,
                    "win.record_id": 99,
                },
            ),
            LogRecord(
                ts=base,
                message="panic in handler",
                source_type="kubernetes",
                service="api",
                level=ERROR,
                fields={
                    "pod": "api-7d4",
                    "namespace": "prod",
                    "labels": {"app": "api"},
                },
            ),
            LogRecord(
                ts=base,
                message="old entry",
                source_type="azure",
                service="syslog",
                level=INFO,
                src_meta={"azure.table": "Syslog"},
            ),
        ],
    )
    cases = [
        ("kafka.topic:orders", 1),
        ("kafka.partition:3", 1),
        ("kafka.offset>=100", 1),
        ("kafka.header.trace_id:t-1", 1),
        ("win.channel:Security", 1),
        ("win.event_id:4625", 1),
        ("win.record_id:99", 1),
        ("k8s.namespace:prod", 1),
        ("k8s.pod:api-*", 1),
        ("k8s.label.app:api", 1),
        ("azure.table:Syslog", 1),
        ("in(level, ERROR, WARN)", 2),
        ("fields.code:500", 0),
    ]
    for oql, total in cases:
        page = manager.query_records(session_id, oql=oql)
        assert page["total"] == total, oql


def test_empty_query_matches_all() -> None:
    where, params = compile_oql("")
    assert where == "1=1"
    assert params == []


def test_free_text_searches_message_case_insensitive() -> None:
    where, params = compile_oql("timeout")
    assert "message_lc" in where
    assert params == ["%timeout%"]


def test_field_query_and_level_name() -> None:
    where, params = compile_oql("origin_host:app-srv-12 AND level:ERROR")
    assert '"origin_host" = ?' in where
    assert params == ["app-srv-12", 5]


def test_comparison_and_not() -> None:
    where, params = compile_oql("level>=WARN NOT service:noise")
    assert '"level" >= ?' in where
    assert "NOT" in where
    assert params[0] == 4


def test_minus_negation_and_parens() -> None:
    where, params = compile_oql("-(a OR b)")
    assert where.count("NOT") == 1
    assert params == ["%a%", "%b%"]


def test_quoted_value_with_colon() -> None:
    where, params = compile_oql('service:"C:\\logs\\app.log"')
    assert params == ["C:\\logs\\app.log"]


def test_wildcard_and_exists() -> None:
    where, params = compile_oql("service:app-* AND exists:fields.request_id")
    assert "LIKE" in where
    assert "IS NOT NULL" in where
    assert params[0] == "app-%"


def test_regex_value_is_validated() -> None:
    where, params = compile_oql("message:/err\\d+/")
    assert "REGEXP" in where
    assert params == ["err\\d+"]
    with pytest.raises(OQLSyntaxError):
        compile_oql("message:/([/")


def test_unknown_field_and_bad_syntax() -> None:
    with pytest.raises(OQLSyntaxError):
        compile_oql("nope:value")
    with pytest.raises(OQLSyntaxError):
        compile_oql("(a AND b")
    with pytest.raises(OQLSyntaxError):
        compile_oql("service>5")


def test_injection_attempt_stays_a_parameter() -> None:
    where, params = compile_oql("message:\"x' OR '1'='1\"")
    assert params == ["%x' or '1'='1%"]
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (message_lc TEXT)")
    conn.execute("INSERT INTO t VALUES ('harmless')")
    rows = conn.execute(f"SELECT * FROM t WHERE {where}", params).fetchall()
    assert rows == []


def test_duckdb_dialect() -> None:
    where, params = compile_oql("fields.request_id:abc", dialect="duckdb")
    assert where == "(CAST(json_extract_string(fields, '$.request_id') AS TEXT) = ?)"
    assert params == ["abc"]
    where, params = compile_oql("message:/err\\d+/", dialect="duckdb")
    assert where == 'regexp_matches("message", ?)'
    assert params == ["err\\d+"]
    where, _ = compile_oql("level>=ERROR", dialect="duckdb")
    assert where == '("level" >= ?)'


def test_postgres_dialect() -> None:
    where, params = compile_oql("fields.request_id:abc", dialect="postgres")
    assert where == "(\"fields\"->>'request_id' = %s)"
    assert params == ["abc"]
    where, _ = compile_oql("src_meta.a.b:1", dialect="postgres")
    assert where == "(\"src_meta\"->'a'->>'b' = %s)"
    where, params = compile_oql("message:/err\\d+/", dialect="postgres")
    assert where == '("message" ~ %s)'
    where, params = compile_oql("level>=ERROR AND service:api", dialect="postgres")
    assert "?" not in where
    assert where.count("%s") == 2
    assert params == [5, "api"]


def test_unknown_dialect_rejected() -> None:
    with pytest.raises(NotImplementedError, match="Unknown OQL dialect"):
        compile_oql("x", dialect="mysql")
