"""Tests for the file connector (FR-010..FR-014, read-only)."""

from __future__ import annotations

import gzip
from pathlib import Path
from typing import Any

from opsai.connectors.base import ConnectionProfile, ReadQuery
from opsai.connectors.file import FileConnector, detect_encoding


def _profile(path: str, **config: Any) -> ConnectionProfile:
    merged: dict[str, Any] = {"path": path}
    merged.update(config)
    return ConnectionProfile(id="t", name="t", connector_type="file", config=merged)


async def test_test_and_browse(sample_log: Path) -> None:
    connector = FileConnector()
    result = await connector.test(_profile(str(sample_log)))
    assert result.ok
    assert result.steps[0].message == "1 file(s)"
    missing = await connector.test(_profile(str(sample_log) + ".missing"))
    assert not missing.ok
    items = await connector.browse(_profile(str(sample_log)))
    assert items[0]["name"] == "sample.log"


async def test_read_parses_ts_level_and_host(sample_log: Path) -> None:
    connector = FileConnector()
    records = []
    async for batch in connector.read(_profile(str(sample_log)), ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 4  # traceback grouped into one event
    assert records[0].ts is not None
    assert records[0].ts.year == 2026
    assert records[1].level_raw == "WARN"
    assert records[2].origin_host == "app-srv-12"
    assert "Traceback" in records[2].message
    assert all(r.src_meta.get("file") == str(sample_log) for r in records)


async def test_read_respects_limits_and_tail(sample_log: Path) -> None:
    connector = FileConnector()
    batches = [
        batch
        async for batch in connector.read(_profile(str(sample_log)), ReadQuery(limit_records=2))
    ]
    assert sum(len(b.records) for b in batches) == 2
    assert batches[-1].truncated
    tail = [
        batch async for batch in connector.read(_profile(str(sample_log)), ReadQuery(tail_lines=2))
    ]
    assert sum(len(b.records) for b in tail) == 2


async def test_read_gzip_and_json(tmp_path: Path) -> None:
    gz_path = tmp_path / "app.log.gz"
    with gzip.open(gz_path, "wt", encoding="utf-8") as handle:
        handle.write('{"message": "disk full", "level": "ERROR", "host": {"name": "db-1"}}\n')
        handle.write('{"message": "ok", "level": "INFO"}\n')
    connector = FileConnector()
    records = []
    async for batch in connector.read(_profile(str(gz_path)), ReadQuery()):
        records.extend(batch.records)
    assert len(records) == 2
    assert records[0].level_raw == "ERROR"
    assert records[0].origin_host == "db-1"


def test_detect_encoding_defaults_to_utf8(sample_log: Path) -> None:
    assert detect_encoding(sample_log).lower().replace("_", "-") in {"utf-8", "ascii"}


def test_read_does_not_modify_source(sample_log: Path) -> None:
    before = sample_log.read_bytes()

    async def run() -> None:
        connector = FileConnector()
        async for _batch in connector.read(_profile(str(sample_log)), ReadQuery()):
            pass

    import asyncio

    asyncio.run(run())
    assert sample_log.read_bytes() == before


def test_evtx_is_skipped_with_note(tmp_path: Path) -> None:
    evtx = tmp_path / "sec.evtx"
    evtx.write_bytes(b"fake")
    connector = FileConnector()

    async def run() -> list[int]:
        counts = []
        async for batch in connector.read(_profile(str(evtx)), ReadQuery()):
            counts.append(len(batch.records))
        return counts

    import asyncio

    assert asyncio.run(run()) == []
