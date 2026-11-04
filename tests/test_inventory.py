"""Tests for host inventory and target resolution (FR-510, FR-512)."""

from __future__ import annotations

from pathlib import Path

from opsai.app.bootstrap import init_app_db
from opsai.app.config import Settings
from opsai.core.inventory import InventoryStore
from opsai.db.models import HostRecord


def _store(data_dir: Path) -> InventoryStore:
    from dataclasses import replace

    settings = replace(Settings.from_env(), data_dir=data_dir)
    init_app_db(settings)
    return InventoryStore(settings.data_dir / "app.db")


def test_crud_roundtrip(data_dir: Path) -> None:
    store = _store(data_dir)
    host = store.add(HostRecord(id="", hostname="app-srv-12", environment="prod"))
    assert host.id
    assert store.get(host.id) is not None
    host.environment = "test"
    store.update(host)
    assert store.get(host.id) is not None
    assert store.get(host.id).environment == "test"  # type: ignore[union-attr]
    assert len(store.list_hosts()) == 1
    store.remove(host.id)
    assert store.get(host.id) is None


def test_resolve_exact_alias_fqdn_short_and_ip(data_dir: Path) -> None:
    store = _store(data_dir)
    store.add(
        HostRecord(
            id="",
            hostname="db-01",
            aliases=["primary-db"],
            fqdn="db-01.prod.example.com",
            ip_addresses=["10.0.0.5"],
            environment="prod",
        )
    )
    assert store.resolve("db-01").decision == "single"
    assert store.resolve("DB-01").candidates[0].rule == "hostname"
    assert store.resolve("primary-db").candidates[0].rule == "alias"
    assert store.resolve("db-01.prod.example.com").candidates[0].rule == "fqdn"
    assert store.resolve("10.0.0.5").candidates[0].rule == "ip"


def test_resolve_short_name_and_missing(data_dir: Path) -> None:
    store = _store(data_dir)
    store.add(HostRecord(id="", hostname="cache-02.infra.example.com", environment="prod"))
    resolution = store.resolve("cache-02")
    assert resolution.decision == "single"
    assert resolution.candidates[0].rule == "short-name"
    assert store.resolve("ghost-99").decision == "none"


def test_resolve_ambiguous_and_mixed_env_force_choice(data_dir: Path) -> None:
    store = _store(data_dir)
    store.add(HostRecord(id="", hostname="web-01", environment="prod", aliases=["web"]))
    store.add(HostRecord(id="", hostname="web-02", environment="prod", aliases=["web"]))
    assert store.resolve("web").decision == "choose"
    store.add(HostRecord(id="", hostname="solo", environment="prod"))
    store.add(HostRecord(id="", hostname="solo-test", environment="test", aliases=["solo"]))
    mixed = store.resolve("solo")
    assert mixed.decision == "choose"
    assert mixed.environments_mixed
