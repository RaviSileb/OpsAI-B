"""Tests for saved OQL queries and filter history (FR-163)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from opsai.api.main import create_app
from opsai.app.bootstrap import get_app_db_path, init_app_db
from opsai.app.config import Settings
from opsai.core.saved_queries import HISTORY_LIMIT, QueryStore


def _store(tmp_path: Path) -> QueryStore:
    settings = replace(Settings.from_env(), data_dir=tmp_path / "q-data")
    init_app_db(settings)
    return QueryStore(get_app_db_path(settings))


def _client(tmp_path: Path) -> TestClient:
    settings = replace(Settings.from_env(), data_dir=tmp_path / "api-data", dev_auth=True)
    return TestClient(create_app(settings))


def test_save_and_get_roundtrip(tmp_path: Path) -> None:
    store = _store(tmp_path)
    saved = store.save("u1", "errors", "level:ERROR")
    assert saved.owner_id == "u1"
    assert saved.name == "errors"
    assert saved.oql == "level:ERROR"
    assert saved.shared is False
    assert store.get(saved.id) == saved
    assert store.get("missing") is None


def test_save_rejects_bad_oql_and_name(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="Invalid OQL"):
        store.save("u1", "bad", "level:")
    with pytest.raises(ValueError, match="must not be empty"):
        store.save("u1", "bad", "   ")
    with pytest.raises(ValueError, match="1-100"):
        store.save("u1", "  ", "level:ERROR")
    with pytest.raises(ValueError, match="1-100"):
        store.save("u1", "x" * 101, "level:ERROR")


def test_list_shows_own_and_shared(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.save("u1", "mine", "level:ERROR")
    store.save("u2", "theirs", "level:WARN")
    store.save("u2", "shared", "service:api", shared=True)
    names = {q.name for q in store.list_saved("u1")}
    assert names == {"mine", "shared"}


def test_update_and_delete_ownership(tmp_path: Path) -> None:
    store = _store(tmp_path)
    saved = store.save("u1", "mine", "level:ERROR")
    with pytest.raises(PermissionError):
        store.update(saved.id, "u2", False, name="hijack")
    with pytest.raises(PermissionError):
        store.delete(saved.id, "u2", False)
    updated = store.update(saved.id, "u2", True, name="fixed", shared=True)
    assert updated.name == "fixed"
    assert updated.shared is True
    with pytest.raises(ValueError, match="Invalid OQL"):
        store.update(saved.id, "u1", False, oql="in(")
    store.delete(saved.id, "u2", True)
    assert store.get(saved.id) is None
    with pytest.raises(KeyError):
        store.delete(saved.id, "u1", False)


def test_history_capped_at_limit(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for n in range(HISTORY_LIMIT + 5):
        store.record_history("u1", f"service:s{n}")
    store.record_history("u2", "level:ERROR")
    history = store.history("u1")
    assert len(history) == HISTORY_LIMIT
    assert history[0].oql == f"service:s{HISTORY_LIMIT + 4}"
    assert [e.oql for e in store.history("u2")] == ["level:ERROR"]
    with pytest.raises(ValueError, match="Invalid OQL"):
        store.record_history("u1", "ts:last")


def test_api_saved_query_crud(tmp_path: Path) -> None:
    client = _client(tmp_path)
    created = client.post("/api/v1/queries/saved", json={"name": "errs", "oql": "level:ERROR"})
    assert created.status_code == 201
    query_id = created.json()["id"]
    assert created.json()["name"] == "errs"
    bad = client.post("/api/v1/queries/saved", json={"name": "x", "oql": "level:"})
    assert bad.status_code == 400
    items = client.get("/api/v1/queries/saved").json()["items"]
    assert [item["id"] for item in items] == [query_id]
    patched = client.patch(
        f"/api/v1/queries/saved/{query_id}",
        json={"oql": "level>=WARN", "shared": True},
    ).json()
    assert patched["oql"] == "level>=WARN"
    assert patched["shared"] is True
    assert client.patch("/api/v1/queries/saved/nope", json={"name": "n"}).status_code == 404
    assert client.patch(f"/api/v1/queries/saved/{query_id}", json={"oql": "in("}).status_code == 400
    assert client.delete(f"/api/v1/queries/saved/{query_id}").status_code == 204
    assert client.delete(f"/api/v1/queries/saved/{query_id}").status_code == 404
    assert client.get("/api/v1/queries/saved").json()["items"] == []


def test_api_query_history(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.get("/api/v1/queries/history").json()["items"] == []
    added = client.post("/api/v1/queries/history", json={"oql": "level:ERROR"})
    assert added.status_code == 201
    assert added.json()["oql"] == "level:ERROR"
    assert client.post("/api/v1/queries/history", json={"oql": "level:"}).status_code == 400
    client.post("/api/v1/queries/history", json={"oql": "service:api"})
    items = client.get("/api/v1/queries/history").json()["items"]
    assert [item["oql"] for item in items] == ["service:api", "level:ERROR"]


def test_api_queries_allow_viewer_read(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/queries/saved", headers={"X-Role": "viewer"})
    assert response.status_code == 200
    assert response.json() == {"items": []}
