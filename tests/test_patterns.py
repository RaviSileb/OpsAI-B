"""Tests for template mining backends (FR-200..205)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from opsai.api.main import create_app
from opsai.app.config import Settings
from opsai.core.patterns import (
    DrainUnavailableError,
    compare_windows,
    compute_templates,
    normalize_message,
    resolve_backend,
    spike_buckets,
    template_hash,
)

MESSAGES = [
    "Connection from 10.0.0.1 port 5432 closed",
    "Connection from 10.0.0.2 port 5433 closed",
    "Connection from 10.0.0.1 port 5432 closed",
    "User alice logged in",
    "User bob logged in",
    "Failed job done",
]


def _client(tmp_path: Path) -> TestClient:
    settings = replace(Settings.from_env(), data_dir=tmp_path / "api-data", dev_auth=True)
    return TestClient(create_app(settings))


def test_normalize_placeholders() -> None:
    assert normalize_message("from 10.0.0.1 port 5") == "from <*> port <*>"
    assert normalize_message("job 550e8400-e29b-41d4-a716-446655440000 x") == "job <*> x"
    assert normalize_message("mail bob@example.com ok") == "mail <*> ok"
    assert normalize_message("open /var/log/app.log now") == "open <*> now"
    assert normalize_message("plain words") == "plain words"


def test_template_hash_stable() -> None:
    assert template_hash("a") == template_hash("a")
    assert len(template_hash("a")) == 16
    assert template_hash("a") != template_hash("b")


def test_regex_backend_groups_and_sorts() -> None:
    # Regex masks only IPs/numbers/UUIDs/paths/emails; plain words stay literal.
    infos = compute_templates(MESSAGES, backend="regex")
    assert [(i.template, i.count) for i in infos] == [
        ("Connection from <*> port <*> closed", 3),
        ("Failed job done", 1),
        ("User alice logged in", 1),
        ("User bob logged in", 1),
    ]
    assert all(len(i.hash) == 16 for i in infos)


def test_resolve_backend() -> None:
    assert resolve_backend("regex") == "regex"
    assert resolve_backend("ReGeX") == "regex"
    assert resolve_backend("") == resolve_backend("auto")
    with pytest.raises(ValueError, match="Unknown patterns backend"):
        resolve_backend("bogus")


def test_auto_prefers_drain3_when_installed() -> None:
    drain3 = pytest.importorskip("drain3")
    assert drain3 is not None
    assert resolve_backend("auto") == "drain3"


def test_drain3_backend_groups_like_regex() -> None:
    pytest.importorskip("drain3")
    infos = compute_templates(MESSAGES, backend="drain3")
    assert [(i.template, i.count) for i in infos] == [
        ("Connection from <*> port <*> closed", 3),
        ("User <*> logged in", 2),
        ("Failed job done", 1),
    ]


def test_drain3_backend_handles_empty_and_none() -> None:
    pytest.importorskip("drain3")
    assert compute_templates([], backend="drain3") == []
    assert compute_templates(["", ""], backend="drain3")[0].count == 2
    assert compute_templates([""], backend="regex")[0].count == 1


def test_drain3_unavailable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import opsai.core.drain_miner as miner

    monkeypatch.setattr(miner, "available", lambda: False)
    assert resolve_backend("auto") == "regex"
    with pytest.raises(DrainUnavailableError, match="not installed"):
        resolve_backend("drain3")
    with pytest.raises(DrainUnavailableError, match="not installed"):
        compute_templates(MESSAGES, backend="drain3")


def test_backends_agree_on_identical_messages() -> None:
    pytest.importorskip("drain3")
    same = ["disk failure on sda"] * 7
    for backend in ("regex", "drain3"):
        infos = compute_templates(same, backend=backend)
        assert len(infos) == 1
        assert infos[0].count == 7
        assert infos[0].hash == template_hash(infos[0].template)


def test_compare_windows() -> None:
    old = ["alpha 1"] * 6 + ["beta 2"] * 6
    new = ["alpha 1"] * 6 + ["gamma 3"] * 2
    diff = compare_windows(old, new, backend="regex")
    assert diff["gone"] == [{"template": "beta <*>", "count": 6}]
    assert diff["new"] == [{"template": "gamma <*>", "count": 2}]
    assert diff["changed"] == []
    grown = compare_windows(["alpha 1"] * 6, ["alpha 1"] * 13, backend="regex")
    assert grown["changed"] == [{"template": "alpha <*>", "old": 6, "new": 13}]
    assert grown["new"] == [] and grown["gone"] == []


def test_spike_buckets() -> None:
    assert spike_buckets([1] * 9) == []
    assert spike_buckets([5] * 12) == []
    assert spike_buckets([5] * 11 + [50]) == [11]
    assert spike_buckets([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 100]) == [11]


def test_api_templates_backend_param(tmp_path: Path, sample_log: Path) -> None:
    client = _client(tmp_path)
    session_id = client.post("/api/v1/sessions", json={"name": "t"}).json()["id"]
    client.post(f"/api/v1/sessions/{session_id}/ingest-file", json={"path": str(sample_log)})
    auto = client.get(f"/api/v1/sessions/{session_id}/templates").json()
    assert auto["sampled"] == 4
    assert auto["backend"] == "drain3"
    assert auto["templates"][0]["count"] >= 1
    regex = client.get(
        f"/api/v1/sessions/{session_id}/templates", params={"backend": "regex"}
    ).json()
    assert regex["backend"] == "regex"
    assert regex["sampled"] == 4
    bad = client.get(f"/api/v1/sessions/{session_id}/templates", params={"backend": "bogus"})
    assert bad.status_code == 400
