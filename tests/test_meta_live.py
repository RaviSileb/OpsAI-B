"""Live Meta Model API tests (TBD-101): provider functions end to end.

Skipped unless OPSAI_AI_LIVE=1 and OPSAI_META_API_KEY are set:

    OPSAI_AI_LIVE=1 OPSAI_META_API_KEY="..." pytest tests/test_meta_live.py -m live
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from opsai.api.main import create_app
from opsai.app.config import Settings
from opsai.providers.base import LLMMessage, LLMRequest
from opsai.providers.factory import get_provider, meta_registry
from opsai.providers.meta_provider import DEFAULT_MODEL, MetaProvider
from opsai.providers.schema import validate_analysis

LIVE = os.environ.get("OPSAI_AI_LIVE") == "1" and bool(os.environ.get("OPSAI_META_API_KEY"))

pytestmark = pytest.mark.skipif(not LIVE, reason="live Meta API test (needs key)")


def _provider() -> MetaProvider:
    provider, live = get_provider("meta", Settings.from_env())
    assert live is True
    assert isinstance(provider, MetaProvider)
    return provider


def test_live_list_models() -> None:
    models = _provider().list_models()
    assert DEFAULT_MODEL in models
    assert "muse-wonder-1.0" in models
    assert "muse-spark-1.3-contributor" in models


def test_live_generate_with_schema() -> None:
    request = LLMRequest(
        system="Reply with a JSON object only.",
        messages=[LLMMessage(role="user", content="reply ok:true as JSON")],
        response_schema={
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": False,
        },
        max_output_tokens=2048,
    )
    response = _provider().generate(request, DEFAULT_MODEL)
    assert response.data == {"ok": True}
    assert response.tokens_in > 0
    assert response.tokens_out > 0


def test_live_generate_plain() -> None:
    request = LLMRequest(
        system="Reply with exactly: hello",
        messages=[LLMMessage(role="user", content="hi")],
        max_output_tokens=2048,
    )
    response = _provider().generate(request, DEFAULT_MODEL)
    assert response.text.strip() != ""


def test_live_reasoning_effort_accepted() -> None:
    provider = MetaProvider(
        api_key=os.environ["OPSAI_META_API_KEY"],
        registry=meta_registry(),
        reasoning_effort="low",
    )
    request = LLMRequest(
        system="Reply with exactly: hello",
        messages=[LLMMessage(role="user", content="hi")],
        max_output_tokens=2048,
    )
    assert provider.generate(request, DEFAULT_MODEL).text.strip() != ""


def test_live_contributor_blocked_client_side() -> None:
    with pytest.raises(PermissionError):
        _provider().generate(
            LLMRequest(system="s", messages=[LLMMessage(role="user", content="x")]),
            "muse-spark-1.3-contributor",
        )


def test_live_analysis_flow(tmp_path: Path, sample_log: Path) -> None:
    """Full preview -> send flow against the real Meta API."""
    settings = replace(
        Settings.from_env(), data_dir=tmp_path / "live-data", dev_auth=True, ai_live=True
    )
    client = TestClient(create_app(settings))
    session_id = client.post("/api/v1/sessions", json={"name": "live"}).json()["id"]
    client.post(f"/api/v1/sessions/{session_id}/ingest-file", json={"path": str(sample_log)})
    preview = client.post(
        "/api/v1/analyses/preview",
        json={
            "session_id": session_id,
            "oql": "",
            "mode": "full",
            "provider": "meta",
            "model": DEFAULT_MODEL,
        },
    ).json()
    send = client.post(
        "/api/v1/analyses",
        json={"stage_id": preview["stage_id"], "payload_sha256": preview["payload_sha256"]},
    )
    assert send.status_code == 200, send.text[:500]
    body = send.json()
    assert body["live"] is True
    assert body["provider"] == "meta"
    assert validate_analysis(body["display"]) == []
    assert body["display"]["remediation_plan"]["steps"]
