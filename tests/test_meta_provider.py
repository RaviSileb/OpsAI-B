"""Tests for the Meta provider: API shape, policy, factory (FR-300..311).

All HTTP traffic goes through httpx.MockTransport; no network is used.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from opsai.api.main import create_app
from opsai.app.config import Settings
from opsai.providers.base import LLMMessage, LLMRequest, ModelRegistry
from opsai.providers.factory import CONTRIBUTOR_DENY_PATTERN, get_provider, meta_registry
from opsai.providers.meta_provider import (
    DEFAULT_MODEL,
    KNOWN_MODELS,
    MetaProvider,
    is_contributor_model,
)


def _request(schema: bool = True) -> LLMRequest:
    return LLMRequest(
        system="sys",
        messages=[LLMMessage(role="user", content="R1: boom")],
        response_schema={"type": "object"} if schema else None,
    )


def _completion_json(text: str = '{"summary": "ok"}') -> dict[str, Any]:
    return {
        "choices": [{"message": {"content": text}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


def _patched_client(monkeypatch: pytest.MonkeyPatch, handler: Any) -> list[httpx.Request]:
    """Patch httpx.Client to use MockTransport; return captured requests."""
    seen: list[httpx.Request] = []

    def capture(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    transport = httpx.MockTransport(capture)
    real_client = httpx.Client

    def factory(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", factory)
    return seen


def _registry() -> ModelRegistry:
    return ModelRegistry(
        allowed_models=[DEFAULT_MODEL],
        permanent_denied_patterns=(CONTRIBUTOR_DENY_PATTERN,),
        default_model=DEFAULT_MODEL,
    )


def test_generate_posts_meta_chat_completions(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_completion_json())

    seen = _patched_client(monkeypatch, handler)
    provider = MetaProvider(api_key="k", registry=_registry())
    response = provider.generate(_request(), DEFAULT_MODEL)

    assert response.provider == "meta"
    assert response.model == DEFAULT_MODEL
    assert response.tokens_in == 10
    assert response.tokens_out == 5
    assert response.data == {"summary": "ok"}
    assert len(seen) == 1
    request = seen[0]
    assert request.url == "https://api.meta.ai/v1/chat/completions"
    assert request.headers["Authorization"] == "Bearer k"
    payload = json.loads(request.content.decode("utf-8"))
    assert payload["model"] == DEFAULT_MODEL
    assert payload["messages"][0] == {"role": "system", "content": "sys"}
    assert payload["temperature"] == 0.2
    assert payload["max_tokens"] == 4096
    assert payload["response_format"]["type"] == "json_schema"
    assert payload["response_format"]["json_schema"]["name"] == "opsai_analysis"


def test_generate_never_uses_grounding(monkeypatch: pytest.MonkeyPatch) -> None:
    """FR-311: no web/search grounding parameters are ever sent."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_completion_json())

    seen = _patched_client(monkeypatch, handler)
    provider = MetaProvider(api_key="k", registry=_registry())
    provider.generate(_request(), DEFAULT_MODEL)
    provider.generate(_request(schema=False), DEFAULT_MODEL)

    assert len(seen) == 2
    for request in seen:
        payload = json.loads(request.content.decode("utf-8"))
        assert "tools" not in payload
        assert "tool_choice" not in payload
        assert "search" not in json.dumps(payload).lower()
        assert "grounding" not in json.dumps(payload).lower()
    plain = json.loads(seen[1].content.decode("utf-8"))
    assert "response_format" not in plain


def test_generate_tolerates_non_json_text(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_completion_json("not json"))

    _patched_client(monkeypatch, handler)
    provider = MetaProvider(api_key="k", registry=_registry())
    response = provider.generate(_request(schema=False), DEFAULT_MODEL)
    assert response.text == "not json"
    assert response.data is None


def test_list_models(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.meta.ai/v1/models"
        return httpx.Response(200, json={"data": [{"id": DEFAULT_MODEL}]})

    _patched_client(monkeypatch, handler)
    provider = MetaProvider(api_key="k", registry=_registry())
    assert provider.list_models() == [DEFAULT_MODEL]


def test_missing_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patched_client(monkeypatch, lambda request: httpx.Response(200, json={}))
    provider = MetaProvider(api_key="", registry=_registry())
    with pytest.raises(RuntimeError, match="Missing API key"):
        provider.generate(_request(schema=False), DEFAULT_MODEL)


def test_retry_honors_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    """FR-303: HTTP 429 is retried, Retry-After is honored."""
    import opsai.providers.base as base_mod

    calls = {"count": 0}
    sleeps: list[float] = []
    monkeypatch.setattr(base_mod.time, "sleep", lambda s: sleeps.append(s))

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            return httpx.Response(429, headers={"Retry-After": "2"}, json={})
        return httpx.Response(200, json=_completion_json())

    _patched_client(monkeypatch, handler)
    provider = MetaProvider(api_key="k", registry=_registry())
    response = provider.generate(_request(schema=False), DEFAULT_MODEL)
    assert response.data == {"summary": "ok"}
    assert calls["count"] == 2
    assert sleeps == [2.0]


def test_contributor_models_rejected() -> None:
    """FR-310: contributor models are denied even when whitelisted."""
    assert is_contributor_model("muse-spark-1.3-contributor")
    assert not is_contributor_model("muse-spark-1.3")
    registry = ModelRegistry(
        allowed_models=["muse-spark-1.3-contributor", DEFAULT_MODEL],
        permanent_denied_patterns=(CONTRIBUTOR_DENY_PATTERN,),
        default_model=DEFAULT_MODEL,
    )
    assert not registry.is_allowed("muse-spark-1.3-contributor")
    assert registry.is_allowed(DEFAULT_MODEL)
    provider = MetaProvider(api_key="k", registry=registry)
    with pytest.raises(PermissionError):
        provider.generate(_request(schema=False), "muse-spark-1.3-contributor")


def test_admin_patterns_extend_policy() -> None:
    registry = ModelRegistry(denied_patterns=[r"muse-wonder-.*"])
    assert not registry.is_allowed("muse-wonder-1.0")
    assert registry.is_allowed("muse-spark-1.3")


def test_meta_registry_defaults() -> None:
    registry = meta_registry()
    assert registry.default_model == DEFAULT_MODEL
    assert registry.allowed_models == list(KNOWN_MODELS)
    assert not registry.is_allowed("muse-spark-1.3-contributor")
    assert not registry.is_allowed("unknown-model")
    assert registry.estimate_cost(1_000_000, 1_000_000) == pytest.approx(5.50)


def test_factory_meta_and_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    live = replace(Settings.from_env(), ai_live=True)
    offline = replace(Settings.from_env(), ai_live=False)
    monkeypatch.setenv("OPSAI_META_API_KEY", "k")

    provider, is_live = get_provider("meta", live)
    assert isinstance(provider, MetaProvider)
    assert is_live is True

    provider, is_live = get_provider("meta", offline)
    assert provider.name == "mock"
    assert is_live is False

    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider("openai", live)
    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider("anthropic", live)
    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider("gemini", live)


def _client(tmp_path: Path) -> TestClient:
    settings = replace(Settings.from_env(), data_dir=tmp_path / "meta-data", dev_auth=True)
    return TestClient(create_app(settings))


def test_providers_endpoint_lists_meta_only(tmp_path: Path) -> None:
    body = _client(tmp_path).get("/api/v1/providers").json()
    assert body["live"] is False
    names = [p["name"] for p in body["providers"]]
    assert names == ["mock", "meta"]
    meta = body["providers"][1]
    assert meta["models"] == list(KNOWN_MODELS)
    assert meta["default_model"] == DEFAULT_MODEL
    assert meta["live"] is False


def test_preview_rejects_variant_a_providers(tmp_path: Path) -> None:
    client = _client(tmp_path)
    session_id = client.post("/api/v1/sessions", json={"name": "x"}).json()["id"]
    for name in ("openai", "anthropic", "gemini"):
        response = client.post(
            "/api/v1/analyses/preview",
            json={
                "session_id": session_id,
                "oql": "",
                "mode": "full",
                "provider": name,
                "model": "whatever",
            },
        )
        assert response.status_code == 400
