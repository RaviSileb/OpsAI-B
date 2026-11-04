"""Tests for providers: mock output, registry, schema validation (FR-300..)."""

from __future__ import annotations

import pytest

from opsai.providers.base import LLMMessage, LLMRequest, ModelRegistry
from opsai.providers.mock_provider import MockProvider
from opsai.providers.schema import validate_analysis


def _request() -> LLMRequest:
    return LLMRequest(
        system="test",
        messages=[LLMMessage(role="user", content="R1: boom\nR2: ok")],
    )


def test_mock_returns_schema_valid_analysis() -> None:
    provider = MockProvider()
    response = provider.generate(_request(), "mock-analysis-v1")
    assert response.provider == "mock"
    assert response.tokens_in > 0
    assert response.tokens_out > 0
    assert validate_analysis(response.data) == []
    assert response.data is not None
    assert response.data["hypotheses"][0]["evidence"] == ["R1", "R2"]


def test_registry_default_deny() -> None:
    registry = ModelRegistry(allowed_models=["a"], denied_models=["b"])
    assert registry.is_allowed("a")
    assert not registry.is_allowed("b")
    assert not registry.is_allowed("unknown")
    open_registry = ModelRegistry()
    assert open_registry.is_allowed("anything")


def test_registry_blocks_disallowed_model() -> None:
    provider = MockProvider(registry=ModelRegistry(allowed_models=["x"]))
    with pytest.raises(PermissionError):
        provider._require_allowed("other")


def test_validate_analysis_catches_bad_output() -> None:
    assert validate_analysis({}) != []
    assert (
        validate_analysis(
            {
                "summary": "x",
                "hypotheses": [],
                "recommendations": [],
                "remediation_plan": {"steps": []},
            }
        )
        == []
    )
    bad_step = {
        "summary": "x",
        "hypotheses": [],
        "recommendations": [],
        "remediation_plan": {"steps": [{"order": 1}]},
    }
    assert len(validate_analysis(bad_step)) >= 3


def test_token_estimate_scales() -> None:
    provider = MockProvider()
    assert provider.estimate_tokens("abcd" * 100) == 100
