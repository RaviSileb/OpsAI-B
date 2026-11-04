"""Live Meta Model API contract tests (TBD-101 follow-up).

Skipped unless OPSAI_AI_LIVE=1 and OPSAI_META_API_KEY are set. Run after
the onboarding in docs/META_ONBOARDING.md is complete:

    OPSAI_AI_LIVE=1 OPSAI_META_API_KEY="..." pytest tests/test_meta_live.py -m live
"""

from __future__ import annotations

import os

import pytest

from opsai.app.config import Settings
from opsai.providers.base import LLMMessage, LLMRequest
from opsai.providers.factory import get_provider, meta_registry
from opsai.providers.meta_provider import DEFAULT_MODEL, MetaProvider

LIVE = os.environ.get("OPSAI_AI_LIVE") == "1" and bool(os.environ.get("OPSAI_META_API_KEY"))

pytestmark = pytest.mark.skipif(not LIVE, reason="live Meta API test (needs key)")


def test_live_list_models() -> None:
    provider, live = get_provider("meta", Settings.from_env())
    assert live is True
    assert isinstance(provider, MetaProvider)
    assert DEFAULT_MODEL in provider.list_models()


def test_live_generate_minimal() -> None:
    provider = MetaProvider(api_key=os.environ["OPSAI_META_API_KEY"], registry=meta_registry())
    request = LLMRequest(
        system="Reply with exactly: {}",
        messages=[LLMMessage(role="user", content="ping")],
        max_output_tokens=64,
    )
    response = provider.generate(request, DEFAULT_MODEL)
    assert response.tokens_in > 0
    assert response.tokens_out > 0
    assert response.text.strip() != ""
