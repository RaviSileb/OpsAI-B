"""Provider selection shared by the API and the execution engine."""

from __future__ import annotations

import os

from opsai.app.config import Settings
from opsai.providers.base import LLMProvider, ModelRegistry
from opsai.providers.meta_provider import (
    DEFAULT_MODEL,
    KNOWN_MODELS,
    PRICE_PER_1M_IN,
    PRICE_PER_1M_OUT,
    MetaProvider,
)
from opsai.providers.mock_provider import MockProvider

CONTRIBUTOR_DENY_PATTERN = r".*-contributor$"

_KEY_ENV = {
    "meta": "OPSAI_META_API_KEY",
}


def meta_registry() -> ModelRegistry:
    """Return the default Meta model registry (FR-301, FR-310)."""
    return ModelRegistry(
        allowed_models=list(KNOWN_MODELS),
        permanent_denied_patterns=(CONTRIBUTOR_DENY_PATTERN,),
        default_model=DEFAULT_MODEL,
        price_per_1m_in=PRICE_PER_1M_IN[DEFAULT_MODEL],
        price_per_1m_out=PRICE_PER_1M_OUT[DEFAULT_MODEL],
    )


def get_provider(name: str, settings: Settings) -> tuple[LLMProvider, bool]:
    """Return ``(provider, live)``; mock is forced unless AI live mode is on."""
    if not settings.ai_live or name == "mock":
        return MockProvider(), False
    env_name = _KEY_ENV.get(name)
    if env_name is None:
        msg = f"Unknown provider {name!r}"
        raise ValueError(msg)
    api_key = os.environ.get(env_name, "")
    return MetaProvider(api_key=api_key, registry=meta_registry()), True
