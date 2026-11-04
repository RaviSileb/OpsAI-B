"""Meta provider via OpenAI-compatible Chat Completions API (variant B, FR-300).

Endpoint: ``https://api.meta.ai/v1`` with ``Authorization: Bearer`` auth.
Web/search grounding is never used (FR-311); ``*-contributor`` models are
rejected by the registry policy (FR-310).
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from opsai.providers.base import (
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ModelRegistry,
    with_retry,
)

DEFAULT_BASE_URL = "https://api.meta.ai/v1"
DEFAULT_MODEL = "muse-spark-1.3"

KNOWN_MODELS: tuple[str, ...] = (
    "muse-spark-1.3",
    "muse-spark-1.2",
    "muse-spark-1.1",
    "muse-wonder-1.0",
)
PREVIEW_MODELS: tuple[str, ...] = ("muse-wonder-1.0",)

PRICE_PER_1M_IN: dict[str, float] = {
    "muse-spark-1.3": 1.25,
    "muse-spark-1.2": 1.25,
    "muse-spark-1.1": 1.25,
    "muse-wonder-1.0": 4.00,
}
PRICE_PER_1M_OUT: dict[str, float] = {
    "muse-spark-1.3": 4.25,
    "muse-spark-1.2": 4.25,
    "muse-spark-1.1": 4.25,
    "muse-wonder-1.0": 20.00,
}

_CONTRIBUTOR_RE = re.compile(r".*-contributor$")


class MetaProvider(LLMProvider):
    """Meta Model API client using the Chat Completions API."""

    name = "meta"

    def __init__(
        self,
        api_key: str = "",
        registry: ModelRegistry | None = None,
        base_url: str = DEFAULT_BASE_URL,
    ) -> None:
        super().__init__(api_key=api_key, registry=registry)
        self.base_url = base_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}

    def list_models(self) -> list[str]:
        self._require_allowed(self.registry.default_model or DEFAULT_MODEL)
        with httpx.Client(timeout=30.0) as client:
            response = with_retry(
                lambda: client.get(f"{self.base_url}/models", headers=self._headers())
            )
        response.raise_for_status()
        data = response.json()
        return [m.get("id", "") for m in data.get("data", []) if m.get("id")]

    def generate(self, request: LLMRequest, model: str) -> LLMResponse:
        self._require_allowed(model)
        messages: list[dict[str, str]] = [{"role": "system", "content": request.system}]
        messages.extend({"role": m.role, "content": m.content} for m in request.messages)
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_output_tokens,
        }
        if request.response_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "opsai_analysis", "schema": request.response_schema},
            }
        with httpx.Client(timeout=request.timeout) as client:
            response = with_retry(
                lambda: client.post(
                    f"{self.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
            )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices", [])
        text = choices[0].get("message", {}).get("content", "") if choices else ""
        usage = data.get("usage", {})
        parsed = _try_parse_json(text)
        return LLMResponse(
            text=text,
            data=parsed,
            tokens_in=int(usage.get("prompt_tokens", self.estimate_tokens(text))),
            tokens_out=int(usage.get("completion_tokens", self.estimate_tokens(text))),
            model=model,
            provider=self.name,
        )


def is_contributor_model(model: str) -> bool:
    """Return True for Meta contributor-mode model ids (FR-310)."""
    return _CONTRIBUTOR_RE.match(model) is not None


def _try_parse_json(text: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None
