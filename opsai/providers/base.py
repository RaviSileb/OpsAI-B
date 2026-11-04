"""LLM provider interface, model registry and retry (TZ FR-300..FR-306)."""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class LLMMessage:
    """One conversation message."""

    role: str
    content: str


@dataclass
class LLMRequest:
    """Provider request (FR-300). Web/search grounding is never used (FR-311)."""

    system: str
    messages: list[LLMMessage]
    response_schema: dict[str, Any] | None = None
    max_output_tokens: int = 4096
    temperature: float = 0.2
    timeout: float = 120.0


@dataclass
class LLMResponse:
    """Provider response with usage for cost evidence (FR-304)."""

    text: str
    data: dict[str, Any] | None
    tokens_in: int
    tokens_out: int
    model: str
    provider: str


@dataclass
class ModelRegistry:
    """Admin-managed whitelist/blacklist per provider (FR-301, FR-310)."""

    allowed_models: list[str] | None = None
    denied_models: list[str] = field(default_factory=list)
    denied_patterns: list[str] = field(default_factory=list)
    permanent_denied_patterns: tuple[str, ...] = ()
    default_model: str = ""
    price_per_1m_in: float = 0.0
    price_per_1m_out: float = 0.0

    def is_allowed(self, model: str) -> bool:
        """Default-deny: unknown ids are rejected when a whitelist exists."""
        if model in self.denied_models:
            return False
        for pattern in (*self.permanent_denied_patterns, *self.denied_patterns):
            if re.match(pattern, model):
                return False
        if self.allowed_models is not None:
            return model in self.allowed_models
        return True

    def estimate_cost(self, tokens_in: int, tokens_out: int) -> float:
        """Estimate request cost from configured per-model prices."""
        return (tokens_in * self.price_per_1m_in + tokens_out * self.price_per_1m_out) / 1_000_000


class LLMProvider(ABC):
    """Abstract AI provider (FR-300)."""

    name: str = "base"

    def __init__(self, api_key: str = "", registry: ModelRegistry | None = None) -> None:
        self.api_key = api_key
        self.registry = registry or ModelRegistry()

    @abstractmethod
    def list_models(self) -> list[str]:
        """List models known to the provider account."""

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimate (~4 chars per token) for pre-send preview."""
        return max(1, len(text) // 4)

    @abstractmethod
    def generate(self, request: LLMRequest, model: str) -> LLMResponse:
        """Generate one completion; must honor the model registry."""

    def _require_allowed(self, model: str) -> None:
        if not self.registry.is_allowed(model):
            msg = f"Model {model!r} is not allowed for provider {self.name!r}"
            raise PermissionError(msg)
        if not self.api_key:
            msg = f"Missing API key for provider {self.name!r}"
            raise RuntimeError(msg)


def with_retry(
    call: Any,
    max_attempts: int = 3,
    base_delay: float = 1.0,
) -> Any:
    """Run an HTTP call with backoff, honoring Retry-After (FR-303)."""
    last_error: Exception | None = None
    for attempt in range(max_attempts):
        try:
            response = call()
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            last_error = exc
            response = None
        if response is not None and not _is_retryable(response):
            return response
        if response is not None and _is_retryable(response):
            last_error = RuntimeError(f"Provider HTTP {response.status_code}")
        if attempt < max_attempts - 1:
            delay = _retry_delay(response, attempt, base_delay)
            time.sleep(delay)
    assert last_error is not None
    raise last_error


def _is_retryable(response: httpx.Response) -> bool:
    return response.status_code in {429, 500, 502, 503, 504}


def _retry_delay(response: httpx.Response | None, attempt: int, base: float) -> float:
    if response is not None:
        header = response.headers.get("retry-after", "").strip()
        if header.isdigit():
            return min(float(header), 60.0)
    jitter = (attempt * 0.37) % 0.5
    delay: float = min(base * (2**attempt) + jitter, 30.0)
    return delay
