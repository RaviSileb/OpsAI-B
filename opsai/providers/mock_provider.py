"""Offline mock provider for tests, demos and CI without API keys."""

from __future__ import annotations

import json
import re
from typing import Any

from opsai.providers.base import LLMProvider, LLMRequest, LLMResponse

_REF_RE = re.compile(r"\bR(\d+)\b")


class MockProvider(LLMProvider):
    """Deterministic provider that returns schema-valid analysis JSON."""

    name = "mock"

    def list_models(self) -> list[str]:
        return ["mock-analysis-v1"]

    def generate(self, request: LLMRequest, model: str) -> LLMResponse:
        joined = "\n".join(m.content for m in request.messages)
        refs = sorted({f"R{n}" for n in _REF_RE.findall(joined)})[:5] or ["R1"]
        data: dict[str, Any] = {
            "summary": "Mock analysis: most frequent ERROR pattern points at one host.",
            "hypotheses": [
                {
                    "cause": "Repeated ERROR entries on one host service",
                    "confidence": 0.55,
                    "confidence_label": "possible",
                    "evidence": refs[:2],
                    "reasoning": "Same template dominates the selected window.",
                }
            ],
            "recommendations": ["Verify the service on the affected host (read-only checks)."],
            "remediation_plan": {
                "steps": [
                    {
                        "order": 1,
                        "title": "Check service status",
                        "phase": "diagnose",
                        "target": "local",
                        "shell": "bash",
                        "command": "systemctl status opsai-demo --no-pager",
                        "purpose": "Confirm the failing service state",
                        "risk": "read_only",
                        "expected": {
                            "exit_code": 0,
                            "stdout_regex": None,
                            "description": "Service state line is shown",
                        },
                        "verify_command": None,
                        "rollback_command": None,
                        "requires_downtime": False,
                    }
                ]
            },
            "missing_information": [],
            "follow_up_questions": ["Which host should the fix target?"],
        }
        text = json.dumps(data, ensure_ascii=False)
        tokens_in = self.estimate_tokens(request.system + joined)
        return LLMResponse(
            text=text,
            data=data,
            tokens_in=tokens_in,
            tokens_out=self.estimate_tokens(text),
            model=model,
            provider=self.name,
        )
