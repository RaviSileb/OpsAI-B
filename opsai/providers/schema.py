"""Analysis response JSON schema (TZ 9.5) with lightweight validation."""

from __future__ import annotations

from typing import Any

CONFIDENCE_LABELS = {"proven", "likely", "possible", "speculative"}
PHASES = {"diagnose", "fix", "verify", "rollback"}
SHELLS = {"bash", "powershell", "kubectl", "kafka-cli", "az", "other"}
RISKS = {"read_only", "change", "destructive"}

ANALYSIS_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["summary", "hypotheses", "recommendations", "remediation_plan"],
    "properties": {
        "summary": {"type": "string"},
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["cause", "confidence", "confidence_label", "evidence", "reasoning"],
                "properties": {
                    "cause": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "confidence_label": {"type": "string"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "reasoning": {"type": "string"},
                },
            },
        },
        "recommendations": {"type": "array", "items": {"type": "string"}},
        "remediation_plan": {
            "type": "object",
            "required": ["steps"],
            "properties": {
                "steps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "order",
                            "title",
                            "phase",
                            "target",
                            "shell",
                            "command",
                            "purpose",
                            "risk",
                            "expected",
                        ],
                        "properties": {
                            "order": {"type": "integer"},
                            "title": {"type": "string"},
                            "phase": {"type": "string"},
                            "target": {"type": "string"},
                            "shell": {"type": "string"},
                            "command": {"type": "string"},
                            "purpose": {"type": "string"},
                            "risk": {"type": "string"},
                            "expected": {"type": "object"},
                            "verify_command": {"type": ["string", "null"]},
                            "rollback_command": {"type": ["string", "null"]},
                            "requires_downtime": {"type": "boolean"},
                        },
                    },
                }
            },
        },
        "missing_information": {"type": "array", "items": {"type": "string"}},
        "follow_up_questions": {"type": "array", "items": {"type": "string"}},
    },
}


def validate_analysis(data: Any) -> list[str]:
    """Validate parsed AI output; return a list of errors (empty = valid)."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["response is not a JSON object"]
    for key in ("summary", "hypotheses", "recommendations", "remediation_plan"):
        if key not in data:
            errors.append(f"missing key: {key}")
    if not isinstance(data.get("summary", ""), str):
        errors.append("summary must be a string")
    hypotheses = data.get("hypotheses", [])
    if not isinstance(hypotheses, list):
        errors.append("hypotheses must be a list")
    else:
        for i, hyp in enumerate(hypotheses):
            errors.extend(_validate_hypothesis(i, hyp))
    plan = data.get("remediation_plan", {})
    if not isinstance(plan, dict) or not isinstance(plan.get("steps"), list):
        errors.append("remediation_plan.steps must be a list")
    else:
        for i, step in enumerate(plan["steps"]):
            errors.extend(_validate_step(i, step))
    return errors


def _validate_hypothesis(index: int, hyp: Any) -> list[str]:
    errors: list[str] = []
    prefix = f"hypotheses[{index}]"
    if not isinstance(hyp, dict):
        return [f"{prefix} must be an object"]
    for key in ("cause", "confidence", "confidence_label", "evidence", "reasoning"):
        if key not in hyp:
            errors.append(f"{prefix} missing key: {key}")
    confidence = hyp.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        errors.append(f"{prefix}.confidence must be a number in 0..1")
    if hyp.get("confidence_label") not in CONFIDENCE_LABELS:
        errors.append(f"{prefix}.confidence_label must be one of {sorted(CONFIDENCE_LABELS)}")
    if not isinstance(hyp.get("evidence"), list):
        errors.append(f"{prefix}.evidence must be a list")
    return errors


def _validate_step(index: int, step: Any) -> list[str]:
    errors: list[str] = []
    prefix = f"remediation_plan.steps[{index}]"
    if not isinstance(step, dict):
        return [f"{prefix} must be an object"]
    for key in ("target", "shell", "command", "purpose", "risk", "expected", "phase"):
        if key not in step or step[key] in (None, ""):
            errors.append(f"{prefix} missing or empty key: {key}")
    if step.get("phase") not in PHASES:
        errors.append(f"{prefix}.phase must be one of {sorted(PHASES)}")
    if step.get("shell") not in SHELLS:
        errors.append(f"{prefix}.shell must be one of {sorted(SHELLS)}")
    if step.get("risk") not in RISKS:
        errors.append(f"{prefix}.risk must be one of {sorted(RISKS)}")
    expected = step.get("expected")
    if not isinstance(expected, dict) or "exit_code" not in expected:
        errors.append(f"{prefix}.expected must be an object with exit_code")
    return errors
