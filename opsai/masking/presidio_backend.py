"""Optional Presidio PII detectors (gap entities for the masking engine).

Presidio supplements the regex detectors M-01..M-07 with entity types the
regexes do not cover: phone numbers, credit cards, IBANs, bare URLs and
person names. Email and IP findings are intentionally excluded -- the regex
detectors already cover them with higher precision for log text.

The ``presidio-analyzer`` package is optional; :func:`available` reports
whether it can be imported. The analyzer holds one cached engine (loading
the NLP model takes ~2s); per-text analysis runs in milliseconds.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from opsai.masking.detectors import DetectorFinding

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine

# Presidio entity -> OpsAI token entity. Only gaps are mapped; EMAIL_ADDRESS
# and IP_ADDRESS stay with the regex detectors to avoid duplicate findings.
ENTITY_MAP = {
    "PHONE_NUMBER": "PHONE",
    "CREDIT_CARD": "CARD",
    "IBAN_CODE": "ACCT",
    "URL": "URLPARAM",
    "PERSON": "PERSON",
}

# Presidio scores valid log phones around 0.4; 0.35 keeps them while the
# sub-0.1 noise (bank numbers, driver licences) stays filtered.
MIN_SCORE = 0.35


class PresidioUnavailableError(Exception):
    """Raised when presidio mode 'on' is used but the package is missing."""


def available() -> bool:
    """Return True when the optional ``presidio-analyzer`` is importable."""
    try:
        import presidio_analyzer  # noqa: F401
    except ImportError:
        return False
    return True


@lru_cache(maxsize=1)
def _engine() -> AnalyzerEngine:
    from presidio_analyzer import AnalyzerEngine

    return AnalyzerEngine()


def detect_presidio(text: str, min_score: float = MIN_SCORE) -> list[DetectorFinding]:
    """Run Presidio over the text and map hits to OpsAI findings."""
    if not text:
        return []
    results = _engine().analyze(text=text, language="en", entities=sorted(ENTITY_MAP))
    findings = []
    for result in results:
        entity = ENTITY_MAP.get(result.entity_type)
        if entity is None or result.score < min_score:
            continue
        findings.append(
            DetectorFinding(entity, text[result.start : result.end], result.start, result.end)
        )
    return findings
