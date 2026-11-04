"""Tests for the optional Presidio PII detectors."""

from __future__ import annotations

import pytest

from opsai.masking.engine import MaskingEngine
from opsai.masking.presidio_backend import (
    MIN_SCORE,
    PresidioUnavailableError,
    available,
    detect_presidio,
)

pytestmark = pytest.mark.skipif(not available(), reason="presidio-analyzer not installed")


def test_gap_entities_mapped() -> None:
    findings = {
        f.entity: f.value
        for f in detect_presidio(
            "Call 415-555-2671, card 4111111111111111,"
            " IBAN GB29NWBK60161331926819, see https://example.com/x"
        )
    }
    assert findings["PHONE"] == "415-555-2671"
    assert findings["CARD"] == "4111111111111111"
    assert findings["ACCT"] == "GB29NWBK60161331926819"
    assert findings["URLPARAM"] == "https://example.com/x"


def test_person_detected() -> None:
    findings = detect_presidio("Contact John Smith at the office")
    assert [(f.entity, f.value) for f in findings] == [("PERSON", "John Smith")]


def test_email_and_ip_stay_with_regex() -> None:
    entities = {f.entity for f in detect_presidio("mail bob@example.com from 10.0.0.5")}
    assert "EMAIL" not in entities
    assert not any(e.startswith("IP") for e in entities)


def test_min_score_filters_low_confidence() -> None:
    assert MIN_SCORE == 0.35
    assert detect_presidio("Call 415-555-2671", min_score=0.9) == []
    assert [f.entity for f in detect_presidio("Call 415-555-2671")] == ["PHONE"]
    assert detect_presidio("") == []


def test_engine_auto_masks_gaps() -> None:
    engine = MaskingEngine()
    result = engine.mask_text("Call 415-555-2671, card 4111111111111111")
    assert result.masked == "Call <<PHONE_001>>, card <<CARD_001>>"
    assert result.counts == {"PHONE": 1, "CARD": 1}
    assert engine.verify_masked(result.masked) == []


def test_engine_off_skips_presidio() -> None:
    engine = MaskingEngine(presidio="off")
    result = engine.mask_text("Call 415-555-2671")
    assert result.masked == "Call 415-555-2671"
    assert result.counts == {}


def test_regex_wins_overlap_with_person() -> None:
    engine = MaskingEngine()
    result = engine.mask_text("user=alice level=INFO login ok")
    assert "<<USER_001>>" in result.masked
    assert "PERSON" not in result.counts


def test_invalid_mode_rejected() -> None:
    with pytest.raises(ValueError, match="Invalid presidio mode"):
        MaskingEngine(presidio="bogus")


def test_on_without_package_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    import opsai.masking.engine as engine_module

    monkeypatch.setattr(engine_module, "available", lambda: False)
    with pytest.raises(PresidioUnavailableError, match="not installed"):
        MaskingEngine(presidio="on").scan("Call 415-555-2671")
    # Auto degrades to regex silently.
    assert MaskingEngine(presidio="auto").scan("Call 415-555-2671") == []
    assert MaskingEngine(presidio="off").scan("Call 415-555-2671") == []
