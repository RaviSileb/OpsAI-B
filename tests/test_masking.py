"""Tests for the masking engine (FR-400..FR-408, FR-414..415)."""

from __future__ import annotations

from pathlib import Path

from opsai.masking.engine import MaskingEngine, PseudonymMap


def _valid_birth_number() -> str:
    for suffix in range(0, 10000):
        candidate = f"860101{suffix:04d}"
        if int(candidate) % 11 == 0:
            return f"860101/{suffix:04d}"
    raise AssertionError("no valid birth number found")


def test_detectors_find_each_entity() -> None:
    engine = MaskingEngine(known_hosts=["app-srv-12"])
    text = (
        "from 10.1.2.3 user=alice mail alice@example.com password=hunter2 "
        "token ghp_ABCDEFGHIJKLMNOPQRSTUV host app-srv-12 rc " + _valid_birth_number()
    )
    result = engine.mask_text(text)
    assert result.counts["IP_PRIV"] == 1
    assert result.counts["USER"] >= 1
    assert result.counts["EMAIL"] == 1
    assert result.counts["SECRET"] == 1
    assert result.counts["TOKEN"] >= 1
    assert result.counts["HOST"] == 1
    assert result.counts["RC"] == 1
    assert "hunter2" not in result.masked
    assert "10.1.2.3" not in result.masked


def _invalid_birth_number() -> str:
    for suffix in range(0, 10000):
        candidate = f"860101{suffix:04d}"
        if int(candidate) % 11 != 0:
            return f"860101/{suffix:04d}"
    raise AssertionError("no invalid birth number found")


def test_invalid_birth_number_is_ignored() -> None:
    engine = MaskingEngine()
    result = engine.mask_text(f"rc {_invalid_birth_number()}")
    assert "RC" not in result.counts


def test_allowlist_wins_over_detectors() -> None:
    engine = MaskingEngine()
    result = engine.mask_text("user=root from 127.0.0.1")
    assert "USER" not in result.counts
    assert "root" in result.masked
    assert result.counts.get("IP_LOOPBACK") == 1


def test_masking_is_consistent_within_session() -> None:
    engine = MaskingEngine()
    first = engine.mask_text("from 10.9.9.9")
    second = engine.mask_text("again 10.9.9.9")
    assert first.masked == "from <<IP_PRIV_001>>"
    assert second.masked == "again <<IP_PRIV_001>>"
    assert engine.pseudonyms.value_for("<<IP_PRIV_001>>") == "10.9.9.9"


def test_post_mask_verification_finds_leak() -> None:
    engine = MaskingEngine()
    leaked = "all masked <<IP_PRIV_001>> but password=plainleak stayed"
    findings = engine.verify_masked(leaked)
    assert [f.entity for f in findings] == ["SECRET"]


def test_manual_masking_covers_all_occurrences() -> None:
    engine = MaskingEngine()
    result = engine.mask_manual("alpha beta alpha", "alpha")
    assert result.masked == "<<MANUAL_001>> beta <<MANUAL_001>>"
    assert result.counts == {"MANUAL": 2}


def test_depseudonymize_restores_and_flags_unknown() -> None:
    mapping = {"<<HOST_003>>": "app-srv-12"}
    restored, unknown = MaskingEngine.depseudonymize("run on host_3 now", mapping)
    assert restored == "run on app-srv-12 now"
    assert unknown == []
    restored, unknown = MaskingEngine.depseudonymize("run on <<HOST_099>> now", mapping)
    assert restored == "run on <<HOST_099>> now"
    assert unknown == ["<<HOST_099>>"]


def test_depseudonymize_ignores_plain_text() -> None:
    restored, unknown = MaskingEngine.depseudonymize("error_404 happened", {})
    assert (restored, unknown) == ("error_404 happened", [])


def test_pseudonym_map_encrypted_roundtrip(tmp_path: Path) -> None:
    mapping = PseudonymMap()
    mapping.token_for("HOST", "db-01")
    mapping.token_for("SECRET", "s3cret")
    key = b"0" * 32
    path = tmp_path / "map.json"
    mapping.save_encrypted(path, key)
    assert "s3cret" not in path.read_text(encoding="utf-8")
    loaded = PseudonymMap.load_encrypted(path, key)
    assert loaded.value_for("<<HOST_001>>") == "db-01"
    assert loaded.value_for("<<SECRET_001>>") == "s3cret"
    assert loaded.token_for("HOST", "DB-01") == "<<HOST_001>>"
