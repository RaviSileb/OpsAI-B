"""Tests for local risk classification and policy (FR-541..544)."""

from __future__ import annotations

from opsai.core.risk import check_policy, classify_risk, combine_risk


def test_destructive_beats_ai_label() -> None:
    assert classify_risk("kubectl delete pod web-1") == "change"
    assert classify_risk("kubectl delete namespace prod") == "destructive"
    assert combine_risk("read_only", "kubectl delete namespace prod") == "destructive"
    assert combine_risk("change", "kubectl delete pod web-1") == "change"


def test_read_only_and_unknown() -> None:
    assert classify_risk("kubectl logs web-1 | grep ERROR") == "read_only"
    assert classify_risk("journalctl -u kafka --since today") == "read_only"
    assert classify_risk("frobnicate --warp 9") == "change"


def test_chaining_blocked_pipe_allowed() -> None:
    allowed, _ = check_policy("kubectl logs web-1 | grep ERROR")
    assert allowed
    for chained in ["id; rm -rf /", "a && b", "a || b", "echo $(id)", "echo `id`", "a\nb"]:
        allowed, reason = check_policy(chained)
        assert not allowed, chained
        assert reason
    allowed, _ = check_policy("rm -rf /")
    assert not allowed
