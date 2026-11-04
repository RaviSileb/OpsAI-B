"""Tests for the execution policy (FR-540..544)."""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from opsai.core.policy import ExecutionPolicy


def test_deny_list_blocks() -> None:
    policy = ExecutionPolicy()
    decision = policy.evaluate("rm -rf /", "destructive", "dev", "local")
    assert not decision.allowed
    assert any("deny" in r for r in decision.reasons)


def test_single_pipe_allowed_chains_blocked() -> None:
    policy = ExecutionPolicy()
    assert policy.evaluate("kubectl logs web | grep ERROR", "read_only", "dev", "local").allowed
    assert not policy.evaluate("id; rm -rf /tmp/x", "change", "dev", "local").allowed
    assert not policy.evaluate("a && b", "change", "dev", "local").allowed


def test_chain_allowlist_permits_listed_pattern() -> None:
    policy = ExecutionPolicy(chain_allowlist=[r"^migrate --to latest && verify$"])
    assert policy.evaluate("migrate --to latest && verify", "change", "dev", "local").allowed
    assert not policy.evaluate("other && verify", "change", "dev", "local").allowed


def test_env_risk_cap_and_four_eyes() -> None:
    policy = ExecutionPolicy(
        env_max_risk={"prod": "change"},
        four_eyes_envs=["prod"],
        four_eyes_risks=["change", "destructive"],
    )
    assert not policy.evaluate("rm -rf /data/x", "destructive", "prod", "local").allowed
    decision = policy.evaluate("systemctl restart app", "change", "prod", "local")
    assert decision.allowed
    assert decision.requires_approval
    dev = policy.evaluate("systemctl restart app", "change", "dev", "local")
    assert dev.allowed
    assert not dev.requires_approval


def test_allow_only_mode() -> None:
    policy = ExecutionPolicy(allow_only=[r"^kubectl get ", r"^systemctl status "])
    assert policy.evaluate("kubectl get pods", "read_only", "dev", "local").allowed
    assert not policy.evaluate("kubectl delete pod x", "change", "dev", "local").allowed


def test_executor_allowlist() -> None:
    policy = ExecutionPolicy(allowed_executors=["ssh"])
    assert policy.evaluate("echo hi", "read_only", "dev", "ssh").allowed
    assert not policy.evaluate("echo hi", "read_only", "dev", "local").allowed


def test_time_windows() -> None:
    policy = ExecutionPolicy(time_windows=["0 2 * * *"], timezone="UTC")
    inside = datetime(2026, 10, 27, 2, 0, 30, tzinfo=ZoneInfo("UTC"))
    outside = datetime(2026, 10, 27, 3, 0, 0, tzinfo=ZoneInfo("UTC"))
    assert policy.evaluate("echo hi", "read_only", "dev", "local", now=inside).allowed
    assert not policy.evaluate("echo hi", "read_only", "dev", "local", now=outside).allowed


def test_invalid_policy_rejected() -> None:
    with pytest.raises(ValueError):
        ExecutionPolicy.from_dict({"env_max_risk": {"prod": "nuke"}})
    with pytest.raises(ValueError):
        ExecutionPolicy.from_dict({"time_windows": ["not a cron"]})
    with pytest.raises(ValueError):
        ExecutionPolicy.from_dict({"deny_patterns": ["(["]})
