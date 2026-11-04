"""Execution API integration tests (mock AI, local executor, no network)."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from opsai.api.main import create_app
from opsai.app.config import Settings
from opsai.providers.base import LLMMessage, LLMRequest
from opsai.providers.mock_provider import MockProvider

OPERATOR = {"X-Role": "operator", "X-User": "alice"}
APPROVER = {"X-Role": "approver", "X-User": "bob"}
ADMIN = {"X-Role": "admin", "X-User": "root"}


def _client(tmp_path: Path, **overrides: Any) -> TestClient:
    kwargs: dict[str, Any] = {
        "data_dir": tmp_path / "exec-data",
        "execution_enabled": True,
        "local_exec_enabled": True,
        "dev_auth": True,
    }
    kwargs.update(overrides)
    settings = replace(Settings.from_env(), **kwargs)
    return TestClient(create_app(settings))


def _mock_analysis_id(client: TestClient, tmp_path: Path, sample_log: Path) -> str:
    session_id = client.post("/api/v1/sessions", json={"name": "ex"}).json()["id"]
    client.post(f"/api/v1/sessions/{session_id}/ingest-file", json={"path": str(sample_log)})
    preview = client.post(
        "/api/v1/analyses/preview",
        json={"session_id": session_id, "mode": "full"},
    ).json()
    send = client.post(
        "/api/v1/analyses",
        json={"stage_id": preview["stage_id"], "payload_sha256": preview["payload_sha256"]},
    ).json()
    return str(send["id"])


def _custom_analysis(client: TestClient, tmp_path: Path, steps: list[dict[str, Any]]) -> str:
    data = (
        MockProvider()
        .generate(
            LLMRequest(system="t", messages=[LLMMessage(role="user", content="R1: x")]),
            "mock-analysis-v1",
        )
        .data
    )
    assert data is not None
    data["remediation_plan"]["steps"] = steps
    analysis_id = "a" * 32
    db_path = tmp_path / "exec-data" / "app.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO analyses (id, session_id, provider, model, payload_mode,"
            " payload_sha256, status, prompt_version, created_at, response_json)"
            " VALUES (?, 's', 'mock', 'mock-analysis-v1', 'full', 'x', 'DONE', 'v1', '', ?)",
            (analysis_id, json.dumps(data)),
        )
        conn.commit()
    return analysis_id


def _step(order: int, command: str, **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "order": order,
        "title": f"step {order}",
        "phase": "fix",
        "target": "local",
        "shell": "bash",
        "command": command,
        "purpose": "test",
        "risk": "read_only",
        "expected": {"exit_code": 0, "stdout_regex": None, "description": "ok"},
        "verify_command": None,
        "rollback_command": None,
        "requires_downtime": False,
    }
    base.update(extra)
    return base


def test_dry_run_renders_without_executing(tmp_path: Path, sample_log: Path) -> None:
    client = _client(tmp_path)
    analysis_id = _mock_analysis_id(client, tmp_path, sample_log)
    dry = client.post(
        f"/api/v1/plans/{analysis_id}/runs", json={"dry_run": True}, headers=OPERATOR
    ).json()
    assert dry["steps"][0]["executor"] == "local"
    assert dry["steps"][0]["status"] == "PENDING"


def test_run_step_with_edit_completes(tmp_path: Path, sample_log: Path) -> None:
    client = _client(tmp_path)
    analysis_id = _mock_analysis_id(client, tmp_path, sample_log)
    run = client.post(f"/api/v1/plans/{analysis_id}/runs", json={}, headers=OPERATOR).json()
    assert run["status"] == "DRAFT"
    finished = client.post(
        f"/api/v1/runs/{run['id']}/steps/1/run",
        json={"command": "echo hello"},
        headers=OPERATOR,
    ).json()
    step = finished["steps"][0]
    assert step["status"] == "SUCCEEDED"
    assert step["stdout_text"].strip() == "hello"
    assert step["command_original"] != step["command_final"]
    assert finished["status"] == "COMPLETED"
    events = client.get("/api/v1/audit/events", headers=ADMIN).json()["items"]
    kinds = {e["event_type"] for e in events}
    assert {"run.created", "step.finished"} <= kinds


def test_four_eyes_flow(tmp_path: Path, sample_log: Path) -> None:
    client = _client(tmp_path)
    policy = client.get("/api/v1/policies/execution", headers=ADMIN).json()
    policy["four_eyes_risks"] = ["read_only"]
    policy["four_eyes_envs"] = ["local"]
    saved = client.put("/api/v1/policies/execution", json=policy, headers=ADMIN).json()
    assert saved["version"] == 1
    analysis_id = _mock_analysis_id(client, tmp_path, sample_log)
    run = client.post(f"/api/v1/plans/{analysis_id}/runs", json={}, headers=OPERATOR).json()
    waiting = client.post(
        f"/api/v1/runs/{run['id']}/steps/1/run", json={"command": "echo hi"}, headers=OPERATOR
    )
    assert waiting.status_code == 409
    assert waiting.json()["code"] == "ApprovalRequiredError"
    fetched = client.get(f"/api/v1/runs/{run['id']}", headers=OPERATOR).json()
    assert fetched["steps"][0]["status"] == "AWAITING_APPROVAL"
    self_approve = client.post(
        f"/api/v1/runs/{run['id']}/steps/1/approve",
        json={},
        headers={"X-Role": "approver", "X-User": "alice"},
    )
    assert self_approve.status_code == 400
    done = client.post(
        f"/api/v1/runs/{run['id']}/steps/1/approve", json={"note": "ok"}, headers=APPROVER
    ).json()
    assert done["steps"][0]["status"] == "SUCCEEDED"
    assert done["steps"][0]["stdout_text"].strip() == "hi"
    assert done["status"] == "COMPLETED"


def test_rollback_reverses_succeeded_steps(tmp_path: Path) -> None:
    client = _client(tmp_path)
    analysis_id = _custom_analysis(
        client,
        tmp_path,
        [
            _step(1, "echo do-1", rollback_command="echo rb-1"),
            _step(2, "echo do-2", rollback_command="echo rb-2"),
        ],
    )
    run = client.post(
        f"/api/v1/plans/{analysis_id}/runs", json={"run_all": True}, headers=OPERATOR
    ).json()
    assert run["status"] == "COMPLETED"
    rollback = client.post(f"/api/v1/runs/{run['id']}/rollback", headers=OPERATOR).json()
    assert [s["command_final"] for s in rollback["steps"]] == ["echo rb-2", "echo rb-1"]
    assert rollback["irreversible"] == []
    done = client.post(f"/api/v1/runs/{rollback['id']}/run-all", headers=OPERATOR).json()
    assert done["status"] == "COMPLETED"
    parent = client.get(f"/api/v1/runs/{run['id']}", headers=OPERATOR).json()
    assert parent["status"] == "ROLLED_BACK"


def test_unknown_token_target_blocks_step(tmp_path: Path) -> None:
    client = _client(tmp_path)
    analysis_id = _custom_analysis(client, tmp_path, [_step(1, "echo x", target="<<HOST_999>>")])
    dry = client.post(
        f"/api/v1/plans/{analysis_id}/runs", json={"dry_run": True}, headers=OPERATOR
    ).json()
    assert dry["steps"][0]["status"] == "BLOCKED"
    assert "Unknown pseudonym" in dry["steps"][0]["policy_reason"]


def test_gates_and_skip(tmp_path: Path, sample_log: Path) -> None:
    client = _client(tmp_path)
    assert (
        client.post("/api/v1/plans/xx/runs", json={}, headers={"X-Role": "viewer"}).status_code
        == 403
    )
    analysis_id = _mock_analysis_id(client, tmp_path, sample_log)
    run = client.post(f"/api/v1/plans/{analysis_id}/runs", json={}, headers=OPERATOR).json()
    assert (
        client.post(
            f"/api/v1/runs/{run['id']}/steps/1/skip", json={"reason": ""}, headers=OPERATOR
        ).status_code
        == 400
    )
    skipped = client.post(
        f"/api/v1/runs/{run['id']}/steps/1/skip",
        json={"reason": "not needed"},
        headers=OPERATOR,
    ).json()
    assert skipped["steps"][0]["status"] == "SKIPPED"
    assert skipped["status"] == "COMPLETED"
    disabled = _client(tmp_path, execution_enabled=False)
    assert disabled.post("/api/v1/plans/xx/runs", json={}, headers=OPERATOR).status_code == 403


def test_inventory_and_policy_endpoints(tmp_path: Path) -> None:
    client = _client(tmp_path)
    host = client.post(
        "/api/v1/inventory",
        json={"hostname": "db-01", "environment": "prod", "aliases": ["primary"]},
        headers=ADMIN,
    ).json()
    assert host["hostname"] == "db-01"
    resolved = client.post(
        "/api/v1/inventory/resolve", json={"target": "primary"}, headers=OPERATOR
    ).json()
    assert resolved["decision"] == "single"
    assert client.get(f"/api/v1/inventory/{host['id']}", headers=OPERATOR).status_code == 200
    assert (
        client.post(
            "/api/v1/inventory",
            json={"hostname": "x"},
            headers=OPERATOR,
        ).status_code
        == 403
    )
    bad = client.put("/api/v1/policies/execution", json={"time_windows": ["nope"]}, headers=ADMIN)
    assert bad.status_code == 400


def test_deny_list_blocks_edit(tmp_path: Path) -> None:
    client = _client(tmp_path)
    analysis_id = _custom_analysis(client, tmp_path, [_step(1, "echo safe")])
    run = client.post(f"/api/v1/plans/{analysis_id}/runs", json={}, headers=OPERATOR).json()
    blocked = client.post(
        f"/api/v1/runs/{run['id']}/steps/1/run",
        json={"command": "rm -rf /"},
        headers=OPERATOR,
    )
    assert blocked.status_code == 400
    fetched = client.get(f"/api/v1/runs/{run['id']}", headers=OPERATOR).json()
    assert fetched["steps"][0]["status"] == "BLOCKED"
