"""API integration tests over an isolated data dir (mock AI, no network)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from opsai.api.main import create_app
from opsai.app.config import Settings


def _client(tmp_path: Path) -> TestClient:
    from dataclasses import replace

    settings = replace(Settings.from_env(), data_dir=tmp_path / "api-data", dev_auth=True)
    return TestClient(create_app(settings))


def test_health_and_metrics(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.get("/api/v1/health/live").json() == {"status": "ok"}
    assert client.get("/api/v1/health/ready").json() == {"status": "ready"}
    metrics = client.get("/api/v1/metrics").text
    assert "opsai_sessions_total 0" in metrics


def test_rbac_denies_viewer_writes(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post("/api/v1/sessions", json={"name": "x"}, headers={"X-Role": "viewer"})
    assert response.status_code == 403
    assert response.headers["content-type"] == "application/problem+json"


def test_session_ingest_query_flow(tmp_path: Path, sample_log: Path) -> None:
    client = _client(tmp_path)
    session_id = client.post("/api/v1/sessions", json={"name": "api"}).json()["id"]
    ingest = client.post(
        f"/api/v1/sessions/{session_id}/ingest-file", json={"path": str(sample_log)}
    ).json()
    assert ingest["added"] == 4
    assert ingest["status"] == "OPEN"
    page = client.get(
        f"/api/v1/sessions/{session_id}/records", params={"oql": "level>=ERROR"}
    ).json()
    assert page["total"] == 1
    detail = client.get(f"/api/v1/sessions/{session_id}/records/{page['items'][0]['rid']}").json()
    assert "Traceback" in detail["message"]
    stats = client.get(f"/api/v1/sessions/{session_id}/stats").json()
    assert stats["total"] == 4
    templates = client.get(f"/api/v1/sessions/{session_id}/templates").json()
    assert templates["sampled"] == 4
    assert client.get("/api/v1/sessions").json()["items"][0]["name"] == "api"


def test_preview_send_mock_flow_with_audit(tmp_path: Path, sample_log: Path) -> None:
    client = _client(tmp_path)
    session_id = client.post("/api/v1/sessions", json={"name": "ai"}).json()["id"]
    client.post(f"/api/v1/sessions/{session_id}/ingest-file", json={"path": str(sample_log)})
    preview = client.post(
        "/api/v1/analyses/preview",
        json={
            "session_id": session_id,
            "oql": "",
            "mode": "full",
            "provider": "mock",
            "model": "mock-analysis-v1",
        },
    ).json()
    assert preview["records"] == 4
    assert "hunter2" not in preview["payload"]
    assert "<<SECRET_001>>" in preview["payload"]
    assert preview["masking_counts"].get("SECRET") == 1
    send = client.post(
        "/api/v1/analyses",
        json={"stage_id": preview["stage_id"], "payload_sha256": preview["payload_sha256"]},
    ).json()
    assert send["live"] is False
    assert send["display"]["remediation_plan"]["steps"][0]["risk"] == "read_only"
    fetched = client.get(f"/api/v1/analyses/{send['id']}").json()
    assert fetched["payload_sha256"] == preview["payload_sha256"]
    events = client.get("/api/v1/audit/events").json()["items"]
    assert any(e["event_type"] == "ai.dispatch" for e in events)
    verify = client.get("/api/v1/audit/verify").json()
    assert verify == {"ok": True, "checked": 1}
    # Stage is single-use.
    retry = client.post(
        "/api/v1/analyses",
        json={"stage_id": preview["stage_id"], "payload_sha256": preview["payload_sha256"]},
    )
    assert retry.status_code == 410


def test_runs_forbidden_when_execution_disabled(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post("/api/v1/runs", headers={"X-Role": "operator"})
    assert response.status_code == 403


def test_generic_ingest_flow(tmp_path: Path) -> None:
    client = _client(tmp_path)
    session_id = client.post("/api/v1/sessions", json={"name": "push"}).json()["id"]
    ingest = client.post(
        f"/api/v1/sessions/{session_id}/ingest",
        json={
            "source": "webhook-1",
            "records": [
                {
                    "message": "user login failed",
                    "ts": "2026-10-27T10:00:00Z",
                    "level": "ERROR",
                    "host": "web-1",
                    "service": "auth",
                    "fields": {"user": "bob"},
                },
                {"message": "plain line without metadata"},
            ],
        },
    ).json()
    assert ingest == {"added": 2, "status": "OPEN"}
    page = client.get(
        f"/api/v1/sessions/{session_id}/records", params={"oql": "level>=ERROR"}
    ).json()
    assert page["total"] == 1
    assert page["items"][0]["origin_host"] == "web-1"
    assert page["items"][0]["service"] == "auth"


def test_generic_ingest_validation(tmp_path: Path) -> None:
    client = _client(tmp_path)
    session_id = client.post("/api/v1/sessions", json={"name": "push"}).json()["id"]
    url = f"/api/v1/sessions/{session_id}/ingest"
    bad_ts = client.post(
        url, json={"source": "s", "records": [{"message": "m", "ts": "yesterday-ish"}]}
    )
    assert bad_ts.status_code == 422
    empty = client.post(url, json={"source": "s", "records": []})
    assert empty.status_code == 422
    bad_source = client.post(url, json={"source": "../evil", "records": [{"message": "m"}]})
    assert bad_source.status_code == 422
    missing = client.post(
        "/api/v1/sessions/nope/ingest",
        json={"source": "s", "records": [{"message": "m"}]},
    )
    assert missing.status_code == 404
    denied = client.post(
        url,
        json={"source": "s", "records": [{"message": "m"}]},
        headers={"X-Role": "viewer"},
    )
    assert denied.status_code == 403
