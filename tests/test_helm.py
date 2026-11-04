"""Tests for the Helm chart (lint + rendered manifests)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

CHART = Path(__file__).resolve().parent.parent / "helm" / "opsai"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")


def _run(args: list[str]) -> str:
    completed = subprocess.run(
        ["helm", *args], capture_output=True, text=True, check=True, timeout=120
    )
    return completed.stdout


def _render(extra: list[str] | None = None) -> list[dict[str, Any]]:
    docs = _run(["template", "opsai-test", str(CHART), *(extra or [])])
    return [doc for doc in yaml.safe_load_all(docs) if doc]


def _by_kind(docs: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [doc for doc in docs if doc.get("kind") == kind]


def test_helm_lint() -> None:
    out = _run(["lint", str(CHART)])
    assert "0 chart(s) failed" in out


def test_default_render_matches_base() -> None:
    docs = _render()
    assert sorted(d["kind"] for d in docs) == [
        "ConfigMap",
        "Deployment",
        "PersistentVolumeClaim",
        "Service",
    ]
    (deployment,) = _by_kind(docs, "Deployment")
    assert deployment["spec"]["strategy"]["type"] == "Recreate"
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == "ghcr.io/ravisileb/opsai-a:latest"
    assert container["livenessProbe"]["httpGet"]["path"] == "/api/v1/health/live"
    assert container["readinessProbe"]["httpGet"]["path"] == "/api/v1/health/ready"
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert container["resources"]["limits"]["memory"] == "3Gi"
    env = {item["name"]: item for item in container["env"]}
    assert env["OPSAI_MASTER_KEY"]["valueFrom"]["secretKeyRef"]["optional"] is True
    (config,) = _by_kind(docs, "ConfigMap")
    assert config["data"]["OPSAI_MODE"] == "server"
    assert config["data"]["OPSAI_PORT"] == "8080"
    assert config["data"]["OPSAI_SESSION_BACKEND"] == "duckdb"
    (pvc,) = _by_kind(docs, "PersistentVolumeClaim")
    assert pvc["spec"]["resources"]["requests"]["storage"] == "20Gi"


def test_secret_and_ingress_are_opt_in() -> None:
    docs = _render(["--set", "secrets.masterKey=dummy", "--set", "ingress.enabled=true"])
    (secret,) = _by_kind(docs, "Secret")
    assert secret["stringData"] == {"master-key": "dummy"}
    (ingress,) = _by_kind(docs, "Ingress")
    assert ingress["spec"]["rules"][0]["host"] == "opsai.local"


def test_persistence_can_be_disabled() -> None:
    docs = _render(["--set", "persistence.enabled=false"])
    assert _by_kind(docs, "PersistentVolumeClaim") == []
    (deployment,) = _by_kind(docs, "Deployment")
    volumes = {
        volume["name"]: volume for volume in deployment["spec"]["template"]["spec"]["volumes"]
    }
    assert volumes["data"] == {"name": "data", "emptyDir": {}}


def test_image_and_service_overrides() -> None:
    docs = _render(
        [
            "--set",
            "image.repository=example.com/opsai",
            "--set",
            "image.tag=v1",
            "--set",
            "service.port=8080",
        ]
    )
    (deployment,) = _by_kind(docs, "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == "example.com/opsai:v1"
    (service,) = _by_kind(docs, "Service")
    assert service["spec"]["ports"][0]["port"] == 8080
