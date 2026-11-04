"""Execution engine: runs, approvals, output checks, rollback (TZ FR-500..530).

MVP notes: synchronous step execution (no background jobs yet); ``local``
and ``ssh`` executors only; AI output verdict reuses the analysis provider.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opsai.app.config import Settings
from opsai.core.audit import AuditWriter
from opsai.core.inventory import InventoryStore
from opsai.core.policy import ExecutionPolicy, PolicyStore
from opsai.core.risk import combine_risk
from opsai.core.states import (
    RunStatus,
    StepStatus,
    TransitionError,
    check_run_transition,
    check_step_transition,
)
from opsai.db.models import HostRecord
from opsai.execution.base import ExecOptions, Executor
from opsai.execution.local_exec import LocalExecutor
from opsai.execution.ssh_exec import SshExecutor
from opsai.masking.engine import MaskingEngine
from opsai.providers.base import LLMMessage, LLMRequest
from opsai.providers.factory import get_provider

_RUN_COLUMNS = (
    "id, analysis_id, requested_by, status, dry_run, run_all, parent_run_id,"
    " started_at, finished_at"
)
_STEP_COLUMNS = (
    "id, run_id, ord, title, phase, target, target_host_id, shell, command_original,"
    " command_final, revisions, risk, status, exit_code, stdout_text, stderr_text,"
    " duration_ms, approvals, verify_command, rollback_command, policy_reason"
)
# Full SELECT literals (kept in sync with the column lists above).
_RUN_SELECT = (
    "SELECT id, analysis_id, requested_by, status, dry_run, run_all, parent_run_id,"
    " started_at, finished_at FROM execution_runs WHERE id = ?"
)
_STEP_SELECT = (
    "SELECT id, run_id, ord, title, phase, target, target_host_id, shell, command_original,"
    " command_final, revisions, risk, status, exit_code, stdout_text, stderr_text,"
    " duration_ms, approvals, verify_command, rollback_command, policy_reason"
    " FROM execution_steps WHERE run_id = ? ORDER BY ord ASC"
)

_VERDICT_SYSTEM = (
    "You judge one executed remediation command. Reply with JSON only:"
    ' {"verdict": "ok"|"fail"|"unclear", "reason": "short reason"}.'
    " Mark fail when the output shows the command did not achieve its purpose."
)


class ExecutionError(ValueError):
    """Raised when a run operation cannot proceed (mapped to 4xx)."""


class ApprovalRequiredError(ExecutionError):
    """Raised when a step waits for four-eyes approval."""


class TargetRequiredError(ExecutionError):
    """Raised when a step target must be chosen explicitly."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class ExecutionEngine:
    """Orchestrate remediation runs over inventory, policy and executors."""

    def __init__(
        self,
        settings: Settings,
        app_db: Path,
        audit: AuditWriter,
        inventory: InventoryStore | None = None,
        policies: PolicyStore | None = None,
        executors: dict[str, Executor] | None = None,
    ) -> None:
        self.settings = settings
        self.app_db = app_db
        self.audit = audit
        self.inventory = inventory or InventoryStore(app_db)
        self.policies = policies or PolicyStore(app_db)
        self.executors = executors or {"local": LocalExecutor(), "ssh": SshExecutor()}

    # -- runs ------------------------------------------------------------

    def dry_run(
        self,
        analysis_id: str,
        mapping: dict[str, str],
        target_overrides: dict[int, str] | None = None,
    ) -> dict[str, Any]:
        """Render the plan with resolved targets; never executes (FR-526)."""
        _analysis, steps = self._load_plan(analysis_id)
        policy = self.policies.get_execution()
        rendered = [
            self._render_step(policy, step, mapping, target_overrides or {}) for step in steps
        ]
        return {"analysis_id": analysis_id, "steps": rendered}

    def create_run(
        self,
        analysis_id: str,
        requested_by: str,
        mapping: dict[str, str],
        run_all: bool = False,
        target_overrides: dict[int, str] | None = None,
    ) -> dict[str, Any]:
        """Create a run from an analysis plan (FR-520: starts DRAFT)."""
        _analysis, steps = self._load_plan(analysis_id)
        if not steps:
            raise ExecutionError("Analysis has no remediation steps")
        policy = self.policies.get_execution()
        run_id = uuid.uuid4().hex
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "INSERT INTO execution_runs (id, analysis_id, requested_by, status,"
                " dry_run, run_all, started_at) VALUES (?, ?, ?, 'DRAFT', 0, ?, ?)",
                (run_id, analysis_id, requested_by, int(run_all), _now()),
            )
            for step in steps:
                rendered = self._render_step(policy, step, mapping, target_overrides or {})
                conn.execute(
                    "INSERT INTO execution_steps (id, run_id, ord, title, phase, target,"
                    " target_host_id, shell, command_original, command_final, revisions,"
                    " risk, status, verify_command, rollback_command, policy_reason)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        uuid.uuid4().hex,
                        run_id,
                        rendered["order"],
                        rendered["title"],
                        rendered["phase"],
                        rendered["target_raw"],
                        rendered["target_host_id"],
                        rendered["shell"],
                        rendered["command"],
                        rendered["command"],
                        "[]",
                        rendered["risk"],
                        rendered["status"],
                        rendered["verify_command"],
                        rendered["rollback_command"],
                        rendered["policy_reason"],
                    ),
                )
            conn.commit()
        self.audit.append(
            "run.created",
            actor=requested_by,
            object_type="run",
            object_id=run_id,
            details={"analysis_id": analysis_id, "steps": len(steps), "run_all": run_all},
        )
        run = self.get_run(run_id)
        if run_all:
            self.run_remaining(run_id, requested_by)
            run = self.get_run(run_id)
        return run

    def get_run(self, run_id: str) -> dict[str, Any]:
        """Return a run with its steps ordered."""
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(_RUN_SELECT, (run_id,)).fetchone()
            if row is None:
                raise ExecutionError(f"Unknown run {run_id!r}")
            step_rows = conn.execute(_STEP_SELECT, (run_id,)).fetchall()
        run: dict[str, Any] = dict(zip(_RUN_COLUMNS.split(", "), row, strict=True))
        run["steps"] = [self._step_to_dict(r) for r in step_rows]
        return run

    def abort_run(self, run_id: str, user: str) -> dict[str, Any]:
        """Abort a run and its unfinished steps."""
        run = self.get_run(run_id)
        check_run_transition(run["status"], RunStatus.ABORTED.value)
        self._set_run_status(run_id, RunStatus.ABORTED.value)
        for step in run["steps"]:
            if step["status"] in {
                "PENDING",
                "AWAITING_APPROVAL",
                "RUNNING",
                "FAILED",
                "TIMEOUT",
                "BLOCKED",
            }:
                self._set_step_status(run_id, step["ord"], StepStatus.ABORTED.value)
        self.audit.append(
            "run.aborted", actor=user, object_type="run", object_id=run_id, details={}
        )
        return self.get_run(run_id)

    # -- steps -----------------------------------------------------------

    def run_step(
        self,
        run_id: str,
        order: int,
        user: str,
        command: str | None = None,
        target_host_id: str | None = None,
        ai_check: bool = False,
    ) -> dict[str, Any]:
        """Run = approval: execute one step (FR-521)."""
        run = self.get_run(run_id)
        if run["status"] not in {"DRAFT", "IN_PROGRESS", "PAUSED"}:
            raise ExecutionError(f"Run is {run['status']}, cannot run steps")
        step = self._find_step(run, order)
        self._ensure_basic(run, step, target_host_id)
        if command is not None and command != step["command_final"]:
            self._add_revision(run_id, order, step, command, user)
            step = self._find_step(self.get_run(run_id), order)
        # Edited commands are re-checked: policy runs on the final text.
        self._enforce_policy(run_id, step)
        self._enforce_approval(run_id, step)
        self._move_run(run_id, run["status"], RunStatus.IN_PROGRESS.value)
        self._set_step_status(run_id, order, StepStatus.RUNNING.value)
        policy = self.policies.get_execution()
        timeout = min(policy.default_timeout_s, policy.max_timeout_s)
        result = self._execute(step, timeout)
        return self._finish_step(run_id, order, user, result, step, ai_check)

    def approve_step(self, run_id: str, order: int, user: str, note: str = "") -> dict[str, Any]:
        """Approve and immediately run a waiting step (FR-522)."""
        run = self.get_run(run_id)
        step = self._find_step(run, order)
        if user == run["requested_by"]:
            raise ExecutionError("Approver must differ from the requester (four-eyes)")
        approvals = json.loads(step["approvals"] or "[]")
        approvals.append({"by": user, "at": _now(), "note": note})
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "UPDATE execution_steps SET approvals = ? WHERE run_id = ? AND ord = ?",
                (json.dumps(approvals), run_id, order),
            )
            conn.commit()
        self.audit.append(
            "step.approved",
            actor=user,
            object_type="step",
            object_id=f"{run_id}:{order}",
            details={"note": note},
        )
        return self.run_step(run_id, order, run["requested_by"])

    def skip_step(self, run_id: str, order: int, user: str, reason: str) -> dict[str, Any]:
        """Skip a step with a mandatory reason (FR-524)."""
        if not reason.strip():
            raise ExecutionError("Skipping a step requires a reason")
        run = self.get_run(run_id)
        step = self._find_step(run, order)
        check_step_transition(step["status"], StepStatus.SKIPPED.value)
        self._set_step_status(run_id, order, StepStatus.SKIPPED.value)
        self.audit.append(
            "step.skipped",
            actor=user,
            object_type="step",
            object_id=f"{run_id}:{order}",
            details={"reason": reason},
        )
        self._refresh_run_status(run_id)
        return self.get_run(run_id)

    def abort_step(self, run_id: str, order: int, user: str) -> dict[str, Any]:
        """Abort one step (marks it ABORTED; running commands time out)."""
        run = self.get_run(run_id)
        step = self._find_step(run, order)
        check_step_transition(step["status"], StepStatus.ABORTED.value)
        self._set_step_status(run_id, order, StepStatus.ABORTED.value)
        self.audit.append(
            "step.aborted",
            actor=user,
            object_type="step",
            object_id=f"{run_id}:{order}",
            details={},
        )
        self._refresh_run_status(run_id)
        return self.get_run(run_id)

    def run_remaining(self, run_id: str, user: str, ai_check: bool = False) -> dict[str, Any]:
        """Run all remaining steps; stop on failure, block or choice (FR-521)."""
        run = self.get_run(run_id)
        for step in run["steps"]:
            if step["status"] not in {"PENDING", "AWAITING_APPROVAL", "FAILED", "TIMEOUT"}:
                continue
            try:
                self.run_step(run_id, step["ord"], user, ai_check=ai_check)
            except (ApprovalRequiredError, TargetRequiredError, ExecutionError):
                break
            current = self._find_step(self.get_run(run_id), step["ord"])
            if current["status"] in {"FAILED", "TIMEOUT", "BLOCKED", "ABORTED"}:
                break
        return self.get_run(run_id)

    def start_rollback(self, run_id: str, user: str) -> dict[str, Any]:
        """Create a rollback run from succeeded steps, reversed (FR-525)."""
        run = self.get_run(run_id)
        if run["status"] not in {"PAUSED", "FAILED", "IN_PROGRESS", "COMPLETED"}:
            raise ExecutionError(f"Cannot roll back a {run['status']} run")
        rollback_steps = [
            s
            for s in reversed(run["steps"])
            if s["status"] == "SUCCEEDED" and s["rollback_command"]
        ]
        irreversible = [
            s["ord"]
            for s in run["steps"]
            if s["status"] == "SUCCEEDED" and not s["rollback_command"]
        ]
        if not rollback_steps:
            raise ExecutionError("No succeeded steps with a rollback command")
        rollback_id = uuid.uuid4().hex
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "INSERT INTO execution_runs (id, analysis_id, requested_by, status,"
                " dry_run, run_all, parent_run_id, started_at)"
                " VALUES (?, ?, ?, 'IN_PROGRESS', 0, 0, ?, ?)",
                (rollback_id, run["analysis_id"], user, run_id, _now()),
            )
            for position, source in enumerate(rollback_steps, start=1):
                conn.execute(
                    "INSERT INTO execution_steps (id, run_id, ord, title, phase, target,"
                    " target_host_id, shell, command_original, command_final, revisions,"
                    " risk, status, verify_command, rollback_command)"
                    " VALUES (?, ?, ?, ?, 'rollback', ?, ?, ?, ?, ?, '[]', ?, 'PENDING', '', '')",
                    (
                        uuid.uuid4().hex,
                        rollback_id,
                        position,
                        f"Rollback: {source['title']}",
                        source["target"],
                        source["target_host_id"],
                        source["shell"],
                        source["rollback_command"],
                        source["rollback_command"],
                        source["risk"],
                    ),
                )
            conn.commit()
        self._move_run(run_id, run["status"], RunStatus.ROLLING_BACK.value)
        self.audit.append(
            "rollback.started",
            actor=user,
            object_type="run",
            object_id=rollback_id,
            details={"parent": run_id, "steps": len(rollback_steps), "irreversible": irreversible},
        )
        result = self.get_run(rollback_id)
        result["irreversible"] = irreversible
        return result

    # -- internals --------------------------------------------------------

    def _load_plan(self, analysis_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT id, session_id, provider, model, payload_mode, payload_sha256, status"
                " FROM analyses WHERE id = ?",
                (analysis_id,),
            ).fetchone()
            if row is None:
                raise ExecutionError(f"Unknown analysis {analysis_id!r}")
            response = conn.execute(
                "SELECT response_json FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
        analysis = {
            "id": row[0],
            "session_id": row[1],
            "provider": row[2],
            "model": row[3],
        }
        data = json.loads(response[0]) if response else {}
        steps = data.get("remediation_plan", {}).get("steps", [])
        return analysis, steps

    def _render_step(
        self,
        policy: ExecutionPolicy,
        step: dict[str, Any],
        mapping: dict[str, str],
        overrides: dict[int, str],
    ) -> dict[str, Any]:
        order = int(step.get("order", 0))
        target_raw = str(step.get("target", ""))
        restored, unknown = MaskingEngine.depseudonymize(target_raw, mapping)
        shell = str(step.get("shell", "bash"))
        risk = combine_risk(str(step.get("risk", "change")), str(step.get("command", "")))
        rendered: dict[str, Any] = {
            "order": order,
            "title": str(step.get("title", "")),
            "phase": str(step.get("phase", "fix")),
            "target_raw": target_raw,
            "target": restored,
            "target_host_id": "",
            "host_label": restored,
            "environment": "other",
            "executor": "",
            "shell": shell,
            "command": str(step.get("command", "")),
            "risk": risk,
            "status": StepStatus.PENDING.value,
            "policy_reason": "",
            "verify_command": str(step.get("verify_command") or ""),
            "rollback_command": str(step.get("rollback_command") or ""),
            "candidates": [],
            "needs_target": False,
        }
        if unknown:
            rendered["status"] = StepStatus.BLOCKED.value
            rendered["policy_reason"] = f"Unknown pseudonym tokens: {unknown}"
            return rendered
        override = overrides.get(order)
        if override:
            host = self.inventory.get(override)
            if host is None:
                raise ExecutionError(f"Unknown override host {override!r}")
            self._assign_host(rendered, host, "override")
        elif restored == "local":
            rendered["executor"] = "local"
            rendered["environment"] = "local"
            rendered["host_label"] = "local"
        elif restored.startswith("cluster:"):
            rendered["status"] = StepStatus.BLOCKED.value
            rendered["policy_reason"] = "kubectl executor is not in this milestone"
            return rendered
        else:
            resolution = self.inventory.resolve(restored)
            if resolution.decision == "single":
                assert resolution.single is not None
                self._assign_host(rendered, resolution.single, resolution.candidates[0].rule)
            else:
                rendered["needs_target"] = True
                rendered["candidates"] = [
                    {
                        "host_id": c.host.id,
                        "hostname": c.host.hostname,
                        "environment": c.host.environment,
                        "rule": c.rule,
                    }
                    for c in resolution.candidates
                ]
                rendered["policy_reason"] = (
                    "No inventory match; create the host or pick a target"
                    if resolution.decision == "none"
                    else "Ambiguous target; pick one explicitly"
                )
                return rendered
        decision = policy.evaluate(
            rendered["command"], risk, rendered["environment"], rendered["executor"] or "local"
        )
        reasons = list(decision.reasons)
        executor_name = rendered["executor"]
        executor = self.executors.get(executor_name)
        if executor is None:
            reasons.append(f"Executor {executor_name!r} is not available in this milestone")
        elif shell not in executor.shells:
            reasons.append(f"Shell {shell!r} is not supported by {executor_name!r}")
        if executor_name == "local" and not self._local_allowed():
            reasons.append("Local executor is disabled (OPSAI_LOCAL_EXEC_ENABLED=false)")
        if reasons:
            rendered["status"] = StepStatus.BLOCKED.value
            rendered["policy_reason"] = "; ".join(reasons)
        rendered["requires_approval"] = decision.requires_approval
        return rendered

    def _assign_host(self, rendered: dict[str, Any], host: HostRecord, rule: str) -> None:
        rendered["target_host_id"] = host.id
        rendered["host_label"] = host.hostname
        rendered["environment"] = host.environment
        rendered["executor"] = host.executor_type or "ssh"
        rendered["match_rule"] = rule

    def _local_allowed(self) -> bool:
        return bool(self.settings.local_exec_enabled and self.settings.mode == "desktop")

    def _ensure_basic(
        self, run: dict[str, Any], step: dict[str, Any], target_host_id: str | None
    ) -> None:
        if step["status"] == StepStatus.BLOCKED.value:
            self._recheck_blocked(run["id"], step)
            step = self._find_step(self.get_run(run["id"]), step["ord"])
            if step["status"] == StepStatus.BLOCKED.value:
                raise ExecutionError(f"Step is blocked: {step['policy_reason']}")
        if step["status"] not in {"PENDING", "AWAITING_APPROVAL", "FAILED", "TIMEOUT"}:
            raise ExecutionError(f"Step is {step['status']}, cannot run")
        if target_host_id:
            host = self.inventory.get(target_host_id)
            if host is None:
                raise ExecutionError(f"Unknown host {target_host_id!r}")
            with sqlite3.connect(self.app_db) as conn:
                conn.execute(
                    "UPDATE execution_steps SET target_host_id = ? WHERE run_id = ? AND ord = ?",
                    (target_host_id, run["id"], step["ord"]),
                )
                conn.commit()
            step["target_host_id"] = target_host_id
        if not step["target_host_id"] and step["target"] != "local":
            raise TargetRequiredError("Step target is ambiguous; pick target_host_id explicitly")

    def _enforce_policy(self, run_id: str, step: dict[str, Any]) -> None:
        policy = self.policies.get_execution()
        env = self._step_environment(step)
        executor_name = self._step_executor(step)
        decision = policy.evaluate(step["command_final"], step["risk"], env, executor_name)
        reasons = list(decision.reasons)
        executor = self.executors.get(executor_name)
        if executor is None:
            reasons.append(f"Executor {executor_name!r} is not available in this milestone")
        elif step["shell"] not in executor.shells:
            reasons.append(f"Shell {step['shell']!r} is not supported by {executor_name!r}")
        if executor_name == "local" and not self._local_allowed():
            reasons.append("Local executor is disabled (OPSAI_LOCAL_EXEC_ENABLED=false)")
        if reasons:
            if step["status"] != StepStatus.BLOCKED.value:
                self._set_step_status(run_id, step["ord"], StepStatus.BLOCKED.value)
            self._set_policy_reason(run_id, step["ord"], "; ".join(reasons))
            raise ExecutionError(f"Step blocked by policy: {'; '.join(reasons)}")

    def _enforce_approval(self, run_id: str, step: dict[str, Any]) -> None:
        run = self.get_run(run_id)
        policy = self.policies.get_execution()
        env = self._step_environment(step)
        decision = policy.evaluate(
            step["command_final"], step["risk"], env, self._step_executor(step)
        )
        if not decision.requires_approval:
            return
        approvals = json.loads(step["approvals"] or "[]")
        if not any(a.get("by") != run["requested_by"] for a in approvals):
            if step["status"] != StepStatus.AWAITING_APPROVAL.value:
                self._set_step_status(run_id, step["ord"], StepStatus.AWAITING_APPROVAL.value)
            raise ApprovalRequiredError("Step needs four-eyes approval by another user")

    def _step_environment(self, step: dict[str, Any]) -> str:
        if step["target_host_id"]:
            host = self.inventory.get(step["target_host_id"])
            if host:
                return host.environment
        if step["target"] == "local":
            return "local"
        return "other"

    def _step_executor(self, step: dict[str, Any]) -> str:
        if step["target_host_id"]:
            host = self.inventory.get(step["target_host_id"])
            if host:
                return host.executor_type or "ssh"
        if step["target"] == "local":
            return "local"
        return "ssh"

    def _recheck_blocked(self, run_id: str, step: dict[str, Any]) -> None:
        policy = self.policies.get_execution()
        env = self._step_environment(step)
        executor_name = self._step_executor(step)
        if not step["target_host_id"] and step["target"] != "local":
            return
        decision = policy.evaluate(step["command_final"], step["risk"], env, executor_name)
        executor = self.executors.get(executor_name)
        shell_ok = executor is not None and step["shell"] in executor.shells
        local_ok = executor_name != "local" or self._local_allowed()
        if decision.allowed and shell_ok and local_ok:
            self._set_step_status(run_id, step["ord"], StepStatus.PENDING.value)
            self._set_policy_reason(run_id, step["ord"], "")

    def _execute(self, step: dict[str, Any], timeout: int) -> Any:
        executor_name = self._step_executor(step)
        executor = self.executors.get(executor_name)
        if executor is None:
            raise ExecutionError(f"Executor {executor_name!r} is not available")
        target = self._target_config(step, executor_name)
        options = ExecOptions(timeout_s=timeout)
        return executor.run(step["command_final"], step["shell"], target, options)

    def _target_config(self, step: dict[str, Any], executor_name: str) -> dict[str, Any]:
        if executor_name == "local":
            return {"host": "localhost"}
        host = self.inventory.get(step["target_host_id"]) if step["target_host_id"] else None
        config: dict[str, Any] = {"host": host.hostname if host else step["target"]}
        if host and host.connection_profile_id:
            with sqlite3.connect(self.app_db) as conn:
                row = conn.execute(
                    "SELECT config_json FROM connection_profiles WHERE id = ?",
                    (host.connection_profile_id,),
                ).fetchone()
            if row:
                try:
                    config.update(json.loads(row[0]))
                except json.JSONDecodeError:
                    pass
        config.setdefault("host", config["host"])
        return config

    def _finish_step(
        self,
        run_id: str,
        order: int,
        user: str,
        result: Any,
        step: dict[str, Any],
        ai_check: bool,
    ) -> dict[str, Any]:
        expected = self._expected_for_step(run_id, order)
        ok, verdict = self._output_check(step, result, run_id, ai_check)
        final_status = StepStatus.SUCCEEDED.value if ok else StepStatus.FAILED.value
        if result.timed_out:
            final_status = StepStatus.TIMEOUT.value
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "UPDATE execution_steps SET status = ?, exit_code = ?, stdout_text = ?,"
                " stderr_text = ?, duration_ms = ?, policy_reason = ?"
                " WHERE run_id = ? AND ord = ?",
                (
                    final_status,
                    result.exit_code,
                    result.stdout,
                    result.stderr,
                    result.duration_ms,
                    verdict,
                    run_id,
                    order,
                ),
            )
            conn.commit()
        self.audit.append(
            "step.finished",
            actor=user,
            object_type="step",
            object_id=f"{run_id}:{order}",
            details={
                "command_final": step["command_final"],
                "command_original": step["command_original"],
                "target": step["target"],
                "target_host_id": step["target_host_id"],
                "executor": self._step_executor(step),
                "status": final_status,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "stdout_sha": _short_hash(result.stdout),
                "stderr_sha": _short_hash(result.stderr),
                "verdict": verdict,
                "expected_exit": expected["exit_code"],
                "expected_regex": expected["stdout_regex"],
            },
        )
        self._refresh_run_status(run_id)
        return self.get_run(run_id)

    def _output_check(
        self, step: dict[str, Any], result: Any, run_id: str, ai_check: bool
    ) -> tuple[bool, str]:
        if result.timed_out:
            return False, "timeout"
        expected = self._expected_for_step(run_id, step["ord"])
        if result.exit_code != expected["exit_code"]:
            return False, f"exit {result.exit_code} != expected {expected['exit_code']}"
        if expected["stdout_regex"]:
            try:
                if not re.search(expected["stdout_regex"], result.stdout):
                    return False, "stdout did not match expected regex"
            except re.error:
                return False, "invalid expected stdout regex"
        if ai_check:
            verdict, reason = self._ai_verdict(step, result, run_id)
            if verdict != "ok":
                return False, f"ai-verdict:{verdict}:{reason}"
            return True, f"ai-verdict:ok:{reason}"
        return True, "exit+regex ok"

    def _expected_for_step(self, run_id: str, order: int) -> dict[str, Any]:
        run = self.get_run(run_id)
        _analysis, steps = self._load_plan(run["analysis_id"])
        # Rollback runs mirror parent steps; find by title fallback when order shifts.
        candidates = [s for s in steps if int(s.get("order", -1)) == order]
        if not candidates:
            return {"exit_code": 0, "stdout_regex": ""}
        expected = candidates[0].get("expected", {}) or {}
        return {
            "exit_code": int(expected.get("exit_code", 0)),
            "stdout_regex": str(expected.get("stdout_regex") or ""),
        }

    def _ai_verdict(self, step: dict[str, Any], result: Any, run_id: str) -> tuple[str, str]:
        run = self.get_run(run_id)
        analysis_id = run["analysis_id"]
        with sqlite3.connect(self.app_db) as conn:
            row = conn.execute(
                "SELECT provider, model FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
        provider_name, model = (row[0], row[1]) if row else ("mock", "mock-analysis-v1")
        provider, _live = get_provider(provider_name, self.settings)
        engine = MaskingEngine()
        blob = f"STDOUT:\n{result.stdout[-32000:]}\nSTDERR:\n{result.stderr[-32000:]}"
        masked = engine.mask_text(blob).masked
        request = LLMRequest(
            system=_VERDICT_SYSTEM,
            messages=[
                LLMMessage(
                    role="user",
                    content=f"Command: {step['command_final']}\nExpected exit 0.\n{masked}",
                )
            ],
            max_output_tokens=256,
        )
        try:
            response = provider.generate(request, model)
            data = response.data if isinstance(response.data, dict) else {}
        except Exception:  # noqa: BLE001 - verdict failure pauses, never crashes
            return "unclear", "provider error"
        verdict = str(data.get("verdict", "unclear")).lower()
        if verdict not in {"ok", "fail", "unclear"}:
            return "unclear", "unparseable verdict"
        return verdict, str(data.get("reason", ""))[:200]

    def _refresh_run_status(self, run_id: str) -> None:
        run = self.get_run(run_id)
        if run["status"] in {"COMPLETED", "ROLLED_BACK", "ABORTED"}:
            return
        statuses = [s["status"] for s in run["steps"]]
        if not statuses:
            return
        if all(s in {"SUCCEEDED", "SKIPPED"} for s in statuses):
            self._move_run(run_id, run["status"], RunStatus.COMPLETED.value)
            self._maybe_close_parent(run)
            return
        if any(s in {"FAILED", "TIMEOUT"} for s in statuses):
            if run["parent_run_id"]:
                self._move_run(run_id, run["status"], RunStatus.FAILED.value)
                parent = self.get_run(run["parent_run_id"])
                if parent["status"] == RunStatus.ROLLING_BACK.value:
                    self._move_run(parent["id"], parent["status"], RunStatus.FAILED.value)
            elif run["status"] == RunStatus.IN_PROGRESS.value:
                self._move_run(run_id, run["status"], RunStatus.PAUSED.value)
            return
        if any(s in {"RUNNING", "AWAITING_APPROVAL", "PENDING", "BLOCKED"} for s in statuses):
            if run["status"] in {"DRAFT", "PAUSED"}:
                self._move_run(run_id, run["status"], RunStatus.IN_PROGRESS.value)

    def _maybe_close_parent(self, run: dict[str, Any]) -> None:
        if not run["parent_run_id"]:
            return
        try:
            parent = self.get_run(run["parent_run_id"])
        except ExecutionError:
            return
        if parent["status"] == RunStatus.ROLLING_BACK.value:
            self._move_run(parent["id"], parent["status"], RunStatus.ROLLED_BACK.value)

    def _move_run(self, run_id: str, old: str, new: str) -> None:
        if old == new:
            return
        try:
            check_run_transition(old, new)
        except (TransitionError, ValueError):
            return
        self._set_run_status(run_id, new)

    def _set_run_status(self, run_id: str, status: str) -> None:
        finished = _now() if status in {"COMPLETED", "FAILED", "ROLLED_BACK", "ABORTED"} else ""
        with sqlite3.connect(self.app_db) as conn:
            if finished:
                conn.execute(
                    "UPDATE execution_runs SET status = ?, finished_at = ? WHERE id = ?",
                    (status, finished, run_id),
                )
            else:
                conn.execute("UPDATE execution_runs SET status = ? WHERE id = ?", (status, run_id))
            conn.commit()

    def _set_step_status(self, run_id: str, order: int, status: str) -> None:
        step = self._find_step(self.get_run(run_id), order)
        check_step_transition(step["status"], status)
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "UPDATE execution_steps SET status = ? WHERE run_id = ? AND ord = ?",
                (status, run_id, order),
            )
            conn.commit()

    def _set_policy_reason(self, run_id: str, order: int, reason: str) -> None:
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "UPDATE execution_steps SET policy_reason = ? WHERE run_id = ? AND ord = ?",
                (reason, run_id, order),
            )
            conn.commit()

    def _add_revision(
        self, run_id: str, order: int, step: dict[str, Any], command: str, user: str
    ) -> None:
        revisions = json.loads(step["revisions"] or "[]")
        revisions.append({"command": step["command_final"], "by": user, "at": _now()})
        risk = combine_risk(step["risk"], command)
        with sqlite3.connect(self.app_db) as conn:
            conn.execute(
                "UPDATE execution_steps SET command_final = ?, revisions = ?, risk = ?"
                " WHERE run_id = ? AND ord = ?",
                (command, json.dumps(revisions), risk, run_id, order),
            )
            conn.commit()

    def _find_step(self, run: dict[str, Any], order: int) -> dict[str, Any]:
        for step in run["steps"]:
            if step["ord"] == order:
                found: dict[str, Any] = step
                return found
        raise ExecutionError(f"Run has no step {order}")

    @staticmethod
    def _step_to_dict(row: Any) -> dict[str, Any]:
        keys = _STEP_COLUMNS.split(", ")
        item: dict[str, Any] = dict(zip(keys, row, strict=True))
        item["approvals"] = item["approvals"] or "[]"
        item["revisions"] = item["revisions"] or "[]"
        return item
