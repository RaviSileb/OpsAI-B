"""Execution state machines for runs and steps (TZ FR-520)."""

from __future__ import annotations

from enum import StrEnum


class RunStatus(StrEnum):
    """Run lifecycle states."""

    DRAFT = "DRAFT"
    IN_PROGRESS = "IN_PROGRESS"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    ABORTED = "ABORTED"


class StepStatus(StrEnum):
    """Step lifecycle states (run = approval, no separate approve state)."""

    PENDING = "PENDING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    ABORTED = "ABORTED"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"


class TransitionError(ValueError):
    """Raised when a state transition is not allowed."""


_RUN_TRANSITIONS: dict[RunStatus, set[RunStatus]] = {
    RunStatus.DRAFT: {RunStatus.IN_PROGRESS, RunStatus.ABORTED, RunStatus.COMPLETED},
    RunStatus.IN_PROGRESS: {
        RunStatus.PAUSED,
        RunStatus.COMPLETED,
        RunStatus.FAILED,
        RunStatus.ABORTED,
        RunStatus.ROLLING_BACK,
    },
    RunStatus.PAUSED: {
        RunStatus.IN_PROGRESS,
        RunStatus.ABORTED,
        RunStatus.ROLLING_BACK,
    },
    RunStatus.FAILED: {RunStatus.ROLLING_BACK, RunStatus.ABORTED},
    RunStatus.ROLLING_BACK: {
        RunStatus.ROLLED_BACK,
        RunStatus.FAILED,
        RunStatus.PAUSED,
    },
    RunStatus.COMPLETED: {RunStatus.ROLLING_BACK},
    RunStatus.ROLLED_BACK: set(),
    RunStatus.ABORTED: set(),
}

_STEP_TRANSITIONS: dict[StepStatus, set[StepStatus]] = {
    StepStatus.PENDING: {
        StepStatus.RUNNING,
        StepStatus.AWAITING_APPROVAL,
        StepStatus.SKIPPED,
        StepStatus.BLOCKED,
        StepStatus.ABORTED,
    },
    StepStatus.AWAITING_APPROVAL: {
        StepStatus.RUNNING,
        StepStatus.SKIPPED,
        StepStatus.ABORTED,
    },
    StepStatus.RUNNING: {
        StepStatus.SUCCEEDED,
        StepStatus.FAILED,
        StepStatus.TIMEOUT,
        StepStatus.ABORTED,
    },
    StepStatus.FAILED: {StepStatus.PENDING, StepStatus.SKIPPED, StepStatus.ABORTED},
    StepStatus.TIMEOUT: {StepStatus.PENDING, StepStatus.SKIPPED, StepStatus.ABORTED},
    StepStatus.BLOCKED: {StepStatus.PENDING, StepStatus.SKIPPED, StepStatus.ABORTED},
    StepStatus.SUCCEEDED: set(),
    StepStatus.SKIPPED: set(),
    StepStatus.ABORTED: set(),
}


def check_run_transition(old: RunStatus | str, new: RunStatus | str) -> None:
    """Validate a run transition, raising :class:`TransitionError`."""
    old_status = old if isinstance(old, RunStatus) else RunStatus(str(old))
    new_status = new if isinstance(new, RunStatus) else RunStatus(str(new))
    if old_status == new_status:
        return
    if new_status not in _RUN_TRANSITIONS[old_status]:
        msg = f"Run transition {old_status.value} -> {new_status.value} is not allowed"
        raise TransitionError(msg)


def check_step_transition(old: StepStatus | str, new: StepStatus | str) -> None:
    """Validate a step transition, raising :class:`TransitionError`."""
    old_status = old if isinstance(old, StepStatus) else StepStatus(str(old))
    new_status = new if isinstance(new, StepStatus) else StepStatus(str(new))
    if old_status == new_status:
        return
    if new_status not in _STEP_TRANSITIONS[old_status]:
        msg = f"Step transition {old_status.value} -> {new_status.value} is not allowed"
        raise TransitionError(msg)
