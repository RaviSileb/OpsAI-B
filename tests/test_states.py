"""Tests for execution state machines (FR-520)."""

from __future__ import annotations

import pytest

from opsai.core.states import (
    RunStatus,
    StepStatus,
    TransitionError,
    check_run_transition,
    check_step_transition,
)


def test_run_happy_path() -> None:
    check_run_transition(RunStatus.DRAFT, RunStatus.IN_PROGRESS)
    check_run_transition(RunStatus.IN_PROGRESS, RunStatus.PAUSED)
    check_run_transition(RunStatus.PAUSED, RunStatus.IN_PROGRESS)
    check_run_transition(RunStatus.IN_PROGRESS, RunStatus.COMPLETED)
    check_run_transition("DRAFT", "ABORTED")


def test_run_rollback_path() -> None:
    check_run_transition(RunStatus.PAUSED, RunStatus.ROLLING_BACK)
    check_run_transition(RunStatus.ROLLING_BACK, RunStatus.ROLLED_BACK)
    check_run_transition(RunStatus.FAILED, RunStatus.ROLLING_BACK)


def test_run_terminal_states_reject_moves() -> None:
    for terminal in ("COMPLETED", "ROLLED_BACK", "ABORTED"):
        with pytest.raises(TransitionError):
            check_run_transition(terminal, "IN_PROGRESS")
    check_run_transition("COMPLETED", "ROLLING_BACK")


def test_run_skips_are_rejected() -> None:
    with pytest.raises(TransitionError):
        check_run_transition(RunStatus.PAUSED, RunStatus.COMPLETED)
    with pytest.raises(TransitionError):
        check_run_transition(RunStatus.DRAFT, RunStatus.ROLLED_BACK)


def test_step_happy_path_with_approval() -> None:
    check_step_transition(StepStatus.PENDING, StepStatus.AWAITING_APPROVAL)
    check_step_transition(StepStatus.AWAITING_APPROVAL, StepStatus.RUNNING)
    check_step_transition(StepStatus.RUNNING, StepStatus.SUCCEEDED)


def test_step_retry_and_skip_paths() -> None:
    check_step_transition(StepStatus.FAILED, StepStatus.PENDING)
    check_step_transition(StepStatus.TIMEOUT, StepStatus.SKIPPED)
    check_step_transition(StepStatus.BLOCKED, StepStatus.PENDING)
    check_step_transition(StepStatus.PENDING, StepStatus.BLOCKED)
    check_step_transition(StepStatus.PENDING, StepStatus.SKIPPED)


def test_step_terminal_states_reject_moves() -> None:
    for terminal in ("SUCCEEDED", "SKIPPED", "ABORTED"):
        with pytest.raises(TransitionError):
            check_step_transition(terminal, "PENDING")
