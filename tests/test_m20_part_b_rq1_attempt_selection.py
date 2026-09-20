"""Tests for the predefined M20 Part-B RQ1 patch-attempt decision procedure."""

from __future__ import annotations

import pytest

from experiments.rq1_attempt_selection import (
    RQ1AttemptSelectionError,
    RQ1RetryStressTrace,
    RQ1SyntheticAttempt,
    select_rq1_attempt_budget,
)
from schemas.common import VulnerabilityClass, WorkflowState
from schemas.experiments import RetryFeedbackMode


def _trace(fixture_id: str, vulnerability: VulnerabilityClass, states: tuple[WorkflowState, ...]):
    return RQ1RetryStressTrace(
        fixture_id=fixture_id,
        vulnerability_class=vulnerability,
        shared_context_sha256="a" * 64,
        attempts=tuple(
            RQ1SyntheticAttempt(attempt_number=index, final_state=state, duration_ms=100 * index)
            for index, state in enumerate(states, start=1)
        ),
    )


def _base_traces():
    return (
        _trace(
            "sqli-a",
            VulnerabilityClass.SQL_INJECTION,
            (WorkflowState.REJECTED, WorkflowState.ACCEPTED),
        ),
        _trace(
            "xss-a",
            VulnerabilityClass.XSS,
            (WorkflowState.REJECTED, WorkflowState.ACCEPTED),
        ),
        _trace("path-a", VulnerabilityClass.PATH_TRAVERSAL, (WorkflowState.ACCEPTED,)),
    )


def test_k1_selected_when_second_attempt_is_operationally_infeasible() -> None:
    decision = select_rq1_attempt_budget(
        traces=_base_traces(),
        k2_operationally_feasible=False,
        k3_operationally_feasible=False,
    )
    assert decision.selected_max_patch_attempts == 1
    assert decision.derived_max_model_calls == 7
    assert decision.retry_feedback_mode == RetryFeedbackMode.NONE


def test_k1_selected_when_k2_lacks_cross_class_recovery_information() -> None:
    traces = (
        _trace(
            "sqli-a",
            VulnerabilityClass.SQL_INJECTION,
            (WorkflowState.REJECTED, WorkflowState.ACCEPTED),
        ),
        _trace(
            "sqli-b",
            VulnerabilityClass.SQL_INJECTION,
            (WorkflowState.REJECTED, WorkflowState.ACCEPTED),
        ),
        _trace("xss-a", VulnerabilityClass.XSS, (WorkflowState.REJECTED, WorkflowState.REJECTED)),
        _trace(
            "path-a",
            VulnerabilityClass.PATH_TRAVERSAL,
            (WorkflowState.REJECTED, WorkflowState.REJECTED),
        ),
    )
    decision = select_rq1_attempt_budget(
        traces=traces,
        k2_operationally_feasible=True,
        k3_operationally_feasible=True,
    )
    assert decision.selected_max_patch_attempts == 1
    assert decision.second_attempt_recovery_count == 2
    assert decision.second_attempt_recovery_classes == {VulnerabilityClass.SQL_INJECTION}


def test_k2_selected_as_smallest_informative_budget_without_k3_incremental_evidence() -> None:
    decision = select_rq1_attempt_budget(
        traces=_base_traces(),
        k2_operationally_feasible=True,
        k3_operationally_feasible=True,
    )
    assert decision.selected_max_patch_attempts == 2
    assert decision.derived_max_model_calls == 8
    assert decision.second_attempt_recovery_count == 2
    assert len(decision.second_attempt_recovery_classes) == 2


def test_k3_requires_two_incremental_third_attempt_recoveries_across_two_classes() -> None:
    traces = (
        _trace(
            "sqli-a",
            VulnerabilityClass.SQL_INJECTION,
            (WorkflowState.REJECTED, WorkflowState.ACCEPTED),
        ),
        _trace(
            "xss-a",
            VulnerabilityClass.XSS,
            (WorkflowState.REJECTED, WorkflowState.ACCEPTED),
        ),
        _trace(
            "sqli-b",
            VulnerabilityClass.SQL_INJECTION,
            (WorkflowState.REJECTED, WorkflowState.REJECTED, WorkflowState.ACCEPTED),
        ),
        _trace(
            "path-a",
            VulnerabilityClass.PATH_TRAVERSAL,
            (WorkflowState.REJECTED, WorkflowState.REJECTED, WorkflowState.ACCEPTED),
        ),
    )
    decision = select_rq1_attempt_budget(
        traces=traces,
        k2_operationally_feasible=True,
        k3_operationally_feasible=True,
    )
    assert decision.selected_max_patch_attempts == 3
    assert decision.derived_max_model_calls == 9
    assert decision.third_attempt_recovery_count == 2
    assert len(decision.third_attempt_recovery_classes) == 2


def test_retry_trace_rejects_continuing_after_acceptance_and_requires_class_coverage() -> None:
    with pytest.raises(ValueError, match="cannot continue"):
        _trace(
            "bad",
            VulnerabilityClass.XSS,
            (WorkflowState.ACCEPTED, WorkflowState.REJECTED),
        )

    with pytest.raises(RQ1AttemptSelectionError, match="cover all vulnerability classes"):
        select_rq1_attempt_budget(
            traces=(
                _trace("a", VulnerabilityClass.SQL_INJECTION, (WorkflowState.REJECTED,)),
                _trace("b", VulnerabilityClass.SQL_INJECTION, (WorkflowState.REJECTED,)),
                _trace("c", VulnerabilityClass.XSS, (WorkflowState.REJECTED,)),
            ),
            k2_operationally_feasible=True,
            k3_operationally_feasible=True,
        )
