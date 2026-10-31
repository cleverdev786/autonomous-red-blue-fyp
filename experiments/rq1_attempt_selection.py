"""Deterministic M20 Part-B RQ1 1-vs-2-vs-3 patch-attempt decision evaluator."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.common import Identifier, VulnerabilityClass, WorkflowState
from schemas.experiments import RetryFeedbackMode


_SHA256 = r"^[0-9a-f]{64}$"


class RQ1AttemptSelectionError(ValueError):
    """Raised when retry-stress evidence cannot support the predeclared decision rule."""


class RQ1SyntheticAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attempt_number: int = Field(ge=1, le=3)
    final_state: WorkflowState
    duration_ms: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def terminal_patch_state_only(self) -> "RQ1SyntheticAttempt":
        if self.final_state not in {
            WorkflowState.ACCEPTED,
            WorkflowState.REJECTED,
            WorkflowState.FAILED,
            WorkflowState.POLICY_BLOCKED,
        }:
            raise ValueError("synthetic RQ1 patch attempt must use a terminal patch state")
        return self


class RQ1RetryStressTrace(BaseModel):
    """One synthetic malicious fixture's sequential K<=3 patch-generation trace."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_id: Identifier
    vulnerability_class: VulnerabilityClass
    shared_context_sha256: str = Field(pattern=_SHA256)
    retry_feedback_mode: RetryFeedbackMode = RetryFeedbackMode.NONE
    attempts: tuple[RQ1SyntheticAttempt, ...] = Field(min_length=1, max_length=3)

    @model_validator(mode="after")
    def sequential_attempts(self) -> "RQ1RetryStressTrace":
        if self.retry_feedback_mode != RetryFeedbackMode.NONE:
            raise ValueError("RQ1 retry-stress traces cannot use structured failure feedback")
        numbers = [item.attempt_number for item in self.attempts]
        if numbers != list(range(1, len(numbers) + 1)):
            raise ValueError("RQ1 synthetic attempts must be sequential from attempt 1")
        for index, attempt in enumerate(self.attempts[:-1]):
            if attempt.final_state == WorkflowState.ACCEPTED:
                raise ValueError("trace cannot continue after an accepted patch")
            if attempt.final_state in {WorkflowState.FAILED, WorkflowState.POLICY_BLOCKED}:
                raise ValueError("trace cannot continue after failed/policy-blocked patch")
        return self


class RQ1AttemptBudgetDecision(BaseModel):
    """Pre-final methodological choice produced from synthetic retry-stress evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    selected_max_patch_attempts: int = Field(ge=1, le=3)
    derived_max_model_calls: int = Field(ge=7, le=9)
    retry_feedback_mode: RetryFeedbackMode
    second_attempt_recovery_count: int = Field(ge=0)
    second_attempt_recovery_classes: frozenset[VulnerabilityClass] = frozenset()
    third_attempt_recovery_count: int = Field(ge=0)
    third_attempt_recovery_classes: frozenset[VulnerabilityClass] = frozenset()
    rationale: tuple[str, ...]


def select_rq1_attempt_budget(
    *,
    traces: tuple[RQ1RetryStressTrace, ...],
    k2_operationally_feasible: bool,
    k3_operationally_feasible: bool,
) -> RQ1AttemptBudgetDecision:
    """Apply the approved ordered K1/K2/K3 decision rules without final-result tuning."""
    if len(traces) < 3:
        raise RQ1AttemptSelectionError(
            "retry-stress evidence requires at least three malicious fixtures"
        )
    fixture_ids = [trace.fixture_id for trace in traces]
    if len(fixture_ids) != len(set(fixture_ids)):
        raise RQ1AttemptSelectionError("retry-stress fixture IDs must be unique")
    if {trace.vulnerability_class for trace in traces} != set(VulnerabilityClass):
        raise RQ1AttemptSelectionError("retry-stress evidence must cover all vulnerability classes")

    second = [trace for trace in traces if _accepted_exactly_on_attempt(trace, 2)]
    second_classes = frozenset(trace.vulnerability_class for trace in second)
    third = [trace for trace in traces if _accepted_exactly_on_attempt(trace, 3)]
    third_classes = frozenset(trace.vulnerability_class for trace in third)

    rationale: list[str] = []
    if not k2_operationally_feasible:
        selected = 1
        rationale.append("K2 is operationally infeasible; select K1")
    elif len(second) < 2 or len(second_classes) < 2:
        selected = 1
        rationale.append(
            "K2 lacks demonstrated second-attempt recovery on two fixtures across two classes"
        )
    elif k3_operationally_feasible and len(third) >= 2 and len(third_classes) >= 2:
        selected = 3
        rationale.append(
            "K3 adds demonstrated third-attempt recovery on two fixtures across two classes"
        )
    else:
        selected = 2
        rationale.append("K2 is the smallest demonstrated informative and feasible retry budget")
        if not k3_operationally_feasible:
            rationale.append("K3 is operationally infeasible")
        else:
            rationale.append("K3 lacks required incremental third-attempt information")

    return RQ1AttemptBudgetDecision(
        selected_max_patch_attempts=selected,
        derived_max_model_calls=6 + selected,
        retry_feedback_mode=RetryFeedbackMode.NONE,
        second_attempt_recovery_count=len(second),
        second_attempt_recovery_classes=second_classes,
        third_attempt_recovery_count=len(third),
        third_attempt_recovery_classes=third_classes,
        rationale=tuple(rationale),
    )


def _accepted_exactly_on_attempt(trace: RQ1RetryStressTrace, attempt_number: int) -> bool:
    if len(trace.attempts) < attempt_number:
        return False
    target = trace.attempts[attempt_number - 1]
    if target.final_state != WorkflowState.ACCEPTED:
        return False
    for prior in trace.attempts[: attempt_number - 1]:
        if prior.final_state != WorkflowState.REJECTED:
            return False
    return True
