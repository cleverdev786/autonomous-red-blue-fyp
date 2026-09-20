"""Tests for M20 Part-B RQ3 shared-first-attempt pairing infrastructure."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from experiments.rq3_shared_attempt import (
    RQ3MatchedPairOutcome,
    RQ3RetryBranch,
    RQ3SharedAttemptBundle,
    RQ3TreatmentOutcome,
    RQ3TreatmentOutcomeState,
    build_rq3_conditional_run_unit,
    build_rq3_paired_retry_plan,
    rq3_call_accounting,
    shared_bundle_sha256,
)
from schemas.common import WorkflowState
from schemas.experiments import RetryFeedbackMode


def _bundle(**updates):
    values = {
        "rq3_unit_id": "rq3-unit-001",
        "scenario_id": "scenario-synthetic",
        "repetition_index": 1,
        "common_configuration_sha256": "1" * 64,
        "baseline_git_commit": "a" * 40,
        "provider_binding_sha256": "2" * 64,
        "prompt_set_sha256": "3" * 64,
        "red_evidence_sha256": "4" * 64,
        "blue_analysis_sha256": "5" * 64,
        "patch_proposal_sha256": "6" * 64,
        "prepared_patch_sha256": "7" * 64,
        "verification_sha256": "8" * 64,
        "attempt1_agent_calls_sha256": "9" * 64,
        "attempt1_timing_sha256": "a" * 64,
        "attempt1_telemetry_sha256": "b" * 64,
        "shared_budget_snapshot_sha256": "c" * 64,
        "baseline_restoration_sha256": "d" * 64,
        "attempt1_final_state": WorkflowState.REJECTED,
        "baseline_restored": True,
        "remaining_patch_attempts_per_branch": 1,
        "remaining_model_calls_per_branch": 1,
        "common_model_calls": 7,
    }
    values.update(updates)
    return RQ3SharedAttemptBundle(**values)


def test_conditional_run_unit_predeclares_shared_and_treatment_slots() -> None:
    unit = build_rq3_conditional_run_unit(
        scenario_id="scenario-synthetic",
        repetition_index=2,
        common_configuration_sha256="f" * 64,
    )
    assert unit.children_conditional
    assert len(
        {
            unit.shared_attempt_slot_id,
            unit.none_retry_slot_id,
            unit.structured_retry_slot_id,
        }
    ) == 3
    again = build_rq3_conditional_run_unit(
        scenario_id="scenario-synthetic",
        repetition_index=2,
        common_configuration_sha256="f" * 64,
    )
    assert again == unit



def test_shared_bundle_requires_genuine_rejection_restore_and_branch_allowance() -> None:
    bundle = _bundle()
    assert bundle.attempt1_final_state == WorkflowState.REJECTED
    with pytest.raises(ValidationError, match="genuine REJECTED"):
        _bundle(attempt1_final_state=WorkflowState.ACCEPTED)
    with pytest.raises(ValidationError, match="baseline restoration"):
        _bundle(baseline_restored=False)
    with pytest.raises(ValidationError, match="each RQ3 branch requires one remaining patch"):
        _bundle(remaining_patch_attempts_per_branch=0)


def test_pair_plan_binds_both_treatments_to_the_same_immutable_bundle_hash() -> None:
    bundle = _bundle()
    digest = shared_bundle_sha256(bundle)
    assert digest == shared_bundle_sha256(bundle)
    plan = build_rq3_paired_retry_plan(bundle)
    assert plan.shared_bundle_sha256 == digest
    assert {branch.retry_feedback_mode for branch in plan.branches} == {
        RetryFeedbackMode.NONE,
        RetryFeedbackMode.STRUCTURED,
    }
    assert all(branch.shared_bundle_sha256 == digest for branch in plan.branches)
    assert {branch.receives_structured_feedback for branch in plan.branches} == {False, True}


def test_retry_branch_rejects_feedback_flag_that_does_not_match_treatment() -> None:
    with pytest.raises(ValidationError, match="flag must match"):
        RQ3RetryBranch(
            rq3_unit_id="rq3-unit-001",
            retry_feedback_mode=RetryFeedbackMode.NONE,
            shared_bundle_sha256="9" * 64,
            receives_structured_feedback=True,
        )


def test_rq3_call_accounting_does_not_double_count_common_physical_calls() -> None:
    accounting = rq3_call_accounting(common_calls=7)
    assert accounting.physical_provider_calls == 9
    assert accounting.none_cumulative_equivalent_calls == 8
    assert accounting.structured_cumulative_equivalent_calls == 8


def test_matched_pair_retains_incomplete_and_terminal_treatment_outcomes() -> None:
    pair = RQ3MatchedPairOutcome(
        rq3_unit_id="rq3-unit-001",
        shared_bundle_sha256="a" * 64,
        none=RQ3TreatmentOutcome(
            retry_feedback_mode=RetryFeedbackMode.NONE,
            final_state=RQ3TreatmentOutcomeState.INCOMPLETE,
            actual_retry_model_calls=1,
        ),
        structured=RQ3TreatmentOutcome(
            retry_feedback_mode=RetryFeedbackMode.STRUCTURED,
            final_state=RQ3TreatmentOutcomeState.ACCEPTED,
            actual_retry_model_calls=1,
        ),
    )
    assert pair.none.final_state == RQ3TreatmentOutcomeState.INCOMPLETE
    assert pair.structured.final_state == RQ3TreatmentOutcomeState.ACCEPTED
