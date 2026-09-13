"""Milestone 19 trusted structured retry-feedback tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from schemas.common import PatchDecision, WorkflowState
from schemas.patches import (
    PatchGenerationResult,
    PatchProposal,
    PreparedFileChange,
    PreparedPatch,
    ProposedFileChange,
)
from schemas.red_team import EvidenceItem, TestExecutionResult as RegisteredTestExecutionResult
from schemas.verification import (
    PatchVerificationResult,
    VerificationCheckResult,
    VerificationCheckStatus,
    VerificationResult,
    VerificationStageResult,
)
from services.patch_retry_feedback import PatchRetryFeedbackBuilder, PatchRetryFeedbackError
from services.target_registry import TargetRegistry


ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "rq3-feedback"
TARGET_ID = "vulnerable-store"
SOURCE = "dummy_apps/vulnerable_store/app/scenario_routes.py"
BASE = "a" * 40


@pytest.fixture
def registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


def _generation() -> PatchGenerationResult:
    original = "return request.query_params.get('q', '')"
    replacement = "return escape(request.query_params.get('q', ''))"
    diff = f"--- a/{SOURCE}\n+++ b/{SOURCE}\n@@\n-{original}\n+{replacement}\n"
    prepared = PreparedPatch(
        run_id=RUN_ID,
        target_id=TARGET_ID,
        attempt_number=1,
        files=(
            PreparedFileChange(
                file_path=SOURCE,
                original_sha256=hashlib.sha256(original.encode()).hexdigest(),
                replacement_sha256=hashlib.sha256(replacement.encode()).hexdigest(),
                replacement_content=replacement,
            ),
        ),
        unified_diff=diff,
        diff_sha256=hashlib.sha256(diff.encode()).hexdigest(),
        files_changed=1,
        inserted_lines=1,
        deleted_lines=1,
        total_diff_bytes=len(diff.encode()),
    )
    proposal = PatchProposal(
        run_id=RUN_ID,
        target_id=TARGET_ID,
        attempt_number=1,
        changes=(
            ProposedFileChange(
                file_path=SOURCE,
                original_content=original,
                replacement_content=replacement,
                rationale="Bounded fixture.",
            ),
        ),
        security_rationale="Bounded fixture.",
        expected_effect="Bounded fixture.",
    )
    return PatchGenerationResult(
        run_id=RUN_ID,
        target_id=TARGET_ID,
        attempt_number=1,
        proposal=proposal,
        prepared_patch=prepared,
        final_state=WorkflowState.PATCH_VALIDATING,
    )


def _execution(*, test_id: str, exploit: bool) -> RegisteredTestExecutionResult:
    evidence = (
        EvidenceItem(
            evidence_id="evidence-1",
            evidence_type="response-marker",
            summary="Controlled exploit evidence.",
        ),
    ) if exploit else ()
    return RegisteredTestExecutionResult(
        run_id=RUN_ID,
        target_id=TARGET_ID,
        test_id=test_id,
        attempt_number=1,
        request_count=1,
        completed=True,
        timed_out=False,
        status_code=200,
        evidence=evidence,
        duration_ms=3,
    )


def _rejected_result(*, stages: tuple[VerificationStageResult, ...]) -> PatchVerificationResult:
    verification = VerificationResult(
        run_id=RUN_ID,
        patch_attempt_number=1,
        stages=stages,
        decision=PatchDecision.REJECTED,
        rejection_reason="Evaluator-only rejection detail that must never be forwarded.",
        total_duration_ms=sum(stage.duration_ms for stage in stages),
    )
    return PatchVerificationResult(
        run_id=RUN_ID,
        target_id=TARGET_ID,
        attempt_number=1,
        branch_name="agent-patch/rq3-feedback/attempt-1",
        base_commit=BASE,
        git_diff_sha256="b" * 64,
        verification=verification,
        baseline_restored=True,
        final_state=WorkflowState.REJECTED,
        failure_reason=verification.rejection_reason,
    )


def test_builder_uses_only_fixed_safe_feedback_and_never_raw_stage_details(
    registry: TargetRegistry,
) -> None:
    raw = "RAW_STDOUT /home/user/project traceback secret=do-not-forward"
    regression = VerificationStageResult(
        stage_id="regression",
        required=True,
        passed=False,
        duration_ms=4,
        details=raw,
    )
    replay = VerificationStageResult(
        stage_id="original_replay",
        required=True,
        passed=False,
        duration_ms=3,
        details=raw,
        test_execution=_execution(test_id="xss-reflection-001", exploit=True),
    )

    feedback = PatchRetryFeedbackBuilder(target_registry=registry).build(
        generation=_generation(),
        verification=_rejected_result(stages=(regression, replay)),
    )

    assert feedback.failed_stage == "regression"
    assert feedback.failing_test_id is None
    assert feedback.error_summary == "Trusted regression allowlist failed."
    assert feedback.original_replay_succeeded is True
    assert feedback.regression_failure_ids == ()
    assert feedback.policy_reason_code is None
    assert feedback.prior_diff_summary == (
        "Prior patch: files=1; inserted=1; deleted=1; generated_test=no."
    )
    assert raw not in repr(feedback.model_dump(mode="json"))


def test_functional_check_id_may_be_summarized_but_is_not_promoted_to_test_id(
    registry: TargetRegistry,
) -> None:
    functional = VerificationStageResult(
        stage_id="functional",
        required=True,
        passed=False,
        duration_ms=2,
        details="RAW functional details",
        checks=(
            VerificationCheckResult(
                check_id="normal_login",
                status=VerificationCheckStatus.FAILED,
                duration_ms=1,
                details="RAW assertion text",
            ),
        ),
    )
    feedback = PatchRetryFeedbackBuilder(target_registry=registry).build(
        generation=_generation(),
        verification=_rejected_result(stages=(functional,)),
    )
    assert feedback.failing_test_id is None
    assert feedback.error_summary == "Functional check 'normal_login' failed."
    assert "RAW" not in repr(feedback.model_dump(mode="json"))


def test_registered_security_id_is_allowed_and_unregistered_id_fails_closed(
    registry: TargetRegistry,
) -> None:
    builder = PatchRetryFeedbackBuilder(target_registry=registry)
    registered = VerificationStageResult(
        stage_id="security",
        required=True,
        passed=False,
        duration_ms=3,
        details="RAW security output",
        test_execution=_execution(test_id="xss-reflection-001", exploit=True),
    )
    feedback = builder.build(
        generation=_generation(),
        verification=_rejected_result(stages=(registered,)),
    )
    assert feedback.failing_test_id == "xss-reflection-001"
    assert feedback.error_summary == (
        "Registered security test 'xss-reflection-001' still observed exploit evidence."
    )

    unregistered = registered.model_copy(
        update={"test_execution": _execution(test_id="unregistered-test", exploit=True)}
    )
    with pytest.raises(PatchRetryFeedbackError, match="unregistered"):
        builder.build(
            generation=_generation(),
            verification=_rejected_result(stages=(unregistered,)),
        )
