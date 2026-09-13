"""Trusted deterministic construction of bounded RQ3 patch-retry feedback."""

from __future__ import annotations

from schemas.common import PatchDecision, WorkflowState
from schemas.patches import PatchGenerationResult, PatchRetryFeedback
from schemas.verification import (
    PatchVerificationResult,
    VerificationCheckStatus,
    VerificationStageResult,
)
from services.target_registry import TargetRegistry, UnknownSecurityTestError


class PatchRetryFeedbackError(RuntimeError):
    """Raised when prior evidence cannot safely produce RQ3 retry feedback."""


class PatchRetryFeedbackBuilder:
    """Build only approved structured feedback from typed previous-attempt evidence."""

    def __init__(self, *, target_registry: TargetRegistry) -> None:
        self.target_registry = target_registry

    def build(
        self,
        *,
        generation: PatchGenerationResult,
        verification: PatchVerificationResult,
    ) -> PatchRetryFeedback:
        self._validate_previous_attempt(generation=generation, verification=verification)
        assert verification.verification is not None

        failed_stage = next(
            (
                stage
                for stage in verification.verification.stages
                if stage.required and not stage.passed
            ),
            None,
        )
        if failed_stage is None:
            raise PatchRetryFeedbackError(
                "rejected verification must contain a failed required stage"
            )

        failing_test_id, error_summary = self._safe_stage_feedback(
            target_id=verification.target_id,
            stage=failed_stage,
        )
        return PatchRetryFeedback(
            failed_stage=failed_stage.stage_id,
            failing_test_id=failing_test_id,
            error_summary=error_summary,
            original_replay_succeeded=self._original_exploit_replay_succeeded(
                verification.verification.stages
            ),
            regression_failure_ids=(),
            prior_diff_summary=self._prior_diff_summary(generation),
            policy_reason_code=None,
        )

    @staticmethod
    def _validate_previous_attempt(
        *,
        generation: PatchGenerationResult,
        verification: PatchVerificationResult,
    ) -> None:
        if generation.run_id != verification.run_id:
            raise PatchRetryFeedbackError("generation and verification run_id differ")
        if generation.target_id != verification.target_id:
            raise PatchRetryFeedbackError("generation and verification target_id differ")
        if generation.attempt_number != verification.attempt_number:
            raise PatchRetryFeedbackError("generation and verification attempt numbers differ")
        if verification.final_state != WorkflowState.REJECTED:
            raise PatchRetryFeedbackError("retry feedback requires a rejected previous attempt")
        if not verification.baseline_restored:
            raise PatchRetryFeedbackError("retry feedback requires restored baseline state")
        if verification.verification is None:
            raise PatchRetryFeedbackError("rejected attempt requires verification evidence")
        if verification.verification.decision != PatchDecision.REJECTED:
            raise PatchRetryFeedbackError("retry feedback requires a rejected patch decision")

    def _safe_stage_feedback(
        self,
        *,
        target_id: str,
        stage: VerificationStageResult,
    ) -> tuple[str | None, str]:
        if stage.stage_id == "syntax_import":
            return None, "Syntax/import verification failed."
        if stage.stage_id == "application_startup":
            return None, "Application startup/isolation verification failed."
        if stage.stage_id == "functional":
            failed_check = next(
                (
                    check
                    for check in stage.checks
                    if check.status == VerificationCheckStatus.FAILED
                ),
                None,
            )
            if failed_check is not None:
                return None, f"Functional check '{failed_check.check_id}' failed."
            return None, "Functional verification failed."
        if stage.stage_id in {"security", "original_replay"}:
            execution = stage.test_execution
            if execution is None:
                raise PatchRetryFeedbackError(
                    f"{stage.stage_id} failure lacks structured test execution evidence"
                )
            try:
                registered = self.target_registry.get_security_test(execution.test_id)
            except UnknownSecurityTestError as exc:
                raise PatchRetryFeedbackError(
                    "retry feedback cannot expose an unregistered security test identifier"
                ) from exc
            if registered.target_id != target_id or execution.target_id != target_id:
                raise PatchRetryFeedbackError(
                    "retry security-test evidence does not match the registered target"
                )
            if stage.stage_id == "original_replay":
                if execution.completed and not execution.timed_out and execution.evidence:
                    return (
                        execution.test_id,
                        "Original registered attack replay still observed exploit evidence.",
                    )
                return (
                    execution.test_id,
                    "Original registered attack replay did not reach a passing "
                    "verification outcome.",
                )
            if execution.completed and not execution.timed_out and execution.evidence:
                return execution.test_id, (
                    f"Registered security test '{execution.test_id}' still observed "
                    "exploit evidence."
                )
            return execution.test_id, (
                f"Registered security test '{execution.test_id}' did not reach a passing "
                "verification outcome."
            )
        if stage.stage_id == "regression":
            return None, "Trusted regression allowlist failed."
        if stage.stage_id == "patch_policy":
            return None, "Patch-policy verification failed."
        if stage.stage_id == "path_diff":
            return None, "Patch path/diff integrity verification failed."
        return None, f"Verification stage '{stage.stage_id}' failed."

    @staticmethod
    def _original_exploit_replay_succeeded(
        stages: tuple[VerificationStageResult, ...],
    ) -> bool | None:
        replay = next((stage for stage in stages if stage.stage_id == "original_replay"), None)
        if replay is None or replay.test_execution is None:
            return None
        execution = replay.test_execution
        if not execution.completed or execution.timed_out:
            return None
        return bool(execution.evidence)

    @staticmethod
    def _prior_diff_summary(generation: PatchGenerationResult) -> str:
        patch = generation.prepared_patch
        generated = "yes" if patch.generated_test_path is not None else "no"
        return (
            "Prior patch: "
            f"files={patch.files_changed}; inserted={patch.inserted_lines}; "
            f"deleted={patch.deleted_lines}; generated_test={generated}."
        )
