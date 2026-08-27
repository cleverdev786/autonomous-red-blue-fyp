"""Deterministic acceptance/rejection decisions for patch verification."""

from __future__ import annotations

from schemas.common import PatchDecision
from schemas.verification import VerificationResult, VerificationStageResult


def decide_verification(
    *,
    run_id: str,
    attempt_number: int,
    stages: tuple[VerificationStageResult, ...],
) -> VerificationResult:
    """Accept only when every required stage passes; otherwise reject deterministically."""
    failed = next((stage for stage in stages if stage.required and not stage.passed), None)
    total_duration_ms = sum(stage.duration_ms for stage in stages)
    if failed is None:
        return VerificationResult(
            run_id=run_id,
            patch_attempt_number=attempt_number,
            stages=stages,
            decision=PatchDecision.ACCEPTED,
            total_duration_ms=total_duration_ms,
        )
    return VerificationResult(
        run_id=run_id,
        patch_attempt_number=attempt_number,
        stages=stages,
        decision=PatchDecision.REJECTED,
        rejection_reason=f"Mandatory verification stage {failed.stage_id!r} failed: {failed.details}",
        total_duration_ms=total_duration_ms,
    )
