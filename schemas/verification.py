"""Policy and deterministic patch-verification result schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.common import (
    Identifier,
    NonEmptyText,
    PatchDecision,
    PolicyReasonCode,
)


class PolicyDecision(BaseModel):
    """Structured authorization result produced before a sensitive operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    reason_code: PolicyReasonCode
    message: NonEmptyText

    @model_validator(mode="after")
    def reason_matches_decision(self) -> "PolicyDecision":
        if self.allowed and self.reason_code != PolicyReasonCode.ALLOWED:
            raise ValueError("allowed policy decision must use reason_code='allowed'")
        if not self.allowed and self.reason_code == PolicyReasonCode.ALLOWED:
            raise ValueError("blocked policy decision cannot use reason_code='allowed'")
        return self


class VerificationStageResult(BaseModel):
    """One mandatory verification stage result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage_id: Identifier
    required: bool = True
    passed: bool
    duration_ms: int = Field(ge=0)
    details: NonEmptyText


class VerificationResult(BaseModel):
    """Deterministic patch-verification result.

    Acceptance is valid only when every required stage passed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    patch_attempt_number: int = Field(ge=1)
    stages: tuple[VerificationStageResult, ...] = Field(min_length=1)
    decision: PatchDecision
    rejection_reason: NonEmptyText | None = None
    total_duration_ms: int = Field(ge=0)

    @model_validator(mode="after")
    def decision_matches_required_stages(self) -> "VerificationResult":
        all_required_passed = all(stage.passed for stage in self.stages if stage.required)

        if self.decision == PatchDecision.ACCEPTED and not all_required_passed:
            raise ValueError("accepted patch requires every mandatory stage to pass")

        if self.decision == PatchDecision.REJECTED and self.rejection_reason is None:
            raise ValueError("rejected patch requires a rejection_reason")

        if self.decision == PatchDecision.ACCEPTED and self.rejection_reason is not None:
            raise ValueError("accepted patch must not include a rejection_reason")

        return self
