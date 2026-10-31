"""M20 Part-B RQ3 canonical shared-first-attempt and paired-retry contracts."""

from __future__ import annotations

import hashlib
import json

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.common import Identifier, WorkflowState
from schemas.experiments import RetryFeedbackMode


_SHA256 = r"^[0-9a-f]{64}$"
_COMMIT = r"^[0-9a-f]{40}$"


class RQ3PairingError(ValueError):
    """Raised when a shared-attempt bundle is not retry-eligible or pair-safe."""




class RQ3ConditionalRunUnit(BaseModel):
    """Predetermined common slot plus conditional treatment-child slots."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rq3_unit_id: Identifier
    scenario_id: Identifier
    repetition_index: int = Field(ge=1)
    common_configuration_sha256: str = Field(pattern=_SHA256)
    shared_attempt_slot_id: Identifier
    none_retry_slot_id: Identifier
    structured_retry_slot_id: Identifier
    children_conditional: bool = True

    @model_validator(mode="after")
    def slots_are_unique_and_conditional(self) -> "RQ3ConditionalRunUnit":
        slots = {
            self.shared_attempt_slot_id,
            self.none_retry_slot_id,
            self.structured_retry_slot_id,
        }
        if len(slots) != 3:
            raise ValueError("RQ3 shared/NONE/STRUCTURED slots must be distinct")
        if not self.children_conditional:
            raise ValueError("RQ3 retry child slots must remain conditional")
        return self


class RQ3SharedAttemptBundle(BaseModel):
    """Immutable common attempt-1 evidence from which both RQ3 treatments fork."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rq3_unit_id: Identifier
    scenario_id: Identifier
    repetition_index: int = Field(ge=1)
    common_configuration_sha256: str = Field(pattern=_SHA256)
    baseline_git_commit: str = Field(pattern=_COMMIT)
    provider_binding_sha256: str = Field(pattern=_SHA256)
    prompt_set_sha256: str = Field(pattern=_SHA256)
    red_evidence_sha256: str = Field(pattern=_SHA256)
    blue_analysis_sha256: str = Field(pattern=_SHA256)
    patch_proposal_sha256: str = Field(pattern=_SHA256)
    prepared_patch_sha256: str = Field(pattern=_SHA256)
    verification_sha256: str = Field(pattern=_SHA256)
    attempt1_agent_calls_sha256: str = Field(pattern=_SHA256)
    attempt1_timing_sha256: str = Field(pattern=_SHA256)
    attempt1_telemetry_sha256: str = Field(pattern=_SHA256)
    shared_budget_snapshot_sha256: str = Field(pattern=_SHA256)
    baseline_restoration_sha256: str = Field(pattern=_SHA256)
    attempt1_final_state: WorkflowState
    baseline_restored: bool
    remaining_patch_attempts_per_branch: int = Field(ge=0)
    remaining_model_calls_per_branch: int = Field(ge=0)
    common_model_calls: int = Field(default=7, ge=1)

    @model_validator(mode="after")
    def shared_attempt_must_be_retry_eligible(self) -> "RQ3SharedAttemptBundle":
        if self.attempt1_final_state != WorkflowState.REJECTED:
            raise ValueError("RQ3 paired retry requires a genuine REJECTED shared attempt 1")
        if not self.baseline_restored:
            raise ValueError("RQ3 paired retry requires successful baseline restoration")
        if self.remaining_patch_attempts_per_branch < 1:
            raise ValueError("each RQ3 branch requires one remaining patch attempt")
        if self.remaining_model_calls_per_branch < 1:
            raise ValueError("each RQ3 branch requires one remaining model call")
        return self


class RQ3RetryBranch(BaseModel):
    """One conditional second-attempt treatment bound to the same shared bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rq3_unit_id: Identifier
    retry_feedback_mode: RetryFeedbackMode
    shared_bundle_sha256: str = Field(pattern=_SHA256)
    patch_attempt_number: int = Field(default=2, ge=2, le=2)
    receives_structured_feedback: bool

    @model_validator(mode="after")
    def feedback_flag_matches_treatment(self) -> "RQ3RetryBranch":
        expected = self.retry_feedback_mode == RetryFeedbackMode.STRUCTURED
        if self.receives_structured_feedback != expected:
            raise ValueError("structured-feedback flag must match retry treatment")
        return self


class RQ3PairedRetryPlan(BaseModel):
    """Predetermined conditional NONE/STRUCTURED child slots for one shared unit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rq3_unit_id: Identifier
    shared_bundle_sha256: str = Field(pattern=_SHA256)
    branches: tuple[RQ3RetryBranch, RQ3RetryBranch]

    @model_validator(mode="after")
    def exact_pair(self) -> "RQ3PairedRetryPlan":
        modes = {branch.retry_feedback_mode for branch in self.branches}
        if modes != {RetryFeedbackMode.NONE, RetryFeedbackMode.STRUCTURED}:
            raise ValueError("RQ3 paired plan requires exactly NONE and STRUCTURED branches")
        for branch in self.branches:
            if branch.rq3_unit_id != self.rq3_unit_id:
                raise ValueError("RQ3 child branch unit ID differs from pair plan")
            if branch.shared_bundle_sha256 != self.shared_bundle_sha256:
                raise ValueError("RQ3 child branch does not reference the shared bundle")
        return self


class RQ3TreatmentOutcomeState(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    FAILED = "failed"
    POLICY_BLOCKED = "policy_blocked"
    INCOMPLETE = "incomplete"


class RQ3TreatmentOutcome(BaseModel):
    """One actual treatment retry outcome retained in the matched-pair evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    retry_feedback_mode: RetryFeedbackMode
    final_state: RQ3TreatmentOutcomeState
    actual_retry_model_calls: int = Field(default=1, ge=0)


class RQ3MatchedPairOutcome(BaseModel):
    """Matched outcomes from one common rejected first attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rq3_unit_id: Identifier
    shared_bundle_sha256: str = Field(pattern=_SHA256)
    none: RQ3TreatmentOutcome
    structured: RQ3TreatmentOutcome

    @model_validator(mode="after")
    def treatment_labels_are_fixed(self) -> "RQ3MatchedPairOutcome":
        if self.none.retry_feedback_mode != RetryFeedbackMode.NONE:
            raise ValueError("none outcome must use retry_feedback_mode=NONE")
        if self.structured.retry_feedback_mode != RetryFeedbackMode.STRUCTURED:
            raise ValueError("structured outcome must use retry_feedback_mode=STRUCTURED")
        return self


class RQ3CallAccounting(BaseModel):
    """Distinguish physical provider calls from treatment-equivalent accounting."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    common_calls: int = Field(ge=1)
    none_retry_calls: int = Field(ge=0)
    structured_retry_calls: int = Field(ge=0)
    physical_provider_calls: int = Field(ge=1)
    none_cumulative_equivalent_calls: int = Field(ge=1)
    structured_cumulative_equivalent_calls: int = Field(ge=1)



def build_rq3_conditional_run_unit(
    *,
    scenario_id: str,
    repetition_index: int,
    common_configuration_sha256: str,
) -> RQ3ConditionalRunUnit:
    if repetition_index < 1:
        raise RQ3PairingError("RQ3 repetition_index must be >= 1")
    if len(common_configuration_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in common_configuration_sha256
    ):
        raise RQ3PairingError("common configuration SHA-256 must be lowercase hex")
    identity = json.dumps(
        {
            "scenario_id": scenario_id,
            "repetition_index": repetition_index,
            "common_configuration_sha256": common_configuration_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    unit_id = f"rq3-{hashlib.sha256(identity).hexdigest()[:24]}"
    return RQ3ConditionalRunUnit(
        rq3_unit_id=unit_id,
        scenario_id=scenario_id,
        repetition_index=repetition_index,
        common_configuration_sha256=common_configuration_sha256,
        shared_attempt_slot_id=f"{unit_id}-shared",
        none_retry_slot_id=f"{unit_id}-none",
        structured_retry_slot_id=f"{unit_id}-structured",
    )

def shared_bundle_sha256(bundle: RQ3SharedAttemptBundle) -> str:
    payload = json.dumps(
        bundle.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_rq3_paired_retry_plan(bundle: RQ3SharedAttemptBundle) -> RQ3PairedRetryPlan:
    digest = shared_bundle_sha256(bundle)
    branches = (
        RQ3RetryBranch(
            rq3_unit_id=bundle.rq3_unit_id,
            retry_feedback_mode=RetryFeedbackMode.NONE,
            shared_bundle_sha256=digest,
            receives_structured_feedback=False,
        ),
        RQ3RetryBranch(
            rq3_unit_id=bundle.rq3_unit_id,
            retry_feedback_mode=RetryFeedbackMode.STRUCTURED,
            shared_bundle_sha256=digest,
            receives_structured_feedback=True,
        ),
    )
    return RQ3PairedRetryPlan(
        rq3_unit_id=bundle.rq3_unit_id,
        shared_bundle_sha256=digest,
        branches=branches,
    )


def rq3_call_accounting(
    *,
    common_calls: int,
    none_retry_calls: int = 1,
    structured_retry_calls: int = 1,
) -> RQ3CallAccounting:
    if common_calls < 1 or none_retry_calls < 0 or structured_retry_calls < 0:
        raise RQ3PairingError("RQ3 call-accounting values must be non-negative")
    return RQ3CallAccounting(
        common_calls=common_calls,
        none_retry_calls=none_retry_calls,
        structured_retry_calls=structured_retry_calls,
        physical_provider_calls=common_calls + none_retry_calls + structured_retry_calls,
        none_cumulative_equivalent_calls=common_calls + none_retry_calls,
        structured_cumulative_equivalent_calls=common_calls + structured_retry_calls,
    )
