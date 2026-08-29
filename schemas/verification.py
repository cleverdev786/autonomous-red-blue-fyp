"""Policy and deterministic patch-verification result schemas."""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schemas.red_team import TestExecutionResult

from schemas.common import (
    Identifier,
    NonEmptyText,
    PatchDecision,
    PolicyReasonCode,
    VulnerabilityClass,
    WorkflowState,
)


_MODULE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")


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


class VerificationCheckStatus(str, Enum):
    """Outcome of one fixed normal-behavior verification check."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"


class VerificationCheckResult(BaseModel):
    """Typed observational result for one fixed check inside a verification stage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    check_id: Identifier
    status: VerificationCheckStatus
    duration_ms: int = Field(ge=0)
    details: NonEmptyText

    @property
    def passed(self) -> bool:
        return self.status == VerificationCheckStatus.PASSED


class VerificationStageResult(BaseModel):
    """One deterministic verification stage result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage_id: Identifier
    required: bool = True
    passed: bool
    duration_ms: int = Field(ge=0)
    details: NonEmptyText
    checks: tuple[VerificationCheckResult, ...] = ()
    test_execution: TestExecutionResult | None = None


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


class VerificationPolicyConfig(BaseModel):
    """Human-controlled common verification policy used for every Blue condition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: Identifier
    fixed_import_module: str = Field(min_length=1, max_length=200)
    security_test_by_vulnerability: dict[VulnerabilityClass, Identifier]
    required_regression_tests: tuple[str, ...] = Field(min_length=1, max_length=50)
    stage_output_limit_chars: int = Field(default=4000, ge=500, le=20_000)
    health_timeout_seconds: int = Field(default=60, ge=5, le=300)

    @field_validator("fixed_import_module")
    @classmethod
    def validate_module_name(cls, value: str) -> str:
        if _MODULE_PATTERN.fullmatch(value) is None:
            raise ValueError("fixed_import_module must be a dotted Python module name")
        return value

    @field_validator("required_regression_tests")
    @classmethod
    def validate_regression_allowlist(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("required_regression_tests must be unique")
        for node_id in value:
            if not node_id.startswith("dummy_apps/vulnerable_store/tests/"):
                raise ValueError("regression tests must stay inside vulnerable_store tests")
            if "::" not in node_id and not node_id.endswith("test_baseline.py"):
                raise ValueError("non-baseline regression entries must be exact pytest node IDs")
            lowered = node_id.lower()
            if any(
                marker in lowered
                for marker in (
                    "reproducibly_vulnerable",
                    "reproducibly_reflects",
                    "reaches_synthetic_private_file",
                )
            ):
                raise ValueError("vulnerability-proving tests cannot be mandatory regressions")
        return value

    @model_validator(mode="after")
    def require_all_vulnerability_classes(self) -> "VerificationPolicyConfig":
        if set(self.security_test_by_vulnerability) != set(VulnerabilityClass):
            raise ValueError("security_test_by_vulnerability must cover exactly the frozen classes")
        if len(set(self.security_test_by_vulnerability.values())) != len(VulnerabilityClass):
            raise ValueError("each frozen vulnerability class must map to a distinct registered test")
        return self


class PatchVerificationResult(BaseModel):
    """Aggregate Milestone 14 result including workflow, Git and cleanup evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    target_id: Identifier
    attempt_number: int = Field(ge=1)
    branch_name: str = Field(min_length=1, max_length=240)
    base_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    git_diff_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verification: VerificationResult | None = None
    accepted_commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    baseline_restored: bool
    final_state: WorkflowState
    failure_reason: NonEmptyText | None = None

    @model_validator(mode="after")
    def validate_result_state(self) -> "PatchVerificationResult":
        allowed = {
            WorkflowState.ACCEPTED,
            WorkflowState.REJECTED,
            WorkflowState.FAILED,
            WorkflowState.POLICY_BLOCKED,
        }
        if self.final_state not in allowed:
            raise ValueError("PatchVerificationResult must end in accepted/rejected/failed/policy_blocked")

        if self.final_state == WorkflowState.ACCEPTED:
            if self.verification is None or self.verification.decision != PatchDecision.ACCEPTED:
                raise ValueError("accepted workflow result requires accepted verification")
            if self.accepted_commit_sha is None:
                raise ValueError("accepted workflow result requires local accepted commit SHA")
            if not self.baseline_restored:
                raise ValueError("accepted workflow result requires restored baseline")
            if self.failure_reason is not None:
                raise ValueError("accepted workflow result cannot include failure_reason")

        if self.final_state == WorkflowState.REJECTED:
            if self.verification is None or self.verification.decision != PatchDecision.REJECTED:
                raise ValueError("rejected workflow result requires rejected verification")
            if self.accepted_commit_sha is not None:
                raise ValueError("rejected patch cannot claim an accepted commit")
            if not self.baseline_restored:
                raise ValueError("rejected workflow result requires restored baseline")

        if self.final_state in {WorkflowState.FAILED, WorkflowState.POLICY_BLOCKED}:
            if self.failure_reason is None:
                raise ValueError("failed/policy-blocked workflow result requires failure_reason")

        return self
