"""Structured Red Team agent and executor outputs."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schemas.common import (
    Confidence,
    HttpMethod,
    Identifier,
    NonEmptyText,
    VulnerabilityClass,
    WorkflowState,
)


class ReconnaissanceEndpoint(BaseModel):
    """Approved endpoint observation produced by reconnaissance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint_id: Identifier
    allowed_methods: tuple[HttpMethod, ...] = Field(min_length=1)
    input_fields: tuple[Identifier, ...] = ()


class RestrictedReconnaissanceContext(BaseModel):
    """Narrow attack-surface metadata visible to reconnaissance reasoning."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: Identifier
    endpoints: tuple[ReconnaissanceEndpoint, ...] = Field(min_length=1)


class ReconnaissanceResult(BaseModel):
    """Bounded reconnaissance result over approved target metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: Identifier
    candidate_endpoints: tuple[ReconnaissanceEndpoint, ...] = ()
    rationale: NonEmptyText


class RegisteredTestResourceCost(BaseModel):
    """Bounded cost of one registered test descriptor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_requests: int = Field(ge=1, le=20)
    timeout_seconds: int = Field(ge=1, le=120)


class RegisteredTestOption(BaseModel):
    """Vetted, parameter-bound descriptor visible only to attack planning."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    test_id: Identifier
    target_id: Identifier
    vulnerability_class: VulnerabilityClass
    endpoint_id: Identifier
    path: str = Field(min_length=1, max_length=300)
    method: HttpMethod
    allowed_parameter_names: tuple[Identifier, ...] = ()
    request_template_id: Identifier
    oracle_id: Identifier
    resource_cost: RegisteredTestResourceCost
    safe_description: NonEmptyText


class AttackPlanningCatalog(BaseModel):
    """Deterministic registered-test options for one approved target."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: Identifier
    options: tuple[RegisteredTestOption, ...] = Field(min_length=1)


class AttackPlan(BaseModel):
    """LLM recommendation selecting one already-registered security test."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: Identifier
    test_id: Identifier
    endpoint_id: Identifier
    vulnerability_class: VulnerabilityClass
    parameter_choices: dict[Identifier, str] = Field(default_factory=dict)
    rationale: NonEmptyText


class EvidenceItem(BaseModel):
    """Sanitized evidence reference from deterministic execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: Identifier
    evidence_type: Identifier
    summary: NonEmptyText


class HttpExchangeEvidence(BaseModel):
    """Sanitized structured record for one controlled HTTP exchange."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exchange_id: Identifier
    request_id: Identifier
    step_id: Identifier
    endpoint_id: Identifier
    method: str
    status_code: int = Field(ge=100, le=599)
    body_excerpt: str = Field(default="", max_length=2000)
    redirect_location: str | None = Field(default=None, max_length=500)
    duration_ms: int = Field(ge=0)


class TestExecutionResult(BaseModel):
    """Result returned by the deterministic controlled executor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    target_id: Identifier
    test_id: Identifier
    attempt_number: int = Field(ge=1)
    request_count: int = Field(ge=0)
    completed: bool
    timed_out: bool = False
    status_code: int | None = Field(default=None, ge=100, le=599)
    evidence: tuple[EvidenceItem, ...] = ()
    exchanges: tuple[HttpExchangeEvidence, ...] = ()
    duration_ms: int = Field(ge=0)
    error_code: Identifier | None = None


class ControlledHttpReceipt(BaseModel):
    """Bounded result of one policy-admitted registered HTTP reproduction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    receipt_id: Identifier
    operation_id: Identifier
    plan_version: Identifier
    run_id: Identifier
    attempt_number: int = Field(ge=1)
    target_id: Identifier
    target_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    test_id: Identifier
    vulnerability_class: VulnerabilityClass
    method: HttpMethod
    request_count: int = Field(ge=0)
    duration_ms: int = Field(ge=0)
    status_code: int | None = Field(default=None, ge=100, le=599)
    status: Literal["completed", "timeout", "failed"]
    error_class: Literal[
        "request-timeout",
        "transport-error",
        "redirect-blocked",
        "evidence-not-observed",
    ] | None = None
    evidence_ids: tuple[Identifier, ...] = ()


class AttackVerification(BaseModel):
    """Red Team verification decision over structured execution evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: Identifier
    test_id: Identifier
    confirmed: bool
    confidence: Confidence
    evidence_ids: tuple[Identifier, ...] = ()
    reason: NonEmptyText


class RedTeamRunResult(BaseModel):
    """Aggregate result for one Milestone 8 single-attempt Red Team flow."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    target_id: Identifier
    attempt_number: int = Field(ge=1)
    reconnaissance: ReconnaissanceResult
    attack_plan: AttackPlan
    execution: TestExecutionResult
    verification: AttackVerification | None = None
    final_state: WorkflowState

    @model_validator(mode="after")
    def validate_final_state(self) -> RedTeamRunResult:
        if self.final_state not in {
            WorkflowState.BLUE_MONITORING,
            WorkflowState.REJECTED,
        }:
            raise ValueError(
                "Milestone 8 run result must stop at blue_monitoring or rejected"
            )
        if (
            self.final_state == WorkflowState.BLUE_MONITORING
            and self.verification is None
        ):
            raise ValueError("confirmed handoff requires an attack verification")
        return self


# Red v1 contract-only records. Legacy Milestone 8 provider types above remain for
# historical compatibility; execution policy and stage dispatch are later tasks.


class RedWorkerStatus(str, Enum):
    SUCCEEDED = "succeeded"
    BLOCKED = "blocked"
    FAILED = "failed"


class RedScopeReference(BaseModel):
    """Immutable identifiers shared by every Red worker; not authorization itself."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    assessment_id: Identifier
    target_id: Identifier
    target_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    authorization_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")


class RedWorkerError(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: Identifier
    message: NonEmptyText


class _RedWork(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scope: RedScopeReference


class _RedWorkResult(_RedWork):
    status: RedWorkerStatus = RedWorkerStatus.SUCCEEDED
    error: RedWorkerError | None = None

    @model_validator(mode="after")
    def validate_status(self):
        if self.status == RedWorkerStatus.SUCCEEDED and self.error is not None:
            raise ValueError("successful worker result cannot contain an error")
        if self.status != RedWorkerStatus.SUCCEEDED and self.error is None:
            raise ValueError("blocked/failed worker result requires a typed error")
        return self


class RedEndpointCandidate(BaseModel):
    """Untrusted endpoint candidate, never an executable operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: Identifier
    method: HttpMethod
    path: str = Field(min_length=1, max_length=500)
    parameter_names: tuple[Identifier, ...] = ()
    source: Literal["registered", "zap"]
    observed_at: datetime

    @field_validator("path")
    @classmethod
    def local_path_only(cls, path: str) -> str:
        if not path.startswith("/") or path.startswith("//") or "\\" in path:
            raise ValueError("candidate path must be a local absolute path")
        return path


class ReconnaissancePreviewCandidate(BaseModel):
    """Server-classified view of one stored candidate; never execution authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate: RedEndpointCandidate
    policy_status: Literal["candidate_only", "unsupported"]
    registered_endpoint_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_registration(self):
        if (self.policy_status == "candidate_only") != (self.registered_endpoint_id is not None):
            raise ValueError("candidate-only status requires a registered endpoint")
        return self


class ReconnaissancePreviewLimitation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=500)
    reason: Literal["authentication_required", "method_out_of_scope", "no_template"]


class ReconnaissancePreview(BaseModel):
    """Read-only projection of persisted reconnaissance; does not run a test."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: RedScopeReference
    effect: Literal["read_only_preview"] = "read_only_preview"
    execution_enabled: Literal[False] = False
    candidates: tuple[ReconnaissancePreviewCandidate, ...] = ()
    limitations: tuple[ReconnaissancePreviewLimitation, ...] = ()


class ReconnaissanceWork(_RedWork):
    """Candidate mapping under an already fixed scope; no execution permission."""

    stage: Literal["reconnaissance"] = "reconnaissance"
    authorized_seed_endpoint_ids: tuple[Identifier, ...] = ()


class ReconnaissanceWorkResult(_RedWorkResult):
    stage: Literal["reconnaissance"] = "reconnaissance"
    candidates: tuple[RedEndpointCandidate, ...] = ()


class PlanningWork(_RedWork):
    """Plan against a specific reconnaissance surface snapshot."""

    stage: Literal["planning"] = "planning"
    surface_revision: Identifier
    candidates: tuple[RedEndpointCandidate, ...] = ()
    vetted_test_ids: tuple[Identifier, ...] = ()


class PlanningWorkResult(_RedWorkResult):
    stage: Literal["planning"] = "planning"
    plan_version: Identifier | None = None
    operation_ids: tuple[Identifier, ...] = ()
    coverage_gap_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def validate_plan(self):
        if self.status == RedWorkerStatus.SUCCEEDED and self.plan_version is None:
            raise ValueError("successful plan requires a version")
        return self


class ExecutionWork(_RedWork):
    """Reference an admitted operation; this record does not authorize it."""

    stage: Literal["execution"] = "execution"
    plan_version: Identifier
    operation_id: Identifier


class ExecutionWorkResult(_RedWorkResult):
    stage: Literal["execution"] = "execution"
    plan_version: Identifier
    operation_id: Identifier
    receipt_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def validate_receipts(self):
        if self.status == RedWorkerStatus.SUCCEEDED and not self.receipt_ids:
            raise ValueError("successful execution requires a receipt")
        return self


class VerificationWork(_RedWork):
    """Verify an execution using identified prior receipts, without rerunning it."""

    stage: Literal["verification"] = "verification"
    plan_version: Identifier
    operation_id: Identifier
    receipt_ids: tuple[Identifier, ...] = Field(min_length=1)
    oracle_id: Identifier


class VerificationWorkResult(_RedWorkResult):
    stage: Literal["verification"] = "verification"
    plan_version: Identifier
    operation_id: Identifier
    outcome: Literal[
        "confirmed", "suspected", "not_confirmed", "inconclusive", "not_tested"
    ] | None = None
    evidence_receipt_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def validate_confirmation(self):
        if self.status == RedWorkerStatus.SUCCEEDED and self.outcome is None:
            raise ValueError("successful verification requires an outcome")
        if self.outcome == "confirmed" and (
            self.status != RedWorkerStatus.SUCCEEDED or not self.evidence_receipt_ids
        ):
            raise ValueError("confirmation requires successful, referenced evidence")
        return self


# T03: only the trusted Standard profile; these records do not grant dispatch
# authority until the operator-approval and per-operation gates (T07/T08).
class RedStandardBudget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: Literal["standard"] = "standard"
    max_http_requests: int = Field(default=24, ge=1, le=24)
    max_crawl_requests: int = Field(default=12, ge=1, le=12)
    max_tests: int = Field(default=3, ge=1, le=3)
    max_runtime_seconds: int = Field(default=180, ge=1, le=180)
    max_parallel_operations: int = Field(default=1, ge=1, le=1)
    max_depth: int = Field(default=2, ge=0, le=2)
    max_retries: int = Field(default=0, ge=0, le=0)
    max_cpu_cores: float = Field(default=0.5, gt=0, le=0.5)
    max_memory_mb: int = Field(default=512, ge=64, le=512)


class RedStandardAuthorization(BaseModel):
    """Frozen, fingerprinted approval *reference*; not proof of operator consent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: RedScopeReference
    approval_id: Identifier
    scheme: Literal["http"]
    hostname: Identifier
    port: int = Field(ge=1, le=65535)
    budget: RedStandardBudget
    allowed_methods: frozenset[HttpMethod] = Field(min_length=1)
    allowed_classes: frozenset[VulnerabilityClass] = Field(min_length=1)


class RedPolicyUsage(BaseModel):
    """Trusted counter snapshot; later runtime admission must update atomically."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    http_requests: int = Field(default=0, ge=0)
    crawl_requests: int = Field(default=0, ge=0)
    tests_started: int = Field(default=0, ge=0)
    elapsed_seconds: float = Field(default=0, ge=0)
    active_operations: int = Field(default=0, ge=0)


class RedPolicyOperation(BaseModel):
    """Only trusted operation data. No URL, arbitrary command or raw payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: RedScopeReference
    kind: Literal["crawl", "test"]
    scheme: Literal["http"]
    hostname: Identifier
    port: int = Field(ge=1, le=65535)
    method: HttpMethod
    endpoint_id: Identifier
    test_id: Identifier | None = None
    vulnerability_class: VulnerabilityClass | None = None
    requests: int = Field(default=1, ge=1, le=24)
    depth: int = Field(default=0, ge=0, le=20)
    retry_number: int = Field(default=0, ge=0, le=10)
