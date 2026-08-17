"""Structured Red Team agent and executor outputs."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


class RegisteredTestOption(BaseModel):
    """Restricted registered-test metadata visible only to attack planning."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    test_id: Identifier
    vulnerability_class: VulnerabilityClass
    endpoint_id: Identifier
    allowed_parameter_names: tuple[Identifier, ...] = ()
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

    target_id: Identifier
    attempt_number: int = Field(ge=1)
    reconnaissance: ReconnaissanceResult
    attack_plan: AttackPlan
    execution: TestExecutionResult
    verification: AttackVerification | None = None
    final_state: WorkflowState

    @model_validator(mode="after")
    def validate_final_state(self) -> "RedTeamRunResult":
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
