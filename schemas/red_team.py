"""Structured Red Team agent and executor outputs."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import Confidence, Identifier, NonEmptyText, VulnerabilityClass


class ReconnaissanceEndpoint(BaseModel):
    """Approved endpoint observation produced by reconnaissance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint_id: Identifier
    input_fields: tuple[Identifier, ...] = ()
    candidate_categories: tuple[VulnerabilityClass, ...] = ()


class ReconnaissanceResult(BaseModel):
    """Bounded reconnaissance result over approved target metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: Identifier
    candidate_endpoints: tuple[ReconnaissanceEndpoint, ...] = ()
    rationale: NonEmptyText


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
