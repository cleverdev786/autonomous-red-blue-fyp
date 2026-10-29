"""T04 Red assessment lifecycle and read-only API DTOs.

Pure contracts: no database writes, tool dispatch, or generated execution authority.
Legacy Milestone-8 data models remain in schemas.red_team for compatibility.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schemas.common import Identifier, NonEmptyText
from schemas.red_team import RedEndpointCandidate, RedScopeReference


class AssessmentState(str, Enum):
    CREATED = "created"
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_LIMITATIONS = "completed_with_limitations"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class StageState(str, Enum):
    NOT_STARTED = "not_started"
    READY = "ready"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    STALE = "stale"


class FindingState(str, Enum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not_confirmed"
    INCONCLUSIVE = "inconclusive"


class GapState(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"


_FINDING_NEXT = {
    FindingState.SUSPECTED: {
        FindingState.CONFIRMED, FindingState.NOT_CONFIRMED, FindingState.INCONCLUSIVE,
    },
    FindingState.INCONCLUSIVE: {FindingState.SUSPECTED},
    FindingState.NOT_CONFIRMED: {FindingState.SUSPECTED},
}
_GAP_NEXT = {GapState.OPEN: {GapState.RESOLVED}}


_ASSESSMENT_NEXT = {
    AssessmentState.CREATED: {AssessmentState.AWAITING_AUTHORIZATION, AssessmentState.CANCELLED},
    AssessmentState.AWAITING_AUTHORIZATION: {AssessmentState.QUEUED, AssessmentState.CANCELLED, AssessmentState.BLOCKED},
    AssessmentState.QUEUED: {AssessmentState.RUNNING, AssessmentState.CANCELLED, AssessmentState.BLOCKED},
    AssessmentState.RUNNING: {
        AssessmentState.COMPLETED, AssessmentState.COMPLETED_WITH_LIMITATIONS,
        AssessmentState.FAILED, AssessmentState.CANCELLED, AssessmentState.BLOCKED,
    },
}
_STAGE_NEXT = {
    StageState.NOT_STARTED: {StageState.READY},
    StageState.READY: {StageState.QUEUED, StageState.CANCELLED, StageState.BLOCKED},
    StageState.QUEUED: {StageState.RUNNING, StageState.CANCELLED, StageState.BLOCKED},
    StageState.RUNNING: {StageState.SUCCEEDED, StageState.FAILED, StageState.CANCELLED, StageState.BLOCKED},
    StageState.SUCCEEDED: {StageState.STALE, StageState.READY},
    StageState.FAILED: {StageState.READY},
    StageState.BLOCKED: {StageState.READY},
    StageState.CANCELLED: {StageState.READY},
    StageState.STALE: {StageState.READY},
}


def require_assessment_transition(before: AssessmentState, after: AssessmentState) -> None:
    if AssessmentState(after) not in _ASSESSMENT_NEXT.get(AssessmentState(before), set()):
        raise ValueError(f"invalid assessment transition: {before} -> {after}")


def require_stage_transition(before: StageState, after: StageState) -> None:
    if StageState(after) not in _STAGE_NEXT.get(StageState(before), set()):
        raise ValueError(f"invalid stage transition: {before} -> {after}")


def require_finding_transition(before: FindingState, after: FindingState) -> None:
    if FindingState(after) not in _FINDING_NEXT.get(FindingState(before), set()):
        raise ValueError(f"invalid finding transition: {before} -> {after}")


def require_gap_transition(before: GapState, after: GapState) -> None:
    if GapState(after) not in _GAP_NEXT.get(GapState(before), set()):
        raise ValueError(f"invalid gap transition: {before} -> {after}")


class _RedDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: RedScopeReference


class CoverageDTO(BaseModel):
    """Eligible is the denominator. Unexecuted tests are not counted as passes."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    eligible: int = Field(default=0, ge=0)
    executed: int = Field(default=0, ge=0)
    completed: int = Field(default=0, ge=0)
    blocked: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    observed_candidate_gaps: int = Field(default=0, ge=0)
    unresolved_observations: int = Field(default=0, ge=0)
    coverage_complete: bool | None = None

    @model_validator(mode="after")
    def check_counts(self):
        if self.executed + self.blocked + self.skipped != self.eligible:
            raise ValueError("eligible coverage must account for executed/blocked/skipped")
        if self.completed > self.executed:
            raise ValueError("completed cannot exceed executed")
        actual = (
            self.eligible > 0 and self.completed == self.eligible
            and self.blocked == self.skipped == self.observed_candidate_gaps
            == self.unresolved_observations == 0
        )
        if self.coverage_complete is not None and self.coverage_complete != actual:
            raise ValueError("coverage_complete inconsistent with observed counts")
        object.__setattr__(self, "coverage_complete", actual)
        return self


_TERMINAL = {
    AssessmentState.COMPLETED, AssessmentState.COMPLETED_WITH_LIMITATIONS,
    AssessmentState.FAILED, AssessmentState.CANCELLED, AssessmentState.BLOCKED,
}


class AssessmentDTO(_RedDTO):
    mode: Literal["manual", "autonomous"]
    profile: Literal["standard"] = "standard"
    status: AssessmentState
    workflow_complete: bool
    coverage: CoverageDTO

    @model_validator(mode="after")
    def check_workflow(self):
        if self.workflow_complete != (self.status in _TERMINAL):
            raise ValueError("workflow completion must reflect terminal assessment state")
        if self.status == AssessmentState.COMPLETED and not self.coverage.coverage_complete:
            raise ValueError("completed assessment requires complete coverage")
        if (self.status == AssessmentState.COMPLETED_WITH_LIMITATIONS
                and self.coverage.coverage_complete):
            raise ValueError("limited completion requires a coverage limitation")
        return self


class StageDTO(_RedDTO):
    stage: Literal["reconnaissance", "planning", "execution", "verification"]
    status: StageState
    plan_version: Identifier | None = None


class StageTransitionEventDTO(_RedDTO):
    """One durable coordinator transition around a Red worker dispatch."""

    event_id: Identifier
    stage: Literal["reconnaissance", "planning", "execution", "verification"]
    previous_status: StageState
    status: StageState
    phase: Literal["before_worker", "after_worker", "recovery"]
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def timestamp_is_aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("stage transition timestamp requires timezone")
        return value

    @model_validator(mode="after")
    def transition_is_legal(self):
        require_stage_transition(self.previous_status, self.status)
        return self


class PlanVersionDTO(_RedDTO):
    plan_version: Identifier
    surface_revision: Identifier
    status: Literal["draft", "approved", "stale"]
    plan_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class SurfaceRevisionDTO(_RedDTO):
    surface_revision: Identifier
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_ids: tuple[Identifier, ...] = ()
    observed_at: datetime

    @model_validator(mode="after")
    def unique_candidates(self):
        if len(self.candidate_ids) != len(set(self.candidate_ids)):
            raise ValueError("surface candidate IDs must be unique")
        return self


class OperationDTO(_RedDTO):
    operation_id: Identifier
    plan_version: Identifier
    candidate_id: Identifier
    test_id: Identifier | None = None
    status: Literal["proposed", "approved", "running", "completed", "blocked", "cancelled"]


class ReceiptExchangeDTO(BaseModel):
    """Secret-free digest of one bounded controlled HTTP response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: Identifier
    endpoint_id: Identifier
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    status_code: int = Field(ge=100, le=599)
    body_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    body_length: int = Field(ge=0, le=2000)


class ReceiptDTO(_RedDTO):
    receipt_id: Identifier
    operation_id: Identifier
    plan_version: Identifier
    test_id: Identifier
    run_id: Identifier
    target_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    recorded_at: datetime
    source: Literal["controlled_http", "zap"]
    observation_status: Literal["suspected", "not_observed"] | None = None
    status: Literal["completed", "timeout", "failed", "blocked", "cancelled"]
    request_count: int = Field(ge=0, le=24)
    exchanges: tuple[ReceiptExchangeDTO, ...] = Field(default=(), max_length=20)
    raw_response_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_id: Identifier

    @field_validator("recorded_at")
    @classmethod
    def timestamp_is_aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("receipt timestamp requires timezone")
        return value

    @model_validator(mode="after")
    def controlled_exchange_count_matches(self):
        if self.source == "controlled_http":
            observed = len(self.exchanges)
            if (
                (self.status == "completed" and self.request_count != observed)
                or self.request_count < observed
                or self.request_count > observed + 1
            ):
                raise ValueError("controlled receipt exchange count mismatch")
            if self.observation_status is not None:
                raise ValueError("controlled receipt cannot contain scanner classification")
        elif self.observation_status is None:
            raise ValueError("ZAP receipt requires an explicit observation classification")
        return self


class EvidenceArtifactDTO(_RedDTO):
    evidence_id: Identifier
    receipt_id: Identifier
    operation_id: Identifier | None = None
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    content_type: str = Field(min_length=3, max_length=100)
    storage_ref: str = Field(min_length=1, max_length=250)

    @field_validator("storage_ref")
    @classmethod
    def safe_relative_reference(cls, value):
        path = PurePosixPath(value)
        if (path.is_absolute() or ".." in path.parts or "\\" in value
                or value.startswith(".") or "//" in value or ":" in value):
            raise ValueError("evidence location must be a safe relative reference")
        return value


class FindingDTO(_RedDTO):
    finding_id: Identifier
    operation_id: Identifier
    status: FindingState
    oracle_id: Identifier | None = None
    evidence_receipt_ids: tuple[Identifier, ...] = ()
    severity: Literal["informational", "low", "medium", "high", "critical"] | None = None
    category: Identifier | None = None
    route: str | None = Field(default=None, min_length=1, max_length=500)
    provenance: Literal["controlled_http", "zap"] | None = None
    reproduction_scope: Literal["registered_local_lab", "targeted_scanner"] | None = None
    evidence_id: Identifier | None = None

    @model_validator(mode="after")
    def check_evidence_claim(self):
        if self.status == FindingState.CONFIRMED and (
            self.oracle_id is None or not self.evidence_receipt_ids
            or self.severity is None or self.category is None or self.route is None
            or self.provenance != "controlled_http"
            or self.reproduction_scope != "registered_local_lab"
            or self.evidence_id is None
        ):
            raise ValueError(
                "confirmed finding requires an oracle and controlled evidence provenance"
            )
        if self.route is not None and (
            not self.route.startswith("/") or self.route.startswith("//") or "\\" in self.route
        ):
            raise ValueError("finding route must be a local absolute path")
        return self


class CoverageGapDTO(_RedDTO):
    gap_id: Identifier
    status: GapState = GapState.OPEN
    surface_revision: Identifier | None = None
    reason: Literal[
        "no_template", "method_out_of_scope", "unsupported_class",
        "authentication_required", "budget_exhausted", "execution_blocked",
        "timeout", "skipped", "not_tested",
    ]
    candidate_id: Identifier | None = None
    test_id: Identifier | None = None
    recommendation: NonEmptyText | None = None


class PlanningDecisionDTO(BaseModel):
    """Deterministic planning output; references only vetted operations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: PlanVersionDTO
    operations: tuple[OperationDTO, ...] = ()
    coverage_gaps: tuple[CoverageGapDTO, ...] = ()

    @model_validator(mode="after")
    def validate_links(self):
        scope = self.plan.scope
        if any(item.scope != scope for item in (*self.operations, *self.coverage_gaps)):
            raise ValueError("planning output scope mismatch")
        if any(item.plan_version != self.plan.plan_version for item in self.operations):
            raise ValueError("planning operation references another plan")
        return self


class TimelineEventDTO(_RedDTO):
    event_id: Identifier
    action: Identifier
    occurred_at: datetime


class PendingHandoffDTO(_RedDTO):
    finding_id: Identifier
    data_only: Literal[True] = True


class RedAssessmentSummaryDTO(BaseModel):
    """Truthful rollup that never infers safety from a zero finding count."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: RedScopeReference
    status: Literal["completed", "completed_with_limitations"]
    coverage: CoverageDTO
    findings: tuple[FindingDTO, ...] = ()
    coverage_gaps: tuple[CoverageGapDTO, ...] = ()
    pending_handoffs: tuple[PendingHandoffDTO, ...] = ()
    warnings: tuple[
        Literal[
            "unauthenticated_only_coverage",
            "unsupported_vulnerability_classes",
            "incomplete_or_uncertain_coverage",
        ], ...
    ] = ()


class RedAssessmentDetailDTO(BaseModel):
    """Snapshot DTO, validated at API/storage edges. Persistence comes in T05."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    assessment: AssessmentDTO
    stages: tuple[StageDTO, ...] = ()
    candidates: tuple[RedEndpointCandidate, ...] = ()
    surfaces: tuple[SurfaceRevisionDTO, ...] = ()
    plans: tuple[PlanVersionDTO, ...] = ()
    operations: tuple[OperationDTO, ...] = ()
    receipts: tuple[ReceiptDTO, ...] = ()
    evidence: tuple[EvidenceArtifactDTO, ...] = ()
    findings: tuple[FindingDTO, ...] = ()
    coverage_gaps: tuple[CoverageGapDTO, ...] = ()
    events: tuple[TimelineEventDTO, ...] = ()
    pending_handoffs: tuple[PendingHandoffDTO, ...] = ()

    @model_validator(mode="after")
    def validate_linkage(self):
        scope = self.assessment.scope
        for group in (
            self.stages, self.surfaces, self.plans, self.operations, self.receipts,
            self.evidence, self.findings, self.coverage_gaps,
            self.events, self.pending_handoffs,
        ):
            if any(item.scope != scope for item in group):
                raise ValueError("scope mismatch in assessment snapshot")

        def index(items, key):
            keys = [getattr(item, key) for item in items]
            if len(keys) != len(set(keys)):
                raise ValueError(f"duplicate {key} in assessment snapshot")
            return {getattr(item, key): item for item in items}

        candidates = index(self.candidates, "candidate_id")
        surfaces = index(self.surfaces, "surface_revision")
        plans = index(self.plans, "plan_version")
        operations = index(self.operations, "operation_id")
        receipts = index(self.receipts, "receipt_id")
        index(self.evidence, "evidence_id")
        index(self.findings, "finding_id")
        index(self.coverage_gaps, "gap_id")
        index(self.events, "event_id")

        for stage in self.stages:
            if stage.plan_version is not None and stage.plan_version not in plans:
                raise ValueError("stage references unknown plan version")

        if surfaces:
            for surface in self.surfaces:
                if any(candidate_id not in candidates for candidate_id in surface.candidate_ids):
                    raise ValueError("surface references unknown candidate")
            for plan in self.plans:
                if plan.surface_revision not in surfaces:
                    raise ValueError("plan references unknown surface revision")

        for op in self.operations:
            plan = plans.get(op.plan_version)
            if plan is None or plan.scope != op.scope:
                raise ValueError("operation references unknown plan version")
            if op.candidate_id not in candidates:
                raise ValueError("operation references unknown candidate")
            if op.status in {"approved", "running"} and plan.status != "approved":
                raise ValueError("stale or unapproved plan cannot have an active operation")

        for receipt in self.receipts:
            operation = operations.get(receipt.operation_id)
            if operation is None or receipt.plan_version != operation.plan_version:
                raise ValueError("receipt references an unknown/mismatched operation and plan")

        for artifact in self.evidence:
            if artifact.receipt_id not in receipts:
                raise ValueError("evidence references unknown receipt")

        for finding in self.findings:
            if finding.operation_id not in operations:
                raise ValueError("finding references unknown operation")
            referenced = [receipts.get(rid) for rid in finding.evidence_receipt_ids]
            if any(r is None or r.operation_id != finding.operation_id for r in referenced):
                raise ValueError("finding references unrelated receipt")
            if (
                finding.status in {FindingState.CONFIRMED, FindingState.NOT_CONFIRMED}
                and (
                    not referenced
                    or not any(
                        r.source == "controlled_http" and r.status == "completed"
                        for r in referenced
                    )
                )
            ):
                raise ValueError(
                    "confirmed/negative verdict requires completed controlled receipt"
                )

        for gap in self.coverage_gaps:
            if gap.candidate_id is not None and gap.candidate_id not in candidates:
                raise ValueError("coverage gap references unknown candidate")
            if (
                gap.surface_revision is not None
                and gap.surface_revision not in surfaces
            ):
                raise ValueError("coverage gap references unknown surface revision")

        for handoff in self.pending_handoffs:
            if not any(
                f.finding_id == handoff.finding_id and f.status == FindingState.CONFIRMED
                for f in self.findings
            ):
                raise ValueError("handoff requires a confirmed finding")

        return self


class RedPaginationDTO(BaseModel):
    """Stable offset pagination shared by Red dashboard list reads."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    total: int = Field(ge=0)


class RedTargetReadDTO(BaseModel):
    """Safe target catalogue projection; runtime coordinates stay server-side."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    target_id: Identifier
    compatibility: Literal["supported"] = "supported"
    supported_classes: tuple[
        Literal["path_traversal", "sql_injection", "xss"], ...
    ]
    limitations: tuple[Literal["unauthenticated_only"], ...] = (
        "unauthenticated_only",
    )


class RedTargetPageDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    items: tuple[RedTargetReadDTO, ...]
    pagination: RedPaginationDTO


class RedAssessmentListItemDTO(BaseModel):
    """Compact server-authoritative assessment history row."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    assessment_id: Identifier
    target_id: Identifier
    mode: Literal["manual", "autonomous"]
    profile: Literal["standard"]
    status: AssessmentState
    workflow_complete: bool
    coverage: CoverageDTO
    current_plan_version: Identifier | None = None
    current_surface_revision: Identifier | None = None
    stage_statuses: dict[
        Literal["reconnaissance", "planning", "execution", "verification"],
        StageState,
    ] = Field(default_factory=dict)


class RedAssessmentPageDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    items: tuple[RedAssessmentListItemDTO, ...]
    pagination: RedPaginationDTO


class RedAssessmentWorkspaceDTO(BaseModel):
    """Assessment workspace state without raw receipts or evidence locations."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    assessment: RedAssessmentListItemDTO
    stages: tuple[StageDTO, ...] = ()
    plans: tuple[PlanVersionDTO, ...] = ()
    candidate_count: int = Field(ge=0)
    planned_operation_count: int = Field(ge=0)
    finding_counts: dict[FindingState, int]
    coverage_gap_count: int = Field(ge=0)


class RedEventReadDTO(BaseModel):
    """Bounded major-step timeline projection; technical details are omitted."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    event_id: Identifier
    action: Identifier
    status: Identifier
    stage: Literal[
        "reconnaissance", "planning", "execution", "verification"
    ] | None = None
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def event_timestamp_is_aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("event timestamp requires timezone")
        return value


class RedEventPageDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    items: tuple[RedEventReadDTO, ...]
    pagination: RedPaginationDTO


class RedFindingReadDTO(BaseModel):
    """Finding-table projection with an evidence flag, never a filesystem path."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    finding_id: Identifier
    assessment_id: Identifier
    target_id: Identifier
    status: FindingState
    severity: Literal["informational", "low", "medium", "high", "critical"] | None
    category: Identifier | None
    route: str | None
    provenance: Literal["controlled_http", "zap"] | None
    reproduction_scope: Literal["registered_local_lab", "targeted_scanner"] | None
    has_evidence: bool


class RedFindingPageDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    items: tuple[RedFindingReadDTO, ...]
    pagination: RedPaginationDTO
    coverage_gap_count: int = Field(ge=0)


class RedEvidenceMetadataReadDTO(BaseModel):
    """Integrity metadata only; storage references and evidence bytes are omitted."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_id: Identifier
    receipt_id: Identifier
    operation_id: Identifier | None
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    content_type: str = Field(min_length=3, max_length=100)


class RedFindingDetailDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    finding: RedFindingReadDTO
    operation_id: Identifier
    plan_version: Identifier
    test_id: Identifier | None
    oracle_id: Identifier | None
    evidence_receipt_ids: tuple[Identifier, ...] = ()
    evidence: tuple[RedEvidenceMetadataReadDTO, ...] = ()


class RedCoverageReadDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    assessment_id: Identifier
    target_id: Identifier
    coverage: CoverageDTO
    gaps: tuple[CoverageGapDTO, ...] = ()
    warnings: tuple[
        Literal[
            "unauthenticated_only_coverage",
            "unsupported_vulnerability_classes",
            "incomplete_or_uncertain_coverage",
        ], ...
    ] = ()


class RedDashboardSummaryDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    target_id: Identifier | None = None
    assessment_count: int = Field(ge=0)
    confirmed_findings: int = Field(ge=0)
    suspected_findings: int = Field(ge=0)
    tested: int = Field(ge=0)
    eligible: int = Field(ge=0)
    active_assessments: int = Field(ge=0)
    queued_assessments: int = Field(ge=0)
    active_stages: int = Field(ge=0)
    coverage_gaps: int = Field(ge=0)


class RedCommandReceiptDTO(BaseModel):
    """Stable acknowledgement for one idempotent operator command."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    assessment_id: Identifier
    request_id: Identifier
    status: Literal[
        "awaiting_authorization", "queued", "cancellation_requested", "cancelled"
    ]
    job_ids: tuple[Identifier, ...] = ()
