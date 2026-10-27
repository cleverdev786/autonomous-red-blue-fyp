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

from schemas.common import Identifier
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


class PlanVersionDTO(_RedDTO):
    plan_version: Identifier
    surface_revision: Identifier
    status: Literal["draft", "approved", "stale"]


class OperationDTO(_RedDTO):
    operation_id: Identifier
    plan_version: Identifier
    candidate_id: Identifier
    test_id: Identifier | None = None
    status: Literal["proposed", "approved", "running", "completed", "blocked", "cancelled"]


class ReceiptDTO(_RedDTO):
    receipt_id: Identifier
    operation_id: Identifier
    plan_version: Identifier
    source: Literal["controlled_http", "zap"]
    status: Literal["completed", "timeout", "failed", "blocked"]


class EvidenceArtifactDTO(_RedDTO):
    evidence_id: Identifier
    receipt_id: Identifier
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

    @model_validator(mode="after")
    def check_evidence_claim(self):
        if self.status == FindingState.CONFIRMED and (
            self.oracle_id is None or not self.evidence_receipt_ids
        ):
            raise ValueError("confirmed finding requires an oracle and evidence receipts")
        return self


class CoverageGapDTO(_RedDTO):
    gap_id: Identifier
    status: GapState = GapState.OPEN
    reason: Literal[
        "no_template", "method_out_of_scope", "unsupported_class",
        "authentication_required", "budget_exhausted", "execution_blocked",
        "timeout", "skipped", "not_tested",
    ]
    candidate_id: Identifier | None = None


class TimelineEventDTO(_RedDTO):
    event_id: Identifier
    action: Identifier
    occurred_at: datetime


class PendingHandoffDTO(_RedDTO):
    finding_id: Identifier
    data_only: Literal[True] = True


class RedAssessmentDetailDTO(BaseModel):
    """Snapshot DTO, validated at API/storage edges. Persistence comes in T05."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    assessment: AssessmentDTO
    stages: tuple[StageDTO, ...] = ()
    candidates: tuple[RedEndpointCandidate, ...] = ()
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
            self.stages, self.plans, self.operations, self.receipts,
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
            if finding.status in {FindingState.CONFIRMED, FindingState.NOT_CONFIRMED}:
                if not referenced or not any(
                    r.source == "controlled_http" and r.status == "completed"
                    for r in referenced
                ):
                    raise ValueError("confirmed/negative verdict requires completed controlled receipt")

        for gap in self.coverage_gaps:
            if gap.candidate_id is not None and gap.candidate_id not in candidates:
                raise ValueError("coverage gap references unknown candidate")

        for handoff in self.pending_handoffs:
            if not any(
                f.finding_id == handoff.finding_id and f.status == FindingState.CONFIRMED
                for f in self.findings
            ):
                raise ValueError("handoff requires a confirmed finding")

        return self
