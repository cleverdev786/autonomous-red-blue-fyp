"""Bounded read models exposed by the Milestone 16 dashboard API."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from schemas.scoring import ScoreResult


class DashboardModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HealthView(DashboardModel):
    status: str
    database_read_only: bool


class RunListItem(DashboardModel):
    run_id: str
    config_id: str
    research_question: str
    run_type: str
    scenario_id: str | None = None
    dataset_id: str | None = None
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    red_score: Decimal | None = None
    blue_score: Decimal | None = None


class OverviewView(DashboardModel):
    total_runs: int = Field(ge=0)
    status_counts: dict[str, int]
    research_question_counts: dict[str, int]
    recent_runs: tuple[RunListItem, ...]


class RunDetailView(DashboardModel):
    run: RunListItem
    repetition_index: int
    baseline_commit: str
    blue_team_mode: str
    classification_mode: str
    retry_feedback_mode: str
    experience_mode: str
    model_provider: str
    model_name: str
    system_error_code: str | None = None
    system_error_summary: str | None = None
    provenance_versions: dict[str, str | int | None]
    red_attempts: int = Field(ge=0)
    patch_attempts: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    policy_event_references: int = Field(ge=0)
    total_runtime_ms: int | None = Field(default=None, ge=0)


class FindingView(DashboardModel):
    run_id: str
    predicted_label: str | None = None
    classification_mode: str | None = None
    classification_confidence: float | None = None
    file_path: str | None = None
    function_or_route: str | None = None
    localization_confidence: float | None = None


class FunctionalCheckView(DashboardModel):
    check_id: str
    status: str
    duration_ms: int
    details: str


class VerificationStageView(DashboardModel):
    stage_id: str
    sequence_number: int
    required: bool
    passed: bool
    duration_ms: int
    details: str
    checks: tuple[FunctionalCheckView, ...] = ()


class PatchAttemptView(DashboardModel):
    attempt_number: int
    final_state: str | None = None
    patch_decision: str | None = None
    prepared_diff_sha256: str | None = None
    files_changed: int | None = None
    inserted_lines: int | None = None
    deleted_lines: int | None = None
    total_diff_bytes: int | None = None
    changed_paths: tuple[str, ...] = ()
    rejection_reason: str | None = None
    failure_reason: str | None = None
    accepted_commit_sha: str | None = None
    diff_excerpt: str | None = None
    diff_truncated: bool = False
    stages: tuple[VerificationStageView, ...] = ()


class PatchVerificationView(DashboardModel):
    run_id: str
    attempts: tuple[PatchAttemptView, ...]


class ScoreView(DashboardModel):
    score_type: str
    score_value: Decimal
    scoring_version: str
    evidence_reference: str
    evidence_sha256: str | None = None
    evidence_integrity: bool
    breakdown: ScoreResult | None = None


class RunScoresView(DashboardModel):
    run_id: str
    applicability: str
    scores: tuple[ScoreView, ...]


class PolicyEventView(DashboardModel):
    audit_event_id: str
    operation: str
    policy_decision: str
    policy_reason: str | None = None
    execution_status: str
    error_code: str | None = None


class AuditView(DashboardModel):
    run_id: str
    audit_source: str | None = None
    event_count: int = 0
    blocked_count: int = 0
    failed_count: int = 0
    first_event_id: str | None = None
    last_event_id: str | None = None
    canonical_run_audit_sha256: str | None = None
    policy_events: tuple[PolicyEventView, ...] = ()
