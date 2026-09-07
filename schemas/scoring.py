"""Typed deterministic game-score evidence for Milestone 16.

These schemas are observational post-run evidence. They do not authorize
experiment execution, patching, Git, Docker, shell, or model actions.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.common import Identifier


class ScoreType(str, Enum):
    RED = "red"
    BLUE = "blue"


class ScoreApplicability(str, Enum):
    SCORED = "scored"
    NOT_APPLICABLE = "not_applicable"
    INELIGIBLE_INCOMPLETE = "ineligible_incomplete"


class ScoreComponentObservation(BaseModel):
    """One independently observable positive scoring component."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    component_id: Identifier
    observed: bool
    points_possible: int = Field(ge=0, le=100)
    points_awarded: int = Field(ge=0, le=100)
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=50)

    @model_validator(mode="after")
    def validate_points(self) -> "ScoreComponentObservation":
        expected = self.points_possible if self.observed else 0
        if self.points_awarded != expected:
            raise ValueError("points_awarded must equal points_possible exactly when observed")
        if any(not item or len(item) > 240 for item in self.evidence_ids):
            raise ValueError("score component evidence references must be bounded non-empty strings")
        return self


class ScorePenaltyObservation(BaseModel):
    """One bounded deterministic scoring penalty."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    penalty_id: Identifier
    observed_count: int = Field(ge=0, le=1000)
    counted_occurrences: int = Field(ge=0, le=100)
    max_counted_occurrences: int = Field(ge=0, le=100)
    points_per_occurrence: int = Field(ge=0, le=100)
    points_deducted: int = Field(ge=0, le=100)
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=100)

    @model_validator(mode="after")
    def validate_penalty(self) -> "ScorePenaltyObservation":
        expected_count = min(self.observed_count, self.max_counted_occurrences)
        if self.counted_occurrences != expected_count:
            raise ValueError("counted_occurrences must use the declared deterministic cap")
        if self.points_deducted != self.counted_occurrences * self.points_per_occurrence:
            raise ValueError("points_deducted does not match the deterministic penalty")
        if any(not item or len(item) > 240 for item in self.evidence_ids):
            raise ValueError("score penalty evidence references must be bounded non-empty strings")
        return self


class ScoreResult(BaseModel):
    """Canonical immutable evidence for one Red or Blue score."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    score_type: ScoreType
    scoring_version: Identifier
    components: tuple[ScoreComponentObservation, ...]
    penalties: tuple[ScorePenaltyObservation, ...]
    selected_patch_attempt: int | None = Field(default=None, ge=1)
    attributed_policy_event_ids: tuple[Identifier, ...] = ()
    subtotal: int = Field(ge=0, le=100)
    total_penalty: int = Field(ge=0, le=100)
    final_score: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def validate_totals(self) -> "ScoreResult":
        if self.subtotal != sum(item.points_awarded for item in self.components):
            raise ValueError("subtotal must equal component points")
        if self.total_penalty != sum(item.points_deducted for item in self.penalties):
            raise ValueError("total_penalty must equal penalty deductions")
        expected = max(0, min(100, self.subtotal - self.total_penalty))
        if self.final_score != expected:
            raise ValueError("final_score must be the clamped deterministic total")
        policy_ids = {
            evidence_id.removeprefix("policy_event:")
            for penalty in self.penalties
            if penalty.penalty_id == "policy_violation"
            for evidence_id in penalty.evidence_ids
            if evidence_id.startswith("policy_event:")
        }
        if set(self.attributed_policy_event_ids) != policy_ids:
            raise ValueError("attributed_policy_event_ids must match policy penalty evidence")
        return self


class ScoringRunOutcome(BaseModel):
    """Result of an explicit offline scoring invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    applicability: ScoreApplicability
    scores: tuple[ScoreResult, ...] = ()
    reason: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def validate_applicability(self) -> "ScoringRunOutcome":
        if self.applicability == ScoreApplicability.SCORED and not self.scores:
            raise ValueError("scored outcome requires score results")
        if self.applicability != ScoreApplicability.SCORED and self.scores:
            raise ValueError("non-scored outcome cannot contain score results")
        return self
