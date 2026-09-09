"""Bounded stored-experience and deterministic selection contracts for Milestone 17."""

from __future__ import annotations

from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import Identifier, RunStatus
from schemas.experiments import ExperienceMode


class ExperienceSummary(BaseModel):
    """Small read-only projection of one prior terminal experiment run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_run_id: Identifier
    scenario_id: Identifier
    strategy_id: Identifier
    run_status: RunStatus
    blue_score: Decimal | None = Field(default=None, ge=Decimal("0"), le=Decimal("100"))
    patch_accepted: bool
    regression_detected: bool
    policy_block_count: int = Field(ge=0)
    duplicate_patch_count: int = Field(ge=0)
    attempt_count: int = Field(ge=0)


class ExperienceSnapshot(BaseModel):
    """Deterministic bounded history supplied to the selection policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: Identifier
    history_limit_per_strategy: int = Field(ge=1, le=100)
    ordering_version: Identifier
    summaries: tuple[ExperienceSummary, ...] = ()


class StrategyHistoryObservation(BaseModel):
    """Aggregated deterministic evidence used to rank one trusted strategy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    strategy_id: Identifier
    total_history_count: int = Field(ge=0)
    scored_history_count: int = Field(ge=0)
    mean_blue_score: Decimal | None = Field(default=None, ge=Decimal("0"), le=Decimal("100"))
    patch_acceptance_rate: Decimal = Field(ge=Decimal("0"), le=Decimal("1"))
    regression_rate: Decimal = Field(ge=Decimal("0"), le=Decimal("1"))
    policy_block_count: int = Field(ge=0)
    duplicate_patch_count: int = Field(ge=0)
    mean_attempt_count: Decimal = Field(ge=Decimal("0"))


class SelectionDecision(BaseModel):
    """Auditable choice among trusted registered and policy-approved strategies."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    experience_mode: ExperienceMode
    scenario_id: Identifier
    candidate_strategy_ids: tuple[Identifier, ...]
    eligible_strategy_ids: tuple[Identifier, ...]
    selected_strategy_id: Identifier
    history_limit_per_strategy: int = Field(ge=0, le=100)
    snapshot_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    observations: tuple[StrategyHistoryObservation, ...] = ()
    reason: str = Field(min_length=1, max_length=2000)
