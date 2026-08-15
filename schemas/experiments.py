"""Experiment configuration and run-summary schemas."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.common import (
    Identifier,
    ResearchQuestion,
    RunStatus,
    RunType,
)


class BlueTeamMode(str, Enum):
    """RQ1 architecture condition."""

    SINGLE_AGENT = "single_agent"
    MULTI_AGENT = "multi_agent"


class ClassificationMode(str, Enum):
    """RQ2 classification condition."""

    RULE_ONLY = "rule_only"
    LLM_ONLY = "llm_only"
    HYBRID = "hybrid"


class RetryFeedbackMode(str, Enum):
    """RQ3 patch-retry condition."""

    NONE = "none"
    STRUCTURED = "structured"


class ExperienceMode(str, Enum):
    """Stored-experience selector state for experiment control."""

    DISABLED = "disabled"
    FROZEN_IDENTICAL = "frozen_identical"
    ENABLED_EXPLORATORY = "enabled_exploratory"


class ModelConfiguration(BaseModel):
    """Provider-neutral model settings recorded for reproducibility."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: Identifier
    model_name: Identifier
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_output_tokens: int = Field(default=2000, ge=1, le=100_000)
    seed: int | None = None


class ExperimentLimits(BaseModel):
    """Hard budgets enforced by the orchestrator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_model_calls: int = Field(default=20, ge=1, le=500)
    max_attack_attempts: int = Field(default=3, ge=1, le=20)
    max_patch_attempts: int = Field(default=3, ge=1, le=20)
    max_http_requests: int = Field(default=20, ge=1, le=500)
    max_runtime_seconds: int = Field(default=600, ge=1, le=86_400)


class ExperimentConfiguration(BaseModel):
    """Frozen configuration for one experiment condition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    config_id: Identifier
    run_type: RunType
    research_question: ResearchQuestion
    scenario_ids: tuple[Identifier, ...] = Field(min_length=1)
    repetitions: int = Field(default=1, ge=1, le=100)
    blue_team_mode: BlueTeamMode = BlueTeamMode.MULTI_AGENT
    classification_mode: ClassificationMode = ClassificationMode.HYBRID
    retry_feedback_mode: RetryFeedbackMode = RetryFeedbackMode.NONE
    experience_mode: ExperienceMode = ExperienceMode.DISABLED
    model: ModelConfiguration
    limits: ExperimentLimits = ExperimentLimits()

    @model_validator(mode="after")
    def protect_primary_research_comparisons(self) -> "ExperimentConfiguration":
        if (
            self.run_type == RunType.FINAL_EVALUATION
            and self.research_question in {ResearchQuestion.RQ1, ResearchQuestion.RQ2}
            and self.experience_mode == ExperienceMode.ENABLED_EXPLORATORY
        ):
            raise ValueError(
                "final RQ1/RQ2 runs must disable experience-guided selection "
                "or use an identical frozen experience state"
            )
        return self


class ExperimentRunSummary(BaseModel):
    """Small status object safe to display in the dashboard later."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    config_id: Identifier
    scenario_id: Identifier
    status: RunStatus
    attack_attempts: int = Field(default=0, ge=0)
    patch_attempts: int = Field(default=0, ge=0)
    model_calls: int = Field(default=0, ge=0)
    policy_violation_count: int = Field(default=0, ge=0)
    total_runtime_ms: int = Field(default=0, ge=0)
