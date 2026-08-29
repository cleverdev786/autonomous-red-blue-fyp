"""Typed research-storage records for Milestone 15.

These contracts are observational. They describe evidence and provenance but
never authorize agent, HTTP, Git, Docker, patch, or verification actions.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.common import AgentRole, Identifier, RunStatus


class ArtifactType(str, Enum):
    LOG_READ_RESULT = "log_read_result"
    MONITORING_RESULT = "monitoring_result"
    SOURCE_READ_RESULT = "source_read_result"
    RED_TEAM_RUN_RESULT = "red_team_run_result"
    BLUE_TEAM_ANALYSIS_RESULT = "blue_team_analysis_result"
    PATCH_GENERATION_RESULT = "patch_generation_result"
    PATCH_BRANCH_RESULT = "patch_branch_result"
    PATCH_VERIFICATION_RESULT = "patch_verification_result"
    PATCH_RETRY_FEEDBACK = "patch_retry_feedback"


class TokenUsageStatus(str, Enum):
    REPORTED = "reported"
    NOT_REPORTED = "not_reported"
    NOT_APPLICABLE = "not_applicable"


class CostUsageStatus(str, Enum):
    PROVIDER_REPORTED = "provider_reported"
    DERIVED = "derived"
    NOT_REPORTED = "not_reported"
    NOT_APPLICABLE = "not_applicable"


class StageTimingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    stage_id: Identifier
    sequence_number: int = Field(ge=1)
    duration_ms: int = Field(ge=0)
    attempt_number: int | None = Field(default=None, ge=1)
    started_at: datetime | None = None
    completed_at: datetime | None = None


class RunProvenance(BaseModel):
    """Immutable version manifest recorded with one experiment run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    framework_git_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    baseline_git_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    prompt_set_version: Identifier
    schema_set_version: Identifier
    agent_configuration_version: Identifier
    context_policy_version: Identifier
    scenario_version: Identifier | None = None
    dataset_version: Identifier | None = None
    rule_version: Identifier
    test_suite_version: Identifier
    verification_policy_version: Identifier
    python_version: str = Field(min_length=1, max_length=100)
    docker_version: str | None = Field(default=None, max_length=200)
    compose_version: str | None = Field(default=None, max_length=200)
    software_versions: dict[Identifier, str] = Field(default_factory=dict, max_length=30)
    prompt_versions: dict[AgentRole, Identifier] = Field(default_factory=dict, max_length=20)
    random_seed: int | None = None

    @model_validator(mode="after")
    def require_exact_evaluation_version(self) -> "RunProvenance":
        if (self.scenario_version is None) == (self.dataset_version is None):
            raise ValueError("provenance requires exactly one of scenario_version or dataset_version")
        return self


class AgentCallRecord(BaseModel):
    """One observed provider/model invocation with explicit telemetry semantics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    call_id: Identifier
    agent_role: AgentRole
    sequence_number: int = Field(ge=1)
    provider: Identifier
    model_name: Identifier
    duration_ms: int = Field(ge=0)
    result_status: RunStatus
    classification_observation_id: int | None = Field(default=None, ge=1)
    patch_attempt_number: int | None = Field(default=None, ge=1)
    red_attempt_number: int | None = Field(default=None, ge=1)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    token_usage_status: TokenUsageStatus
    estimated_cost: Decimal | None = Field(default=None, ge=Decimal("0"))
    cost_status: CostUsageStatus
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    pricing_version: Identifier | None = None
    source_audit_event_id: Identifier | None = None

    @model_validator(mode="after")
    def telemetry_matches_status(self) -> "AgentCallRecord":
        if self.token_usage_status == TokenUsageStatus.REPORTED:
            if self.input_tokens is None or self.output_tokens is None:
                raise ValueError("reported token usage requires input_tokens and output_tokens")
        elif self.input_tokens is not None or self.output_tokens is not None:
            raise ValueError("unreported/not-applicable token usage cannot contain token counts")

        if self.cost_status in {CostUsageStatus.PROVIDER_REPORTED, CostUsageStatus.DERIVED}:
            if self.estimated_cost is None or self.currency is None:
                raise ValueError("reported/derived cost requires estimated_cost and currency")
            if self.cost_status == CostUsageStatus.DERIVED and self.pricing_version is None:
                raise ValueError("derived cost requires pricing_version")
        elif self.estimated_cost is not None or self.currency is not None or self.pricing_version is not None:
            raise ValueError("unreported/not-applicable cost cannot contain cost metadata")
        return self
