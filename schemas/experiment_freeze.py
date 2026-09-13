"""Typed contracts for the Milestone 20 experiment-freeze infrastructure.

These models define generic freeze/run-plan evidence only. They do not choose
final model settings, RQ1 controls, or optional RQ3 settings.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schemas.common import AgentRole, Identifier, ResearchQuestion


_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_COMMIT_PATTERN = r"^[0-9a-f]{40}$"


class FrozenFileKind(str, Enum):
    """High-level reason one project file is controlled by the freeze."""

    SOURCE = "source"
    CONFIGURATION = "configuration"
    PROMPT = "prompt"
    SCHEMA = "schema"
    RULE = "rule"
    TEST = "test"
    VERIFICATION = "verification"
    ANALYSIS = "analysis"
    ENVIRONMENT = "environment"
    DATASET = "dataset"


class FrozenFileReference(BaseModel):
    """One project-relative frozen file and its exact bytes hash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=500)
    sha256: str = Field(pattern=_SHA256_PATTERN)
    kind: FrozenFileKind

    @field_validator("path")
    @classmethod
    def require_safe_relative_path(cls, value: str) -> str:
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts or value != candidate.as_posix():
            raise ValueError("frozen paths must be normalized project-relative paths")
        return value


class FrozenConfigurationReference(BaseModel):
    """Canonical identity for one approved final configuration payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    config_id: Identifier
    configuration_sha256: str = Field(pattern=_SHA256_PATTERN)


class PromptAssetReference(BaseModel):
    """Hash/version reference for one explicit prompt asset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt_id: Identifier
    version: Identifier
    role: AgentRole
    path: str = Field(min_length=1, max_length=500)
    sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("path")
    @classmethod
    def require_safe_relative_path(cls, value: str) -> str:
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts or value != candidate.as_posix():
            raise ValueError("prompt paths must be normalized project-relative paths")
        return value


class EnvironmentManifest(BaseModel):
    """Observed runtime/tool versions captured before final evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="1.0", pattern=r"^1\.0$")
    python_version: str = Field(min_length=1, max_length=100)
    software_versions: dict[Identifier, str] = Field(default_factory=dict, max_length=30)
    docker_version: str | None = Field(default=None, max_length=200)
    compose_version: str | None = Field(default=None, max_length=200)


class RunPlanEntry(BaseModel):
    """One predeclared final execution slot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: Identifier
    config_id: Identifier
    research_question: ResearchQuestion
    repetition_index: int = Field(ge=1, le=100)
    baseline_git_commit: str = Field(pattern=_COMMIT_PATTERN)
    subject_version: Identifier
    scenario_id: Identifier | None = None
    dataset_id: Identifier | None = None
    random_seed: int | None = None

    @model_validator(mode="after")
    def require_exact_subject(self) -> "RunPlanEntry":
        if (self.scenario_id is None) == (self.dataset_id is None):
            raise ValueError("run-plan entry requires exactly one of scenario_id or dataset_id")
        if self.research_question == ResearchQuestion.RQ2 and self.dataset_id is None:
            raise ValueError("RQ2 run-plan entries require dataset_id")
        if self.research_question != ResearchQuestion.RQ2 and self.scenario_id is None:
            raise ValueError("RQ1/RQ3 run-plan entries require scenario_id")
        return self


class ExperimentRunPlan(BaseModel):
    """Canonical precommitted final-run schedule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="1.0", pattern=r"^1\.0$")
    freeze_id: Identifier
    entries: tuple[RunPlanEntry, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def require_unique_entries(self) -> "ExperimentRunPlan":
        ids = [entry.entry_id for entry in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("run-plan entry IDs must be unique")
        return self


class ExperimentFreezeManifest(BaseModel):
    """Canonical authority over all artifacts controlled by one final freeze."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="1.0", pattern=r"^1\.0$")
    freeze_id: Identifier
    framework_ref: Identifier
    source_parent_commit: str = Field(pattern=_COMMIT_PATTERN)
    configuration_refs: tuple[FrozenConfigurationReference, ...] = Field(min_length=1)
    run_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    environment_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_set_version: Identifier
    schema_set_version: Identifier
    agent_configuration_version: Identifier
    context_policy_version: Identifier
    rule_version: Identifier
    test_suite_version: Identifier
    verification_policy_version: Identifier
    prompt_assets: tuple[PromptAssetReference, ...] = Field(min_length=1)
    frozen_files: tuple[FrozenFileReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def require_unique_references(self) -> "ExperimentFreezeManifest":
        config_ids = [item.config_id for item in self.configuration_refs]
        if len(config_ids) != len(set(config_ids)):
            raise ValueError("freeze configuration IDs must be unique")
        paths = [item.path for item in self.frozen_files]
        if len(paths) != len(set(paths)):
            raise ValueError("freeze file paths must be unique")
        prompt_ids = [item.prompt_id for item in self.prompt_assets]
        if len(prompt_ids) != len(set(prompt_ids)):
            raise ValueError("freeze prompt IDs must be unique")
        prompt_roles = [item.role for item in self.prompt_assets]
        if len(prompt_roles) != len(set(prompt_roles)):
            raise ValueError("freeze prompt roles must be unique")
        prompt_paths = [item.path for item in self.prompt_assets]
        if len(prompt_paths) != len(set(prompt_paths)):
            raise ValueError("freeze prompt paths must be unique")
        return self


class FinalEvaluationPreflightReceipt(BaseModel):
    """Proof that one final run passed the deterministic freeze preflight."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    freeze_id: Identifier
    freeze_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_plan_entry_id: Identifier
    config_id: Identifier
    configuration_sha256: str = Field(pattern=_SHA256_PATTERN)
    research_question: ResearchQuestion
    repetition_index: int = Field(ge=1, le=100)
    framework_git_commit: str = Field(pattern=_COMMIT_PATTERN)
    baseline_git_commit: str = Field(pattern=_COMMIT_PATTERN)
    scenario_id: Identifier | None = None
    dataset_id: Identifier | None = None
    scenario_version: Identifier | None = None
    dataset_version: Identifier | None = None
    random_seed: int | None = None
    prompt_set_version: Identifier
    prompt_versions: dict[AgentRole, Identifier] = Field(default_factory=dict, max_length=20)
    schema_set_version: Identifier
    agent_configuration_version: Identifier
    context_policy_version: Identifier
    rule_version: Identifier
    test_suite_version: Identifier
    verification_policy_version: Identifier
    environment_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    python_version: str = Field(min_length=1, max_length=100)
    software_versions: dict[Identifier, str] = Field(default_factory=dict, max_length=30)
    docker_version: str | None = Field(default=None, max_length=200)
    compose_version: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def require_exact_subject_version(self) -> "FinalEvaluationPreflightReceipt":
        if (self.scenario_id is None) == (self.dataset_id is None):
            raise ValueError("preflight receipt requires exactly one subject identity")
        if (self.scenario_version is None) == (self.dataset_version is None):
            raise ValueError("preflight receipt requires exactly one subject version")
        if self.research_question == ResearchQuestion.RQ2:
            if self.dataset_id is None or self.dataset_version is None:
                raise ValueError("RQ2 preflight receipt requires dataset identity/version")
        elif self.scenario_id is None or self.scenario_version is None:
            raise ValueError("RQ1/RQ3 preflight receipt requires scenario identity/version")
        return self
