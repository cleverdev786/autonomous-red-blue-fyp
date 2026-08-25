"""Patch proposal, preparation, and structured retry-feedback schemas."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schemas.common import Identifier, NonEmptyText, RelativeProjectPath, WorkflowState


_TEST_NAME_PATTERN = re.compile(r"^test_[A-Za-z0-9_]+$")


class ProposedFileChange(BaseModel):
    """One grounded exact-text edit proposed by an untrusted patch agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_path: RelativeProjectPath
    original_content: str = Field(min_length=1, max_length=20_000)
    replacement_content: str = Field(max_length=20_000)
    rationale: NonEmptyText

    @field_validator("file_path")
    @classmethod
    def reject_obvious_escape(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
            raise ValueError("patch proposal path must be project-relative")
        return value

    @model_validator(mode="after")
    def require_actual_change(self) -> "ProposedFileChange":
        if self.original_content == self.replacement_content:
            raise ValueError("replacement_content must differ from original_content")
        return self


class ProposedSecurityTest(BaseModel):
    """Optional generated security-test proposal with service-derived destination."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    test_name: Identifier
    target_file: RelativeProjectPath
    purpose: NonEmptyText
    proposed_test_content: str = Field(min_length=1, max_length=50_000)

    @field_validator("test_name")
    @classmethod
    def validate_test_name(cls, value: str) -> str:
        if _TEST_NAME_PATTERN.fullmatch(value) is None:
            raise ValueError(
                "test_name must start with 'test_' and contain only letters, digits, and underscores"
            )
        return value


class PatchProposal(BaseModel):
    """LLM patch recommendation. This object never writes directly to disk."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    target_id: Identifier
    attempt_number: int = Field(ge=1)
    changes: tuple[ProposedFileChange, ...] = Field(min_length=1, max_length=10)
    security_rationale: NonEmptyText
    expected_effect: NonEmptyText
    regression_risks: tuple[NonEmptyText, ...] = ()
    proposed_security_test: ProposedSecurityTest | None = None


class PreparedFileChange(BaseModel):
    """Trusted in-memory result for one policy-approved prepared file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_path: RelativeProjectPath
    original_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replacement_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replacement_content: str = Field(max_length=120_000)
    is_new_file: bool = False


class PreparedPatch(BaseModel):
    """Deterministic policy-approved patch artifact that is not yet applied."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    target_id: Identifier
    attempt_number: int = Field(ge=1)
    files: tuple[PreparedFileChange, ...] = Field(min_length=1, max_length=10)
    unified_diff: str = Field(min_length=1, max_length=100_000)
    diff_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files_changed: int = Field(ge=1)
    inserted_lines: int = Field(ge=0)
    deleted_lines: int = Field(ge=0)
    total_diff_bytes: int = Field(ge=1)
    generated_test_path: RelativeProjectPath | None = None

    @model_validator(mode="after")
    def validate_counts(self) -> "PreparedPatch":
        if self.files_changed != len(self.files):
            raise ValueError("files_changed must equal the number of prepared files")
        return self


class PatchGenerationResult(BaseModel):
    """Typed Milestone 12 output before Git/application/verification milestones."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    target_id: Identifier
    attempt_number: int = Field(ge=1)
    proposal: PatchProposal
    prepared_patch: PreparedPatch
    final_state: WorkflowState


class PatchRetryFeedback(BaseModel):
    """Sanitized structured failure feedback allowed in RQ3."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    failed_stage: Identifier
    failing_test_id: Identifier | None = None
    error_summary: NonEmptyText
    original_replay_succeeded: bool | None = None
    regression_failure_ids: tuple[Identifier, ...] = ()
    prior_diff_summary: NonEmptyText | None = None
    policy_reason_code: Identifier | None = None
