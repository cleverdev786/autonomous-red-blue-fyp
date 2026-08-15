"""Patch proposal and structured retry-feedback schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.common import Identifier, NonEmptyText, RelativeProjectPath


class ProposedFileChange(BaseModel):
    """One requested file edit. The Patch Service still decides whether it is allowed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_path: RelativeProjectPath
    replacement_content: str = Field(max_length=100_000)
    rationale: NonEmptyText

    @field_validator("file_path")
    @classmethod
    def reject_obvious_escape(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
            raise ValueError("patch proposal path must be project-relative")
        return value


class ProposedSecurityTest(BaseModel):
    """Optional bounded test proposal accompanying a patch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    test_name: Identifier
    target_file: RelativeProjectPath
    purpose: NonEmptyText
    proposed_test_content: str = Field(max_length=50_000)


class PatchProposal(BaseModel):
    """LLM patch recommendation. This object never writes directly to disk."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    attempt_number: int = Field(ge=1)
    changes: tuple[ProposedFileChange, ...] = Field(min_length=1, max_length=10)
    security_rationale: NonEmptyText
    expected_effect: NonEmptyText
    regression_risks: tuple[NonEmptyText, ...] = ()
    proposed_security_test: ProposedSecurityTest | None = None


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
