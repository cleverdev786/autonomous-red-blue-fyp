"""Typed, observational R3 trusted-compiler persistence contract.

Distinct from model-authored RemediationAttemptResult.PREPARED.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TrustedCompilerStoredOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["r3-deterministic-v1"] = "r3-deterministic-v1"
    run_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    attempt_number: int = Field(ge=1)
    origin: Literal["trusted_deterministic_builder"] = "trusted_deterministic_builder"
    model_decision_used: Literal[False] = False
    model_input_sha256: None = None
    model_response_sha256: None = None
    status: Literal["prepared", "rejected"]
    reason_code: str = Field(min_length=1, max_length=100)
    rule_id: str | None = None
    strategy: str | None = None
    source_file: str | None = None
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    function_ast_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    blue_analysis_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compiler_version: str = Field(min_length=1)
    compiler_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proposal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    prepared_diff_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    generation_artifact_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def enforce_truthful_origin(self) -> "TrustedCompilerStoredOutcome":
        if self.status == "prepared":
            if not all((
                self.source_sha256, self.function_ast_sha256, self.source_file,
                self.rule_id, self.strategy, self.proposal_sha256,
                self.prepared_diff_sha256, self.generation_artifact_sha256,
            )) or self.reason_code != "prepared":
                raise ValueError("prepared outcome requires full genuine compilation linkage")
        elif any((self.proposal_sha256, self.prepared_diff_sha256,
                  self.generation_artifact_sha256)):
            raise ValueError("rejection must not claim a prepared artifact")
        return self
