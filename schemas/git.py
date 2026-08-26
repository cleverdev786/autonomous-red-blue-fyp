"""Typed contracts for restricted local Git patch-attempt isolation."""

from __future__ import annotations

import hashlib
import re
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from schemas.common import Identifier, RelativeProjectPath, WorkflowState


_GIT_REF_COMPONENT = r"[A-Za-z0-9][A-Za-z0-9._-]*"
_GIT_BRANCH_PATTERN = re.compile(rf"^{_GIT_REF_COMPONENT}(?:/{_GIT_REF_COMPONENT})*$")

def _validate_git_branch_name(value: str) -> str:
    if _GIT_BRANCH_PATTERN.fullmatch(value) is None:
        raise ValueError("Git names must use safe slash-separated identifier components")
    if any(
        part.endswith((".lock", ".")) or ".." in part
        for part in value.split("/")
    ):
        raise ValueError("Git names must not contain reserved ref syntax")
    return value


GitBranchName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=240),
    AfterValidator(_validate_git_branch_name),
]


class GitPolicyConfig(BaseModel):
    """Human-controlled local Git policy for patch-attempt branches."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    baseline_branch: GitBranchName = "main"
    patch_branch_prefix: GitBranchName = "agent-patch"

    @model_validator(mode="after")
    def baseline_must_not_use_patch_namespace(self) -> "GitPolicyConfig":
        if self.baseline_branch == self.patch_branch_prefix or self.baseline_branch.startswith(
            f"{self.patch_branch_prefix}/"
        ):
            raise ValueError("baseline branch must be outside the patch branch namespace")
        return self

    def branch_name(self, *, run_id: Identifier, attempt_number: int) -> str:
        """Return the deterministic branch name for one patch attempt."""
        if attempt_number < 1:
            raise ValueError("attempt_number must be >= 1")
        branch = f"{self.patch_branch_prefix}/{run_id}/attempt-{attempt_number}"
        if len(branch) > 240 or _GIT_BRANCH_PATTERN.fullmatch(branch) is None:
            raise ValueError("generated patch branch is not a valid bounded Git ref")
        return branch


class PatchBranchResult(BaseModel):
    """Deterministic evidence for one isolated materialized patch attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    target_id: Identifier
    attempt_number: int = Field(ge=1)
    baseline_branch: GitBranchName
    base_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    branch_name: GitBranchName
    prepared_diff_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    git_diff: str = Field(min_length=1, max_length=100_000)
    git_diff_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    changed_paths: tuple[RelativeProjectPath, ...] = Field(min_length=1, max_length=10)
    final_state: WorkflowState

    @model_validator(mode="after")
    def validate_branch_result(self) -> "PatchBranchResult":
        if self.branch_name == self.baseline_branch:
            raise ValueError("patch branch must differ from the baseline branch")
        if len(self.changed_paths) != len(set(self.changed_paths)):
            raise ValueError("changed_paths must be unique")
        if self.final_state != WorkflowState.PATCH_APPLYING:
            raise ValueError("PatchBranchResult must end in patch_applying")
        actual_git_hash = hashlib.sha256(self.git_diff.encode("utf-8")).hexdigest()
        if actual_git_hash != self.git_diff_sha256:
            raise ValueError("git_diff_sha256 must match git_diff")
        return self
