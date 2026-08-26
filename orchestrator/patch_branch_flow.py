"""Trusted orchestration for isolated Git materialization of PreparedPatch artifacts."""

from __future__ import annotations

import time

from orchestrator.policy_engine import PolicyEngine
from schemas.common import WorkflowState
from schemas.git import PatchBranchResult
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from schemas.patches import PatchGenerationResult
from schemas.verification import PolicyDecision
from services.audit_service import AuditService
from services.git_service import GitService


class PatchBranchFlowError(RuntimeError):
    """Raised when Milestone 13 orchestration invariants are violated."""


class PatchBranchPolicyBlocked(PatchBranchFlowError):
    """Raised when an existing deterministic workflow policy blocks transition."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.message)
        self.decision = decision


class PatchBranchFlow:
    """Move a Milestone 12 PreparedPatch onto one isolated local Git branch."""

    def __init__(
        self,
        *,
        git_service: GitService,
        policy_engine: PolicyEngine,
        audit_service: AuditService,
    ) -> None:
        self.git_service = git_service
        self.policy_engine = policy_engine
        self.audit_service = audit_service

    def run(
        self,
        *,
        generation_result: PatchGenerationResult,
        expected_base_commit: str | None = None,
    ) -> PatchBranchResult:
        """Create an isolated branch and materialize the prepared patch before verification."""
        self._validate_generation_result(generation_result)
        prepared = generation_result.prepared_patch
        state = generation_result.final_state

        state = self._transition(
            run_id=generation_result.run_id,
            current=state,
            requested=WorkflowState.PATCH_BRANCH_CREATING,
        )
        base_commit = self.git_service.verify_clean_baseline(
            run_id=generation_result.run_id,
            expected_base_commit=expected_base_commit,
        )
        branch_name = self.git_service.create_patch_branch(
            prepared_patch=prepared,
            base_commit=base_commit,
        )

        try:
            git_diff, git_diff_sha256, changed_paths = (
                self.git_service.materialize_prepared_patch(
                    prepared_patch=prepared,
                    branch_name=branch_name,
                    base_commit=base_commit,
                )
            )
            state = self._transition(
                run_id=generation_result.run_id,
                current=state,
                requested=WorkflowState.PATCH_APPLYING,
            )
        except Exception:
            try:
                self.git_service.restore_baseline(
                    prepared_patch=prepared,
                    branch_name=branch_name,
                    base_commit=base_commit,
                )
            except Exception:
                pass
            raise

        return PatchBranchResult(
            run_id=generation_result.run_id,
            target_id=generation_result.target_id,
            attempt_number=generation_result.attempt_number,
            baseline_branch=self.git_service.git_policy.baseline_branch,
            base_commit=base_commit,
            branch_name=branch_name,
            prepared_diff_sha256=prepared.diff_sha256,
            git_diff=git_diff,
            git_diff_sha256=git_diff_sha256,
            changed_paths=changed_paths,
            final_state=state,
        )

    @staticmethod
    def _validate_generation_result(result: PatchGenerationResult) -> None:
        if result.final_state != WorkflowState.PATCH_VALIDATING:
            raise PatchBranchFlowError(
                "patch branch creation requires a result ending in patch_validating"
            )
        prepared = result.prepared_patch
        if prepared.run_id != result.run_id or result.proposal.run_id != result.run_id:
            raise PatchBranchFlowError("patch generation run identity is inconsistent")
        if prepared.target_id != result.target_id or result.proposal.target_id != result.target_id:
            raise PatchBranchFlowError("patch generation target identity is inconsistent")
        if prepared.attempt_number != result.attempt_number:
            raise PatchBranchFlowError("prepared patch attempt number is inconsistent")
        if result.proposal.attempt_number != result.attempt_number:
            raise PatchBranchFlowError("patch proposal attempt number is inconsistent")

    def _transition(
        self,
        *,
        run_id: str,
        current: WorkflowState,
        requested: WorkflowState,
    ) -> WorkflowState:
        started = time.monotonic()
        decision = self.policy_engine.validate_state_transition(
            current=current,
            requested=requested,
        )
        self.audit_service.record(
            run_id=run_id,
            component="patch_branch_flow",
            actor_type="orchestrator",
            operation="workflow_transition",
            target=f"{current.value}->{requested.value}",
            policy_decision=(
                AuditPolicyDecision.ALLOWED if decision.allowed else AuditPolicyDecision.BLOCKED
            ),
            policy_reason=decision.reason_code,
            execution_status=(
                AuditExecutionStatus.AUTHORIZED
                if decision.allowed
                else AuditExecutionStatus.BLOCKED
            ),
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
            error_code=None if decision.allowed else "policy-blocked",
        )
        if not decision.allowed:
            raise PatchBranchPolicyBlocked(decision)
        return requested
