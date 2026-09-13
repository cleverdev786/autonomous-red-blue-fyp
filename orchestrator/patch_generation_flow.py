"""Typed Milestone 12 patch-generation orchestration without write/Git authority."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import time
from typing import Any

from agents.blue.patch_generation import PatchGenerationAgent
from llm.interface import StructuredGenerationProvider, require_research_recording_for_final_capable
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import BlueTeamAnalysisResult, SourceReadResult
from schemas.common import WorkflowState
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from schemas.patches import PatchGenerationResult, PatchProposal, PatchRetryFeedback
from schemas.verification import PolicyDecision
from services.audit_service import AuditService
from services.patch_service import PatchService
from services.source_reader import SourceReader
from services.target_registry import TargetRegistry


class PatchGenerationFlowError(RuntimeError):
    """Raised when patch-generation input or provider output fails deterministic checks."""


class PatchGenerationPolicyBlocked(PatchGenerationFlowError):
    """Raised when deterministic policy denies a Milestone 12 operation."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.message)
        self.decision = decision


class PatchGenerationFlow:
    """Turn one grounded CodeFinding into a policy-approved in-memory patch."""

    def __init__(
        self,
        *,
        target_registry: TargetRegistry,
        policy_engine: PolicyEngine,
        limits: RunLimitTracker,
        provider: StructuredGenerationProvider,
        audit_service: AuditService,
        project_root: Path,
    ) -> None:
        self.target_registry = target_registry
        self.policy_engine = policy_engine
        self.limits = limits
        require_research_recording_for_final_capable(provider)
        self.provider = provider
        self.audit_service = audit_service
        self.project_root = project_root.resolve(strict=False)
        self.patch_agent = PatchGenerationAgent()
        self.source_reader = SourceReader(
            registry=target_registry,
            policy_engine=policy_engine,
            audit_service=audit_service,
            project_root=project_root,
        )
        self.patch_service = PatchService(
            registry=target_registry,
            policy_engine=policy_engine,
            audit_service=audit_service,
            project_root=project_root,
        )

    def run(
        self,
        *,
        analysis: BlueTeamAnalysisResult,
        attempt_number: int,
        retry_feedback: PatchRetryFeedback | None = None,
        entry_state: WorkflowState | None = None,
    ) -> PatchGenerationResult:
        """Prepare one bounded patch and stop before Git/application/verification work."""
        if attempt_number < 1:
            raise ValueError("attempt_number must be >= 1")
        self._validate_analysis(analysis)
        current_state = entry_state or analysis.final_state
        if current_state not in {WorkflowState.CODE_ANALYSIS, WorkflowState.REJECTED}:
            raise PatchGenerationFlowError(
                "patch generation entry state must be code_analysis or rejected"
            )

        state = self._transition(
            run_id=analysis.run_id,
            current=current_state,
            requested=WorkflowState.PATCH_GENERATING,
        )
        self._require_policy(
            run_id=analysis.run_id,
            operation="patch_attempt_authorization",
            target=f"attempt-{attempt_number}",
            decision=self.policy_engine.validate_patch_attempt_budget(self.limits),
        )
        self.limits.consume_patch_attempts()

        source_context = self._build_patch_context(analysis)
        target = self.target_registry.get_target(analysis.target_id)
        generated_roots = [
            str(root)
            for root in target.writable_patch_roots
            if Path(str(root)).as_posix().endswith("/tests/generated")
        ]
        if len(generated_roots) != 1:
            raise PatchGenerationFlowError(
                "target must define exactly one generated security-test writable root"
            )
        constraints = {
            "allowed_source_file": analysis.code_finding.file_path,
            "allowed_generated_test_root": generated_roots[0],
            "allowed_file_type": ".py",
            "max_files_changed": target.patch_limits.max_files_changed,
            "max_inserted_lines": target.patch_limits.max_inserted_lines,
            "max_deleted_lines": target.patch_limits.max_deleted_lines,
            "max_total_diff_bytes": target.patch_limits.max_total_diff_bytes,
            "exact_text_replacement_required": True,
        }
        proposal = self._invoke_agent(
            run_id=analysis.run_id,
            input_data=self.patch_agent.prepare_input(
                triage=analysis.triage,
                code_finding=analysis.code_finding,
                source_context=source_context,
                attempt_number=attempt_number,
                patch_constraints=constraints,
                retry_feedback=retry_feedback,
            ),
        )
        self._validate_proposal(
            analysis=analysis,
            proposal=proposal,
            attempt_number=attempt_number,
        )

        state = self._transition(
            run_id=analysis.run_id,
            current=state,
            requested=WorkflowState.PATCH_VALIDATING,
        )
        prepared = self.patch_service.prepare_patch(
            proposal=proposal,
            code_finding=analysis.code_finding,
            source_context=source_context,
        )
        return PatchGenerationResult(
            run_id=analysis.run_id,
            target_id=analysis.target_id,
            attempt_number=attempt_number,
            proposal=proposal,
            prepared_patch=prepared,
            final_state=state,
        )

    def _build_patch_context(self, analysis: BlueTeamAnalysisResult) -> SourceReadResult:
        finding = analysis.code_finding
        assert finding is not None
        minimum_line = min(item.start_line for item in finding.supporting_lines)
        snippets = [
            self.source_reader.read_file(
                run_id=analysis.run_id,
                target_id=analysis.target_id,
                relative_path=finding.file_path,
                start_line=1,
                max_lines=30,
            )
        ]
        finding_start = max(1, minimum_line - 12)
        if finding_start > 1:
            snippets.append(
                self.source_reader.read_file(
                    run_id=analysis.run_id,
                    target_id=analysis.target_id,
                    relative_path=finding.file_path,
                    start_line=finding_start,
                    max_lines=70,
                )
            )
        return SourceReadResult(
            run_id=analysis.run_id,
            target_id=analysis.target_id,
            route_names=(),
            snippets=tuple(snippets),
        )

    def _invoke_agent(
        self,
        *,
        run_id: str,
        input_data: Mapping[str, Any],
    ) -> PatchProposal:
        self._require_policy(
            run_id=run_id,
            operation="model_call_authorization",
            target=self.patch_agent.role.value,
            decision=self.policy_engine.validate_model_call_budget(self.limits),
        )
        self.limits.consume_model_calls()
        started = time.monotonic()
        try:
            raw_output = self.provider.generate_structured(
                role=self.patch_agent.role,
                input_data=input_data,
                response_model=self.patch_agent.output_model,
            )
            result = self.patch_agent.validate_output(raw_output)
        except Exception:
            self.audit_service.record(
                run_id=run_id,
                component="patch_generation_flow",
                actor_type="orchestrator",
                operation="model_call",
                target=self.patch_agent.role.value,
                policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
                execution_status=AuditExecutionStatus.FAILED,
                duration_ms=self._elapsed_ms(started),
                error_code="model-call-failed",
            )
            raise
        self.audit_service.record(
            run_id=run_id,
            component="patch_generation_flow",
            actor_type="orchestrator",
            operation="model_call",
            target=self.patch_agent.role.value,
            policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
            execution_status=AuditExecutionStatus.SUCCEEDED,
            duration_ms=self._elapsed_ms(started),
        )
        return result

    @staticmethod
    def _validate_analysis(analysis: BlueTeamAnalysisResult) -> None:
        if analysis.final_state != WorkflowState.CODE_ANALYSIS:
            raise PatchGenerationFlowError(
                "patch generation requires a Blue result ending in code_analysis"
            )
        if analysis.code_finding is None:
            raise PatchGenerationFlowError("patch generation requires a CodeFinding")
        if analysis.code_finding.run_id != analysis.run_id:
            raise PatchGenerationFlowError("CodeFinding run_id does not match analysis")
        if analysis.triage.run_id != analysis.run_id:
            raise PatchGenerationFlowError("TriageResult run_id does not match analysis")
        if not analysis.code_finding.supporting_lines:
            raise PatchGenerationFlowError("CodeFinding must cite supporting source lines")

    @staticmethod
    def _validate_proposal(
        *,
        analysis: BlueTeamAnalysisResult,
        proposal: PatchProposal,
        attempt_number: int,
    ) -> None:
        if proposal.run_id != analysis.run_id:
            raise PatchGenerationFlowError("PatchProposal run_id does not match analysis")
        if proposal.target_id != analysis.target_id:
            raise PatchGenerationFlowError("PatchProposal target_id does not match analysis")
        if proposal.attempt_number != attempt_number:
            raise PatchGenerationFlowError("PatchProposal attempt_number does not match request")

    def _transition(
        self,
        *,
        run_id: str,
        current: WorkflowState,
        requested: WorkflowState,
    ) -> WorkflowState:
        self._require_policy(
            run_id=run_id,
            operation="workflow_transition",
            target=f"{current.value}->{requested.value}",
            decision=self.policy_engine.validate_state_transition(
                current=current,
                requested=requested,
            ),
        )
        return requested

    def _require_policy(
        self,
        *,
        run_id: str,
        operation: str,
        target: str,
        decision: PolicyDecision,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="patch_generation_flow",
            actor_type="orchestrator",
            operation=operation,
            target=target,
            policy_decision=(
                AuditPolicyDecision.ALLOWED if decision.allowed else AuditPolicyDecision.BLOCKED
            ),
            policy_reason=decision.reason_code,
            execution_status=(
                AuditExecutionStatus.AUTHORIZED if decision.allowed else AuditExecutionStatus.BLOCKED
            ),
            error_code=None if decision.allowed else "policy-blocked",
        )
        if not decision.allowed:
            raise PatchGenerationPolicyBlocked(decision)

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return max(0, int((time.monotonic() - started) * 1000))
