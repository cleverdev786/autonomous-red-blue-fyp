"""Trusted, audited termination of a remediation attempt before patch creation.

No provider, compiler, Git, Docker, network, or patch-application authority.
"""
from __future__ import annotations

from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import BlueTeamAnalysisResult
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from schemas.remediation import RemediationAttemptResult
from services.audit_service import AuditService
from storage.repositories import ExperimentWriteRepository


class RemediationTerminationBlocked(RuntimeError):
    """No-patch termination was denied by deterministic policy."""


class RemediationOutcomeFlow:
    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        audit_service: AuditService,
        write_repository: ExperimentWriteRepository,
    ) -> None:
        self.policy_engine = policy_engine
        self.audit_service = audit_service
        self.write_repository = write_repository

    def finish_without_patch(
        self,
        *,
        analysis: BlueTeamAnalysisResult,
        result: RemediationAttemptResult,
    ) -> int:
        decision = self.policy_engine.validate_no_patch_termination(
            analysis=analysis, result=result,
        )
        if not decision.allowed:
            self.audit_service.record(
                run_id=result.run_id,
                component="remediation_outcome_flow",
                actor_type="orchestrator",
                operation="no_patch_termination",
                target=result.target_id,
                policy_decision=AuditPolicyDecision.BLOCKED,
                policy_reason=decision.reason_code,
                execution_status=AuditExecutionStatus.BLOCKED,
                error_code="no-patch-denied",
            )
            raise RemediationTerminationBlocked(decision.message)
        if result.policy_event_id is not None:
            blocked = [
                event for event in self.audit_service.read_run(run_id=result.run_id)
                if event.event_id == result.policy_event_id
                and event.policy_decision == AuditPolicyDecision.BLOCKED
                and event.execution_status == AuditExecutionStatus.BLOCKED
                and event.policy_reason is not None
                and event.policy_reason.value == result.reason_code
                and event.operation != "no_patch_termination"
            ]
            if len(blocked) != 1:
                self.audit_service.record(
                    run_id=result.run_id,
                    component="remediation_outcome_flow",
                    actor_type="orchestrator",
                    operation="no_patch_termination",
                    target=result.target_id,
                    policy_decision=AuditPolicyDecision.BLOCKED,
                    execution_status=AuditExecutionStatus.BLOCKED,
                    error_code="missing-blocked-evidence",
                )
                raise RemediationTerminationBlocked("policy-blocked outcome lacks blocked audit evidence")
        # Authorize visibly first. A failed storage commit records FAILED rather
        # than misreporting an uncommitted termination as SUCCEEDED.
        self.audit_service.record(
            run_id=result.run_id,
            component="remediation_outcome_flow",
            actor_type="orchestrator",
            operation="no_patch_termination",
            target=result.target_id,
            policy_decision=AuditPolicyDecision.ALLOWED,
            policy_reason=decision.reason_code,
            execution_status=AuditExecutionStatus.AUTHORIZED,
        )
        try:
            artifact_id = self.write_repository.finalize_remediation_without_patch(
                result=result, analysis=analysis, policy_engine=self.policy_engine,
            )
        except Exception:
            self.audit_service.record(
                run_id=result.run_id,
                component="remediation_outcome_flow",
                actor_type="orchestrator",
                operation="no_patch_termination",
                target=result.target_id,
                policy_decision=AuditPolicyDecision.ALLOWED,
                policy_reason=decision.reason_code,
                execution_status=AuditExecutionStatus.FAILED,
                error_code="no-patch-storage-failed",
            )
            raise
        self.audit_service.record(
            run_id=result.run_id,
            component="remediation_outcome_flow",
            actor_type="orchestrator",
            operation="no_patch_termination",
            target=result.target_id,
            policy_decision=AuditPolicyDecision.ALLOWED,
            policy_reason=decision.reason_code,
            execution_status=AuditExecutionStatus.SUCCEEDED,
            evidence_reference=f"result_artifact:{artifact_id}",
        )
        return artifact_id
