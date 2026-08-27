"""Deterministic Milestone 14 patch-verification orchestration."""

from __future__ import annotations

import hashlib
import time

from orchestrator.policy_engine import PolicyEngine
from schemas.common import PatchDecision, PolicyReasonCode, WorkflowState
from schemas.git import PatchBranchResult
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from schemas.patches import PreparedPatch
from schemas.red_team import RedTeamRunResult
from schemas.verification import (
    PatchVerificationResult,
    VerificationPolicyConfig,
    VerificationStageResult,
)
from services.audit_service import AuditService
from services.environment_service import (
    EnvironmentService,
    EnvironmentServiceError,
    PatchedApplicationError,
)
from services.git_service import GitService, GitServiceBlocked, GitServiceError
from services.test_runner import TestRunner, TestRunnerError
from verification.decisions import decide_verification
from verification.regression import required_regression_tests
from verification.security import security_stage_result


class VerificationPipelineError(RuntimeError):
    """Base deterministic verification orchestration error."""


class VerificationPolicyBlocked(VerificationPipelineError):
    """Trusted policy/integrity prerequisites blocked patch execution."""


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


class PatchVerificationPipeline:
    """Verify one materialized patch branch without LLM execution authority."""

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        git_service: GitService,
        environment_service: EnvironmentService,
        test_runner: TestRunner,
        verification_policy: VerificationPolicyConfig,
        audit_service: AuditService,
    ) -> None:
        self.policy_engine = policy_engine
        self.git_service = git_service
        self.environment_service = environment_service
        self.test_runner = test_runner
        self.verification_policy = verification_policy
        self.audit_service = audit_service

    def run(
        self,
        *,
        branch_result: PatchBranchResult,
        prepared_patch: PreparedPatch,
        red_run: RedTeamRunResult,
    ) -> PatchVerificationResult:
        """Run the frozen verification order and always attempt safe cleanup/restoration."""
        run_id = branch_result.run_id
        state = branch_result.final_state
        stages: list[VerificationStageResult] = []
        verification = None
        accepted_commit_sha: str | None = None
        final_state: WorkflowState | None = None
        failure_reason: str | None = None
        baseline_restored = False
        environment_touched = False

        try:
            try:
                self._validate_identity(branch_result, prepared_patch, red_run)
            except VerificationPolicyBlocked:
                self._audit_blocked_operation(
                    run_id=run_id,
                    operation="verification_identity_validation",
                    target="identity",
                    error_code="verification-identity-blocked",
                )
                raise
            self._audit_simple(
                run_id=run_id,
                operation="verification_identity_validation",
                status=AuditExecutionStatus.SUCCEEDED,
                evidence_reference=branch_result.branch_name,
            )

            policy_started = time.monotonic()
            try:
                self._validate_patch_policy(prepared_patch)
            except VerificationPolicyBlocked as exc:
                self._audit_blocked_operation(
                    run_id=run_id,
                    operation="verification_patch_policy",
                    target="patch_policy",
                    error_code="verification-patch-policy-blocked",
                )
                raise
            stages.append(
                VerificationStageResult(
                    stage_id="patch_policy",
                    required=True,
                    passed=True,
                    duration_ms=_elapsed_ms(policy_started),
                    details="PreparedPatch hashes, counts and configured size policy revalidated.",
                )
            )
            self._audit_stage(run_id, stages[-1], operation="verification_patch_policy")

            diff_started = time.monotonic()
            try:
                self._validate_paths_and_registered_tests(prepared_patch, red_run)
                self.git_service.verify_materialized_patch(
                    prepared_patch=prepared_patch,
                    branch_result=branch_result,
                )
            except VerificationPolicyBlocked:
                self._audit_blocked_operation(
                    run_id=run_id,
                    operation="verification_git_integrity",
                    target="path_diff",
                    error_code="verification-path-diff-blocked",
                )
                raise
            stages.append(
                VerificationStageResult(
                    stage_id="path_diff",
                    required=True,
                    passed=True,
                    duration_ms=_elapsed_ms(diff_started),
                    details="Patch paths, branch identity, replacement hashes and staged Git diff are exact.",
                )
            )
            self._audit_stage(run_id, stages[-1], operation="verification_git_integrity")

            state = self._transition(run_id, state, WorkflowState.PATCH_VERIFYING)

            self.environment_service.verify_available()
            environment_touched = True
            self.environment_service.build()

            syntax_stage = self.test_runner.run_syntax_import(
                changed_paths=branch_result.changed_paths,
            )
            stages.append(syntax_stage)
            self._audit_stage(run_id, syntax_stage, operation="verification_syntax_import")
            if not syntax_stage.passed:
                verification = decide_verification(
                    run_id=run_id,
                    attempt_number=branch_result.attempt_number,
                    stages=tuple(stages),
                )
                state = self._transition(run_id, state, WorkflowState.REJECTED)
                final_state = state
                failure_reason = verification.rejection_reason
                self._audit_decision(run_id, verification.decision.value)
            else:
                startup_started = time.monotonic()
                try:
                    self.environment_service.start()
                    self.environment_service.wait_healthy()
                    self.environment_service.verify_isolation()
                except PatchedApplicationError as exc:
                    startup_stage = VerificationStageResult(
                        stage_id="application_startup",
                        required=True,
                        passed=False,
                        duration_ms=_elapsed_ms(startup_started),
                        details=str(exc)[:4000],
                    )
                    stages.append(startup_stage)
                    self._audit_stage(
                        run_id,
                        startup_stage,
                        operation="verification_application_startup",
                    )
                    verification = decide_verification(
                        run_id=run_id,
                        attempt_number=branch_result.attempt_number,
                        stages=tuple(stages),
                    )
                    state = self._transition(run_id, state, WorkflowState.REJECTED)
                    final_state = state
                    failure_reason = verification.rejection_reason
                    self._audit_decision(run_id, verification.decision.value)
                else:
                    startup_stage = VerificationStageResult(
                        stage_id="application_startup",
                        required=True,
                        passed=True,
                        duration_ms=_elapsed_ms(startup_started),
                        details="Patched application and controlled-executor are healthy; isolation probe passed.",
                    )
                    stages.append(startup_stage)
                    self._audit_stage(
                        run_id,
                        startup_stage,
                        operation="verification_application_startup",
                    )
                    self._run_behavioral_stages(
                        branch_result=branch_result,
                        red_run=red_run,
                        stages=stages,
                    )
                    verification = decide_verification(
                        run_id=run_id,
                        attempt_number=branch_result.attempt_number,
                        stages=tuple(stages),
                    )
                    requested = (
                        WorkflowState.ACCEPTED
                        if verification.decision == PatchDecision.ACCEPTED
                        else WorkflowState.REJECTED
                    )
                    state = self._transition(run_id, state, requested)
                    final_state = state
                    if verification.decision == PatchDecision.REJECTED:
                        failure_reason = verification.rejection_reason
                    self._audit_decision(run_id, verification.decision.value)
                    if verification.decision == PatchDecision.ACCEPTED:
                        accepted_commit_sha = self.git_service.commit_accepted_patch(
                            branch_result=branch_result,
                            decision=PatchDecision.ACCEPTED,
                        )

        except VerificationPolicyBlocked as exc:
            failure_reason = str(exc)[:4000]
            self._audit_blocked_operation(
                run_id=run_id,
                operation="verification_policy_blocked",
                target="pipeline",
                error_code="verification-policy-blocked",
            )
            final_state = self._safe_terminal_transition(
                run_id, state, WorkflowState.POLICY_BLOCKED
            )
        except GitServiceBlocked as exc:
            failure_reason = f"{exc.error_code}: {str(exc)}"[:4000]
            final_state = self._safe_terminal_transition(
                run_id, state, WorkflowState.POLICY_BLOCKED
            )
        except (EnvironmentServiceError, TestRunnerError, GitServiceError) as exc:
            error_code = getattr(exc, "error_code", "verification-failed")
            failure_reason = f"{error_code}: {str(exc)}"[:4000]
            self._audit_simple(
                run_id=run_id,
                operation="verification_infrastructure_failure",
                status=AuditExecutionStatus.FAILED,
                error_code=error_code,
            )
            final_state = self._safe_terminal_transition(run_id, state, WorkflowState.FAILED)
        except Exception as exc:  # trusted orchestration failure; do not misclassify as patch rejection
            failure_reason = f"verification-internal-error: {type(exc).__name__}: {str(exc)}"[:4000]
            final_state = self._safe_terminal_transition(run_id, state, WorkflowState.FAILED)
        finally:
            cleanup_errors: list[str] = []
            if environment_touched:
                try:
                    self.environment_service.cleanup()
                    self._audit_simple(
                        run_id=run_id,
                        operation="verification_environment_cleanup",
                        status=AuditExecutionStatus.SUCCEEDED,
                    )
                except Exception as exc:
                    cleanup_errors.append(f"environment cleanup failed: {str(exc)}")
                    self._audit_simple(
                        run_id=run_id,
                        operation="verification_environment_cleanup",
                        status=AuditExecutionStatus.FAILED,
                        error_code=getattr(exc, "error_code", "verification-cleanup-failed"),
                    )
            try:
                self.git_service.restore_baseline(
                    prepared_patch=prepared_patch,
                    branch_name=branch_result.branch_name,
                    base_commit=branch_result.base_commit,
                )
                baseline_restored = True
            except Exception as exc:
                cleanup_errors.append(f"baseline restoration failed: {str(exc)}")

            if cleanup_errors:
                final_state = self._safe_terminal_transition(
                    run_id, final_state or state, WorkflowState.FAILED
                )
                suffix = "; ".join(cleanup_errors)
                failure_reason = f"{failure_reason + '; ' if failure_reason else ''}{suffix}"[:4000]

        if final_state is None:
            final_state = WorkflowState.FAILED
            failure_reason = failure_reason or "verification ended without a deterministic final state"

        return PatchVerificationResult(
            run_id=branch_result.run_id,
            target_id=branch_result.target_id,
            attempt_number=branch_result.attempt_number,
            branch_name=branch_result.branch_name,
            base_commit=branch_result.base_commit,
            git_diff_sha256=branch_result.git_diff_sha256,
            verification=verification,
            accepted_commit_sha=accepted_commit_sha,
            baseline_restored=baseline_restored,
            final_state=final_state,
            failure_reason=failure_reason,
        )

    def _run_behavioral_stages(
        self,
        *,
        branch_result: PatchBranchResult,
        red_run: RedTeamRunResult,
        stages: list[VerificationStageResult],
    ) -> None:
        functional = self.test_runner.run_functional_checks()
        stages.append(functional)
        self._audit_stage(branch_result.run_id, functional, operation="verification_functional")

        relevant_test_id = self.verification_policy.security_test_by_vulnerability[
            red_run.attack_plan.vulnerability_class
        ]
        security_execution = self.test_runner.run_registered_security_test(
            stage_id="security",
            test_id=relevant_test_id,
            attempt_number=branch_result.attempt_number,
            run_id=branch_result.run_id,
        )
        security = security_stage_result(stage_id="security", execution=security_execution)
        stages.append(security)
        self._audit_stage(
            branch_result.run_id,
            security,
            operation="verification_security_test",
            evidence_reference=relevant_test_id,
        )

        replay_execution = self.test_runner.run_registered_security_test(
            stage_id="original_replay",
            test_id=red_run.execution.test_id,
            attempt_number=branch_result.attempt_number,
            run_id=branch_result.run_id,
        )
        replay = security_stage_result(stage_id="original_replay", execution=replay_execution)
        stages.append(replay)
        self._audit_stage(
            branch_result.run_id,
            replay,
            operation="verification_original_replay",
            evidence_reference=red_run.execution.test_id,
        )

        # Calling this helper makes the trusted allowlist dependency explicit; the TestRunner
        # itself also refuses caller-provided regression arguments.
        required_regression_tests(self.verification_policy)
        regression = self.test_runner.run_regression_suite()
        stages.append(regression)
        self._audit_stage(
            branch_result.run_id,
            regression,
            operation="verification_regression",
        )

    def _validate_identity(
        self,
        branch_result: PatchBranchResult,
        prepared_patch: PreparedPatch,
        red_run: RedTeamRunResult,
    ) -> None:
        if branch_result.final_state != WorkflowState.PATCH_APPLYING:
            raise VerificationPolicyBlocked("verification requires PatchBranchResult at patch_applying")
        if self.verification_policy.target_id != branch_result.target_id:
            raise VerificationPolicyBlocked("verification policy target does not match patch target")
        expected = (branch_result.run_id, branch_result.target_id, branch_result.attempt_number)
        if (prepared_patch.run_id, prepared_patch.target_id, prepared_patch.attempt_number) != expected:
            raise VerificationPolicyBlocked("PreparedPatch identity does not match PatchBranchResult")
        if red_run.run_id != branch_result.run_id or red_run.target_id != branch_result.target_id:
            raise VerificationPolicyBlocked("original Red run identity does not match patch attempt")
        if red_run.final_state != WorkflowState.BLUE_MONITORING:
            raise VerificationPolicyBlocked("original Red run did not reach confirmed Blue handoff")
        if (
            red_run.attack_plan.target_id != branch_result.target_id
            or red_run.execution.target_id != branch_result.target_id
            or red_run.execution.run_id != branch_result.run_id
        ):
            raise VerificationPolicyBlocked("original Red nested target/run identity is inconsistent")
        if red_run.verification is None or not red_run.verification.confirmed:
            raise VerificationPolicyBlocked("patch verification requires a confirmed original Red attack")
        if red_run.verification.target_id != branch_result.target_id:
            raise VerificationPolicyBlocked("original Red verification target is inconsistent")
        ids = {
            red_run.attack_plan.test_id,
            red_run.execution.test_id,
            red_run.verification.test_id,
        }
        if len(ids) != 1:
            raise VerificationPolicyBlocked("original Red plan/execution/verification test IDs differ")
        if not red_run.execution.completed or red_run.execution.timed_out:
            raise VerificationPolicyBlocked("original Red execution did not complete successfully")
        if not red_run.execution.evidence:
            raise VerificationPolicyBlocked("original Red execution contains no exploit evidence")
        execution_evidence_ids = {item.evidence_id for item in red_run.execution.evidence}
        if not red_run.verification.evidence_ids or not set(red_run.verification.evidence_ids).issubset(
            execution_evidence_ids
        ):
            raise VerificationPolicyBlocked("original Red verification cites invalid exploit evidence")

    def _validate_patch_policy(self, prepared_patch: PreparedPatch) -> None:
        if hashlib.sha256(prepared_patch.unified_diff.encode("utf-8")).hexdigest() != prepared_patch.diff_sha256:
            raise VerificationPolicyBlocked("PreparedPatch unified diff hash drifted")
        if len(prepared_patch.unified_diff.encode("utf-8")) != prepared_patch.total_diff_bytes:
            raise VerificationPolicyBlocked("PreparedPatch diff byte count drifted")
        inserted = sum(
            1 for line in prepared_patch.unified_diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        deleted = sum(
            1 for line in prepared_patch.unified_diff.splitlines()
            if line.startswith("-") and not line.startswith("---")
        )
        if inserted != prepared_patch.inserted_lines or deleted != prepared_patch.deleted_lines:
            raise VerificationPolicyBlocked("PreparedPatch diff line counts drifted")
        if prepared_patch.files_changed != len(prepared_patch.files):
            raise VerificationPolicyBlocked("PreparedPatch file count drifted")
        for item in prepared_patch.files:
            if hashlib.sha256(item.replacement_content.encode("utf-8")).hexdigest() != item.replacement_sha256:
                raise VerificationPolicyBlocked(f"replacement hash drifted for {item.file_path!r}")
        decision = self.policy_engine.validate_patch_size(
            target_id=prepared_patch.target_id,
            files_changed=prepared_patch.files_changed,
            inserted_lines=prepared_patch.inserted_lines,
            deleted_lines=prepared_patch.deleted_lines,
            total_diff_bytes=prepared_patch.total_diff_bytes,
        )
        if not decision.allowed:
            raise VerificationPolicyBlocked(decision.message)

    def _validate_paths_and_registered_tests(
        self,
        prepared_patch: PreparedPatch,
        red_run: RedTeamRunResult,
    ) -> None:
        paths = {item.file_path for item in prepared_patch.files}
        for item in prepared_patch.files:
            decision = self.policy_engine.validate_patch_path(
                target_id=prepared_patch.target_id,
                relative_path=item.file_path,
            )
            if not decision.allowed:
                raise VerificationPolicyBlocked(decision.message)
        if prepared_patch.generated_test_path is not None:
            generated = next(
                (item for item in prepared_patch.files if item.file_path == prepared_patch.generated_test_path),
                None,
            )
            if generated is None or not generated.is_new_file:
                raise VerificationPolicyBlocked("generated test path is not the recorded new prepared file")
            if "/tests/generated/" not in f"/{prepared_patch.generated_test_path}":
                raise VerificationPolicyBlocked("generated test path escaped trusted generated-test root")
        if len(paths) != len(prepared_patch.files):
            raise VerificationPolicyBlocked("PreparedPatch paths must be unique")

        relevant = self.verification_policy.security_test_by_vulnerability[
            red_run.attack_plan.vulnerability_class
        ]
        red_metadata = self.policy_engine.registry.get_security_test(red_run.execution.test_id)
        relevant_metadata = self.policy_engine.registry.get_security_test(relevant)
        if red_metadata.vulnerability_class != red_run.attack_plan.vulnerability_class:
            raise VerificationPolicyBlocked("original Red test vulnerability class mismatches its plan")
        if relevant_metadata.vulnerability_class != red_run.attack_plan.vulnerability_class:
            raise VerificationPolicyBlocked("trusted relevant security test mapping mismatches vulnerability class")
        relevant_decision = self.policy_engine.validate_security_test(
            target_id=prepared_patch.target_id,
            test_id=relevant,
        )
        if not relevant_decision.allowed:
            raise VerificationPolicyBlocked(relevant_decision.message)
        replay_decision = self.policy_engine.validate_security_test(
            target_id=prepared_patch.target_id,
            test_id=red_run.execution.test_id,
            endpoint_id=red_run.attack_plan.endpoint_id,
        )
        if not replay_decision.allowed:
            raise VerificationPolicyBlocked(replay_decision.message)

    def _transition(self, run_id: str, current: WorkflowState, requested: WorkflowState) -> WorkflowState:
        started = time.monotonic()
        decision = self.policy_engine.validate_state_transition(current=current, requested=requested)
        self.audit_service.record(
            run_id=run_id,
            component="patch_verification_pipeline",
            actor_type="orchestrator",
            operation="workflow_transition",
            target=f"{current.value}->{requested.value}",
            policy_decision=(AuditPolicyDecision.ALLOWED if decision.allowed else AuditPolicyDecision.BLOCKED),
            policy_reason=decision.reason_code,
            execution_status=(AuditExecutionStatus.AUTHORIZED if decision.allowed else AuditExecutionStatus.BLOCKED),
            duration_ms=_elapsed_ms(started),
            error_code=None if decision.allowed else "policy-blocked",
        )
        if not decision.allowed:
            raise VerificationPolicyBlocked(decision.message)
        return requested

    def _safe_terminal_transition(
        self,
        run_id: str,
        current: WorkflowState,
        requested: WorkflowState,
    ) -> WorkflowState:
        try:
            return self._transition(run_id, current, requested)
        except Exception:
            return requested

    def _audit_stage(
        self,
        run_id: str,
        stage: VerificationStageResult,
        *,
        operation: str,
        evidence_reference: str | None = None,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="patch_verification_pipeline",
            actor_type="deterministic_verification",
            operation=operation,
            target=stage.stage_id,
            policy_decision=AuditPolicyDecision.ALLOWED,
            policy_reason=PolicyReasonCode.ALLOWED,
            execution_status=(AuditExecutionStatus.SUCCEEDED if stage.passed else AuditExecutionStatus.FAILED),
            duration_ms=stage.duration_ms,
            evidence_reference=evidence_reference,
            error_code=None if stage.passed else f"verification-{stage.stage_id}-failed",
        )

    def _audit_blocked_operation(
        self,
        *,
        run_id: str,
        operation: str,
        target: str,
        error_code: str,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="patch_verification_pipeline",
            actor_type="deterministic_verification",
            operation=operation,
            target=target,
            policy_decision=AuditPolicyDecision.BLOCKED,
            policy_reason=PolicyReasonCode.PROHIBITED_OPERATION,
            execution_status=AuditExecutionStatus.BLOCKED,
            duration_ms=0,
            error_code=error_code,
        )

    def _audit_decision(self, run_id: str, decision: str) -> None:
        self._audit_simple(
            run_id=run_id,
            operation="verification_decision",
            status=AuditExecutionStatus.SUCCEEDED,
            evidence_reference=decision,
        )

    def _audit_simple(
        self,
        *,
        run_id: str,
        operation: str,
        status: AuditExecutionStatus,
        evidence_reference: str | None = None,
        error_code: str | None = None,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="patch_verification_pipeline",
            actor_type="deterministic_verification",
            operation=operation,
            target=self.verification_policy.target_id,
            policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
            execution_status=status,
            duration_ms=0,
            evidence_reference=evidence_reference,
            error_code=error_code,
        )
