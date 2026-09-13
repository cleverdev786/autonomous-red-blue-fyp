"""Focused RQ3 structured-feedback patch-retry controller."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import func, select

from agents.blue.patch_generation import PatchGenerationAgent
from agents.blue.single_agent import SingleGeneralBlueAgent
from llm.interface import StructuredGenerationProvider
from llm.research_provider import ResearchRecordingProvider
from orchestrator.limits import LimitExceededError, RunLimitTracker
from orchestrator.patch_branch_flow import PatchBranchFlow, PatchBranchPolicyBlocked
from orchestrator.patch_generation_flow import (
    PatchGenerationFlow,
    PatchGenerationPolicyBlocked,
)
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import BlueTeamAnalysisResult
from schemas.common import AgentRole, PatchDecision, ResearchQuestion, RunStatus, RunType, WorkflowState
from schemas.experiments import (
    BlueTeamMode,
    ExperimentConfiguration,
    RetryFeedbackMode,
)
from schemas.git import PatchBranchResult
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from schemas.patches import PatchGenerationResult, PatchProposal, PatchRetryFeedback
from schemas.red_team import RedTeamRunResult
from schemas.verification import PatchVerificationResult
from services.audit_service import AuditService
from services.git_service import GitServiceBlocked
from services.patch_retry_feedback import PatchRetryFeedbackBuilder
from services.patch_service import PatchServiceBlocked
from services.source_reader import SourceReadBlocked
from services.target_registry import TargetRegistry
from storage.models import (
    AgentCallRow,
    ExperimentConfigurationRow,
    ExperimentRunRow,
    PatchAttemptRow,
)
from storage.repositories import ExperimentWriteRepository, ResearchReadRepository
from verification.pipeline import PatchVerificationPipeline


class RQ3RunnerError(RuntimeError):
    """Raised when stored RQ3 evidence/configuration cannot safely execute retries."""


@dataclass(frozen=True, slots=True)
class RQ3PatchAttemptExecution:
    """Observed outcome of one RQ3 patch attempt, including pre-verification failures."""

    attempt_number: int
    final_state: WorkflowState
    retry_feedback: PatchRetryFeedback | None = None
    generation: PatchGenerationResult | None = None
    branch: PatchBranchResult | None = None
    verification: PatchVerificationResult | None = None
    failure_reason: str | None = None


@dataclass(frozen=True, slots=True)
class RQ3ExecutionResult:
    """One RQ3 treatment execution over the original Blue/Red evidence."""

    run_id: str
    retry_feedback_mode: RetryFeedbackMode
    attempts: tuple[RQ3PatchAttemptExecution, ...]


def validate_rq3_configuration_pair(
    no_feedback: ExperimentConfiguration,
    structured: ExperimentConfiguration,
) -> None:
    """Require an RQ3 pair to differ only in config ID and retry-feedback mode."""
    if (
        no_feedback.research_question != ResearchQuestion.RQ3
        or structured.research_question != ResearchQuestion.RQ3
    ):
        raise RQ3RunnerError("both paired configurations must be RQ3")
    if no_feedback.retry_feedback_mode != RetryFeedbackMode.NONE:
        raise RQ3RunnerError("first paired configuration must use no retry feedback")
    if structured.retry_feedback_mode != RetryFeedbackMode.STRUCTURED:
        raise RQ3RunnerError("second paired configuration must use structured retry feedback")

    ignored = {"config_id", "retry_feedback_mode"}
    left = no_feedback.model_dump(mode="json", exclude=ignored)
    right = structured.model_dump(mode="json", exclude=ignored)
    if left != right:
        differing = tuple(sorted(key for key in left if left.get(key) != right.get(key)))
        raise RQ3RunnerError(
            "paired RQ3 configurations differ outside retry feedback mode: "
            + ", ".join(differing)
        )


class RQ3PatchRetryRunner:
    """Execute only the RQ3 patch/retry treatment from fixed prior Blue/Red evidence."""

    def __init__(
        self,
        *,
        target_registry: TargetRegistry,
        policy_engine: PolicyEngine,
        provider: StructuredGenerationProvider,
        audit_service: AuditService,
        project_root: Path,
        patch_branch_flow: PatchBranchFlow,
        verification_pipeline: PatchVerificationPipeline,
        read_repository: ResearchReadRepository,
        write_repository: ExperimentWriteRepository,
    ) -> None:
        self.target_registry = target_registry
        self.policy_engine = policy_engine
        self.provider = provider
        self.audit_service = audit_service
        self.project_root = project_root
        self.patch_branch_flow = patch_branch_flow
        self.verification_pipeline = verification_pipeline
        self.read_repository = read_repository
        self.write_repository = write_repository
        self.feedback_builder = PatchRetryFeedbackBuilder(target_registry=target_registry)

    def run(
        self,
        *,
        run_id: str,
        analysis: BlueTeamAnalysisResult,
        red_run: RedTeamRunResult,
        limits: RunLimitTracker,
    ) -> RQ3ExecutionResult:
        stored_run, config = self._stored_context(run_id)
        self._validate_inputs(
            run_id=run_id,
            stored_run=stored_run,
            config=config,
            analysis=analysis,
            red_run=red_run,
            limits=limits,
        )
        self._require_fresh_patch_attempt_scope(run_id)
        if config.run_type == RunType.FINAL_EVALUATION:
            self._require_recorded_upstream_calls(
                run_id=run_id,
                config=config,
                red_attempt_number=red_run.attempt_number,
            )

        recording_provider = ResearchRecordingProvider(
            delegate=self.provider,
            run_id=run_id,
            model_configuration=config.model,
            write_repository=self.write_repository,
            first_sequence_number=self._next_agent_sequence(run_id),
            require_verified_binding=(config.run_type == RunType.FINAL_EVALUATION),
        )
        patch_flow = self._patch_flow(
            config=config,
            limits=limits,
            provider=recording_provider,
        )

        observed: list[RQ3PatchAttemptExecution] = []
        previous_generation: PatchGenerationResult | None = None
        previous_verification: PatchVerificationResult | None = None
        attempt_number = 1

        while True:
            if not self._precheck_patch_attempt_budget(
                run_id=run_id,
                attempt_number=attempt_number,
                limits=limits,
            ):
                if attempt_number == 1:
                    raise RQ3RunnerError("shared budget does not authorize the first patch attempt")
                break

            self.write_repository.begin_patch_attempt(
                run_id=run_id,
                attempt_number=attempt_number,
            )
            feedback: PatchRetryFeedback | None = None
            generation: PatchGenerationResult | None = None
            branch: PatchBranchResult | None = None
            try:
                if (
                    attempt_number > 1
                    and config.retry_feedback_mode == RetryFeedbackMode.STRUCTURED
                ):
                    if previous_generation is None or previous_verification is None:
                        raise RQ3RunnerError("structured retry lacks previous-attempt evidence")
                    feedback = self.feedback_builder.build(
                        generation=previous_generation,
                        verification=previous_verification,
                    )
                    self.write_repository.record_patch_retry_feedback(
                        run_id=run_id,
                        source_attempt_number=attempt_number - 1,
                        receiving_attempt_number=attempt_number,
                        feedback=feedback,
                    )

                generation = patch_flow.run(
                    analysis=analysis,
                    attempt_number=attempt_number,
                    retry_feedback=feedback,
                    entry_state=(
                        WorkflowState.CODE_ANALYSIS
                        if attempt_number == 1
                        else WorkflowState.REJECTED
                    ),
                )
                self.write_repository.record_patch_generation_result(generation)

                branch = self.patch_branch_flow.run(
                    generation_result=generation,
                    expected_base_commit=stored_run.baseline_commit,
                )
                self.write_repository.record_patch_branch_result(branch)

                verification = self.verification_pipeline.run(
                    branch_result=branch,
                    prepared_patch=generation.prepared_patch,
                    red_run=red_run,
                )
                self.write_repository.record_patch_verification_result(verification)
            except Exception as exc:
                final_state = (
                    WorkflowState.POLICY_BLOCKED
                    if self._is_policy_block(exc)
                    else WorkflowState.FAILED
                )
                failure_reason = self._failure_summary(exc)
                self.write_repository.record_patch_attempt_terminal_failure(
                    run_id=run_id,
                    attempt_number=attempt_number,
                    final_state=final_state,
                    failure_reason=failure_reason,
                )
                observed.append(
                    RQ3PatchAttemptExecution(
                        attempt_number=attempt_number,
                        final_state=final_state,
                        retry_feedback=feedback,
                        generation=generation,
                        branch=branch,
                        failure_reason=failure_reason,
                    )
                )
                break

            observed.append(
                RQ3PatchAttemptExecution(
                    attempt_number=attempt_number,
                    final_state=verification.final_state,
                    retry_feedback=feedback,
                    generation=generation,
                    branch=branch,
                    verification=verification,
                    failure_reason=verification.failure_reason,
                )
            )
            if verification.final_state != WorkflowState.REJECTED:
                break
            if (
                verification.verification is None
                or verification.verification.decision != PatchDecision.REJECTED
                or not verification.baseline_restored
            ):
                raise RQ3RunnerError(
                    "only a verified rejected attempt with restored baseline may retry"
                )

            previous_generation = generation
            previous_verification = verification
            attempt_number += 1

        return RQ3ExecutionResult(
            run_id=run_id,
            retry_feedback_mode=config.retry_feedback_mode,
            attempts=tuple(observed),
        )

    def _patch_flow(
        self,
        *,
        config: ExperimentConfiguration,
        limits: RunLimitTracker,
        provider: StructuredGenerationProvider,
    ) -> PatchGenerationFlow:
        flow = PatchGenerationFlow(
            target_registry=self.target_registry,
            policy_engine=self.policy_engine,
            limits=limits,
            provider=provider,
            audit_service=self.audit_service,
            project_root=self.project_root,
        )
        if config.blue_team_mode == BlueTeamMode.SINGLE_AGENT:
            general_agent = SingleGeneralBlueAgent()
            flow.patch_agent = general_agent.stage(
                output_model=PatchProposal,
                input_builder=PatchGenerationAgent.prepare_input,
            )
        return flow

    def _stored_context(
        self,
        run_id: str,
    ) -> tuple[ExperimentRunRow, ExperimentConfiguration]:
        with self.read_repository.session() as session:
            run = session.get(ExperimentRunRow, run_id)
            if run is None:
                raise RQ3RunnerError(f"experiment run {run_id!r} does not exist")
            config_row = session.get(ExperimentConfigurationRow, run.config_id)
            if config_row is None:
                raise RQ3RunnerError("stored experiment configuration does not exist")
            config = ExperimentConfiguration.model_validate_json(config_row.configuration_json)
            session.expunge(run)
            return run, config

    def _require_fresh_patch_attempt_scope(self, run_id: str) -> None:
        with self.read_repository.session() as session:
            count = session.scalar(
                select(func.count(PatchAttemptRow.id)).where(PatchAttemptRow.run_id == run_id)
            )
        if count:
            raise RQ3RunnerError(
                "RQ3 patch/retry controller requires no pre-existing patch attempts"
            )

    def _next_agent_sequence(self, run_id: str) -> int:
        with self.read_repository.session() as session:
            maximum = session.scalar(
                select(func.max(AgentCallRow.sequence_number)).where(AgentCallRow.run_id == run_id)
            )
        return int(maximum or 0) + 1


    def _require_recorded_upstream_calls(
        self,
        *,
        run_id: str,
        config: ExperimentConfiguration,
        red_attempt_number: int,
    ) -> None:
        with self.read_repository.session() as session:
            rows = tuple(
                session.scalars(
                    select(AgentCallRow)
                    .where(AgentCallRow.run_id == run_id)
                    .order_by(AgentCallRow.sequence_number.asc())
                )
            )
        red_rows = tuple(row for row in rows if row.red_attempt_number == red_attempt_number)
        expected_red = {
            AgentRole.RED_RECONNAISSANCE.value,
            AgentRole.RED_ATTACK_PLANNER.value,
            AgentRole.RED_ATTACK_VERIFIER.value,
        }
        if len(red_rows) != 3 or {row.agent_role for row in red_rows} != expected_red:
            raise RQ3RunnerError("final RQ3 requires exactly recorded Red model-call evidence")
        if any(row.result_status != RunStatus.COMPLETED.value for row in red_rows):
            raise RQ3RunnerError("final RQ3 Red model-call evidence must be completed")

        upstream = tuple(row for row in rows if row.red_attempt_number is None and row.patch_attempt_number is None)
        if config.blue_team_mode == BlueTeamMode.SINGLE_AGENT:
            if len(upstream) != 3 or any(
                row.agent_role != AgentRole.BLUE_SINGLE_AGENT.value for row in upstream
            ):
                raise RQ3RunnerError("final single-agent RQ3 requires three recorded upstream Blue calls")
        else:
            expected_blue = {
                AgentRole.BLUE_MONITORING.value,
                AgentRole.BLUE_CODE_ANALYSIS.value,
            }
            if config.classification_mode.value != "rule_only":
                expected_blue.add(AgentRole.BLUE_TRIAGE.value)
            if len(upstream) != len(expected_blue) or {row.agent_role for row in upstream} != expected_blue:
                raise RQ3RunnerError("final RQ3 requires complete recorded upstream Blue model-call evidence")
        if any(row.result_status != RunStatus.COMPLETED.value for row in upstream):
            raise RQ3RunnerError("final RQ3 upstream Blue model-call evidence must be completed")

    def _precheck_patch_attempt_budget(
        self,
        *,
        run_id: str,
        attempt_number: int,
        limits: RunLimitTracker,
    ) -> bool:
        decision = self.policy_engine.validate_patch_attempt_budget(limits)
        self.audit_service.record(
            run_id=run_id,
            component="rq3_runner",
            actor_type="orchestrator",
            operation="rq3_patch_attempt_budget_precheck",
            target=f"attempt-{attempt_number}",
            policy_decision=(
                AuditPolicyDecision.ALLOWED if decision.allowed else AuditPolicyDecision.BLOCKED
            ),
            policy_reason=decision.reason_code,
            execution_status=(
                AuditExecutionStatus.AUTHORIZED
                if decision.allowed
                else AuditExecutionStatus.BLOCKED
            ),
            error_code=None if decision.allowed else "policy-blocked",
        )
        return decision.allowed

    def _validate_inputs(
        self,
        *,
        run_id: str,
        stored_run: ExperimentRunRow,
        config: ExperimentConfiguration,
        analysis: BlueTeamAnalysisResult,
        red_run: RedTeamRunResult,
        limits: RunLimitTracker,
    ) -> None:
        if config.research_question != ResearchQuestion.RQ3:
            raise RQ3RunnerError("RQ3PatchRetryRunner requires a stored RQ3 configuration")
        if stored_run.status != RunStatus.RUNNING.value:
            raise RQ3RunnerError("RQ3 experiment run must be in running state")
        if stored_run.scenario_id not in config.scenario_ids:
            raise RQ3RunnerError("stored run scenario is not part of the RQ3 configuration")
        if limits.limits != config.limits:
            raise RQ3RunnerError("shared RunLimitTracker limits differ from stored configuration")
        if limits.snapshot().patch_attempts != 0:
            raise RQ3RunnerError(
                "RQ3 patch/retry controller requires an unconsumed patch-attempt budget"
            )
        if analysis.run_id != run_id or red_run.run_id != run_id:
            raise RQ3RunnerError("RQ3 input evidence must match the stored run_id")
        if analysis.target_id != red_run.target_id:
            raise RQ3RunnerError("RQ3 Blue and Red evidence must reference the same target")
        if analysis.classification_mode != config.classification_mode:
            raise RQ3RunnerError(
                "Blue analysis classification mode differs from stored configuration"
            )
        if analysis.final_state != WorkflowState.CODE_ANALYSIS or analysis.code_finding is None:
            raise RQ3RunnerError("RQ3 requires an actionable Blue code-analysis result")
        if red_run.final_state != WorkflowState.BLUE_MONITORING:
            raise RQ3RunnerError("RQ3 requires a confirmed Red-to-Blue handoff")
        if red_run.verification is None or not red_run.verification.confirmed:
            raise RQ3RunnerError("RQ3 requires confirmed original Red evidence")
        self.target_registry.get_target(analysis.target_id)
        registered = self.target_registry.get_security_test(red_run.execution.test_id)
        if registered.target_id != analysis.target_id:
            raise RQ3RunnerError("original Red test is not registered for the analyzed target")

    @staticmethod
    def _is_policy_block(exc: Exception) -> bool:
        return isinstance(
            exc,
            (
                PatchGenerationPolicyBlocked,
                PatchBranchPolicyBlocked,
                PatchServiceBlocked,
                SourceReadBlocked,
                GitServiceBlocked,
                LimitExceededError,
            ),
        )

    @staticmethod
    def _failure_summary(exc: Exception) -> str:
        return f"{type(exc).__name__}: {str(exc)}"[:4000]
