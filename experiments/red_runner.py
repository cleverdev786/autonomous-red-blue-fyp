"""Experiment-side Red execution with mandatory model-call research recording."""

from __future__ import annotations

from llm.interface import StructuredGenerationProvider
from llm.research_provider import ResearchRecordingProvider
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from orchestrator.red_team_flow import RedTeamFlow
from schemas.common import AgentRole, ResearchQuestion, RunStatus, RunType
from schemas.red_team import RedTeamRunResult
from services.audit_service import AuditService
from services.controlled_executor import ControlledExecutor
from services.target_registry import TargetRegistry
from storage.repositories import ExperimentExecutionReadRepository, ExperimentWriteRepository


class ExperimentRedRunnerError(RuntimeError):
    """Raised when experiment Red execution violates stored run controls."""


class ExperimentRedTeamRunner:
    """Run the existing Red flow through the common research provider recorder."""

    def __init__(
        self,
        *,
        target_registry: TargetRegistry,
        policy_engine: PolicyEngine,
        executor: ControlledExecutor,
        provider: StructuredGenerationProvider,
        audit_service: AuditService,
        execution_repository: ExperimentExecutionReadRepository,
        write_repository: ExperimentWriteRepository,
    ) -> None:
        self.target_registry = target_registry
        self.policy_engine = policy_engine
        self.executor = executor
        self.provider = provider
        self.audit_service = audit_service
        self.execution_repository = execution_repository
        self.write_repository = write_repository

    def run(
        self,
        *,
        run_id: str,
        target_id: str,
        limits: RunLimitTracker,
        attempt_number: int = 1,
    ) -> RedTeamRunResult:
        stored = self.execution_repository.run_context(run_id)
        config = stored.configuration
        if config.research_question not in {ResearchQuestion.RQ1, ResearchQuestion.RQ3}:
            raise ExperimentRedRunnerError("Red experiment runner is only valid for RQ1/RQ3")
        if stored.status != RunStatus.RUNNING.value:
            raise ExperimentRedRunnerError("experiment Red run must be in running state")
        if stored.scenario_id not in config.scenario_ids or stored.dataset_id is not None:
            raise ExperimentRedRunnerError("stored Red run is not scoped to its configured scenario")
        if limits.limits != config.limits:
            raise ExperimentRedRunnerError("shared Red limit tracker differs from stored configuration")
        if self.executor.limits is not limits:
            raise ExperimentRedRunnerError("ControlledExecutor must share the exact experiment limit tracker")
        if attempt_number < 1:
            raise ExperimentRedRunnerError("Red attempt_number must be >= 1")

        def red_linkage(role: AgentRole, _input) -> dict[str, int | None]:
            return {
                "classification_observation_id": None,
                "patch_attempt_number": None,
                "red_attempt_number": attempt_number,
            }

        recorder = ResearchRecordingProvider(
            delegate=self.provider,
            run_id=run_id,
            model_configuration=config.model,
            first_sequence_number=self.execution_repository.next_agent_sequence(run_id),
            write_repository=self.write_repository,
            linkage_resolver=red_linkage,
            require_verified_binding=(config.run_type == RunType.FINAL_EVALUATION),
        )
        flow = RedTeamFlow(
            target_registry=self.target_registry,
            policy_engine=self.policy_engine,
            limits=limits,
            executor=self.executor,
            provider=recorder,
            audit_service=self.audit_service,
        )
        return flow.run(
            run_id=run_id,
            target_id=target_id,
            attempt_number=attempt_number,
        )
