"""Experiment-side Blue analysis with mandatory model-call research recording."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agents.blue import CodeAnalysisAgent, MonitoringAgent, TriageAgent
from agents.blue.single_agent import SingleGeneralBlueAgent
from llm.interface import StructuredGenerationProvider
from llm.research_provider import ResearchRecordingProvider
from orchestrator.blue_team_flow import BlueTeamFlow
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import BlueTeamAnalysisResult, MonitoringResult
from schemas.common import ResearchQuestion, RunStatus, RunType
from schemas.experiments import BlueTeamMode, ClassificationMode
from schemas.logging import LogReadResult
from services.audit_service import AuditService
from services.target_registry import TargetRegistry
from storage.repositories import ExperimentExecutionReadRepository, ExperimentWriteRepository


class ExperimentBlueRunnerError(RuntimeError):
    """Raised when upstream RQ3 Blue analysis violates stored experiment controls."""


class _SingleAgentBlueTeamFlow(BlueTeamFlow):
    def __init__(self, *, general_agent: SingleGeneralBlueAgent, **kwargs) -> None:
        super().__init__(**kwargs)
        self.monitoring_agent = general_agent.stage(
            output_model=self.monitoring_agent.output_model,
            input_builder=MonitoringAgent.prepare_input,
        )
        self.triage_agent = general_agent.stage(
            output_model=self.triage_agent.output_model,
            input_builder=TriageAgent.prepare_input,
        )
        self.code_analysis_agent = general_agent.stage(
            output_model=self.code_analysis_agent.output_model,
            input_builder=CodeAnalysisAgent.prepare_input,
        )


@dataclass(frozen=True, slots=True)
class ExperimentBlueAnalysisExecution:
    monitoring: MonitoringResult
    analysis: BlueTeamAnalysisResult


class ExperimentBlueAnalysisRunner:
    """Produce RQ3 upstream Blue evidence using the common recorder and shared limits."""

    def __init__(
        self,
        *,
        target_registry: TargetRegistry,
        policy_engine: PolicyEngine,
        provider: StructuredGenerationProvider,
        audit_service: AuditService,
        project_root: Path,
        execution_repository: ExperimentExecutionReadRepository,
        write_repository: ExperimentWriteRepository,
    ) -> None:
        self.target_registry = target_registry
        self.policy_engine = policy_engine
        self.provider = provider
        self.audit_service = audit_service
        self.project_root = project_root
        self.execution_repository = execution_repository
        self.write_repository = write_repository

    def run(
        self,
        *,
        run_id: str,
        logs: LogReadResult,
        limits: RunLimitTracker,
    ) -> ExperimentBlueAnalysisExecution:
        stored = self.execution_repository.run_context(run_id)
        config = stored.configuration
        if config.research_question != ResearchQuestion.RQ3:
            raise ExperimentBlueRunnerError("upstream Blue analysis runner is reserved for RQ3")
        if stored.status != RunStatus.RUNNING.value:
            raise ExperimentBlueRunnerError("RQ3 Blue analysis run must be in running state")
        if stored.scenario_id not in config.scenario_ids or stored.dataset_id is not None:
            raise ExperimentBlueRunnerError("stored RQ3 Blue run is not scoped to its configured scenario")
        if logs.run_id != run_id:
            raise ExperimentBlueRunnerError("Blue logs must match the experiment run_id")
        if limits.limits != config.limits:
            raise ExperimentBlueRunnerError("shared Blue limit tracker differs from stored configuration")

        recorder = ResearchRecordingProvider(
            delegate=self.provider,
            run_id=run_id,
            model_configuration=config.model,
            first_sequence_number=self.execution_repository.next_agent_sequence(run_id),
            write_repository=self.write_repository,
            require_verified_binding=(config.run_type == RunType.FINAL_EVALUATION),
        )
        common = {
            "target_registry": self.target_registry,
            "policy_engine": self.policy_engine,
            "limits": limits,
            "provider": recorder,
            "audit_service": self.audit_service,
            "project_root": self.project_root,
        }
        if config.blue_team_mode == BlueTeamMode.SINGLE_AGENT:
            if config.classification_mode == ClassificationMode.RULE_ONLY:
                raise ExperimentBlueRunnerError(
                    "single-agent RQ3 Blue analysis cannot use rule_only classification"
                )
            flow = _SingleAgentBlueTeamFlow(
                general_agent=SingleGeneralBlueAgent(),
                **common,
            )
        elif config.blue_team_mode == BlueTeamMode.MULTI_AGENT:
            flow = BlueTeamFlow(**common)
        else:  # pragma: no cover
            raise ExperimentBlueRunnerError(f"unsupported Blue Team mode: {config.blue_team_mode!r}")

        monitoring = flow.monitor(logs)
        self.write_repository.record_monitoring_result(monitoring)
        selected = set(monitoring.event_ids)
        monitored_logs = LogReadResult(
            target_id=logs.target_id,
            run_id=logs.run_id,
            events=tuple(event for event in logs.events if event.event_id in selected),
            ignored_line_count=logs.ignored_line_count,
            malformed_line_count=logs.malformed_line_count,
            duplicate_event_count=logs.duplicate_event_count,
        )
        analysis = flow.run(logs=monitored_logs, mode=config.classification_mode)
        self.write_repository.record_blue_result(analysis)
        return ExperimentBlueAnalysisExecution(monitoring=monitoring, analysis=analysis)
