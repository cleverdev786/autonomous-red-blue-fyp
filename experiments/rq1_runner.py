"""Milestone 17 RQ1 condition runner over the existing safe Blue/Patch pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agents.blue import CodeAnalysisAgent, MonitoringAgent, PatchGenerationAgent, TriageAgent
from agents.blue.single_agent import SingleGeneralBlueAgent
from llm.interface import StructuredGenerationProvider
from orchestrator.blue_team_flow import BlueTeamFlow
from orchestrator.limits import RunLimitTracker
from orchestrator.patch_branch_flow import PatchBranchFlow
from orchestrator.patch_generation_flow import PatchGenerationFlow
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import BlueTeamAnalysisResult, MonitoringResult
from schemas.common import ResearchQuestion
from schemas.experiments import BlueTeamMode, ClassificationMode, ExperimentConfiguration
from schemas.git import PatchBranchResult
from schemas.logging import LogReadResult
from schemas.patches import PatchGenerationResult, PatchProposal
from schemas.red_team import RedTeamRunResult
from schemas.verification import PatchVerificationResult
from services.audit_service import AuditService
from services.target_registry import TargetRegistry
from storage.models import ExperimentConfigurationRow, ExperimentRunRow
from storage.repositories import ExperimentWriteRepository, ResearchReadRepository
from verification.pipeline import PatchVerificationPipeline


class RQ1RunnerError(RuntimeError):
    """Raised when a stored run/configuration cannot execute the frozen RQ1 comparison."""


@dataclass(frozen=True, slots=True)
class RQ1ExecutionResult:
    """One RQ1 execution composed from the existing typed evidence contracts."""

    run_id: str
    blue_team_mode: BlueTeamMode
    monitoring: MonitoringResult
    analysis: BlueTeamAnalysisResult
    patch_generation: PatchGenerationResult
    patch_branch: PatchBranchResult
    verification: PatchVerificationResult


def validate_rq1_configuration_pair(
    single: ExperimentConfiguration,
    multi: ExperimentConfiguration,
) -> None:
    """Fail when an RQ1 pair differs in anything except config ID/Blue architecture."""
    if single.research_question != ResearchQuestion.RQ1 or multi.research_question != ResearchQuestion.RQ1:
        raise RQ1RunnerError("both paired configurations must be RQ1")
    if single.blue_team_mode != BlueTeamMode.SINGLE_AGENT:
        raise RQ1RunnerError("first paired configuration must be single_agent")
    if multi.blue_team_mode != BlueTeamMode.MULTI_AGENT:
        raise RQ1RunnerError("second paired configuration must be multi_agent")

    ignored = {"config_id", "blue_team_mode"}
    single_payload = single.model_dump(mode="json", exclude=ignored)
    multi_payload = multi.model_dump(mode="json", exclude=ignored)
    if single_payload != multi_payload:
        differing = tuple(
            sorted(
                key
                for key in single_payload
                if single_payload.get(key) != multi_payload.get(key)
            )
        )
        raise RQ1RunnerError(
            "paired RQ1 configurations differ outside the Blue architecture: "
            + ", ".join(differing)
        )


class _SingleAgentBlueTeamFlow(BlueTeamFlow):
    """Existing BlueTeamFlow with only the reasoning persona replaced."""

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


class _SingleAgentPatchGenerationFlow(PatchGenerationFlow):
    """Existing PatchGenerationFlow with the same general Blue persona."""

    def __init__(self, *, general_agent: SingleGeneralBlueAgent, **kwargs) -> None:
        super().__init__(**kwargs)
        self.patch_agent = general_agent.stage(
            output_model=PatchProposal,
            input_builder=PatchGenerationAgent.prepare_input,
        )


class RQ1ExperimentRunner:
    """Switch RQ1 architecture only from the stored ExperimentConfiguration."""

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

    def run(
        self,
        *,
        run_id: str,
        logs: LogReadResult,
        red_run: RedTeamRunResult,
        attempt_number: int = 1,
        expected_base_commit: str | None = None,
    ) -> RQ1ExecutionResult:
        config = self._stored_configuration(run_id)
        self._validate_inputs(run_id=run_id, config=config, logs=logs, red_run=red_run)

        limits = RunLimitTracker(config.limits)
        common_kwargs = {
            "target_registry": self.target_registry,
            "policy_engine": self.policy_engine,
            "limits": limits,
            "provider": self.provider,
            "audit_service": self.audit_service,
            "project_root": self.project_root,
        }

        if config.blue_team_mode == BlueTeamMode.SINGLE_AGENT:
            if config.classification_mode == ClassificationMode.RULE_ONLY:
                raise RQ1RunnerError(
                    "RQ1 single-agent condition requires the general Blue agent to produce classification; "
                    "M20 may freeze llm_only or hybrid, but rule_only is not a valid single-agent RQ1 condition"
                )
            general_agent = SingleGeneralBlueAgent()
            blue_flow = _SingleAgentBlueTeamFlow(
                general_agent=general_agent,
                **common_kwargs,
            )
            patch_flow = _SingleAgentPatchGenerationFlow(
                general_agent=general_agent,
                **common_kwargs,
            )
        elif config.blue_team_mode == BlueTeamMode.MULTI_AGENT:
            blue_flow = BlueTeamFlow(**common_kwargs)
            patch_flow = PatchGenerationFlow(**common_kwargs)
        else:  # pragma: no cover - enum exhaustiveness guard
            raise RQ1RunnerError(f"unsupported Blue Team mode: {config.blue_team_mode!r}")

        monitoring = blue_flow.monitor(logs)
        self.write_repository.record_monitoring_result(monitoring)
        monitored_logs = self._apply_monitoring_selection(logs, monitoring)

        analysis = blue_flow.run(
            logs=monitored_logs,
            mode=config.classification_mode,
        )
        self.write_repository.record_blue_result(analysis)
        if analysis.code_finding is None:
            raise RQ1RunnerError(
                "RQ1 remediation scenario did not produce an actionable CodeFinding"
            )

        generation = patch_flow.run(
            analysis=analysis,
            attempt_number=attempt_number,
        )
        self.write_repository.record_patch_generation_result(generation)

        branch = self.patch_branch_flow.run(
            generation_result=generation,
            expected_base_commit=expected_base_commit,
        )
        self.write_repository.record_patch_branch_result(branch)

        verification = self.verification_pipeline.run(
            branch_result=branch,
            prepared_patch=generation.prepared_patch,
            red_run=red_run,
        )
        self.write_repository.record_patch_verification_result(verification)

        return RQ1ExecutionResult(
            run_id=run_id,
            blue_team_mode=config.blue_team_mode,
            monitoring=monitoring,
            analysis=analysis,
            patch_generation=generation,
            patch_branch=branch,
            verification=verification,
        )


    @staticmethod
    def _apply_monitoring_selection(
        logs: LogReadResult,
        monitoring: MonitoringResult,
    ) -> LogReadResult:
        selected_ids = set(monitoring.event_ids)
        return LogReadResult(
            target_id=logs.target_id,
            run_id=logs.run_id,
            events=tuple(
                event for event in logs.events if event.event_id in selected_ids
            ),
            ignored_line_count=logs.ignored_line_count,
            malformed_line_count=logs.malformed_line_count,
            duplicate_event_count=logs.duplicate_event_count,
        )

    def _stored_configuration(self, run_id: str) -> ExperimentConfiguration:
        with self.read_repository.session() as session:
            run = session.get(ExperimentRunRow, run_id)
            if run is None:
                raise RQ1RunnerError(f"experiment run {run_id!r} does not exist")
            config_row = session.get(ExperimentConfigurationRow, run.config_id)
            if config_row is None:
                raise RQ1RunnerError("stored experiment configuration does not exist")
            return ExperimentConfiguration.model_validate_json(config_row.configuration_json)

    @staticmethod
    def _validate_inputs(
        *,
        run_id: str,
        config: ExperimentConfiguration,
        logs: LogReadResult,
        red_run: RedTeamRunResult,
    ) -> None:
        if config.research_question != ResearchQuestion.RQ1:
            raise RQ1RunnerError("RQ1ExperimentRunner requires a stored RQ1 configuration")
        if logs.run_id != run_id or red_run.run_id != run_id:
            raise RQ1RunnerError("RQ1 input evidence must match the stored run_id")
        if logs.target_id != red_run.target_id:
            raise RQ1RunnerError("RQ1 Red and Blue evidence must reference the same target")
