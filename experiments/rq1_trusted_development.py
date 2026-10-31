"""Separate RQ1 DEVELOPMENT-only adapter over already-recorded Blue evidence.

No LLM, Red execution, Git branch creation, Docker, or FINAL_EVALUATION.
The original experiments.rq1_runner and RQ2 runner are untouched.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from orchestrator.remediation_outcome_flow import RemediationOutcomeFlow
from schemas.blue_team import BlueTeamAnalysisResult, MonitoringResult
from schemas.common import ClassificationLabel, ResearchQuestion, RunStatus, RunType, WorkflowState
from schemas.experiment_results import ArtifactType
from schemas.red_team import RedTeamRunResult
from schemas.remediation import RemediationAttemptResult
from schemas.experiments import BlueTeamMode, ExperimentConfiguration
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from services.audit_service import AuditService
from services.trusted_remediation_compiler import TrustedRemediationCompiler
from storage.models import ExperimentRunRow, ResultArtifactRow
from storage.repositories import ResearchReadRepository, ResearchStorageError, canonical_sha256, canonical_model_json
from storage.trusted_compilation_repository import TrustedCompilationWriteRepository, TrustedCompilationReceipt


class TrustedRQ1DevelopmentBlocked(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TrustedRQ1DevelopmentResult:
    run_id: str
    blue_team_mode: BlueTeamMode
    status: str
    compiler_receipt: TrustedCompilationReceipt | None
    # Prepared means IN-MEMORY, NOT accepted and NOT verified.
    prepared_diff_sha256: str | None
    accepted: bool = False


class TrustedRQ1DevelopmentAdapter:
    def __init__(
        self, *,
        read_repository: ResearchReadRepository,
        write_repository: TrustedCompilationWriteRepository,
        compiler: TrustedRemediationCompiler,
        policy_engine: PolicyEngine,
        audit_service: AuditService,
    ) -> None:
        self.reader=read_repository
        self.writer=write_repository
        self.compiler=compiler
        self.policy_engine=policy_engine
        self.audit_service=audit_service

    def _check_existing(self, *, run_id: str, monitoring: MonitoringResult,
                        analysis: BlueTeamAnalysisResult, red_run: RedTeamRunResult
                        ) -> ExperimentConfiguration:
        if not all(x.run_id==run_id for x in (monitoring,analysis,red_run)):
            raise TrustedRQ1DevelopmentBlocked("cross-run evidence mismatch")
        if (analysis.target_id!=red_run.target_id
                or analysis.triage.run_id!=run_id):
            raise TrustedRQ1DevelopmentBlocked("target/triage identity mismatch")
        if (red_run.final_state!=WorkflowState.BLUE_MONITORING
            or red_run.verification is None or not red_run.verification.confirmed
            or not red_run.execution.completed or red_run.execution.timed_out
            or not red_run.execution.evidence
            or red_run.attack_plan.target_id!=red_run.target_id
            or red_run.execution.target_id!=red_run.target_id
            or red_run.verification.target_id!=red_run.target_id
            or len({red_run.attack_plan.test_id,red_run.execution.test_id,
                    red_run.verification.test_id})!=1
            or not set(red_run.verification.evidence_ids).issubset(
                {e.evidence_id for e in red_run.execution.evidence})):
            raise TrustedRQ1DevelopmentBlocked("a recorded confirmed Red attack is required")
        with self.reader.session() as session:
            run=session.get(ExperimentRunRow,run_id)
            if run is None or run.status!=RunStatus.RUNNING.value:
                raise TrustedRQ1DevelopmentBlocked("existing running RQ1 run required")
            from storage.models import ExperimentConfigurationRow
            row=session.get(ExperimentConfigurationRow,run.config_id)
            if row is None:
                raise TrustedRQ1DevelopmentBlocked("configuration missing")
            cfg=ExperimentConfiguration.model_validate_json(row.configuration_json)
            if cfg.run_type!=RunType.DEVELOPMENT or cfg.research_question!=ResearchQuestion.RQ1:
                raise TrustedRQ1DevelopmentBlocked("FINAL_EVALUATION and non-RQ1 prohibited")
            if (run.scenario_id not in cfg.scenario_ids or run.dataset_id is not None
                or red_run.target_id!="vulnerable-store"):
                raise TrustedRQ1DevelopmentBlocked("invalid run scenario or target")
            registered_scenarios={
                "sqli-login-001": ("sqli-login-bypass-001","scenario-sqli-login"),
                "xss-search-001": ("xss-reflection-001","scenario-xss-search"),
                "path-traversal-read-001": ("path-traversal-private-file-001",
                                            "scenario-path-traversal-read"),
            }
            registered=registered_scenarios.get(run.scenario_id)
            if registered is None or (
                red_run.attack_plan.test_id,red_run.attack_plan.endpoint_id)!=registered:
                raise TrustedRQ1DevelopmentBlocked(
                    "recorded Red test does not match the configured scenario")
            expectations=(
                (ArtifactType.MONITORING_RESULT,monitoring),
                (ArtifactType.BLUE_TEAM_ANALYSIS_RESULT,analysis),
                (ArtifactType.RED_TEAM_RUN_RESULT,red_run),
            )
            for kind,item in expectations:
                records=session.scalars(select(ResultArtifactRow).where(
                    ResultArtifactRow.run_id==run_id,
                    ResultArtifactRow.artifact_type==kind.value,
                )).all()
                if len(records)!=1 or records[0].payload_sha256!=canonical_sha256(canonical_model_json(item)):
                    raise TrustedRQ1DevelopmentBlocked(f"missing or changed {kind.value} evidence")
        return cfg

    def run_recorded(
        self, *,
        run_id: str,
        monitoring: MonitoringResult,
        analysis: BlueTeamAnalysisResult,
        red_run: RedTeamRunResult,
        attempt_number: int,
        limits: RunLimitTracker,
    ) -> TrustedRQ1DevelopmentResult:
        """Use recorded Red and Blue output; prepare/store only, never apply."""
        cfg=self._check_existing(run_id=run_id,monitoring=monitoring,
                                 analysis=analysis,red_run=red_run)
        if limits.limits!=cfg.limits:
            raise TrustedRQ1DevelopmentBlocked("shared attempt/model budget does not match stored config")
        if attempt_number<1:
            raise TrustedRQ1DevelopmentBlocked("invalid patch attempt number")
        if analysis.triage.classification==ClassificationLabel.BENIGN:
            if (analysis.code_finding is not None or analysis.final_state!=WorkflowState.TRIAGE):
                raise TrustedRQ1DevelopmentBlocked("benign without-patch flow requires TRIAGE and no finding")
            result=RemediationAttemptResult(
                schema_version="1.0",run_id=run_id,target_id=analysis.target_id,
                attempt_number=attempt_number,disposition="no_action",
                reason_code="benign")
            # Existing genuine, model-free benign finalizer. No patch artifact.
            RemediationOutcomeFlow(
                policy_engine=self.policy_engine,audit_service=self.audit_service,
                write_repository=self.writer).finish_without_patch(
                    analysis=analysis,result=result)
            return TrustedRQ1DevelopmentResult(run_id,cfg.blue_team_mode,
                                                "no_action",None,None)
        if (not analysis.triage.is_suspicious or analysis.code_finding is None
            or analysis.final_state!=WorkflowState.CODE_ANALYSIS):
            raise TrustedRQ1DevelopmentBlocked("malicious analysis lacks actionable code finding")
        outcome=self.compiler.prepare(analysis=analysis,attempt_number=attempt_number,
                                      limits=limits)
        try:
            receipt=self.writer.persist(outcome=outcome,analysis=analysis)
        except Exception:
            self.audit_service.record(
                run_id=run_id,component="trusted_rq1_development",
                actor_type="orchestrator",operation="trusted_compilation_storage",
                target=analysis.target_id,policy_decision=AuditPolicyDecision.ALLOWED,
                execution_status=AuditExecutionStatus.FAILED,
                error_code="trusted-compilation-storage-failed")
            raise
        self.audit_service.record(
            run_id=run_id,component="trusted_rq1_development",
            actor_type="orchestrator",operation="trusted_compilation_storage",
            target=analysis.target_id,policy_decision=AuditPolicyDecision.ALLOWED,
            execution_status=AuditExecutionStatus.SUCCEEDED,
            evidence_reference=receipt.provenance_payload_sha256)
        return TrustedRQ1DevelopmentResult(
            run_id=run_id,blue_team_mode=cfg.blue_team_mode,
            status=("prepared_unverified" if receipt.status=="prepared" else "rejected"),
            compiler_receipt=receipt,
            prepared_diff_sha256=(
                outcome.generation.prepared_patch.diff_sha256
                if outcome.generation is not None else None),
        )
