"""Narrow typed repositories for append-oriented experiment evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
import hashlib
import json
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from schemas.blue_team import BlueTeamAnalysisResult, MonitoringResult, SourceReadResult
from schemas.common import ClassificationLabel, RunStatus, WorkflowState
from schemas.experiment_results import AgentCallRecord, ArtifactType, RunProvenance, StageTimingRecord
from schemas.experience import SelectionDecision
from schemas.experiments import ClassificationMode, ExperimentConfiguration
from schemas.git import PatchBranchResult
from schemas.logging import AuditEvent, AuditExecutionStatus, AuditPolicyDecision, LogReadResult
from schemas.patches import PatchGenerationResult, PatchRetryFeedback
from schemas.red_team import RedTeamRunResult
from schemas.scoring import ScoreResult
from schemas.scenarios import ScenarioGroundTruth
from schemas.verification import PatchVerificationResult, VerificationCheckStatus
from storage.models import (
    AgentCallRow,
    AuditRunManifestRow,
    ClassificationTruthRow,
    CodeFindingRow,
    DatasetItemRow,
    EventClassificationRow,
    ExperimentConfigurationRow,
    ExperimentRunRow,
    FunctionalCheckRow,
    PatchAttemptRow,
    PatchFeedbackRow,
    PolicyEventReferenceRow,
    ResultArtifactRow,
    RunClassificationRow,
    RunProvenanceRow,
    ScenarioTruthRow,
    ScoreRecordRow,
    SecurityTestExecutionRow,
    StageTimingRow,
    VerificationStageRow,
)


class ResearchStorageError(RuntimeError):
    pass


T = TypeVar("T", bound=BaseModel)

_ARTIFACT_MODELS: dict[ArtifactType, type[BaseModel]] = {
    ArtifactType.LOG_READ_RESULT: LogReadResult,
    ArtifactType.MONITORING_RESULT: MonitoringResult,
    ArtifactType.SOURCE_READ_RESULT: SourceReadResult,
    ArtifactType.RED_TEAM_RUN_RESULT: RedTeamRunResult,
    ArtifactType.BLUE_TEAM_ANALYSIS_RESULT: BlueTeamAnalysisResult,
    ArtifactType.PATCH_GENERATION_RESULT: PatchGenerationResult,
    ArtifactType.PATCH_BRANCH_RESULT: PatchBranchResult,
    ArtifactType.PATCH_VERIFICATION_RESULT: PatchVerificationResult,
    ArtifactType.PATCH_RETRY_FEEDBACK: PatchRetryFeedback,
    ArtifactType.SCORE_RESULT: ScoreResult,
    ArtifactType.SELECTION_DECISION: SelectionDecision,
}


def canonical_model_json(model: BaseModel) -> str:
    return json.dumps(model.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ExperimentWriteRepository:
    """Write-only execution-side repository. It deliberately exposes no truth reads."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._factory = session_factory

    def create_configuration(self, config: ExperimentConfiguration) -> None:
        payload = canonical_model_json(config)
        row = ExperimentConfigurationRow(
            config_id=config.config_id,
            run_type=config.run_type.value,
            research_question=config.research_question.value,
            scenario_ids_json=json.dumps(list(config.scenario_ids), separators=(",", ":")),
            dataset_id=config.dataset_id,
            repetitions=config.repetitions,
            blue_team_mode=config.blue_team_mode.value,
            classification_mode=config.classification_mode.value,
            retry_feedback_mode=config.retry_feedback_mode.value,
            experience_mode=config.experience_mode.value,
            model_provider=config.model.provider,
            model_name=config.model.model_name,
            configuration_json=payload,
            configuration_sha256=canonical_sha256(payload),
            created_at=datetime.now(UTC),
        )
        self._insert(row, "experiment configuration already exists")

    def create_run(
        self,
        *,
        run_id: str,
        config_id: str,
        repetition_index: int,
        baseline_commit: str,
        scenario_id: str | None = None,
        dataset_id: str | None = None,
        started_at: datetime | None = None,
    ) -> None:
        if repetition_index < 1:
            raise ResearchStorageError("repetition_index must be >= 1")
        if (scenario_id is None) == (dataset_id is None):
            raise ResearchStorageError("run requires exactly one of scenario_id or dataset_id")
        with self._factory() as session:
            config = session.get(ExperimentConfigurationRow, config_id)
            if config is None:
                raise ResearchStorageError("experiment configuration does not exist")
            if config.research_question == "rq2":
                if dataset_id != config.dataset_id or scenario_id is not None:
                    raise ResearchStorageError("RQ2 run must use its configured dataset_id")
            else:
                configured = set(json.loads(config.scenario_ids_json))
                if scenario_id not in configured or dataset_id is not None:
                    raise ResearchStorageError("RQ1/RQ3 run must use a configured scenario_id")
            row = ExperimentRunRow(
                run_id=run_id,
                config_id=config_id,
                repetition_index=repetition_index,
                scenario_id=scenario_id,
                dataset_id=dataset_id,
                status=RunStatus.CREATED.value,
                started_at=started_at or datetime.now(UTC),
                baseline_commit=baseline_commit,
            )
            session.add(row)
            self._commit(session, "experiment run already exists")

    def mark_running(self, run_id: str) -> None:
        self._update_run(run_id, status=RunStatus.RUNNING)

    def finalize_run(
        self,
        run_id: str,
        *,
        status: RunStatus,
        completed_at: datetime | None = None,
        system_error_code: str | None = None,
        system_error_summary: str | None = None,
    ) -> None:
        if status in {RunStatus.CREATED, RunStatus.RUNNING}:
            raise ResearchStorageError("final run status must be terminal")
        self._update_run(
            run_id,
            status=status,
            completed_at=completed_at or datetime.now(UTC),
            system_error_code=system_error_code,
            system_error_summary=system_error_summary,
        )

    def record_provenance(self, run_id: str, provenance: RunProvenance) -> None:
        payload = canonical_model_json(provenance)
        row = RunProvenanceRow(
            run_id=run_id,
            payload_json=payload,
            payload_sha256=canonical_sha256(payload),
            framework_git_commit=provenance.framework_git_commit,
            baseline_git_commit=provenance.baseline_git_commit,
            prompt_set_version=provenance.prompt_set_version,
            schema_set_version=provenance.schema_set_version,
            agent_configuration_version=provenance.agent_configuration_version,
            context_policy_version=provenance.context_policy_version,
            scenario_version=provenance.scenario_version,
            dataset_version=provenance.dataset_version,
            rule_version=provenance.rule_version,
            test_suite_version=provenance.test_suite_version,
            verification_policy_version=provenance.verification_policy_version,
            random_seed=provenance.random_seed,
        )
        self._insert(row, "run provenance already exists")

    def record_log_read_result(self, result: LogReadResult) -> int:
        return self._record_artifact(result.run_id, ArtifactType.LOG_READ_RESULT, result)

    def record_monitoring_result(self, result: MonitoringResult) -> int:
        return self._record_artifact(result.run_id, ArtifactType.MONITORING_RESULT, result)

    def record_source_read_result(self, result: SourceReadResult) -> int:
        return self._record_artifact(result.run_id, ArtifactType.SOURCE_READ_RESULT, result)

    def record_selection_decision(self, result: SelectionDecision) -> int:
        """Persist an already-produced bounded selection decision as canonical evidence."""
        return self._record_artifact(
            result.run_id, ArtifactType.SELECTION_DECISION, result
        )

    def record_red_result(
        self,
        result: RedTeamRunResult,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> int:
        with self._factory() as session:
            artifact = self._artifact_row(result.run_id, ArtifactType.RED_TEAM_RUN_RESULT, result, result.attempt_number)
            session.add(artifact)
            session.flush()
            session.add(SecurityTestExecutionRow(
                run_id=result.run_id,
                purpose="red_attack",
                red_attempt_number=result.attempt_number,
                test_id=result.execution.test_id,
                vulnerability_class=result.attack_plan.vulnerability_class.value,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=result.execution.duration_ms,
                completed=result.execution.completed,
                timed_out=result.execution.timed_out,
                request_count=result.execution.request_count,
                status_code=result.execution.status_code,
                exploit_evidence_observed=bool(result.execution.evidence),
                confirmed=(result.verification.confirmed if result.verification else None),
                error_code=result.execution.error_code,
                artifact_id=artifact.artifact_id,
            ))
            self._commit(session, "duplicate Red result evidence")
            return artifact.artifact_id

    def record_blue_result(self, result: BlueTeamAnalysisResult) -> int:
        with self._factory() as session:
            artifact = self._artifact_row(result.run_id, ArtifactType.BLUE_TEAM_ANALYSIS_RESULT, result)
            session.add(artifact)
            session.flush()
            session.add(RunClassificationRow(
                run_id=result.run_id,
                classification_mode=result.classification_mode.value,
                predicted_label=result.triage.classification.value,
                confidence=result.triage.confidence,
                supporting_event_ids_json=json.dumps(list(result.triage.supporting_event_ids), separators=(",", ":")),
                artifact_id=artifact.artifact_id,
            ))
            if result.code_finding is not None:
                session.add(CodeFindingRow(
                    run_id=result.run_id,
                    file_path=result.code_finding.file_path,
                    function_or_route=result.code_finding.function_or_route,
                    confidence=result.code_finding.confidence,
                    artifact_id=artifact.artifact_id,
                ))
            self._commit(session, "duplicate Blue result evidence")
            return artifact.artifact_id

    def record_patch_generation_result(
        self,
        result: PatchGenerationResult,
        *,
        prepared_at: datetime | None = None,
    ) -> int:
        with self._factory() as session:
            artifact = self._artifact_row(result.run_id, ArtifactType.PATCH_GENERATION_RESULT, result, result.attempt_number)
            session.add(artifact)
            session.flush()
            prepared = result.prepared_patch
            session.add(PatchAttemptRow(
                run_id=result.run_id,
                attempt_number=result.attempt_number,
                prepared_patch_artifact_id=artifact.artifact_id,
                prepared_diff_sha256=prepared.diff_sha256,
                files_changed=prepared.files_changed,
                inserted_lines=prepared.inserted_lines,
                deleted_lines=prepared.deleted_lines,
                total_diff_bytes=prepared.total_diff_bytes,
                changed_paths_json=json.dumps([item.file_path for item in prepared.files], separators=(",", ":")),
                generated_test_path=prepared.generated_test_path,
                final_state=result.final_state.value,
                patch_prepared_at=prepared_at or datetime.now(UTC),
            ))
            self._commit(session, "duplicate patch generation attempt")
            return artifact.artifact_id

    def record_patch_branch_result(self, result: PatchBranchResult) -> int:
        with self._factory() as session:
            attempt = self._patch_attempt(session, result.run_id, result.attempt_number)
            artifact = self._artifact_row(result.run_id, ArtifactType.PATCH_BRANCH_RESULT, result, result.attempt_number)
            session.add(artifact)
            session.flush()
            attempt.branch_artifact_id = artifact.artifact_id
            attempt.branch_name = result.branch_name
            attempt.base_commit = result.base_commit
            attempt.git_diff_sha256 = result.git_diff_sha256
            attempt.changed_paths_json = json.dumps(list(result.changed_paths), separators=(",", ":"))
            attempt.final_state = result.final_state.value
            self._commit(session, "patch branch result could not be recorded")
            return artifact.artifact_id

    def record_patch_verification_result(
        self,
        result: PatchVerificationResult,
        *,
        decision_at: datetime | None = None,
    ) -> int:
        with self._factory() as session:
            attempt = self._patch_attempt(session, result.run_id, result.attempt_number)
            artifact = self._artifact_row(result.run_id, ArtifactType.PATCH_VERIFICATION_RESULT, result, result.attempt_number)
            session.add(artifact)
            session.flush()
            attempt.verification_artifact_id = artifact.artifact_id
            attempt.branch_name = result.branch_name
            attempt.base_commit = result.base_commit
            attempt.git_diff_sha256 = result.git_diff_sha256
            attempt.final_state = result.final_state.value
            attempt.patch_decision = result.verification.decision.value if result.verification else None
            attempt.rejection_reason = result.verification.rejection_reason if result.verification else None
            attempt.failure_reason = result.failure_reason
            attempt.accepted_commit_sha = result.accepted_commit_sha
            attempt.verification_decision_at = decision_at or datetime.now(UTC)
            attempt.attempt_completed_at = decision_at or datetime.now(UTC)
            if result.verification is not None:
                for index, stage in enumerate(result.verification.stages, start=1):
                    session.add(VerificationStageRow(
                        patch_attempt_id=attempt.id,
                        stage_id=stage.stage_id,
                        sequence_number=index,
                        required=stage.required,
                        passed=stage.passed,
                        duration_ms=stage.duration_ms,
                        details=stage.details,
                    ))
                    if stage.stage_id == "functional":
                        for check in stage.checks:
                            session.add(FunctionalCheckRow(
                                patch_attempt_id=attempt.id,
                                check_id=check.check_id,
                                status=check.status.value,
                                duration_ms=check.duration_ms,
                                details=check.details,
                            ))
                    if stage.test_execution is not None and stage.stage_id in {"security", "original_replay"}:
                        execution = stage.test_execution
                        session.add(SecurityTestExecutionRow(
                            run_id=result.run_id,
                            purpose="verification_security" if stage.stage_id == "security" else "original_replay",
                            patch_attempt_number=result.attempt_number,
                            test_id=execution.test_id,
                            duration_ms=execution.duration_ms,
                            completed=execution.completed,
                            timed_out=execution.timed_out,
                            request_count=execution.request_count,
                            status_code=execution.status_code,
                            exploit_evidence_observed=bool(execution.evidence),
                            confirmed=None,
                            error_code=execution.error_code,
                            artifact_id=artifact.artifact_id,
                        ))
            self._commit(session, "duplicate patch verification evidence")
            return artifact.artifact_id

    def record_patch_retry_feedback(
        self,
        *,
        run_id: str,
        source_attempt_number: int,
        receiving_attempt_number: int,
        feedback: PatchRetryFeedback,
    ) -> int:
        """Persist already-produced sanitized feedback; never generate or apply a retry."""
        if source_attempt_number < 1 or receiving_attempt_number <= source_attempt_number:
            raise ResearchStorageError("feedback must link an earlier source attempt to a later receiving attempt")
        with self._factory() as session:
            artifact = self._artifact_row(
                run_id, ArtifactType.PATCH_RETRY_FEEDBACK, feedback, receiving_attempt_number
            )
            session.add(artifact)
            session.flush()
            session.add(PatchFeedbackRow(
                run_id=run_id,
                source_attempt_number=source_attempt_number,
                receiving_attempt_number=receiving_attempt_number,
                feedback_artifact_id=artifact.artifact_id,
            ))
            self._commit(session, "patch retry feedback already exists for receiving attempt")
            return artifact.artifact_id

    def record_stage_timing(self, run_id: str, timing: StageTimingRecord) -> None:
        self._insert(StageTimingRow(
            run_id=run_id,
            attempt_number=timing.attempt_number,
            stage_id=timing.stage_id,
            sequence_number=timing.sequence_number,
            duration_ms=timing.duration_ms,
            started_at=timing.started_at,
            completed_at=timing.completed_at,
        ), "duplicate stage timing sequence")

    def record_event_classification(
        self,
        *,
        run_id: str,
        dataset_item_id: int,
        classification_mode: ClassificationMode,
        predicted_label: ClassificationLabel,
        confidence: float,
        duration_ms: int,
    ) -> int:
        """Record one RQ2 prediction without reading evaluation-only truth."""
        row = EventClassificationRow(
            run_id=run_id,
            dataset_item_id=dataset_item_id,
            classification_mode=classification_mode.value,
            predicted_label=predicted_label.value,
            confidence=confidence,
            duration_ms=duration_ms,
        )
        with self._factory() as session:
            session.add(row)
            self._commit(session, "event classification already exists")
            return row.id

    def record_agent_call(self, run_id: str, call: AgentCallRecord) -> None:
        self._insert(AgentCallRow(
            call_id=call.call_id,
            run_id=run_id,
            sequence_number=call.sequence_number,
            agent_role=call.agent_role.value,
            provider=call.provider,
            model_name=call.model_name,
            duration_ms=call.duration_ms,
            result_status=call.result_status.value,
            classification_observation_id=call.classification_observation_id,
            patch_attempt_number=call.patch_attempt_number,
            red_attempt_number=call.red_attempt_number,
            input_tokens=call.input_tokens,
            output_tokens=call.output_tokens,
            token_usage_status=call.token_usage_status.value,
            estimated_cost=call.estimated_cost,
            cost_status=call.cost_status.value,
            currency=call.currency,
            pricing_version=call.pricing_version,
            source_audit_event_id=call.source_audit_event_id,
        ), "duplicate agent call evidence")

    def record_audit_manifest(self, run_id: str, *, audit_source: str, events: tuple[AuditEvent, ...]) -> None:
        ordered = tuple(event for event in events if event.run_id == run_id)
        payload = "\n".join(canonical_model_json(event) for event in ordered)
        manifest = AuditRunManifestRow(
            run_id=run_id,
            audit_source=audit_source,
            event_count=len(ordered),
            blocked_count=sum(event.policy_decision == AuditPolicyDecision.BLOCKED for event in ordered),
            failed_count=sum(event.execution_status == AuditExecutionStatus.FAILED for event in ordered),
            first_event_id=ordered[0].event_id if ordered else None,
            last_event_id=ordered[-1].event_id if ordered else None,
            canonical_run_audit_sha256=canonical_sha256(payload),
        )
        with self._factory() as session:
            session.add(manifest)
            for event in ordered:
                if event.policy_decision == AuditPolicyDecision.BLOCKED:
                    session.add(PolicyEventReferenceRow(
                        run_id=run_id,
                        audit_event_id=event.event_id,
                        operation=event.operation,
                        policy_decision=event.policy_decision.value,
                        policy_reason=event.policy_reason.value if event.policy_reason else None,
                        execution_status=event.execution_status.value,
                        error_code=event.error_code,
                    ))
            self._commit(session, "audit manifest already exists")

    def _record_artifact(self, run_id: str, artifact_type: ArtifactType, model: BaseModel, attempt_number: int | None = None) -> int:
        with self._factory() as session:
            row = self._artifact_row(run_id, artifact_type, model, attempt_number)
            session.add(row)
            self._commit(session, "artifact could not be recorded")
            return row.artifact_id

    def _artifact_row(self, run_id: str, artifact_type: ArtifactType, model: BaseModel, attempt_number: int | None = None) -> ResultArtifactRow:
        expected = _ARTIFACT_MODELS[artifact_type]
        if not isinstance(model, expected):
            raise ResearchStorageError(f"{artifact_type.value} requires {expected.__name__}")
        payload = canonical_model_json(model)
        return ResultArtifactRow(
            run_id=run_id,
            attempt_number=attempt_number,
            artifact_type=artifact_type.value,
            schema_name=model.__class__.__name__,
            schema_version="1.0",
            payload_json=payload,
            payload_sha256=canonical_sha256(payload),
            created_at=datetime.now(UTC),
        )

    def _patch_attempt(self, session: Session, run_id: str, attempt_number: int) -> PatchAttemptRow:
        row = session.scalar(select(PatchAttemptRow).where(
            PatchAttemptRow.run_id == run_id,
            PatchAttemptRow.attempt_number == attempt_number,
        ))
        if row is None:
            raise ResearchStorageError("patch generation evidence must exist before branch/verification evidence")
        return row

    def _update_run(self, run_id: str, *, status: RunStatus, **fields) -> None:
        with self._factory() as session:
            row = session.get(ExperimentRunRow, run_id)
            if row is None:
                raise ResearchStorageError("experiment run does not exist")
            row.status = status.value
            for key, value in fields.items():
                setattr(row, key, value)
            self._commit(session, "experiment run update failed")

    def _insert(self, row, duplicate_message: str) -> None:
        with self._factory() as session:
            session.add(row)
            self._commit(session, duplicate_message)

    @staticmethod
    def _commit(session: Session, message: str) -> None:
        try:
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise ResearchStorageError(message) from exc


class EvaluationTruthRepository:
    """Evaluation-only truth writes/reads. Never pass this repository to experiment execution."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._factory = session_factory

    def record_scenario_truth(self, truth: ScenarioGroundTruth, *, scenario_version: str) -> int:
        payload = canonical_model_json(truth)
        row = ScenarioTruthRow(
            scenario_id=truth.scenario_id,
            scenario_version=scenario_version,
            vulnerability_class=truth.vulnerability_class.value,
            source_file=truth.vulnerable_source_file,
            function_or_route=truth.vulnerable_function,
            payload_json=payload,
            payload_sha256=canonical_sha256(payload),
        )
        with self._factory() as session:
            session.add(row)
            ExperimentWriteRepository._commit(session, "scenario truth version already exists")
            return row.truth_id

    def record_dataset_item(self, *, dataset_id: str, dataset_version: str, event_id: str, normalized_input: dict) -> int:
        payload = json.dumps(normalized_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        row = DatasetItemRow(
            dataset_id=dataset_id,
            dataset_version=dataset_version,
            event_id=event_id,
            normalized_input_json=payload,
            normalized_input_sha256=canonical_sha256(payload),
        )
        with self._factory() as session:
            session.add(row)
            ExperimentWriteRepository._commit(session, "dataset item already exists")
            return row.id

    def record_classification_truth(self, *, dataset_item_id: int, ground_truth_label: ClassificationLabel, source_notes: str | None = None) -> None:
        with self._factory() as session:
            session.add(ClassificationTruthRow(
                dataset_item_id=dataset_item_id,
                ground_truth_label=ground_truth_label.value,
                source_notes=source_notes,
            ))
            ExperimentWriteRepository._commit(session, "classification truth already exists")


class ResearchReadRepository:
    """Post-execution read/query repository used by metrics and analysis only."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._factory = session_factory

    def session(self) -> Session:
        """Return a post-execution read session for deterministic metrics."""
        return self._factory()


class ScoreRepository:
    """Immutable score/result-artifact persistence; contains no scoring formula."""

    _EVIDENCE_PREFIX = "result_artifact"

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._factory = session_factory

    def record_score(self, result: ScoreResult) -> ScoreRecordRow:
        """Persist canonical ScoreResult evidence and its score atomically.

        The (run_id, score_type, scoring_version) identity is immutable. An
        identical recalculation is an idempotent no-op. Any changed evidence
        or inconsistent score under the same version fails visibly.
        """
        payload = canonical_model_json(result)
        payload_sha256 = canonical_sha256(payload)
        score_value = Decimal(result.final_score)

        with self._factory() as session:
            existing = session.scalar(
                select(ScoreRecordRow).where(
                    ScoreRecordRow.run_id == result.run_id,
                    ScoreRecordRow.score_type == result.score_type.value,
                    ScoreRecordRow.scoring_version == result.scoring_version,
                )
            )
            if existing is not None:
                artifact_id, recorded_sha256 = self._parse_evidence_reference(
                    existing.evidence_reference
                )
                artifact = session.get(ResultArtifactRow, artifact_id)
                if artifact is None or artifact.artifact_type != ArtifactType.SCORE_RESULT.value:
                    raise ResearchStorageError(
                        "existing score evidence artifact is missing or has the wrong type"
                    )
                if artifact.payload_sha256 != recorded_sha256:
                    raise ResearchStorageError(
                        "existing score evidence reference does not match its artifact digest"
                    )
                if existing.score_value != score_value:
                    raise ResearchStorageError(
                        "same scoring version produced an inconsistent score"
                    )
                if artifact.payload_sha256 != payload_sha256 or artifact.payload_json != payload:
                    raise ResearchStorageError(
                        "same scoring version cannot overwrite changed score evidence"
                    )
                return existing

            artifact = ResultArtifactRow(
                run_id=result.run_id,
                attempt_number=result.selected_patch_attempt,
                artifact_type=ArtifactType.SCORE_RESULT.value,
                schema_name=ScoreResult.__name__,
                schema_version="1.0",
                payload_json=payload,
                payload_sha256=payload_sha256,
                created_at=datetime.now(UTC),
            )
            session.add(artifact)
            session.flush()
            evidence_reference = self._format_evidence_reference(
                artifact.artifact_id, payload_sha256
            )
            row = ScoreRecordRow(
                run_id=result.run_id,
                score_type=result.score_type.value,
                score_value=score_value,
                scoring_version=result.scoring_version,
                evidence_reference=evidence_reference,
            )
            session.add(row)
            ExperimentWriteRepository._commit(session, "score could not be recorded")
            return row

    @classmethod
    def _format_evidence_reference(cls, artifact_id: int, payload_sha256: str) -> str:
        return f"{cls._EVIDENCE_PREFIX}:{artifact_id}:sha256:{payload_sha256}"

    @classmethod
    def _parse_evidence_reference(cls, reference: str) -> tuple[int, str]:
        parts = reference.split(":")
        if (
            len(parts) != 4
            or parts[0] != cls._EVIDENCE_PREFIX
            or parts[2] != "sha256"
            or len(parts[3]) != 64
        ):
            raise ResearchStorageError("invalid score evidence reference")
        try:
            artifact_id = int(parts[1])
        except ValueError as exc:
            raise ResearchStorageError("invalid score evidence artifact id") from exc
        if artifact_id < 1 or any(char not in "0123456789abcdef" for char in parts[3]):
            raise ResearchStorageError("invalid score evidence reference")
        return artifact_id, parts[3]
