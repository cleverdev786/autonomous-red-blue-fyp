"""Bounded, read-only queries for dashboard presentation."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from dashboard.api.schemas import (
    AuditView,
    FindingView,
    FunctionalCheckView,
    OverviewView,
    PatchAttemptView,
    PatchVerificationView,
    PolicyEventView,
    RunDetailView,
    RunListItem,
    RunScoresView,
    ScoreView,
    VerificationStageView,
)
from experiments.metrics import (
    compute_normal_application_task_success,
    compute_red_metrics,
    compute_rq1_metrics,
    compute_rq2_metrics,
    compute_rq3_metrics,
)
from schemas.experiment_results import ArtifactType
from schemas.scoring import ScoreResult
from storage.models import (
    AgentCallRow,
    AuditRunManifestRow,
    CodeFindingRow,
    ExperimentConfigurationRow,
    ExperimentRunRow,
    FunctionalCheckRow,
    PatchAttemptRow,
    PolicyEventReferenceRow,
    ResultArtifactRow,
    RunClassificationRow,
    RunProvenanceRow,
    ScoreRecordRow,
    SecurityTestExecutionRow,
    VerificationStageRow,
)
from storage.repositories import ResearchReadRepository


MAX_TEXT_CHARS = 4_000
MAX_DIFF_CHARS = 12_000
MAX_DIFF_LINES = 240
MAX_POLICY_EVENTS = 200


class DashboardNotFoundError(LookupError):
    pass


class DashboardReadService:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._factory = session_factory
        self._research = ResearchReadRepository(session_factory)

    def ping(self) -> None:
        with self._factory() as session:
            session.execute(text("SELECT 1"))

    def overview(self) -> OverviewView:
        with self._factory() as session:
            total = int(session.scalar(select(func.count()).select_from(ExperimentRunRow)) or 0)
            status_counts = {
                status: int(count)
                for status, count in session.execute(
                    select(ExperimentRunRow.status, func.count())
                    .group_by(ExperimentRunRow.status)
                    .order_by(ExperimentRunRow.status)
                )
            }
            rq_counts = {
                rq: int(count)
                for rq, count in session.execute(
                    select(ExperimentConfigurationRow.research_question, func.count())
                    .join(ExperimentRunRow, ExperimentRunRow.config_id == ExperimentConfigurationRow.config_id)
                    .group_by(ExperimentConfigurationRow.research_question)
                    .order_by(ExperimentConfigurationRow.research_question)
                )
            }
            recent = list(
                session.execute(
                    self._run_statement().order_by(ExperimentRunRow.started_at.desc()).limit(10)
                )
            )
            return OverviewView(
                total_runs=total,
                status_counts=status_counts,
                research_question_counts=rq_counts,
                recent_runs=tuple(self._run_item(session, row[0], row[1]) for row in recent),
            )

    def runs(
        self,
        *,
        status: str | None = None,
        research_question: str | None = None,
        limit: int = 100,
    ) -> tuple[RunListItem, ...]:
        with self._factory() as session:
            statement = self._run_statement()
            if status:
                statement = statement.where(ExperimentRunRow.status == status)
            if research_question:
                statement = statement.where(
                    ExperimentConfigurationRow.research_question == research_question
                )
            rows = session.execute(
                statement.order_by(ExperimentRunRow.started_at.desc()).limit(limit)
            ).all()
            return tuple(self._run_item(session, run, config) for run, config in rows)

    def run_detail(self, run_id: str) -> RunDetailView:
        with self._factory() as session:
            run, config = self._run_and_config(session, run_id)
            provenance = session.get(RunProvenanceRow, run_id)
            runtime_ms = None
            if run.completed_at is not None:
                runtime_ms = max(0, int((run.completed_at - run.started_at).total_seconds() * 1000))
            return RunDetailView(
                run=self._run_item(session, run, config),
                repetition_index=run.repetition_index,
                baseline_commit=run.baseline_commit,
                blue_team_mode=config.blue_team_mode,
                classification_mode=config.classification_mode,
                retry_feedback_mode=config.retry_feedback_mode,
                experience_mode=config.experience_mode,
                model_provider=config.model_provider,
                model_name=config.model_name,
                system_error_code=run.system_error_code,
                system_error_summary=self._bounded(run.system_error_summary),
                provenance_versions=(
                    {
                        "framework_git_commit": provenance.framework_git_commit,
                        "baseline_git_commit": provenance.baseline_git_commit,
                        "prompt_set_version": provenance.prompt_set_version,
                        "schema_set_version": provenance.schema_set_version,
                        "agent_configuration_version": provenance.agent_configuration_version,
                        "context_policy_version": provenance.context_policy_version,
                        "scenario_version": provenance.scenario_version,
                        "dataset_version": provenance.dataset_version,
                        "rule_version": provenance.rule_version,
                        "test_suite_version": provenance.test_suite_version,
                        "verification_policy_version": provenance.verification_policy_version,
                        "random_seed": provenance.random_seed,
                    }
                    if provenance is not None
                    else {}
                ),
                red_attempts=int(
                    session.scalar(
                        select(func.count())
                        .select_from(SecurityTestExecutionRow)
                        .where(
                            SecurityTestExecutionRow.run_id == run_id,
                            SecurityTestExecutionRow.purpose == "red_attack",
                        )
                    )
                    or 0
                ),
                patch_attempts=int(
                    session.scalar(
                        select(func.count())
                        .select_from(PatchAttemptRow)
                        .where(PatchAttemptRow.run_id == run_id)
                    )
                    or 0
                ),
                model_calls=int(
                    session.scalar(
                        select(func.count())
                        .select_from(AgentCallRow)
                        .where(AgentCallRow.run_id == run_id)
                    )
                    or 0
                ),
                policy_event_references=int(
                    session.scalar(
                        select(func.count())
                        .select_from(PolicyEventReferenceRow)
                        .where(PolicyEventReferenceRow.run_id == run_id)
                    )
                    or 0
                ),
                total_runtime_ms=runtime_ms,
            )

    def findings(self, run_id: str) -> FindingView:
        with self._factory() as session:
            self._require_run(session, run_id)
            classification = session.scalar(
                select(RunClassificationRow).where(RunClassificationRow.run_id == run_id)
            )
            finding = session.scalar(
                select(CodeFindingRow).where(CodeFindingRow.run_id == run_id)
            )
            return FindingView(
                run_id=run_id,
                predicted_label=classification.predicted_label if classification else None,
                classification_mode=classification.classification_mode if classification else None,
                classification_confidence=classification.confidence if classification else None,
                file_path=finding.file_path if finding else None,
                function_or_route=finding.function_or_route if finding else None,
                localization_confidence=finding.confidence if finding else None,
            )

    def patch_verification(self, run_id: str) -> PatchVerificationView:
        with self._factory() as session:
            self._require_run(session, run_id)
            attempts = list(
                session.scalars(
                    select(PatchAttemptRow)
                    .where(PatchAttemptRow.run_id == run_id)
                    .order_by(PatchAttemptRow.attempt_number)
                )
            )
            views: list[PatchAttemptView] = []
            for attempt in attempts:
                stages = list(
                    session.scalars(
                        select(VerificationStageRow)
                        .where(VerificationStageRow.patch_attempt_id == attempt.id)
                        .order_by(VerificationStageRow.sequence_number)
                    )
                )
                stage_views: list[VerificationStageView] = []
                for stage in stages:
                    checks = list(
                        session.scalars(
                            select(FunctionalCheckRow)
                            .where(FunctionalCheckRow.patch_attempt_id == attempt.id)
                            .order_by(FunctionalCheckRow.id)
                        )
                    ) if stage.stage_id == "functional" else []
                    stage_views.append(
                        VerificationStageView(
                            stage_id=stage.stage_id,
                            sequence_number=stage.sequence_number,
                            required=stage.required,
                            passed=stage.passed,
                            duration_ms=stage.duration_ms,
                            details=self._bounded(stage.details) or "",
                            checks=tuple(
                                FunctionalCheckView(
                                    check_id=check.check_id,
                                    status=check.status,
                                    duration_ms=check.duration_ms,
                                    details=self._bounded(check.details) or "",
                                )
                                for check in checks
                            ),
                        )
                    )
                excerpt, truncated = self._diff_excerpt(session, attempt)
                views.append(
                    PatchAttemptView(
                        attempt_number=attempt.attempt_number,
                        final_state=attempt.final_state,
                        patch_decision=attempt.patch_decision,
                        prepared_diff_sha256=attempt.prepared_diff_sha256,
                        files_changed=attempt.files_changed,
                        inserted_lines=attempt.inserted_lines,
                        deleted_lines=attempt.deleted_lines,
                        total_diff_bytes=attempt.total_diff_bytes,
                        changed_paths=self._json_string_tuple(attempt.changed_paths_json),
                        rejection_reason=self._bounded(attempt.rejection_reason),
                        failure_reason=self._bounded(attempt.failure_reason),
                        accepted_commit_sha=attempt.accepted_commit_sha,
                        diff_excerpt=excerpt,
                        diff_truncated=truncated,
                        stages=tuple(stage_views),
                    )
                )
            return PatchVerificationView(run_id=run_id, attempts=tuple(views))

    def scores(self, run_id: str) -> RunScoresView:
        with self._factory() as session:
            run, config = self._run_and_config(session, run_id)
            if config.research_question == "rq2":
                return RunScoresView(run_id=run_id, applicability="not_applicable", scores=())
            rows = list(
                session.scalars(
                    select(ScoreRecordRow)
                    .where(ScoreRecordRow.run_id == run_id)
                    .order_by(ScoreRecordRow.score_type, ScoreRecordRow.scoring_version)
                )
            )
            if not rows and run.status in {"created", "running"}:
                applicability = "ineligible_incomplete"
            elif not rows:
                applicability = "not_scored"
            else:
                applicability = "scored"
            return RunScoresView(
                run_id=run_id,
                applicability=applicability,
                scores=tuple(self._score_view(session, row) for row in rows),
            )

    def audit(self, run_id: str) -> AuditView:
        with self._factory() as session:
            self._require_run(session, run_id)
            manifest = session.get(AuditRunManifestRow, run_id)
            policy_rows = list(
                session.scalars(
                    select(PolicyEventReferenceRow)
                    .where(PolicyEventReferenceRow.run_id == run_id)
                    .order_by(PolicyEventReferenceRow.id)
                    .limit(MAX_POLICY_EVENTS)
                )
            )
            return AuditView(
                run_id=run_id,
                audit_source=manifest.audit_source if manifest else None,
                event_count=manifest.event_count if manifest else 0,
                blocked_count=manifest.blocked_count if manifest else 0,
                failed_count=manifest.failed_count if manifest else 0,
                first_event_id=manifest.first_event_id if manifest else None,
                last_event_id=manifest.last_event_id if manifest else None,
                canonical_run_audit_sha256=(
                    manifest.canonical_run_audit_sha256 if manifest else None
                ),
                policy_events=tuple(
                    PolicyEventView(
                        audit_event_id=row.audit_event_id,
                        operation=row.operation,
                        policy_decision=row.policy_decision,
                        policy_reason=row.policy_reason,
                        execution_status=row.execution_status,
                        error_code=row.error_code,
                    )
                    for row in policy_rows
                ),
            )

    def rq1_metrics(self, *, final_only: bool = True) -> dict:
        return compute_rq1_metrics(self._research, final_only=final_only)

    def rq2_metrics(self, *, final_only: bool = True) -> dict:
        return compute_rq2_metrics(self._research, final_only=final_only)

    def rq3_metrics(self, *, final_only: bool = True) -> dict:
        return compute_rq3_metrics(self._research, final_only=final_only)

    def red_metrics(self, *, final_only: bool = True) -> dict:
        return compute_red_metrics(self._research, final_only=final_only)

    def normal_metrics(self, *, final_only: bool = True) -> dict:
        return compute_normal_application_task_success(self._research, final_only=final_only)

    @staticmethod
    def _run_statement():
        return select(ExperimentRunRow, ExperimentConfigurationRow).join(
            ExperimentConfigurationRow,
            ExperimentRunRow.config_id == ExperimentConfigurationRow.config_id,
        )

    def _run_and_config(
        self, session: Session, run_id: str
    ) -> tuple[ExperimentRunRow, ExperimentConfigurationRow]:
        row = session.execute(
            self._run_statement().where(ExperimentRunRow.run_id == run_id)
        ).one_or_none()
        if row is None:
            raise DashboardNotFoundError("run not found")
        return row[0], row[1]

    @staticmethod
    def _require_run(session: Session, run_id: str) -> ExperimentRunRow:
        run = session.get(ExperimentRunRow, run_id)
        if run is None:
            raise DashboardNotFoundError("run not found")
        return run

    def _run_item(
        self,
        session: Session,
        run: ExperimentRunRow,
        config: ExperimentConfigurationRow,
    ) -> RunListItem:
        score_rows = list(
            session.scalars(
                select(ScoreRecordRow).where(ScoreRecordRow.run_id == run.run_id)
            )
        )
        scores = {row.score_type: row.score_value for row in score_rows}
        return RunListItem(
            run_id=run.run_id,
            config_id=run.config_id,
            research_question=config.research_question,
            run_type=config.run_type,
            scenario_id=run.scenario_id,
            dataset_id=run.dataset_id,
            status=run.status,
            started_at=run.started_at,
            completed_at=run.completed_at,
            red_score=scores.get("red"),
            blue_score=scores.get("blue"),
        )

    def _score_view(self, session: Session, row: ScoreRecordRow) -> ScoreView:
        artifact_id, referenced_sha = self._parse_score_reference(row.evidence_reference)
        artifact = session.get(ResultArtifactRow, artifact_id) if artifact_id is not None else None
        integrity = False
        breakdown = None
        evidence_sha = None
        if artifact is not None:
            evidence_sha = artifact.payload_sha256
            actual_sha = hashlib.sha256(artifact.payload_json.encode("utf-8")).hexdigest()
            integrity = (
                artifact.artifact_type == ArtifactType.SCORE_RESULT.value
                and referenced_sha == artifact.payload_sha256
                and actual_sha == artifact.payload_sha256
            )
            if integrity:
                try:
                    candidate = ScoreResult.model_validate_json(artifact.payload_json)
                    integrity = (
                        candidate.run_id == row.run_id
                        and candidate.score_type.value == row.score_type
                        and candidate.scoring_version == row.scoring_version
                        and Decimal(candidate.final_score) == row.score_value
                    )
                    if integrity:
                        breakdown = candidate
                except Exception:
                    integrity = False
        return ScoreView(
            score_type=row.score_type,
            score_value=row.score_value,
            scoring_version=row.scoring_version,
            evidence_reference=row.evidence_reference,
            evidence_sha256=evidence_sha,
            evidence_integrity=integrity,
            breakdown=breakdown,
        )

    def _diff_excerpt(
        self, session: Session, attempt: PatchAttemptRow
    ) -> tuple[str | None, bool]:
        if attempt.prepared_patch_artifact_id is None:
            return None, False
        artifact = session.get(ResultArtifactRow, attempt.prepared_patch_artifact_id)
        if artifact is None or artifact.artifact_type != ArtifactType.PATCH_GENERATION_RESULT.value:
            return None, False
        try:
            payload = json.loads(artifact.payload_json)
            raw = str(payload["prepared_patch"]["unified_diff"])
        except Exception:
            return None, False
        lines = raw.splitlines()
        bounded_lines = lines[:MAX_DIFF_LINES]
        excerpt = "\n".join(bounded_lines)
        if len(excerpt) > MAX_DIFF_CHARS:
            excerpt = excerpt[:MAX_DIFF_CHARS]
        truncated = len(lines) > MAX_DIFF_LINES or len(raw) > len(excerpt)
        return excerpt, truncated

    @staticmethod
    def _parse_score_reference(reference: str) -> tuple[int | None, str | None]:
        parts = reference.split(":")
        if (
            len(parts) != 4
            or parts[0] != "result_artifact"
            or parts[2] != "sha256"
            or len(parts[3]) != 64
        ):
            return None, None
        try:
            artifact_id = int(parts[1])
        except ValueError:
            return None, None
        if artifact_id < 1 or any(char not in "0123456789abcdef" for char in parts[3]):
            return None, None
        return artifact_id, parts[3]

    @staticmethod
    def _json_string_tuple(value: str | None) -> tuple[str, ...]:
        if not value:
            return ()
        try:
            parsed = json.loads(value)
        except Exception:
            return ()
        if not isinstance(parsed, list):
            return ()
        return tuple(str(item)[:500] for item in parsed[:50])

    @staticmethod
    def _bounded(value: str | None) -> str | None:
        if value is None:
            return None
        return value[:MAX_TEXT_CHARS]
