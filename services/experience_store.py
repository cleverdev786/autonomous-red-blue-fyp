"""Read-only bounded projection of canonical experiment evidence for Milestone 17."""

from __future__ import annotations

from decimal import Decimal

from sqlalchemy import func, select

from schemas.common import RunStatus
from schemas.experience import ExperienceSnapshot, ExperienceSummary
from storage.models import (
    ExperimentConfigurationRow,
    ExperimentRunRow,
    PatchAttemptRow,
    PolicyEventReferenceRow,
    RunProvenanceRow,
    ScoreRecordRow,
    VerificationStageRow,
)
from storage.repositories import ResearchReadRepository


MAX_EXPERIENCE_RECORDS_PER_STRATEGY = 20
EXPERIENCE_ORDERING_VERSION = "completed_started_run-v1"
EXPERIENCE_SCORE_VERSION = "red-blue-v1"
_TERMINAL_RUN_STATUSES = {
    RunStatus.ACCEPTED.value,
    RunStatus.REJECTED.value,
    RunStatus.FAILED.value,
    RunStatus.POLICY_BLOCKED.value,
    RunStatus.COMPLETED.value,
}


class ExperienceStore:
    """Project prior terminal outcomes into bounded summaries without truth reads."""

    def __init__(self, repository: ResearchReadRepository) -> None:
        self.repository = repository

    def load_snapshot(
        self,
        *,
        scenario_id: str,
        registered_strategy_ids: tuple[str, ...],
        exclude_run_id: str | None = None,
    ) -> ExperienceSnapshot:
        """Return at most the newest N terminal RQ1 runs per trusted strategy."""
        summaries: list[ExperienceSummary] = []

        with self.repository.session() as session:
            for strategy_id in sorted(set(registered_strategy_ids)):
                statement = (
                    select(ExperimentRunRow)
                    .join(
                        ExperimentConfigurationRow,
                        ExperimentConfigurationRow.config_id == ExperimentRunRow.config_id,
                    )
                    .join(
                        RunProvenanceRow,
                        RunProvenanceRow.run_id == ExperimentRunRow.run_id,
                    )
                    .where(
                        ExperimentConfigurationRow.research_question == "rq1",
                        ExperimentRunRow.scenario_id == scenario_id,
                        ExperimentRunRow.status.in_(_TERMINAL_RUN_STATUSES),
                        ExperimentRunRow.completed_at.is_not(None),
                        RunProvenanceRow.agent_configuration_version == strategy_id,
                    )
                    .order_by(
                        ExperimentRunRow.completed_at.desc(),
                        ExperimentRunRow.started_at.desc(),
                        ExperimentRunRow.run_id.asc(),
                    )
                    .limit(MAX_EXPERIENCE_RECORDS_PER_STRATEGY)
                )
                if exclude_run_id is not None:
                    statement = statement.where(ExperimentRunRow.run_id != exclude_run_id)

                for run in session.scalars(statement):
                    summaries.append(self._summary(session, run, strategy_id))

        return ExperienceSnapshot(
            scenario_id=scenario_id,
            history_limit_per_strategy=MAX_EXPERIENCE_RECORDS_PER_STRATEGY,
            ordering_version=EXPERIENCE_ORDERING_VERSION,
            summaries=tuple(summaries),
        )

    @staticmethod
    def _summary(session, run: ExperimentRunRow, strategy_id: str) -> ExperienceSummary:
        score = session.scalar(
            select(ScoreRecordRow.score_value).where(
                ScoreRecordRow.run_id == run.run_id,
                ScoreRecordRow.score_type == "blue",
                ScoreRecordRow.scoring_version == EXPERIENCE_SCORE_VERSION,
            )
        )
        attempts = list(
            session.scalars(
                select(PatchAttemptRow)
                .where(PatchAttemptRow.run_id == run.run_id)
                .order_by(PatchAttemptRow.attempt_number, PatchAttemptRow.id)
            )
        )
        seen_digests: set[str] = set()
        duplicate_count = 0
        for attempt in attempts:
            digest = attempt.prepared_diff_sha256
            if digest is None:
                continue
            if digest in seen_digests:
                duplicate_count += 1
            else:
                seen_digests.add(digest)

        regression_failures = session.scalar(
            select(func.count())
            .select_from(VerificationStageRow)
            .join(PatchAttemptRow, VerificationStageRow.patch_attempt_id == PatchAttemptRow.id)
            .where(
                PatchAttemptRow.run_id == run.run_id,
                VerificationStageRow.stage_id == "regression",
                VerificationStageRow.passed.is_(False),
            )
        )
        blocked_count = session.scalar(
            select(func.count())
            .select_from(PolicyEventReferenceRow)
            .where(
                PolicyEventReferenceRow.run_id == run.run_id,
                PolicyEventReferenceRow.policy_decision == "blocked",
            )
        )

        return ExperienceSummary(
            source_run_id=run.run_id,
            scenario_id=run.scenario_id,
            strategy_id=strategy_id,
            run_status=RunStatus(run.status),
            blue_score=Decimal(score) if score is not None else None,
            patch_accepted=any(item.patch_decision == "accepted" for item in attempts),
            regression_detected=bool(regression_failures),
            policy_block_count=int(blocked_count or 0),
            duplicate_patch_count=duplicate_count,
            attempt_count=len(attempts),
        )
