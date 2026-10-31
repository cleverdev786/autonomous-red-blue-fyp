"""Milestone 16 deterministic scoring and immutable score-evidence tests."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from orchestrator.scoring import DeterministicScorer, ScoringError, score_database_run
from schemas.blue_team import BlueTeamAnalysisResult, CodeFinding, TriageResult
from schemas.common import (
    ClassificationLabel,
    HttpMethod,
    ResearchQuestion,
    RunStatus,
    RunType,
    VulnerabilityClass,
    WorkflowState,
)
from schemas.experiment_freeze import FinalEvaluationPreflightReceipt
from schemas.experiment_results import ArtifactType, RunProvenance
from schemas.experiments import ClassificationMode, ExperimentConfiguration, ModelConfiguration
from schemas.red_team import (
    AttackPlan,
    AttackVerification,
    EvidenceItem,
    ReconnaissanceResult,
    RedTeamRunResult,
    TestExecutionResult as ExecutionResult,
)
from schemas.scenarios import ScenarioGroundTruth
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.models import (
    PatchAttemptRow,
    PolicyEventReferenceRow,
    ResultArtifactRow,
    ScoreRecordRow,
    SecurityTestExecutionRow,
    VerificationStageRow,
)
from storage.repositories import (
    EvaluationTruthRepository,
    ExperimentWriteRepository,
    ResearchStorageError,
    ScoreRepository,
    canonical_model_json,
    canonical_sha256,
)


BASE = "e" * 40
START = datetime(2026, 1, 1, tzinfo=UTC)
STAGES = (
    ("syntax_import", 5),
    ("application_startup", 5),
    ("functional", 10),
    ("security", 20),
    ("original_replay", 25),
    ("regression", 5),
)


@pytest.fixture
def seeded(tmp_path: Path):
    database = tmp_path / "scoring.db"
    engine = create_database_engine(f"sqlite:///{database}", project_root=tmp_path)
    initialize_database(engine)
    factory = make_session_factory(engine)
    return database, ExperimentWriteRepository(factory), EvaluationTruthRepository(factory), factory


def _config(run_id: str, *, rq: ResearchQuestion = ResearchQuestion.RQ1) -> ExperimentConfiguration:
    return ExperimentConfiguration(
        config_id=f"cfg-{run_id}",
        run_type=RunType.FINAL_EVALUATION,
        research_question=rq,
        scenario_ids=("scenario-xss",) if rq != ResearchQuestion.RQ2 else (),
        dataset_id="dataset-rq2" if rq == ResearchQuestion.RQ2 else None,
        repetitions=1,
        classification_mode=ClassificationMode.HYBRID,
        model=ModelConfiguration(provider="mock", model_name="fixture", temperature=0),
    )


def _synthetic_preflight(config: ExperimentConfiguration) -> FinalEvaluationPreflightReceipt:
    rq2 = config.research_question == ResearchQuestion.RQ2
    return FinalEvaluationPreflightReceipt(
        freeze_id="synthetic-final-fixture",
        freeze_manifest_sha256="1" * 64,
        run_plan_entry_id=f"entry-{config.config_id}",
        config_id=config.config_id,
        configuration_sha256=canonical_sha256(canonical_model_json(config)),
        research_question=config.research_question,
        repetition_index=1,
        framework_git_commit=BASE,
        baseline_git_commit=BASE,
        scenario_id="scenario-xss" if not rq2 else None,
        dataset_id="dataset-rq2" if rq2 else None,
        scenario_version="scenario-v1" if not rq2 else None,
        dataset_version="dataset-v1" if rq2 else None,
        prompt_set_version="prompts-v1",
        schema_set_version="schemas-v1",
        agent_configuration_version="agents-v1",
        context_policy_version="context-v1",
        rule_version="rules-v1",
        test_suite_version="tests-v1",
        verification_policy_version="verify-v1",
        environment_manifest_sha256="2" * 64,
        python_version="3.13",
    )


def _provenance(*, rq2: bool = False) -> RunProvenance:
    return RunProvenance(
        framework_git_commit=BASE,
        baseline_git_commit=BASE,
        prompt_set_version="prompts-v1",
        schema_set_version="schemas-v1",
        agent_configuration_version="agents-v1",
        context_policy_version="context-v1",
        scenario_version=None if rq2 else "scenario-v1",
        dataset_version="dataset-v1" if rq2 else None,
        rule_version="rules-v1",
        test_suite_version="tests-v1",
        verification_policy_version="verify-v1",
        python_version="3.13",
    )


def _truth(truth: EvaluationTruthRepository) -> None:
    truth.record_scenario_truth(
        ScenarioGroundTruth(
            scenario_id="scenario-xss",
            test_id="xss-reflection-001",
            vulnerability_class=VulnerabilityClass.XSS,
            endpoint="/scenarios/xss/search",
            method=HttpMethod.GET,
            input_field="q",
            vulnerable_source_file="dummy_apps/vulnerable_store/app/scenario_routes.py",
            vulnerable_function="xss_search",
            root_cause="fixture truth",
            expected_evidence="fixture evidence",
            secure_behavior="escaped output",
            normal_behavior="normal search works",
            baseline_ref="baseline",
            reset_operation_id="reset",
        ),
        scenario_version="scenario-v1",
    )


def _run(
    write: ExperimentWriteRepository,
    *,
    run_id: str,
    rq: ResearchQuestion = ResearchQuestion.RQ1,
) -> None:
    config = _config(run_id, rq=rq)
    write.create_configuration(config)
    write.create_run(
        run_id=run_id,
        config_id=config.config_id,
        repetition_index=1,
        baseline_commit=BASE,
        scenario_id="scenario-xss" if rq != ResearchQuestion.RQ2 else None,
        dataset_id="dataset-rq2" if rq == ResearchQuestion.RQ2 else None,
        started_at=START,
        final_preflight=_synthetic_preflight(config),
    )
    write.record_provenance(run_id, _provenance(rq2=rq == ResearchQuestion.RQ2))
    write.mark_running(run_id)


def _red_result(
    run_id: str, *, attempt: int = 1, test_id: str = "xss-reflection-001"
) -> RedTeamRunResult:
    evidence = EvidenceItem(
        evidence_id=f"evidence-{attempt}",
        evidence_type="registered-test",
        summary="deterministic registered-test evidence",
    )
    return RedTeamRunResult(
        run_id=run_id,
        target_id="vulnerable-store",
        attempt_number=attempt,
        reconnaissance=ReconnaissanceResult(
            target_id="vulnerable-store",
            candidate_endpoints=(),
            rationale="fixture",
        ),
        attack_plan=AttackPlan(
            target_id="vulnerable-store",
            test_id=test_id,
            endpoint_id="scenario-xss-search",
            vulnerability_class=VulnerabilityClass.XSS,
            rationale="registered test",
        ),
        execution=ExecutionResult(
            run_id=run_id,
            target_id="vulnerable-store",
            test_id=test_id,
            attempt_number=attempt,
            request_count=1,
            completed=True,
            timed_out=False,
            status_code=200,
            evidence=(evidence,),
            duration_ms=10,
        ),
        verification=AttackVerification(
            target_id="vulnerable-store",
            test_id=test_id,
            confirmed=True,
            confidence=1.0,
            evidence_ids=(evidence.evidence_id,),
            reason="confirmed by stored evidence",
        ),
        final_state=WorkflowState.BLUE_MONITORING,
    )


def _blue(write: ExperimentWriteRepository, run_id: str, *, correct: bool = True) -> None:
    write.record_blue_result(
        BlueTeamAnalysisResult(
            run_id=run_id,
            target_id="vulnerable-store",
            classification_mode=ClassificationMode.HYBRID,
            triage=TriageResult(
                run_id=run_id,
                is_suspicious=True,
                classification=(ClassificationLabel.XSS if correct else ClassificationLabel.SQL_INJECTION),
                confidence=0.9,
                reason="fixture",
            ),
            code_finding=CodeFinding(
                run_id=run_id,
                file_path=(
                    "dummy_apps/vulnerable_store/app/scenario_routes.py"
                    if correct
                    else "wrong.py"
                ),
                function_or_route="xss_search" if correct else "wrong",
                root_cause="fixture",
                confidence=0.9,
            ),
            final_state=WorkflowState.PATCH_GENERATING,
        )
    )


def _patch_attempt(
    factory,
    *,
    run_id: str,
    attempt_number: int,
    passed_stages: set[str],
    digest: str | None = None,
) -> None:
    with factory() as session:
        attempt = PatchAttemptRow(
            run_id=run_id,
            attempt_number=attempt_number,
            prepared_diff_sha256=digest or f"{attempt_number:064x}",
            final_state="accepted" if len(passed_stages) == len(STAGES) else "rejected",
            patch_decision="accepted" if len(passed_stages) == len(STAGES) else "rejected",
        )
        session.add(attempt)
        session.flush()
        for sequence, (stage_id, _) in enumerate(STAGES, start=1):
            session.add(
                VerificationStageRow(
                    patch_attempt_id=attempt.id,
                    stage_id=stage_id,
                    sequence_number=sequence,
                    required=True,
                    passed=stage_id in passed_stages,
                    duration_ms=1,
                    details=f"<script>stored-{stage_id}</script>",
                )
            )
        session.commit()


def _finish(write: ExperimentWriteRepository, run_id: str, status: RunStatus = RunStatus.ACCEPTED) -> None:
    write.finalize_run(run_id, status=status, completed_at=START)


def _perfect_run(seeded, run_id: str = "perfect"):
    database, write, truth, factory = seeded
    _truth(truth)
    _run(write, run_id=run_id)
    write.record_red_result(_red_result(run_id))
    _blue(write, run_id)
    _patch_attempt(
        factory,
        run_id=run_id,
        attempt_number=1,
        passed_stages={stage for stage, _ in STAGES},
        digest="a" * 64,
    )
    _finish(write, run_id)
    return database, write, truth, factory


def test_perfect_scores_persist_canonical_artifacts_and_recalculate_idempotently(seeded) -> None:
    _, _, _, factory = _perfect_run(seeded)
    scorer = DeterministicScorer(factory)
    first = scorer.score_run("perfect")
    assert [score.final_score for score in first.scores] == [100, 100]
    assert first.scores[1].selected_patch_attempt == 1

    second = scorer.score_run("perfect")
    assert second == first
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(ScoreRecordRow)) == 2
        artifacts = list(
            session.scalars(
                select(ResultArtifactRow).where(
                    ResultArtifactRow.artifact_type == ArtifactType.SCORE_RESULT.value
                )
            )
        )
        assert len(artifacts) == 2
        for artifact in artifacts:
            assert "vulnerable_source_file" not in artifact.payload_json
            assert "scenario_routes.py" not in artifact.payload_json
            assert artifact.payload_sha256


def test_red_score_does_not_trust_normalized_confirmed_column_without_canonical_handoff(seeded) -> None:
    _, write, truth, factory = seeded
    _truth(truth)
    _run(write, run_id="advisory-only")
    with factory() as session:
        session.add(
            SecurityTestExecutionRow(
                run_id="advisory-only",
                purpose="red_attack",
                red_attempt_number=1,
                test_id="xss-reflection-001",
                vulnerability_class="xss",
                duration_ms=1,
                completed=True,
                timed_out=False,
                request_count=1,
                exploit_evidence_observed=True,
                confirmed=True,
            )
        )
        session.commit()
    _finish(write, "advisory-only", RunStatus.REJECTED)
    outcome = DeterministicScorer(factory).score_run("advisory-only")
    red = next(score for score in outcome.scores if score.score_type.value == "red")
    assert red.final_score == 0


def test_policy_attribution_and_duplicate_penalties_are_exact_allowlists(seeded) -> None:
    _, write, _, factory = _perfect_run(seeded, run_id="penalties")
    with factory() as session:
        session.add_all(
            [
                SecurityTestExecutionRow(
                    run_id="penalties",
                    purpose="red_attack",
                    red_attempt_number=2,
                    test_id="xss-reflection-001",
                    vulnerability_class="xss",
                    duration_ms=1,
                    completed=True,
                    timed_out=False,
                    request_count=1,
                    exploit_evidence_observed=False,
                    confirmed=False,
                ),
                PolicyEventReferenceRow(
                    run_id="penalties",
                    audit_event_id="red-mapped",
                    operation="registered_test_authorization",
                    policy_decision="blocked",
                    policy_reason="unknown_test",
                    execution_status="blocked",
                ),
                PolicyEventReferenceRow(
                    run_id="penalties",
                    audit_event_id="neutral-git",
                    operation="verification_git_integrity",
                    policy_decision="blocked",
                    policy_reason="prohibited_operation",
                    execution_status="blocked",
                ),
                PolicyEventReferenceRow(
                    run_id="penalties",
                    audit_event_id="blue-mapped",
                    operation="patch_size_validation",
                    policy_decision="blocked",
                    policy_reason="patch_too_large",
                    execution_status="blocked",
                ),
            ]
        )
        original = session.scalar(
            select(PatchAttemptRow).where(
                PatchAttemptRow.run_id == "penalties", PatchAttemptRow.attempt_number == 1
            )
        )
        session.add(
            PatchAttemptRow(
                run_id="penalties",
                attempt_number=2,
                prepared_diff_sha256=original.prepared_diff_sha256,
                final_state="rejected",
                patch_decision="rejected",
            )
        )
        session.commit()

    outcome = DeterministicScorer(factory).score_run("penalties", persist=False)
    red = next(score for score in outcome.scores if score.score_type.value == "red")
    blue = next(score for score in outcome.scores if score.score_type.value == "blue")
    assert red.final_score == 70
    assert blue.final_score == 70
    assert red.attributed_policy_event_ids == ("red-mapped",)
    assert blue.attributed_policy_event_ids == ("blue-mapped",)


def test_blue_verification_uses_one_best_attempt_and_never_combines_stages(seeded) -> None:
    _, write, truth, factory = seeded
    _truth(truth)
    _run(write, run_id="single-attempt-rule")
    _blue(write, "single-attempt-rule")
    _patch_attempt(
        factory,
        run_id="single-attempt-rule",
        attempt_number=1,
        passed_stages={"syntax_import", "application_startup", "functional"},
        digest="b" * 64,
    )
    _patch_attempt(
        factory,
        run_id="single-attempt-rule",
        attempt_number=2,
        passed_stages={"security", "original_replay", "regression"},
        digest="c" * 64,
    )
    _finish(write, "single-attempt-rule", RunStatus.REJECTED)
    outcome = DeterministicScorer(factory).score_run("single-attempt-rule", persist=False)
    blue = next(score for score in outcome.scores if score.score_type.value == "blue")
    assert blue.selected_patch_attempt == 2
    assert blue.final_score == 80
    awarded = {item.component_id: item.points_awarded for item in blue.components}
    assert awarded["syntax_import"] == 0
    assert awarded["application_startup"] == 0
    assert awarded["functional"] == 0
    assert awarded["security"] == 20
    assert awarded["original_replay"] == 25
    assert awarded["regression"] == 5


def test_rq2_and_incomplete_runs_write_no_score_rows(seeded) -> None:
    _, write, _, factory = seeded
    _run(write, run_id="rq2-run", rq=ResearchQuestion.RQ2)
    _finish(write, "rq2-run", RunStatus.COMPLETED)
    rq2 = DeterministicScorer(factory).score_run("rq2-run")
    assert rq2.applicability.value == "not_applicable"

    _run(write, run_id="running-run")
    running = DeterministicScorer(factory).score_run("running-run")
    assert running.applicability.value == "ineligible_incomplete"

    created_config = _config("created-run")
    write.create_configuration(created_config)
    write.create_run(
        run_id="created-run",
        config_id=created_config.config_id,
        repetition_index=1,
        baseline_commit=BASE,
        scenario_id="scenario-xss",
        started_at=START,
        final_preflight=_synthetic_preflight(created_config),
    )
    created = DeterministicScorer(factory).score_run("created-run")
    assert created.applicability.value == "ineligible_incomplete"
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(ScoreRecordRow)) == 0


def test_same_version_changed_evidence_or_inconsistent_score_fails(seeded) -> None:
    _, _, _, factory = _perfect_run(seeded, run_id="immutable")
    scorer = DeterministicScorer(factory)
    scorer.score_run("immutable")

    with factory() as session:
        session.add(
            PolicyEventReferenceRow(
                run_id="immutable",
                audit_event_id="late-blue-policy",
                operation="patch_size_validation",
                policy_decision="blocked",
                policy_reason="patch_too_large",
                execution_status="blocked",
            )
        )
        session.commit()
    with pytest.raises(ResearchStorageError, match="same scoring version"):
        scorer.score_run("immutable")

    with factory() as session:
        blue = session.scalar(
            select(ScoreRecordRow).where(
                ScoreRecordRow.run_id == "immutable", ScoreRecordRow.score_type == "blue"
            )
        )
        blue.score_value = Decimal("99")
        session.commit()
    original_blue = next(
        score for score in scorer.score_run("immutable", persist=False).scores if score.score_type.value == "blue"
    )
    with pytest.raises(ResearchStorageError, match="inconsistent score"):
        ScoreRepository(factory).record_score(original_blue.model_copy(
            update={
                "penalties": tuple(
                    penalty
                    for penalty in original_blue.penalties
                    if penalty.penalty_id != "policy_violation"
                ) + (original_blue.penalties[-1].model_copy(update={
                    "observed_count": 0,
                    "counted_occurrences": 0,
                    "points_deducted": 0,
                    "evidence_ids": (),
                }),),
                "attributed_policy_event_ids": (),
                "total_penalty": 0,
                "final_score": 100,
            }
        ))



def test_same_version_same_score_but_changed_evidence_fails_and_new_version_is_separate(seeded) -> None:
    _, write, _, factory = _perfect_run(seeded, run_id="evidence-freeze")
    scorer = DeterministicScorer(factory)
    first = scorer.score_run("evidence-freeze")
    red_first = next(score for score in first.scores if score.score_type.value == "red")

    # A second independently trusted confirmation keeps Red at 100 but changes
    # the canonical evidence set, which must not overwrite red-blue-v1.
    write.record_red_result(
        _red_result("evidence-freeze", attempt=2, test_id="xss-reflection-002")
    )
    with pytest.raises(ResearchStorageError, match="changed score evidence"):
        scorer.score_run("evidence-freeze")

    ScoreRepository(factory).record_score(
        red_first.model_copy(update={"scoring_version": "red-blue-v2"})
    )
    with factory() as session:
        versions = list(
            session.scalars(
                select(ScoreRecordRow.scoring_version)
                .where(
                    ScoreRecordRow.run_id == "evidence-freeze",
                    ScoreRecordRow.score_type == "red",
                )
                .order_by(ScoreRecordRow.scoring_version)
            )
        )
        assert versions == ["red-blue-v1", "red-blue-v2"]

def test_database_unique_constraint_rejects_direct_duplicate_score_identity(seeded) -> None:
    _, _, _, factory = _perfect_run(seeded, run_id="unique")
    scorer = DeterministicScorer(factory)
    scorer.score_run("unique")
    with factory() as session:
        session.add(
            ScoreRecordRow(
                run_id="unique",
                score_type="red",
                score_value=Decimal("100"),
                scoring_version="red-blue-v1",
                evidence_reference="result_artifact:1:sha256:" + "a" * 64,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()


def test_offline_entry_point_requires_existing_database_and_persists_scores(seeded, tmp_path: Path) -> None:
    database, _, _, factory = _perfect_run(seeded, run_id="offline")
    outcome = score_database_run(database, "offline")
    assert outcome.applicability.value == "scored"
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(ScoreRecordRow)) == 2
    with pytest.raises(ScoringError, match="must already exist"):
        score_database_run(tmp_path / "missing.db", "offline")
