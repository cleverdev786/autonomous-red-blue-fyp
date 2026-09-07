"""Milestone 15 deterministic research-metric tests from stored raw evidence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import select

from experiments.metrics import (
    compute_normal_application_task_success,
    compute_red_metrics,
    compute_rq1_metrics,
    compute_rq2_metrics,
    compute_rq3_metrics,
)
from schemas.blue_team import BlueTeamAnalysisResult, CodeFinding, TriageResult
from schemas.common import AgentRole, ClassificationLabel, ResearchQuestion, RunStatus, RunType, WorkflowState
from schemas.experiment_results import AgentCallRecord, CostUsageStatus, RunProvenance, TokenUsageStatus
from schemas.experiments import (
    BlueTeamMode,
    ClassificationMode,
    ExperimentConfiguration,
    ModelConfiguration,
    RetryFeedbackMode,
)
from schemas.scenarios import ScenarioGroundTruth
from schemas.scoring import ScoreComponentObservation, ScoreResult, ScoreType
from schemas.common import HttpMethod, VulnerabilityClass
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.models import (
    FunctionalCheckRow,
    PatchAttemptRow,
    PolicyEventReferenceRow,
    SecurityTestExecutionRow,
    VerificationStageRow,
)
from storage.repositories import (
    EvaluationTruthRepository,
    ExperimentWriteRepository,
    ResearchReadRepository,
    ScoreRepository,
)


BASE = "d" * 40
START = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def seeded(tmp_path: Path):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'metrics.db'}", project_root=tmp_path)
    initialize_database(engine)
    factory = make_session_factory(engine)
    write = ExperimentWriteRepository(factory)
    truth = EvaluationTruthRepository(factory)
    read = ResearchReadRepository(factory)
    return write, truth, read, factory


def _prov(*, rq2: bool = False) -> RunProvenance:
    return RunProvenance(
        framework_git_commit=BASE,
        baseline_git_commit=BASE,
        prompt_set_version="p-v1",
        schema_set_version="s-v1",
        agent_configuration_version="a-v1",
        context_policy_version="c-v1",
        scenario_version=None if rq2 else "scenario-v1",
        dataset_version="dataset-v1" if rq2 else None,
        rule_version="rule-v1",
        test_suite_version="tests-v1",
        verification_policy_version="verify-v1",
        python_version="3.12",
    )


def _config(*, config_id: str, rq: ResearchQuestion, blue=BlueTeamMode.MULTI_AGENT, classification=ClassificationMode.HYBRID, retry=RetryFeedbackMode.NONE) -> ExperimentConfiguration:
    return ExperimentConfiguration(
        config_id=config_id,
        run_type=RunType.FINAL_EVALUATION,
        research_question=rq,
        scenario_ids=() if rq == ResearchQuestion.RQ2 else ("scenario-xss",),
        dataset_id="dataset-rq2" if rq == ResearchQuestion.RQ2 else None,
        repetitions=1,
        blue_team_mode=blue,
        classification_mode=classification,
        retry_feedback_mode=retry,
        model=ModelConfiguration(provider="mock", model_name="fixture", temperature=0),
    )


def _run(write, config, run_id: str, *, start_offset: int = 0):
    write.create_configuration(config)
    write.create_run(
        run_id=run_id,
        config_id=config.config_id,
        repetition_index=1,
        baseline_commit=BASE,
        scenario_id=None if config.research_question == ResearchQuestion.RQ2 else "scenario-xss",
        dataset_id="dataset-rq2" if config.research_question == ResearchQuestion.RQ2 else None,
        started_at=START + timedelta(seconds=start_offset),
    )
    write.record_provenance(run_id, _prov(rq2=config.research_question == ResearchQuestion.RQ2))
    write.mark_running(run_id)


def _blue(write, run_id: str, *, mode: ClassificationMode, label: ClassificationLabel, file_path: str, function: str):
    write.record_blue_result(BlueTeamAnalysisResult(
        run_id=run_id,
        target_id="vulnerable-store",
        classification_mode=mode,
        triage=TriageResult(
            run_id=run_id,
            is_suspicious=label not in {ClassificationLabel.BENIGN, ClassificationLabel.UNKNOWN},
            classification=label,
            confidence=0.9,
            reason="fixture",
        ),
        code_finding=CodeFinding(
            run_id=run_id,
            file_path=file_path,
            function_or_route=function,
            root_cause="fixture",
            confidence=0.9,
        ),
        final_state=WorkflowState.PATCH_GENERATING,
    ))


def _patch(factory, *, run_id: str, attempt: int, state: str, prepared_ms: int, decision_ms: int, regression_pass: bool, replay_pass: bool, functional_statuses=("passed", "passed")):
    with factory() as session:
        row = PatchAttemptRow(
            run_id=run_id,
            attempt_number=attempt,
            final_state=state,
            patch_decision="accepted" if state == "accepted" else "rejected",
            patch_prepared_at=START + timedelta(milliseconds=prepared_ms),
            verification_decision_at=START + timedelta(milliseconds=decision_ms),
            attempt_completed_at=START + timedelta(milliseconds=decision_ms),
        )
        session.add(row)
        session.flush()
        session.add_all([
            VerificationStageRow(patch_attempt_id=row.id, stage_id="original_replay", sequence_number=1, required=True, passed=replay_pass, duration_ms=10, details="fixture"),
            VerificationStageRow(patch_attempt_id=row.id, stage_id="regression", sequence_number=2, required=True, passed=regression_pass, duration_ms=10, details="fixture"),
        ])
        for index, status in enumerate(functional_statuses, start=1):
            session.add(FunctionalCheckRow(
                patch_attempt_id=row.id,
                check_id=f"normal-{index}",
                status=status,
                duration_ms=1,
                details="fixture",
            ))
        session.commit()


def test_rq1_metrics_reproduce_acceptance_repair_regression_localization_time_and_usage(seeded) -> None:
    write, truth, read, factory = seeded
    truth.record_scenario_truth(ScenarioGroundTruth(
        scenario_id="scenario-xss",
        test_id="xss-reflection-001",
        vulnerability_class=VulnerabilityClass.XSS,
        endpoint="/scenarios/xss/search",
        method=HttpMethod.GET,
        input_field="q",
        vulnerable_source_file="dummy_apps/vulnerable_store/app/scenario_routes.py",
        vulnerable_function="xss_search",
        root_cause="fixture",
        expected_evidence="fixture",
        secure_behavior="fixture",
        normal_behavior="fixture",
        baseline_ref="baseline",
        reset_operation_id="reset",
    ), scenario_version="scenario-v1")

    multi = _config(config_id="rq1-multi", rq=ResearchQuestion.RQ1, blue=BlueTeamMode.MULTI_AGENT)
    single = _config(config_id="rq1-single", rq=ResearchQuestion.RQ1, blue=BlueTeamMode.SINGLE_AGENT)
    _run(write, multi, "multi-run")
    _run(write, single, "single-run", start_offset=10)
    _blue(write, "multi-run", mode=ClassificationMode.HYBRID, label=ClassificationLabel.XSS, file_path="dummy_apps/vulnerable_store/app/scenario_routes.py", function="xss_search")
    _blue(write, "single-run", mode=ClassificationMode.HYBRID, label=ClassificationLabel.SQL_INJECTION, file_path="wrong.py", function="wrong")
    _patch(factory, run_id="multi-run", attempt=1, state="accepted", prepared_ms=100, decision_ms=300, regression_pass=True, replay_pass=True)
    _patch(factory, run_id="single-run", attempt=1, state="rejected", prepared_ms=10100, decision_ms=10300, regression_pass=False, replay_pass=False, functional_statuses=("passed", "failed"))
    write.finalize_run("multi-run", status=RunStatus.ACCEPTED, completed_at=START + timedelta(milliseconds=400))
    write.finalize_run("single-run", status=RunStatus.REJECTED, completed_at=START + timedelta(seconds=10, milliseconds=400))
    write.record_agent_call("multi-run", AgentCallRecord(
        call_id="multi-call", agent_role=AgentRole.BLUE_TRIAGE, sequence_number=1,
        provider="mock", model_name="fixture", duration_ms=5, result_status=RunStatus.COMPLETED,
        input_tokens=100, output_tokens=20, token_usage_status=TokenUsageStatus.REPORTED,
        estimated_cost=Decimal("0.01"), currency="USD", pricing_version="price-v1", cost_status=CostUsageStatus.DERIVED,
    ))

    result = compute_rq1_metrics(read)
    m = result["conditions"]["multi_agent"]
    s = result["conditions"]["single_agent"]
    assert m["patch_acceptance_rate"] == 1.0 and m["eventual_repair_rate"] == 1.0
    assert s["patch_acceptance_rate"] == 0.0 and s["regression_rate"] == 1.0
    assert m["classification_accuracy"] == 1.0 and s["classification_accuracy"] == 0.0
    assert m["source_file_localization_accuracy"] == 1.0 and s["function_localization_accuracy"] == 0.0
    assert m["time_to_first_patch_ms"]["mean"] == 100.0
    assert m["time_to_accepted_patch_ms"]["mean"] == 300.0
    assert m["model_usage"]["input_tokens"] == 100
    assert m["model_usage"]["estimated_cost"] == "0.01000000"


def test_normal_application_task_success_counts_not_run_as_not_passed(seeded) -> None:
    write, _, read, factory = seeded
    config = _config(config_id="normal-tasks", rq=ResearchQuestion.RQ1)
    _run(write, config, "normal-run")
    _patch(factory, run_id="normal-run", attempt=1, state="rejected", prepared_ms=10, decision_ms=20, regression_pass=False, replay_pass=False, functional_statuses=("passed", "failed", "not_run"))
    metric = compute_normal_application_task_success(read)
    assert metric == {"passed": 1, "total": 3, "normal_application_task_success": pytest.approx(1 / 3)}


def test_rq2_metrics_recompute_all_five_labels_and_keep_unknown_usage_unknown(seeded) -> None:
    write, truth, read, _ = seeded
    actual = list(ClassificationLabel)
    predictions = {
        ClassificationMode.RULE_ONLY: actual,
        ClassificationMode.LLM_ONLY: [ClassificationLabel.XSS, ClassificationLabel.XSS, ClassificationLabel.PATH_TRAVERSAL, ClassificationLabel.SQL_INJECTION, ClassificationLabel.UNKNOWN],
        ClassificationMode.HYBRID: actual,
    }
    item_ids = []
    for index, label in enumerate(actual):
        item = truth.record_dataset_item(
            dataset_id="dataset-rq2",
            dataset_version="dataset-v1",
            event_id=f"evt-{index}",
            normalized_input={"event_id": f"input-{index}", "value": index},
        )
        truth.record_classification_truth(dataset_item_id=item, ground_truth_label=label)
        item_ids.append(item)

    for mode in ClassificationMode:
        config = _config(config_id=f"rq2-{mode.value}", rq=ResearchQuestion.RQ2, classification=mode)
        run_id = f"run-{mode.value}"
        _run(write, config, run_id)
        for index, (item, predicted) in enumerate(zip(item_ids, predictions[mode], strict=True)):
            obs_id = write.record_event_classification(
                run_id=run_id, dataset_item_id=item, classification_mode=mode,
                predicted_label=predicted, confidence=0.8, duration_ms=10 + index,
            )
            if mode != ClassificationMode.RULE_ONLY:
                write.record_agent_call(run_id, AgentCallRecord(
                    call_id=f"call-{mode.value}-{index}", agent_role=AgentRole.BLUE_TRIAGE,
                    sequence_number=index + 1, provider="mock", model_name="fixture", duration_ms=3,
                    result_status=RunStatus.COMPLETED, classification_observation_id=obs_id,
                    token_usage_status=TokenUsageStatus.NOT_REPORTED,
                    cost_status=CostUsageStatus.NOT_REPORTED,
                ))
        write.finalize_run(run_id, status=RunStatus.COMPLETED, completed_at=START + timedelta(seconds=1))

    metrics = compute_rq2_metrics(read)["conditions"]
    assert metrics["rule_only"]["accuracy"] == 1.0
    assert metrics["rule_only"]["macro_f1"] == 1.0
    assert metrics["rule_only"]["model_usage"]["model_calls"] == 0
    assert metrics["rule_only"]["model_usage"]["input_tokens"] == 0
    assert metrics["hybrid"]["unknown_rate"] == pytest.approx(1 / 5)
    llm = metrics["llm_only"]
    assert llm["accuracy"] == pytest.approx(3 / 5)
    assert llm["benign_false_positive_rate"] == 1.0
    assert llm["attack_detection_rate"] == 1.0
    assert llm["model_usage"]["model_calls"] == 5
    assert llm["model_usage"]["input_tokens"] is None
    assert llm["model_usage"]["token_usage_complete"] is False
    assert set(llm["confusion_matrix"]) == {label.value for label in ClassificationLabel}


def test_rq3_metrics_derive_second_attempt_acceptance_repeated_failure_and_additional_usage(seeded) -> None:
    write, _, read, factory = seeded
    for retry, run_id, second_state in (
        (RetryFeedbackMode.STRUCTURED, "rq3-structured", "accepted"),
        (RetryFeedbackMode.NONE, "rq3-none", "rejected"),
    ):
        config = _config(config_id=f"cfg-{run_id}", rq=ResearchQuestion.RQ3, retry=retry)
        _run(write, config, run_id)
        _patch(factory, run_id=run_id, attempt=1, state="rejected", prepared_ms=10, decision_ms=20, regression_pass=False, replay_pass=False)
        _patch(factory, run_id=run_id, attempt=2, state=second_state, prepared_ms=30, decision_ms=50, regression_pass=second_state == "accepted", replay_pass=second_state == "accepted")
        write.record_agent_call(run_id, AgentCallRecord(
            call_id=f"retry-{run_id}", agent_role=AgentRole.BLUE_PATCH_GENERATION, sequence_number=1,
            provider="mock", model_name="fixture", duration_ms=4, result_status=RunStatus.COMPLETED,
            patch_attempt_number=2, input_tokens=50, output_tokens=10,
            token_usage_status=TokenUsageStatus.REPORTED,
            estimated_cost=Decimal("0.005"), currency="USD", pricing_version="price-v1", cost_status=CostUsageStatus.DERIVED,
        ))
        write.finalize_run(run_id, status=RunStatus.ACCEPTED if second_state == "accepted" else RunStatus.REJECTED, completed_at=START + timedelta(milliseconds=60))

    result = compute_rq3_metrics(read)["conditions"]
    assert result["structured"]["second_attempt_acceptance_rate"] == 1.0
    assert result["structured"]["average_attempts_to_accepted_patch"] == 2
    assert result["structured"]["additional_model_usage"]["input_tokens"] == 50
    assert result["none"]["second_attempt_acceptance_rate"] == 0.0
    assert result["none"]["repeated_failure_rate"] == 1.0


def test_red_metrics_cover_confirmation_evidence_duplicates_policy_requests_and_time(seeded) -> None:
    write, _, read, factory = seeded
    config = _config(config_id="red-metrics", rq=ResearchQuestion.RQ1)
    _run(write, config, "red-run")
    with factory() as session:
        session.add_all([
            SecurityTestExecutionRow(
                run_id="red-run", purpose="red_attack", red_attempt_number=1, test_id="xss-reflection-001",
                vulnerability_class="xss", started_at=START, completed_at=START + timedelta(milliseconds=100), duration_ms=100,
                completed=True, timed_out=False, request_count=2, status_code=200, exploit_evidence_observed=True, confirmed=True,
            ),
            SecurityTestExecutionRow(
                run_id="red-run", purpose="red_attack", red_attempt_number=2, test_id="xss-reflection-001",
                vulnerability_class="xss", started_at=START + timedelta(milliseconds=120), completed_at=START + timedelta(milliseconds=200), duration_ms=80,
                completed=True, timed_out=False, request_count=1, status_code=200, exploit_evidence_observed=False, confirmed=False,
            ),
            PolicyEventReferenceRow(
                run_id="red-run", audit_event_id="audit-block", operation="test", policy_decision="blocked",
                execution_status="blocked",
            ),
        ])
        session.commit()
    metric = compute_red_metrics(read)
    assert metric["confirmed_attack_success_rate"] == 0.5
    assert metric["unconfirmed_claim_rate"] == 0.5
    assert metric["reproducible_evidence_rate"] == 0.5
    assert metric["duplicate_attempt_rate"] == 0.5
    assert metric["policy_violation_count"] == 1
    assert metric["requests_per_confirmed_vulnerability"] == 2
    assert metric["time_to_confirmed_vulnerability_ms"]["mean"] == 100.0


def test_development_runs_are_excluded_by_default(seeded) -> None:
    write, truth, read, _ = seeded
    for run_type, config_id, run_id in ((RunType.DEVELOPMENT, "dev-rq2", "dev-run"), (RunType.FINAL_EVALUATION, "final-rq2", "final-run")):
        config = ExperimentConfiguration(
            config_id=config_id, run_type=run_type, research_question=ResearchQuestion.RQ2,
            dataset_id="dataset-rq2", classification_mode=ClassificationMode.RULE_ONLY,
            model=ModelConfiguration(provider="mock", model_name="fixture"),
        )
        _run(write, config, run_id)
        item = truth.record_dataset_item(dataset_id="dataset-rq2", dataset_version="dataset-v1", event_id=f"evt-{run_id}", normalized_input={"run": run_id})
        truth.record_classification_truth(dataset_item_id=item, ground_truth_label=ClassificationLabel.BENIGN)
        write.record_event_classification(run_id=run_id, dataset_item_id=item, classification_mode=ClassificationMode.RULE_ONLY, predicted_label=ClassificationLabel.BENIGN, confidence=1.0, duration_ms=1)
    assert compute_rq2_metrics(read)["conditions"]["rule_only"]["sample_size_events"] == 1
    assert compute_rq2_metrics(read, final_only=False)["conditions"]["rule_only"]["sample_size_events"] == 2


def test_score_rows_cannot_change_research_metrics(seeded) -> None:
    write, truth, read, factory = seeded
    config = _config(config_id="score-rq1", rq=ResearchQuestion.RQ1)
    _run(write, config, "score-run")
    truth.record_scenario_truth(ScenarioGroundTruth(
        scenario_id="scenario-xss", test_id="xss-reflection-001", vulnerability_class=VulnerabilityClass.XSS,
        endpoint="/x", method=HttpMethod.GET, input_field="q", vulnerable_source_file="file.py",
        vulnerable_function="route", root_cause="x", expected_evidence="x", secure_behavior="x", normal_behavior="x",
        baseline_ref="baseline", reset_operation_id="reset",
    ), scenario_version="scenario-v1")
    _blue(write, "score-run", mode=ClassificationMode.HYBRID, label=ClassificationLabel.XSS, file_path="file.py", function="route")
    _patch(factory, run_id="score-run", attempt=1, state="accepted", prepared_ms=10, decision_ms=20, regression_pass=True, replay_pass=True)
    before = compute_rq1_metrics(read)
    ScoreRepository(factory).record_score(ScoreResult(
        run_id="score-run",
        score_type=ScoreType.BLUE,
        scoring_version="future-m16",
        components=(ScoreComponentObservation(
            component_id="fixture", observed=True, points_possible=100, points_awarded=100,
        ),),
        penalties=(),
        subtotal=100,
        total_penalty=0,
        final_score=100,
    ))
    after = compute_rq1_metrics(read)
    assert before == after
