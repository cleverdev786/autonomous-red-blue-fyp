"""Focused Milestone 15 SQLite/storage and observational-boundary tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
import hashlib
import inspect
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import select

import experiments.runner as experiment_runner_module
from experiments.analysis import validate_run_completeness
from experiments.runner import ExperimentRecorder
from schemas.blue_team import BlueTeamAnalysisResult, CodeFinding, TriageResult
from schemas.common import (
    AgentRole,
    ClassificationLabel,
    ResearchQuestion,
    RunStatus,
    RunType,
    WorkflowState,
)
from schemas.experiment_results import (
    AgentCallRecord,
    CostUsageStatus,
    RunProvenance,
    TokenUsageStatus,
)
from schemas.experiments import ClassificationMode, ExperimentConfiguration, ModelConfiguration
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from services.audit_service import AuditService
from storage.database import (
    DatabaseConfigurationError,
    create_database_engine,
    initialize_database,
    make_session_factory,
)
from storage.models import (
    AuditRunManifestRow,
    ExperimentRunRow,
    PolicyEventReferenceRow,
    ResultArtifactRow,
    RunClassificationRow,
)
from storage.repositories import (
    EvaluationTruthRepository,
    ExperimentWriteRepository,
    ResearchStorageError,
    canonical_sha256,
)


BASE = "c" * 40


def _config(*, config_id: str = "rq1-dev", rq: ResearchQuestion = ResearchQuestion.RQ1, run_type: RunType = RunType.DEVELOPMENT) -> ExperimentConfiguration:
    kwargs = {
        "config_id": config_id,
        "run_type": run_type,
        "research_question": rq,
        "repetitions": 2,
        "model": ModelConfiguration(provider="mock", model_name="fixture", temperature=0),
    }
    if rq == ResearchQuestion.RQ2:
        kwargs["dataset_id"] = "rq2-dataset"
    else:
        kwargs["scenario_ids"] = ("scenario-xss", "scenario-sqli")
    return ExperimentConfiguration(**kwargs)


def _provenance(*, rq: ResearchQuestion = ResearchQuestion.RQ1) -> RunProvenance:
    return RunProvenance(
        framework_git_commit=BASE,
        baseline_git_commit=BASE,
        prompt_set_version="prompts-v1",
        schema_set_version="schemas-v1",
        agent_configuration_version="agents-v1",
        context_policy_version="context-v1",
        scenario_version=None if rq == ResearchQuestion.RQ2 else "scenarios-v1",
        dataset_version="dataset-v1" if rq == ResearchQuestion.RQ2 else None,
        rule_version="rules-v1",
        test_suite_version="tests-v1",
        verification_policy_version="verify-v1",
        python_version="3.12",
        prompt_versions={AgentRole.BLUE_TRIAGE: "triage-v1"},
        random_seed=7,
    )


@pytest.fixture
def repositories(tmp_path: Path):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'research.db'}", project_root=tmp_path)
    initialize_database(engine)
    factory = make_session_factory(engine)
    return ExperimentWriteRepository(factory), EvaluationTruthRepository(factory), factory, engine


def _create_run(write: ExperimentWriteRepository, *, run_id: str = "run-one", rq: ResearchQuestion = ResearchQuestion.RQ1, run_type: RunType = RunType.DEVELOPMENT) -> ExperimentConfiguration:
    config = _config(config_id=f"cfg-{run_id}", rq=rq, run_type=run_type)
    write.create_configuration(config)
    write.create_run(
        run_id=run_id,
        config_id=config.config_id,
        repetition_index=1,
        baseline_commit=BASE,
        scenario_id=None if rq == ResearchQuestion.RQ2 else "scenario-xss",
        dataset_id="rq2-dataset" if rq == ResearchQuestion.RQ2 else None,
    )
    write.record_provenance(run_id, _provenance(rq=rq))
    write.mark_running(run_id)
    return config


def test_rq1_rq3_are_scenario_scoped_and_rq2_is_dataset_scoped() -> None:
    assert _config(rq=ResearchQuestion.RQ1).scenario_ids
    assert _config(rq=ResearchQuestion.RQ2).dataset_id == "rq2-dataset"
    with pytest.raises(ValidationError):
        ExperimentConfiguration(
            config_id="bad-rq2",
            run_type=RunType.DEVELOPMENT,
            research_question=ResearchQuestion.RQ2,
            scenario_ids=("fake",),
            model=ModelConfiguration(provider="mock", model_name="fixture"),
        )


def test_sqlite_database_is_local_and_rejects_non_sqlite_or_escape(tmp_path: Path) -> None:
    with pytest.raises(DatabaseConfigurationError):
        create_database_engine("postgresql://host/db", project_root=tmp_path)
    with pytest.raises(DatabaseConfigurationError):
        create_database_engine("sqlite:////tmp/outside.db", project_root=tmp_path)


def test_run_and_provenance_survive_file_backed_reopen(tmp_path: Path) -> None:
    db = tmp_path / "evidence.db"
    engine = create_database_engine(f"sqlite:///{db}", project_root=tmp_path)
    initialize_database(engine)
    write = ExperimentWriteRepository(make_session_factory(engine))
    _create_run(write, run_id="survives")
    engine.dispose()

    reopened = create_database_engine(f"sqlite:///{db}", project_root=tmp_path)
    factory = make_session_factory(reopened)
    with factory() as session:
        row = session.get(ExperimentRunRow, "survives")
        assert row is not None
        assert row.status == RunStatus.RUNNING.value


def test_failed_policy_blocked_and_interrupted_runs_remain_first_class(repositories) -> None:
    write, _, factory, _ = repositories
    for run_id, status in (("failed-run", RunStatus.FAILED), ("blocked-run", RunStatus.POLICY_BLOCKED)):
        _create_run(write, run_id=run_id)
        write.finalize_run(run_id, status=status, system_error_code="fixture-error", system_error_summary="retained")
    _create_run(write, run_id="interrupted")
    with factory() as session:
        assert session.get(ExperimentRunRow, "failed-run").status == "failed"
        assert session.get(ExperimentRunRow, "blocked-run").status == "policy_blocked"
        assert session.get(ExperimentRunRow, "interrupted").status == "running"


def test_duplicate_run_fails_visibly(repositories) -> None:
    write, _, _, _ = repositories
    config = _create_run(write, run_id="duplicate")
    with pytest.raises(ResearchStorageError):
        write.create_run(
            run_id="duplicate",
            config_id=config.config_id,
            repetition_index=2,
            baseline_commit=BASE,
            scenario_id="scenario-xss",
        )


def test_blue_result_atomically_derives_artifact_classification_and_code_finding(repositories) -> None:
    write, _, factory, _ = repositories
    _create_run(write, run_id="blue-run")
    result = BlueTeamAnalysisResult(
        run_id="blue-run",
        target_id="vulnerable-store",
        classification_mode=ClassificationMode.HYBRID,
        triage=TriageResult(
            run_id="blue-run",
            is_suspicious=True,
            classification=ClassificationLabel.XSS,
            confidence=0.9,
            supporting_event_ids=("evt-1",),
            reason="fixture",
        ),
        code_finding=CodeFinding(
            run_id="blue-run",
            file_path="dummy_apps/vulnerable_store/app/scenario_routes.py",
            function_or_route="xss_search",
            root_cause="fixture root cause",
            confidence=0.8,
        ),
        final_state=WorkflowState.PATCH_GENERATING,
    )
    artifact_id = write.record_blue_result(result)
    with factory() as session:
        artifact = session.get(ResultArtifactRow, artifact_id)
        classification = session.scalar(select(RunClassificationRow).where(RunClassificationRow.run_id == "blue-run"))
        assert artifact.payload_sha256 == canonical_sha256(artifact.payload_json)
        assert classification.predicted_label == ClassificationLabel.XSS.value
        assert classification.artifact_id == artifact_id


def test_ground_truth_repository_is_not_available_to_observational_runner(repositories) -> None:
    _, truth, _, _ = repositories
    source = inspect.getsource(experiment_runner_module)
    assert "EvaluationTruthRepository" not in source
    assert not hasattr(ExperimentWriteRepository, "record_scenario_truth")
    assert hasattr(truth, "record_scenario_truth")


def test_agent_usage_distinguishes_zero_from_not_reported() -> None:
    rule_only = AgentCallRecord(
        call_id="rule-none",
        agent_role=AgentRole.BLUE_TRIAGE,
        sequence_number=1,
        provider="deterministic",
        model_name="none",
        duration_ms=1,
        result_status=RunStatus.COMPLETED,
        token_usage_status=TokenUsageStatus.NOT_APPLICABLE,
        cost_status=CostUsageStatus.NOT_APPLICABLE,
    )
    assert rule_only.input_tokens is None
    missing = AgentCallRecord(
        call_id="llm-missing",
        agent_role=AgentRole.BLUE_TRIAGE,
        sequence_number=2,
        provider="mock",
        model_name="fixture",
        duration_ms=2,
        result_status=RunStatus.COMPLETED,
        token_usage_status=TokenUsageStatus.NOT_REPORTED,
        cost_status=CostUsageStatus.NOT_REPORTED,
    )
    assert missing.input_tokens is None
    with pytest.raises(ValidationError):
        AgentCallRecord(
            call_id="bad-telemetry",
            agent_role=AgentRole.BLUE_TRIAGE,
            sequence_number=3,
            provider="mock",
            model_name="fixture",
            duration_ms=2,
            result_status=RunStatus.COMPLETED,
            input_tokens=10,
            token_usage_status=TokenUsageStatus.NOT_REPORTED,
            cost_status=CostUsageStatus.NOT_REPORTED,
        )


def test_derived_cost_requires_reproducible_pricing_version() -> None:
    with pytest.raises(ValidationError):
        AgentCallRecord(
            call_id="bad-derived-cost",
            agent_role=AgentRole.BLUE_PATCH_GENERATION,
            sequence_number=1,
            provider="provider",
            model_name="model",
            duration_ms=3,
            result_status=RunStatus.COMPLETED,
            input_tokens=10,
            output_tokens=5,
            token_usage_status=TokenUsageStatus.REPORTED,
            estimated_cost=Decimal("0.001"),
            currency="USD",
            cost_status=CostUsageStatus.DERIVED,
        )


def test_audit_manifest_stores_digest_and_bounded_policy_references_not_full_payload(repositories, tmp_path: Path) -> None:
    write, _, factory, _ = repositories
    _create_run(write, run_id="audit-run")
    audit = AuditService(project_root=tmp_path)
    audit.record(
        run_id="audit-run",
        component="test",
        actor_type="service",
        operation="allowed_operation",
        target="secret-target-not-for-db-copy",
        policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
        execution_status=AuditExecutionStatus.SUCCEEDED,
    )
    audit.record(
        run_id="audit-run",
        component="test",
        actor_type="service",
        operation="blocked_operation",
        target="blocked-secret-target",
        policy_decision=AuditPolicyDecision.BLOCKED,
        execution_status=AuditExecutionStatus.BLOCKED,
        error_code="blocked-test",
    )
    before = audit.path.read_bytes()
    events = audit.read_run(run_id="audit-run")
    write.record_audit_manifest("audit-run", audit_source="data/audit/audit.jsonl", events=events)
    assert audit.path.read_bytes() == before
    with factory() as session:
        manifest = session.get(AuditRunManifestRow, "audit-run")
        refs = list(session.scalars(select(PolicyEventReferenceRow).where(PolicyEventReferenceRow.run_id == "audit-run")))
        assert manifest.event_count == 2 and manifest.blocked_count == 1
        assert len(refs) == 1
        assert "blocked-secret-target" not in repr(refs[0].__dict__)


def test_completeness_detects_unreported_usage_without_rewriting_it(repositories) -> None:
    write, _, _, _ = repositories
    _create_run(write, run_id="usage-run")
    write.record_agent_call("usage-run", AgentCallRecord(
        call_id="usage-missing",
        agent_role=AgentRole.BLUE_TRIAGE,
        sequence_number=1,
        provider="mock",
        model_name="fixture",
        duration_ms=2,
        result_status=RunStatus.COMPLETED,
        token_usage_status=TokenUsageStatus.NOT_REPORTED,
        cost_status=CostUsageStatus.NOT_REPORTED,
    ))
    from storage.repositories import ResearchReadRepository
    read = ResearchReadRepository(write._factory)
    result = validate_run_completeness(read, "usage-run")
    assert "token_usage_not_reported:usage-missing" in result["findings"]
    assert "cost_not_reported:usage-missing" in result["findings"]


def test_experiment_runner_is_observational_and_has_no_flow_or_condition_dispatch_imports() -> None:
    source = inspect.getsource(experiment_runner_module)
    for prohibited in (
        "RedTeamFlow",
        "BlueTeamFlow",
        "PatchGenerationFlow",
        "PatchBranchFlow",
        "PatchVerificationPipeline",
        "BlueTeamMode",
        "RetryFeedbackMode",
        "ExperienceMode",
        "selection_policy",
    ):
        assert prohibited not in source


def test_complete_accepted_patch_chain_persists_attempt_stages_checks_and_security_evidence(repositories) -> None:
    import hashlib
    from schemas.common import PatchDecision
    from schemas.git import PatchBranchResult
    from schemas.patches import (
        PatchGenerationResult,
        PatchProposal,
        PreparedFileChange,
        PreparedPatch,
        ProposedFileChange,
    )
    from schemas.red_team import TestExecutionResult
    from schemas.verification import (
        PatchVerificationResult,
        VerificationCheckResult,
        VerificationCheckStatus,
        VerificationResult,
        VerificationStageResult,
    )
    from storage.models import FunctionalCheckRow, PatchAttemptRow, SecurityTestExecutionRow, VerificationStageRow

    write, _, factory, _ = repositories
    _create_run(write, run_id="complete-run")
    before = "bad\n"
    after = "good\n"
    diff = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-bad\n+good\n"
    sha = lambda value: hashlib.sha256(value.encode()).hexdigest()
    prepared = PreparedPatch(
        run_id="complete-run",
        target_id="vulnerable-store",
        attempt_number=1,
        files=(PreparedFileChange(
            file_path="dummy_apps/vulnerable_store/app/file.py",
            original_sha256=sha(before),
            replacement_sha256=sha(after),
            replacement_content=after,
        ),),
        unified_diff=diff,
        diff_sha256=sha(diff),
        files_changed=1,
        inserted_lines=1,
        deleted_lines=1,
        total_diff_bytes=len(diff.encode()),
    )
    proposal = PatchProposal(
        run_id="complete-run",
        target_id="vulnerable-store",
        attempt_number=1,
        changes=(ProposedFileChange(
            file_path="dummy_apps/vulnerable_store/app/file.py",
            original_content=before,
            replacement_content=after,
            rationale="fixture",
        ),),
        security_rationale="fixture",
        expected_effect="fixture",
    )
    write.record_patch_generation_result(PatchGenerationResult(
        run_id="complete-run",
        target_id="vulnerable-store",
        attempt_number=1,
        proposal=proposal,
        prepared_patch=prepared,
        final_state=WorkflowState.PATCH_VALIDATING,
    ))
    git_diff = "diff --git a/file.py b/file.py\n+good\n"
    write.record_patch_branch_result(PatchBranchResult(
        run_id="complete-run",
        target_id="vulnerable-store",
        attempt_number=1,
        baseline_branch="main",
        base_commit=BASE,
        branch_name="agent-patch/complete-run/attempt-1",
        prepared_diff_sha256=prepared.diff_sha256,
        git_diff=git_diff,
        git_diff_sha256=sha(git_diff),
        changed_paths=("dummy_apps/vulnerable_store/app/file.py",),
        final_state=WorkflowState.PATCH_APPLYING,
    ))
    security_execution = TestExecutionResult(
        run_id="complete-run-security",
        target_id="vulnerable-store",
        test_id="xss-reflection-001",
        attempt_number=1,
        request_count=1,
        completed=True,
        status_code=200,
        evidence=(),
        duration_ms=4,
    )
    stages = (
        VerificationStageResult(
            stage_id="functional",
            passed=True,
            duration_ms=3,
            details="passed",
            checks=(VerificationCheckResult(
                check_id="health",
                status=VerificationCheckStatus.PASSED,
                duration_ms=1,
                details="passed",
            ),),
        ),
        VerificationStageResult(
            stage_id="security",
            passed=True,
            duration_ms=4,
            details="no evidence",
            test_execution=security_execution,
        ),
        VerificationStageResult(
            stage_id="original_replay",
            passed=True,
            duration_ms=4,
            details="no evidence",
            test_execution=security_execution.model_copy(update={"run_id": "complete-run-replay"}),
        ),
        VerificationStageResult(stage_id="regression", passed=True, duration_ms=2, details="passed"),
    )
    verification = VerificationResult(
        run_id="complete-run",
        patch_attempt_number=1,
        stages=stages,
        decision=PatchDecision.ACCEPTED,
        total_duration_ms=13,
    )
    write.record_patch_verification_result(PatchVerificationResult(
        run_id="complete-run",
        target_id="vulnerable-store",
        attempt_number=1,
        branch_name="agent-patch/complete-run/attempt-1",
        base_commit=BASE,
        git_diff_sha256=sha(git_diff),
        verification=verification,
        accepted_commit_sha="e" * 40,
        baseline_restored=True,
        final_state=WorkflowState.ACCEPTED,
    ))
    write.finalize_run("complete-run", status=RunStatus.ACCEPTED)

    with factory() as session:
        attempt = session.scalar(select(PatchAttemptRow).where(PatchAttemptRow.run_id == "complete-run"))
        assert attempt.accepted_commit_sha == "e" * 40
        assert len(list(session.scalars(select(VerificationStageRow).where(VerificationStageRow.patch_attempt_id == attempt.id)))) == 4
        assert len(list(session.scalars(select(FunctionalCheckRow).where(FunctionalCheckRow.patch_attempt_id == attempt.id)))) == 1
        purposes = {row.purpose for row in session.scalars(select(SecurityTestExecutionRow).where(SecurityTestExecutionRow.run_id == "complete-run"))}
        assert purposes == {"verification_security", "original_replay"}
        for artifact in session.scalars(select(ResultArtifactRow).where(ResultArtifactRow.run_id == "complete-run")):
            assert artifact.payload_sha256 == canonical_sha256(artifact.payload_json)


def test_patch_feedback_is_stored_as_inert_source_to_receiving_attempt_evidence(repositories) -> None:
    from schemas.patches import PatchRetryFeedback
    from storage.models import PatchFeedbackRow

    write, _, factory, _ = repositories
    _create_run(write, run_id="feedback-run")
    artifact_id = write.record_patch_retry_feedback(
        run_id="feedback-run",
        source_attempt_number=1,
        receiving_attempt_number=2,
        feedback=PatchRetryFeedback(
            failed_stage="regression",
            error_summary="sanitized failure",
        ),
    )
    with factory() as session:
        row = session.scalar(select(PatchFeedbackRow).where(PatchFeedbackRow.run_id == "feedback-run"))
        assert row.source_attempt_number == 1
        assert row.receiving_attempt_number == 2
        assert row.feedback_artifact_id == artifact_id
    with pytest.raises(ResearchStorageError):
        write.record_patch_retry_feedback(
            run_id="feedback-run",
            source_attempt_number=2,
            receiving_attempt_number=2,
            feedback=PatchRetryFeedback(failed_stage="regression", error_summary="bad linkage"),
        )
