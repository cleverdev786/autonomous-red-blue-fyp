"""Milestone 19 focused RQ3 patch/retry controller tests."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel
from sqlalchemy import select

from experiments.metrics import compute_rq3_metrics
from experiments.rq3_runner import (
    RQ3PatchRetryRunner,
    RQ3RunnerError,
    validate_rq3_configuration_pair,
)
from llm.mock_provider import MockProvider
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import BlueTeamAnalysisResult, CodeFinding, SourceLineRange, TriageResult
from schemas.common import (
    AgentRole,
    ClassificationLabel,
    PatchDecision,
    ResearchQuestion,
    RunStatus,
    RunType,
    VulnerabilityClass,
    WorkflowState,
)
from schemas.experiment_results import AgentCallRecord, CostUsageStatus, TokenUsageStatus
from schemas.experiments import (
    ClassificationMode,
    ExperimentConfiguration,
    ExperimentLimits,
    ModelConfiguration,
    RetryFeedbackMode,
)
from schemas.git import PatchBranchResult
from schemas.red_team import (
    AttackPlan,
    AttackVerification,
    EvidenceItem,
    ReconnaissanceResult,
    RedTeamRunResult,
    TestExecutionResult as RegisteredTestExecutionResult,
)
from schemas.verification import (
    PatchVerificationResult,
    VerificationResult,
    VerificationStageResult,
)
from services.audit_service import AuditService
from services.target_registry import TargetRegistry
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.models import AgentCallRow, Base, PatchAttemptRow, PatchFeedbackRow
from storage.repositories import ExperimentWriteRepository, ResearchReadRepository


ROOT = Path(__file__).resolve().parents[1]
BASE = "a" * 40
SOURCE = "dummy_apps/vulnerable_store/app/scenario_routes.py"


class CapturingProvider:
    def __init__(self, delegate=None) -> None:
        self.delegate = delegate or MockProvider()
        self.inputs: list[Mapping[str, Any]] = []

    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[BaseModel],
    ):
        self.inputs.append(input_data)
        return self.delegate.generate_structured(
            role=role,
            input_data=input_data,
            response_model=response_model,
        )


class FailSecondPatchCallProvider(CapturingProvider):
    def generate_structured(self, **kwargs):
        self.inputs.append(kwargs["input_data"])
        if len(self.inputs) == 2:
            raise RuntimeError("synthetic provider failure on authorized retry")
        return self.delegate.generate_structured(**kwargs)


class FakePatchBranchFlow:
    def __init__(self) -> None:
        self.expected_bases: list[str | None] = []

    def run(self, *, generation_result, expected_base_commit=None) -> PatchBranchResult:
        self.expected_bases.append(expected_base_commit)
        patch = generation_result.prepared_patch
        git_diff = patch.unified_diff
        return PatchBranchResult(
            run_id=generation_result.run_id,
            target_id=generation_result.target_id,
            attempt_number=generation_result.attempt_number,
            baseline_branch="main",
            base_commit=expected_base_commit or BASE,
            branch_name=(
                f"agent-patch/{generation_result.run_id}/attempt-{generation_result.attempt_number}"
            ),
            prepared_diff_sha256=patch.diff_sha256,
            git_diff=git_diff,
            git_diff_sha256=hashlib.sha256(git_diff.encode()).hexdigest(),
            changed_paths=tuple(item.file_path for item in patch.files),
            final_state=WorkflowState.PATCH_APPLYING,
        )


class ScriptedVerificationPipeline:
    def __init__(self, outcomes: tuple[WorkflowState, ...]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def run(self, *, branch_result, prepared_patch, red_run) -> PatchVerificationResult:
        outcome = self.outcomes[self.calls]
        self.calls += 1
        if outcome == WorkflowState.REJECTED:
            replay = red_run.execution.model_copy(
                update={"attempt_number": branch_result.attempt_number}
            )
            stages = (
                VerificationStageResult(
                    stage_id="regression",
                    required=True,
                    passed=False,
                    duration_ms=2,
                    details=(
                        "RAW_STDOUT /home/zain/project traceback token=must-not-reach-model"
                    ),
                ),
                VerificationStageResult(
                    stage_id="original_replay",
                    required=True,
                    passed=False,
                    duration_ms=2,
                    details="RAW original replay details",
                    test_execution=replay,
                ),
            )
            verification = VerificationResult(
                run_id=branch_result.run_id,
                patch_attempt_number=branch_result.attempt_number,
                stages=stages,
                decision=PatchDecision.REJECTED,
                rejection_reason="RAW rejection reason",
                total_duration_ms=4,
            )
            return PatchVerificationResult(
                run_id=branch_result.run_id,
                target_id=branch_result.target_id,
                attempt_number=branch_result.attempt_number,
                branch_name=branch_result.branch_name,
                base_commit=branch_result.base_commit,
                git_diff_sha256=branch_result.git_diff_sha256,
                verification=verification,
                baseline_restored=True,
                final_state=WorkflowState.REJECTED,
                failure_reason=verification.rejection_reason,
            )
        if outcome != WorkflowState.ACCEPTED:
            raise AssertionError(f"unsupported scripted outcome: {outcome}")
        stages = (
            VerificationStageResult(
                stage_id="regression",
                required=True,
                passed=True,
                duration_ms=2,
                details="Trusted regressions passed.",
            ),
        )
        verification = VerificationResult(
            run_id=branch_result.run_id,
            patch_attempt_number=branch_result.attempt_number,
            stages=stages,
            decision=PatchDecision.ACCEPTED,
            total_duration_ms=2,
        )
        return PatchVerificationResult(
            run_id=branch_result.run_id,
            target_id=branch_result.target_id,
            attempt_number=branch_result.attempt_number,
            branch_name=branch_result.branch_name,
            base_commit=branch_result.base_commit,
            git_diff_sha256=branch_result.git_diff_sha256,
            verification=verification,
            accepted_commit_sha="c" * 40,
            baseline_restored=True,
            final_state=WorkflowState.ACCEPTED,
        )


@pytest.fixture
def registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


@pytest.fixture
def repositories(tmp_path: Path):
    engine = create_database_engine(
        f"sqlite:///{tmp_path / 'rq3.db'}",
        project_root=tmp_path,
    )
    initialize_database(engine)
    factory = make_session_factory(engine)
    return ExperimentWriteRepository(factory), ResearchReadRepository(factory), factory


def _config(
    *,
    config_id: str,
    retry: RetryFeedbackMode,
    limits: ExperimentLimits | None = None,
) -> ExperimentConfiguration:
    return ExperimentConfiguration(
        config_id=config_id,
        run_type=RunType.DEVELOPMENT,
        research_question=ResearchQuestion.RQ3,
        scenario_ids=("scenario-xss",),
        repetitions=1,
        classification_mode=ClassificationMode.HYBRID,
        retry_feedback_mode=retry,
        model=ModelConfiguration(provider="mock", model_name="fixture", temperature=0),
        limits=limits or ExperimentLimits(max_patch_attempts=2, max_model_calls=10),
    )


def _seed_run(
    write: ExperimentWriteRepository,
    config: ExperimentConfiguration,
    run_id: str,
) -> None:
    write.create_configuration(config)
    write.create_run(
        run_id=run_id,
        config_id=config.config_id,
        repetition_index=1,
        baseline_commit=BASE,
        scenario_id="scenario-xss",
    )
    write.mark_running(run_id)


def _analysis(run_id: str) -> BlueTeamAnalysisResult:
    return BlueTeamAnalysisResult(
        run_id=run_id,
        target_id="vulnerable-store",
        classification_mode=ClassificationMode.HYBRID,
        triage=TriageResult(
            run_id=run_id,
            is_suspicious=True,
            classification=ClassificationLabel.XSS,
            confidence=1.0,
            supporting_event_ids=("evt-1",),
            reason="RQ3 fixture.",
        ),
        code_finding=CodeFinding(
            run_id=run_id,
            file_path=SOURCE,
            function_or_route="vulnerable_search",
            root_cause="RQ3 fixture.",
            supporting_lines=(SourceLineRange(start_line=80, end_line=80),),
            confidence=1.0,
        ),
        final_state=WorkflowState.CODE_ANALYSIS,
    )


def _red_run(run_id: str, registry: TargetRegistry) -> RedTeamRunResult:
    registered = registry.get_security_test("xss-reflection-001")
    evidence = EvidenceItem(
        evidence_id="red-evidence",
        evidence_type="response-marker",
        summary="Controlled exploit evidence.",
    )
    execution = RegisteredTestExecutionResult(
        run_id=run_id,
        target_id="vulnerable-store",
        test_id=registered.test_id,
        attempt_number=1,
        request_count=1,
        completed=True,
        timed_out=False,
        status_code=200,
        evidence=(evidence,),
        duration_ms=3,
    )
    return RedTeamRunResult(
        run_id=run_id,
        target_id="vulnerable-store",
        attempt_number=1,
        reconnaissance=ReconnaissanceResult(
            target_id="vulnerable-store",
            candidate_endpoints=(),
            rationale="Fixture.",
        ),
        attack_plan=AttackPlan(
            target_id="vulnerable-store",
            test_id=registered.test_id,
            endpoint_id=registered.endpoint_id,
            vulnerability_class=VulnerabilityClass.XSS,
            rationale="Fixture.",
        ),
        execution=execution,
        verification=AttackVerification(
            target_id="vulnerable-store",
            test_id=registered.test_id,
            confirmed=True,
            confidence=1.0,
            evidence_ids=(evidence.evidence_id,),
            reason="Fixture confirmed.",
        ),
        final_state=WorkflowState.BLUE_MONITORING,
    )


def _runner(
    *,
    registry: TargetRegistry,
    provider,
    branch_flow,
    verification_pipeline,
    write,
    read,
    tmp_path: Path,
) -> RQ3PatchRetryRunner:
    return RQ3PatchRetryRunner(
        target_registry=registry,
        policy_engine=PolicyEngine(registry=registry, project_root=ROOT),
        provider=provider,
        audit_service=AuditService(project_root=tmp_path / "audit"),
        project_root=ROOT,
        patch_branch_flow=branch_flow,
        verification_pipeline=verification_pipeline,
        read_repository=read,
        write_repository=write,
    )


def test_rq3_pair_validator_allows_only_retry_feedback_mode_difference() -> None:
    no_feedback = _config(config_id="rq3-none", retry=RetryFeedbackMode.NONE)
    structured = _config(config_id="rq3-structured", retry=RetryFeedbackMode.STRUCTURED)
    validate_rq3_configuration_pair(no_feedback, structured)

    changed = structured.model_copy(update={"repetitions": 2})
    with pytest.raises(RQ3RunnerError, match="repetitions"):
        validate_rq3_configuration_pair(no_feedback, changed)


def test_structured_retry_uses_previous_attempt_only_shared_budget_and_safe_feedback(
    registry: TargetRegistry,
    repositories,
    tmp_path: Path,
) -> None:
    write, read, factory = repositories
    config = _config(config_id="cfg-structured", retry=RetryFeedbackMode.STRUCTURED)
    run_id = "rq3-structured"
    _seed_run(write, config, run_id)
    write.record_agent_call(
        run_id,
        AgentCallRecord(
            call_id="prior-blue-call",
            agent_role=AgentRole.BLUE_TRIAGE,
            sequence_number=3,
            provider="mock",
            model_name="fixture",
            duration_ms=1,
            result_status=RunStatus.COMPLETED,
            token_usage_status=TokenUsageStatus.NOT_REPORTED,
            cost_status=CostUsageStatus.NOT_REPORTED,
        ),
    )

    tracker = RunLimitTracker(config.limits)
    tracker.consume_model_calls()
    provider = CapturingProvider()
    branch = FakePatchBranchFlow()
    verification = ScriptedVerificationPipeline(
        (WorkflowState.REJECTED, WorkflowState.ACCEPTED)
    )
    result = _runner(
        registry=registry,
        provider=provider,
        branch_flow=branch,
        verification_pipeline=verification,
        write=write,
        read=read,
        tmp_path=tmp_path,
    ).run(
        run_id=run_id,
        analysis=_analysis(run_id),
        red_run=_red_run(run_id, registry),
        limits=tracker,
    )

    assert [attempt.final_state for attempt in result.attempts] == [
        WorkflowState.REJECTED,
        WorkflowState.ACCEPTED,
    ]
    assert tracker.snapshot().patch_attempts == 2
    assert tracker.snapshot().model_calls == 3
    assert branch.expected_bases == [BASE, BASE]
    assert len(provider.inputs) == 2
    assert "retry_feedback" not in provider.inputs[0]
    second_input = provider.inputs[1]
    assert second_input["retry_feedback"]["failed_stage"] == "regression"
    serialized = repr(second_input)
    assert "RAW_STDOUT" not in serialized
    assert "/home/zain" not in serialized
    assert "traceback" not in serialized
    assert second_input["retry_feedback"]["regression_failure_ids"] == []

    with factory() as session:
        attempts = list(
            session.scalars(
                select(PatchAttemptRow)
                .where(PatchAttemptRow.run_id == run_id)
                .order_by(PatchAttemptRow.attempt_number)
            )
        )
        assert [row.final_state for row in attempts] == ["rejected", "accepted"]
        feedback = session.scalar(
            select(PatchFeedbackRow).where(PatchFeedbackRow.run_id == run_id)
        )
        assert feedback.source_attempt_number == 1
        assert feedback.receiving_attempt_number == 2
        calls = list(
            session.scalars(
                select(AgentCallRow)
                .where(AgentCallRow.run_id == run_id)
                .order_by(AgentCallRow.sequence_number)
            )
        )
        patch_calls = [call for call in calls if call.patch_attempt_number is not None]
        assert [call.sequence_number for call in patch_calls] == [4, 5]
        assert all(call.token_usage_status == "not_reported" for call in patch_calls)
        assert all(call.cost_status == "not_reported" for call in patch_calls)
        assert all(
            call.input_tokens is None and call.estimated_cost is None
            for call in patch_calls
        )

    assert len(Base.metadata.tables) == 20


def test_none_condition_never_persists_or_forwards_retry_feedback(
    registry: TargetRegistry,
    repositories,
    tmp_path: Path,
) -> None:
    write, read, factory = repositories
    config = _config(config_id="cfg-none", retry=RetryFeedbackMode.NONE)
    run_id = "rq3-none"
    _seed_run(write, config, run_id)
    provider = CapturingProvider()
    result = _runner(
        registry=registry,
        provider=provider,
        branch_flow=FakePatchBranchFlow(),
        verification_pipeline=ScriptedVerificationPipeline(
            (WorkflowState.REJECTED, WorkflowState.ACCEPTED)
        ),
        write=write,
        read=read,
        tmp_path=tmp_path,
    ).run(
        run_id=run_id,
        analysis=_analysis(run_id),
        red_run=_red_run(run_id, registry),
        limits=RunLimitTracker(config.limits),
    )

    assert len(result.attempts) == 2
    assert all("retry_feedback" not in item for item in provider.inputs)
    with factory() as session:
        assert session.scalar(
            select(PatchFeedbackRow).where(PatchFeedbackRow.run_id == run_id)
        ) is None


def test_authorized_retry_provider_failure_remains_as_failed_second_attempt_and_metric(
    registry: TargetRegistry,
    repositories,
    tmp_path: Path,
) -> None:
    write, read, factory = repositories
    config = _config(config_id="cfg-failed", retry=RetryFeedbackMode.STRUCTURED)
    run_id = "rq3-failed-retry"
    _seed_run(write, config, run_id)
    provider = FailSecondPatchCallProvider()
    tracker = RunLimitTracker(config.limits)
    result = _runner(
        registry=registry,
        provider=provider,
        branch_flow=FakePatchBranchFlow(),
        verification_pipeline=ScriptedVerificationPipeline((WorkflowState.REJECTED,)),
        write=write,
        read=read,
        tmp_path=tmp_path,
    ).run(
        run_id=run_id,
        analysis=_analysis(run_id),
        red_run=_red_run(run_id, registry),
        limits=tracker,
    )

    assert [attempt.final_state for attempt in result.attempts] == [
        WorkflowState.REJECTED,
        WorkflowState.FAILED,
    ]
    assert tracker.snapshot().patch_attempts == 2
    assert tracker.snapshot().model_calls == 2
    with factory() as session:
        second = session.scalar(
            select(PatchAttemptRow).where(
                PatchAttemptRow.run_id == run_id,
                PatchAttemptRow.attempt_number == 2,
            )
        )
        assert second is not None
        assert second.final_state == "failed"
        assert second.prepared_patch_artifact_id is None
        assert second.failure_reason.startswith("RuntimeError:")
        second_call = session.scalar(
            select(AgentCallRow).where(
                AgentCallRow.run_id == run_id,
                AgentCallRow.patch_attempt_number == 2,
            )
        )
        assert second_call.result_status == "failed"
        assert second_call.token_usage_status == "not_reported"
        assert second_call.cost_status == "not_reported"

    write.finalize_run(run_id, status=RunStatus.FAILED)
    metric = compute_rq3_metrics(read, final_only=False)["conditions"]["structured"]
    assert metric["eligible_failed_first_attempt_runs"] == 1
    assert metric["second_attempt_acceptance_rate"] == 0.0
    assert metric["second_attempt_failed_rate"] == 1.0
    assert metric["repeated_failure_rate"] == 0.0
    assert metric["second_attempt_outcome_counts"] == {
        "accepted": 0,
        "rejected": 0,
        "policy_blocked": 0,
        "failed": 1,
        "incomplete": 0,
    }
    assert metric["additional_model_usage"]["model_calls"] == 1
    assert metric["additional_model_usage"]["input_tokens"] is None


def test_second_attempt_model_budget_block_is_preserved_as_policy_blocked(
    registry: TargetRegistry,
    repositories,
    tmp_path: Path,
) -> None:
    write, read, factory = repositories
    limits_config = ExperimentLimits(max_patch_attempts=2, max_model_calls=1)
    config = _config(
        config_id="cfg-policy-blocked",
        retry=RetryFeedbackMode.STRUCTURED,
        limits=limits_config,
    )
    run_id = "rq3-policy-blocked-retry"
    _seed_run(write, config, run_id)
    provider = CapturingProvider()
    result = _runner(
        registry=registry,
        provider=provider,
        branch_flow=FakePatchBranchFlow(),
        verification_pipeline=ScriptedVerificationPipeline((WorkflowState.REJECTED,)),
        write=write,
        read=read,
        tmp_path=tmp_path,
    ).run(
        run_id=run_id,
        analysis=_analysis(run_id),
        red_run=_red_run(run_id, registry),
        limits=RunLimitTracker(config.limits),
    )

    assert [attempt.final_state for attempt in result.attempts] == [
        WorkflowState.REJECTED,
        WorkflowState.POLICY_BLOCKED,
    ]
    assert len(provider.inputs) == 1
    with factory() as session:
        second = session.scalar(
            select(PatchAttemptRow).where(
                PatchAttemptRow.run_id == run_id,
                PatchAttemptRow.attempt_number == 2,
            )
        )
        assert second is not None and second.final_state == "policy_blocked"

    write.finalize_run(run_id, status=RunStatus.POLICY_BLOCKED)
    metric = compute_rq3_metrics(read, final_only=False)["conditions"]["structured"]
    assert metric["second_attempt_policy_blocked_rate"] == 1.0
    assert metric["second_attempt_acceptance_rate"] == 0.0
