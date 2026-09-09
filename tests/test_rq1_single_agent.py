"""Milestone 17 RQ1 single-general-agent comparison tests."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
from pathlib import Path

import pytest
from sqlalchemy import select

from experiments.rq1_runner import (
    RQ1ExperimentRunner,
    RQ1RunnerError,
    validate_rq1_configuration_pair,
)
from llm.mock_provider import MockProvider
from orchestrator.policy_engine import PolicyEngine
from schemas.common import (
    AgentRole,
    ClassificationLabel,
    PatchDecision,
    ResearchQuestion,
    RunType,
    VulnerabilityClass,
    WorkflowState,
)
from schemas.experiments import (
    BlueTeamMode,
    ClassificationMode,
    ExperimentConfiguration,
    ModelConfiguration,
)
from schemas.git import PatchBranchResult
from schemas.logging import ApplicationEventType, ApplicationLogEvent, LogReadResult
from schemas.red_team import (
    AttackPlan,
    AttackVerification,
    EvidenceItem,
    ReconnaissanceResult,
    RedTeamRunResult,
    TestExecutionResult as RedTestExecutionResult,
)
from schemas.verification import (
    PatchVerificationResult,
    VerificationResult,
    VerificationStageResult,
)
from services.audit_service import AuditService
from services.target_registry import TargetRegistry
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.models import ExperimentConfigurationRow, ResultArtifactRow
from storage.repositories import ExperimentWriteRepository, ResearchReadRepository


ROOT = Path(__file__).resolve().parents[1]
BASE = "c" * 40
TARGET_ID = "vulnerable-store"
SCENARIO = "xss-search-001"
NOW = datetime(2026, 9, 9, tzinfo=UTC)


def _config(run_id: str, mode: BlueTeamMode, classification: ClassificationMode) -> ExperimentConfiguration:
    return ExperimentConfiguration(
        config_id=f"cfg-{run_id}",
        run_type=RunType.DEVELOPMENT,
        research_question=ResearchQuestion.RQ1,
        scenario_ids=(SCENARIO,),
        repetitions=1,
        blue_team_mode=mode,
        classification_mode=classification,
        model=ModelConfiguration(provider="mock", model_name="fixture", temperature=0),
    )


def _event(run_id: str) -> ApplicationLogEvent:
    return ApplicationLogEvent(
        schema_version="1.0",
        event_id=f"evt-{run_id}",
        timestamp=NOW,
        run_id=run_id,
        request_id=f"req-{run_id}",
        event_type=ApplicationEventType.VALIDATION_EVENT,
        component="vulnerable-store",
        route_name="search",
        method="GET",
        status_code=200,
        attributes={"value": "<script>fixture()</script>"},
    )


def _logs(run_id: str) -> LogReadResult:
    return LogReadResult(
        target_id=TARGET_ID,
        run_id=run_id,
        events=(_event(run_id),),
    )


def _red_run(run_id: str) -> RedTeamRunResult:
    evidence = EvidenceItem(
        evidence_id=f"evidence-{run_id}",
        evidence_type="registered-test",
        summary="Deterministic RQ1 fixture.",
    )
    return RedTeamRunResult(
        run_id=run_id,
        target_id=TARGET_ID,
        attempt_number=1,
        reconnaissance=ReconnaissanceResult(
            target_id=TARGET_ID,
            candidate_endpoints=(),
            rationale="Fixture.",
        ),
        attack_plan=AttackPlan(
            target_id=TARGET_ID,
            test_id="xss-reflection-001",
            endpoint_id="scenario-xss-search",
            vulnerability_class=VulnerabilityClass.XSS,
            rationale="Fixture.",
        ),
        execution=RedTestExecutionResult(
            run_id=run_id,
            target_id=TARGET_ID,
            test_id="xss-reflection-001",
            attempt_number=1,
            request_count=1,
            completed=True,
            status_code=200,
            evidence=(evidence,),
            duration_ms=1,
        ),
        verification=AttackVerification(
            target_id=TARGET_ID,
            test_id="xss-reflection-001",
            confirmed=True,
            confidence=1.0,
            evidence_ids=(evidence.evidence_id,),
            reason="Fixture.",
        ),
        final_state=WorkflowState.BLUE_MONITORING,
    )


class FakePatchBranchFlow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def run(self, *, generation_result, expected_base_commit=None):
        self.calls.append(generation_result.run_id)
        patch = generation_result.prepared_patch
        git_diff = patch.unified_diff
        return PatchBranchResult(
            run_id=generation_result.run_id,
            target_id=generation_result.target_id,
            attempt_number=generation_result.attempt_number,
            baseline_branch="main",
            base_commit=expected_base_commit or BASE,
            branch_name=f"agent-patch/{generation_result.run_id}/attempt-1",
            prepared_diff_sha256=patch.diff_sha256,
            git_diff=git_diff,
            git_diff_sha256=hashlib.sha256(git_diff.encode()).hexdigest(),
            changed_paths=tuple(item.file_path for item in patch.files),
            final_state=WorkflowState.PATCH_APPLYING,
        )


class FailingPatchBranchFlow:
    def run(self, *, generation_result, expected_base_commit=None):
        raise RuntimeError("synthetic branch failure")


class FakeVerificationPipeline:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def run(self, *, branch_result, prepared_patch, red_run):
        self.calls.append(branch_result.run_id)
        verification = VerificationResult(
            run_id=branch_result.run_id,
            patch_attempt_number=branch_result.attempt_number,
            stages=(
                VerificationStageResult(
                    stage_id="regression",
                    required=True,
                    passed=True,
                    duration_ms=1,
                    details="Common deterministic acceptance fixture.",
                ),
            ),
            decision=PatchDecision.ACCEPTED,
            total_duration_ms=1,
        )
        return PatchVerificationResult(
            run_id=branch_result.run_id,
            target_id=branch_result.target_id,
            attempt_number=branch_result.attempt_number,
            branch_name=branch_result.branch_name,
            base_commit=branch_result.base_commit,
            git_diff_sha256=branch_result.git_diff_sha256,
            verification=verification,
            accepted_commit_sha="d" * 40,
            baseline_restored=True,
            final_state=WorkflowState.ACCEPTED,
        )


def _runner(tmp_path: Path, *, run_id: str, mode: BlueTeamMode, classification: ClassificationMode):
    database = tmp_path / f"{run_id}.db"
    engine = create_database_engine(f"sqlite:///{database}", project_root=tmp_path)
    initialize_database(engine)
    factory = make_session_factory(engine)
    write = ExperimentWriteRepository(factory)
    read = ResearchReadRepository(factory)
    config = _config(run_id, mode, classification)
    write.create_configuration(config)
    write.create_run(
        run_id=run_id,
        config_id=config.config_id,
        repetition_index=1,
        baseline_commit=BASE,
        scenario_id=SCENARIO,
        started_at=NOW,
    )
    write.mark_running(run_id)

    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )
    provider = MockProvider(blue_classification=ClassificationLabel.XSS)
    branch = FakePatchBranchFlow()
    verification = FakeVerificationPipeline()
    runner = RQ1ExperimentRunner(
        target_registry=registry,
        policy_engine=PolicyEngine(registry=registry, project_root=ROOT),
        provider=provider,
        audit_service=AuditService(project_root=tmp_path / "audit"),
        project_root=ROOT,
        patch_branch_flow=branch,
        verification_pipeline=verification,
        read_repository=read,
        write_repository=write,
    )
    return runner, provider, branch, verification, factory, engine


def test_rq1_pair_validator_allows_only_blue_architecture_to_differ() -> None:
    single = _config("pair-single", BlueTeamMode.SINGLE_AGENT, ClassificationMode.HYBRID)
    multi = single.model_copy(
        update={
            "config_id": "cfg-pair-multi",
            "blue_team_mode": BlueTeamMode.MULTI_AGENT,
        }
    )
    validate_rq1_configuration_pair(single, multi)

    unfair = multi.model_copy(
        update={"classification_mode": ClassificationMode.LLM_ONLY}
    )
    with pytest.raises(RQ1RunnerError, match="classification_mode"):
        validate_rq1_configuration_pair(single, unfair)


def test_single_and_multi_conditions_share_pipeline_but_use_expected_agent_roles(tmp_path: Path) -> None:
    outputs = {}
    role_sets = {}

    for mode, expected_roles in (
        (
            BlueTeamMode.SINGLE_AGENT,
            (
                AgentRole.BLUE_SINGLE_AGENT,
                AgentRole.BLUE_SINGLE_AGENT,
                AgentRole.BLUE_SINGLE_AGENT,
                AgentRole.BLUE_SINGLE_AGENT,
            ),
        ),
        (
            BlueTeamMode.MULTI_AGENT,
            (
                AgentRole.BLUE_MONITORING,
                AgentRole.BLUE_TRIAGE,
                AgentRole.BLUE_CODE_ANALYSIS,
                AgentRole.BLUE_PATCH_GENERATION,
            ),
        ),
    ):
        run_id = f"rq1-{mode.value}"
        runner, provider, branch, verification, factory, engine = _runner(
            tmp_path / mode.value,
            run_id=run_id,
            mode=mode,
            classification=ClassificationMode.LLM_ONLY,
        )
        result = runner.run(
            run_id=run_id,
            logs=_logs(run_id),
            red_run=_red_run(run_id),
            expected_base_commit=BASE,
        )
        outputs[mode] = result
        role_sets[mode] = provider.call_roles
        assert provider.call_roles == expected_roles
        assert branch.calls == [run_id]
        assert verification.calls == [run_id]
        assert result.blue_team_mode == mode
        assert result.analysis.classification_mode == ClassificationMode.LLM_ONLY
        assert result.verification.final_state == WorkflowState.ACCEPTED
        assert result.patch_generation.proposal.proposed_security_test is None

        with factory() as session:
            stored_config = session.get(ExperimentConfigurationRow, f"cfg-{run_id}")
            assert stored_config.blue_team_mode == mode.value
            artifact_types = set(session.scalars(select(ResultArtifactRow.artifact_type)))
            assert {
                "monitoring_result",
                "blue_team_analysis_result",
                "patch_generation_result",
                "patch_branch_result",
                "patch_verification_result",
            }.issubset(artifact_types)
        engine.dispose()

    assert outputs[BlueTeamMode.SINGLE_AGENT].patch_generation.prepared_patch.diff_sha256 == (
        outputs[BlueTeamMode.MULTI_AGENT].patch_generation.prepared_patch.diff_sha256
    )
    assert set(role_sets[BlueTeamMode.SINGLE_AGENT]) == {AgentRole.BLUE_SINGLE_AGENT}


def test_rq1_runner_retains_completed_evidence_before_downstream_failure(tmp_path: Path) -> None:
    run_id = "retain-before-branch-failure"
    runner, provider, _, verification, factory, engine = _runner(
        tmp_path,
        run_id=run_id,
        mode=BlueTeamMode.SINGLE_AGENT,
        classification=ClassificationMode.LLM_ONLY,
    )
    runner.patch_branch_flow = FailingPatchBranchFlow()

    with pytest.raises(RuntimeError, match="synthetic branch failure"):
        runner.run(
            run_id=run_id,
            logs=_logs(run_id),
            red_run=_red_run(run_id),
            expected_base_commit=BASE,
        )

    assert provider.call_roles == (
        AgentRole.BLUE_SINGLE_AGENT,
        AgentRole.BLUE_SINGLE_AGENT,
        AgentRole.BLUE_SINGLE_AGENT,
        AgentRole.BLUE_SINGLE_AGENT,
    )
    assert verification.calls == []
    with factory() as session:
        artifact_types = tuple(
            session.scalars(
                select(ResultArtifactRow.artifact_type)
                .where(ResultArtifactRow.run_id == run_id)
                .order_by(ResultArtifactRow.artifact_id)
            )
        )
        assert artifact_types == (
            "monitoring_result",
            "blue_team_analysis_result",
            "patch_generation_result",
        )
    engine.dispose()


def test_rq1_runner_uses_stored_condition_not_a_second_mode_argument(tmp_path: Path) -> None:
    run_id = "stored-single"
    runner, provider, _, _, _, engine = _runner(
        tmp_path,
        run_id=run_id,
        mode=BlueTeamMode.SINGLE_AGENT,
        classification=ClassificationMode.HYBRID,
    )
    result = runner.run(
        run_id=run_id,
        logs=_logs(run_id),
        red_run=_red_run(run_id),
        expected_base_commit=BASE,
    )
    assert result.blue_team_mode == BlueTeamMode.SINGLE_AGENT
    assert result.analysis.classification_mode == ClassificationMode.HYBRID
    assert provider.call_roles == (
        AgentRole.BLUE_SINGLE_AGENT,
        AgentRole.BLUE_SINGLE_AGENT,
        AgentRole.BLUE_SINGLE_AGENT,
        AgentRole.BLUE_SINGLE_AGENT,
    )
    engine.dispose()


def test_rule_only_is_not_a_valid_single_general_agent_rq1_condition(tmp_path: Path) -> None:
    run_id = "single-rule-only"
    runner, provider, branch, verification, _, engine = _runner(
        tmp_path,
        run_id=run_id,
        mode=BlueTeamMode.SINGLE_AGENT,
        classification=ClassificationMode.RULE_ONLY,
    )
    with pytest.raises(RQ1RunnerError, match="requires the general Blue agent to produce classification"):
        runner.run(
            run_id=run_id,
            logs=_logs(run_id),
            red_run=_red_run(run_id),
            expected_base_commit=BASE,
        )
    assert provider.call_roles == ()
    assert branch.calls == []
    assert verification.calls == []
    engine.dispose()
