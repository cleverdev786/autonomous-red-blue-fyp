"""Milestone 17 bounded experience-memory and selection-policy tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from orchestrator.policy_engine import PolicyEngine
from orchestrator.selection_policy import SelectionPolicy, SelectionPolicyError
from schemas.common import AgentRole, ResearchQuestion, RunStatus, RunType
from schemas.experiment_results import ArtifactType, RunProvenance
from schemas.experiments import ExperienceMode, ExperimentConfiguration, ModelConfiguration
from services.experience_store import ExperienceStore, MAX_EXPERIENCE_RECORDS_PER_STRATEGY
from services.target_registry import TargetRegistry
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.models import Base, PatchAttemptRow, PolicyEventReferenceRow, ResultArtifactRow, ScoreRecordRow
from storage.repositories import (
    ExperimentWriteRepository,
    ResearchReadRepository,
    canonical_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
BASE = "c" * 40
SCENARIO = "xss-search-001"


def _repositories(tmp_path: Path):
    engine = create_database_engine(
        f"sqlite:///{tmp_path / 'experience.db'}",
        project_root=tmp_path,
    )
    initialize_database(engine)
    factory = make_session_factory(engine)
    return (
        ExperimentWriteRepository(factory),
        ResearchReadRepository(factory),
        factory,
        engine,
    )


def _policy() -> PolicyEngine:
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )
    return PolicyEngine(registry=registry, project_root=ROOT)


def _config() -> ExperimentConfiguration:
    return ExperimentConfiguration(
        config_id="rq1-experience",
        run_type=RunType.DEVELOPMENT,
        research_question=ResearchQuestion.RQ1,
        scenario_ids=(SCENARIO,),
        repetitions=100,
        model=ModelConfiguration(provider="mock", model_name="fixture", temperature=0),
    )


def _provenance(strategy_id: str) -> RunProvenance:
    return RunProvenance(
        framework_git_commit=BASE,
        baseline_git_commit=BASE,
        prompt_set_version="prompts-v1",
        schema_set_version="schemas-v1",
        agent_configuration_version=strategy_id,
        context_policy_version="context-v1",
        scenario_version="scenarios-v1",
        rule_version="rules-v1",
        test_suite_version="tests-v1",
        verification_policy_version="verify-v1",
        python_version="3.12",
        prompt_versions={AgentRole.BLUE_TRIAGE: "triage-v1"},
    )


def _seed_run(
    *,
    write: ExperimentWriteRepository,
    factory,
    config: ExperimentConfiguration,
    run_id: str,
    strategy_id: str,
    completed_at: datetime,
    score: Decimal | None,
    accepted: bool = True,
    duplicate: bool = False,
    blocked: int = 0,
) -> None:
    write.create_run(
        run_id=run_id,
        config_id=config.config_id,
        repetition_index=1,
        baseline_commit=BASE,
        scenario_id=SCENARIO,
        started_at=completed_at - timedelta(seconds=1),
    )
    write.record_provenance(run_id, _provenance(strategy_id))
    write.mark_running(run_id)
    write.finalize_run(
        run_id,
        status=RunStatus.ACCEPTED if accepted else RunStatus.REJECTED,
        completed_at=completed_at,
    )

    with factory() as session:
        first = PatchAttemptRow(
            run_id=run_id,
            attempt_number=1,
            prepared_diff_sha256=("a" * 64),
            patch_decision="accepted" if accepted else "rejected",
            final_state="accepted" if accepted else "rejected",
        )
        session.add(first)
        if duplicate:
            session.add(
                PatchAttemptRow(
                    run_id=run_id,
                    attempt_number=2,
                    prepared_diff_sha256=("a" * 64),
                    patch_decision="rejected",
                    final_state="rejected",
                )
            )
        for index in range(blocked):
            session.add(
                PolicyEventReferenceRow(
                    run_id=run_id,
                    audit_event_id=f"audit-{run_id}-{index}",
                    operation="fixture_policy",
                    policy_decision="blocked",
                    policy_reason="prohibited_operation",
                    execution_status="blocked",
                    error_code="policy-blocked",
                )
            )
        if score is not None:
            session.add(
                ScoreRecordRow(
                    run_id=run_id,
                    score_type="blue",
                    score_value=score,
                    scoring_version="red-blue-v1",
                    evidence_reference=f"fixture:{run_id}",
                )
            )
        session.commit()


def test_experience_store_is_bounded_stable_and_does_not_read_ground_truth(tmp_path: Path) -> None:
    write, read, factory, engine = _repositories(tmp_path)
    config = _config()
    write.create_configuration(config)
    now = datetime(2026, 9, 9, tzinfo=UTC)

    for index in range(MAX_EXPERIENCE_RECORDS_PER_STRATEGY + 3):
        _seed_run(
            write=write,
            factory=factory,
            config=config,
            run_id=f"run-{index:02d}",
            strategy_id="agents-a-v1",
            completed_at=now + timedelta(minutes=index),
            score=Decimal("80"),
        )

    store = ExperienceStore(read)
    first = store.load_snapshot(
        scenario_id=SCENARIO,
        registered_strategy_ids=("agents-a-v1",),
    )
    second = store.load_snapshot(
        scenario_id=SCENARIO,
        registered_strategy_ids=("agents-a-v1",),
    )

    assert len(first.summaries) == MAX_EXPERIENCE_RECORDS_PER_STRATEGY
    assert first == second
    assert first.summaries[0].source_run_id == "run-22"
    assert first.summaries[-1].source_run_id == "run-03"
    assert all(item.scenario_id == SCENARIO for item in first.summaries)
    assert len(Base.metadata.tables) == 20
    engine.dispose()


def test_selection_rejects_unregistered_and_policy_overrides_history(tmp_path: Path) -> None:
    write, read, factory, engine = _repositories(tmp_path)
    config = _config()
    write.create_configuration(config)
    now = datetime(2026, 9, 9, tzinfo=UTC)
    _seed_run(
        write=write,
        factory=factory,
        config=config,
        run_id="high",
        strategy_id="agents-a-v1",
        completed_at=now,
        score=Decimal("100"),
    )
    _seed_run(
        write=write,
        factory=factory,
        config=config,
        run_id="low",
        strategy_id="agents-b-v1",
        completed_at=now + timedelta(seconds=1),
        score=Decimal("50"),
    )

    selector = SelectionPolicy(
        policy_engine=_policy(),
        registered_strategy_ids=("agents-a-v1", "agents-b-v1"),
    )
    with pytest.raises(SelectionPolicyError, match="unregistered"):
        selector.select(
            run_id="current",
            scenario_id=SCENARIO,
            experience_mode=ExperienceMode.DISABLED,
            candidate_strategy_ids=("invented-strategy",),
            policy_allowed_strategy_ids=("invented-strategy",),
            configured_strategy_id="agents-a-v1",
        )

    decision = selector.select(
        run_id="current",
        scenario_id=SCENARIO,
        experience_mode=ExperienceMode.ENABLED_EXPLORATORY,
        candidate_strategy_ids=("agents-a-v1", "agents-b-v1"),
        policy_allowed_strategy_ids=("agents-b-v1",),
        configured_strategy_id="agents-a-v1",
        experience_store=ExperienceStore(read),
    )
    assert decision.eligible_strategy_ids == ("agents-b-v1",)
    assert decision.selected_strategy_id == "agents-b-v1"
    engine.dispose()


def test_disabled_mode_does_zero_lookup_and_missing_score_is_not_zero(tmp_path: Path) -> None:
    write, read, factory, engine = _repositories(tmp_path)
    config = _config()
    write.create_configuration(config)
    now = datetime(2026, 9, 9, tzinfo=UTC)
    _seed_run(
        write=write,
        factory=factory,
        config=config,
        run_id="a-scored",
        strategy_id="agents-a-v1",
        completed_at=now,
        score=Decimal("80"),
    )
    _seed_run(
        write=write,
        factory=factory,
        config=config,
        run_id="a-unscored",
        strategy_id="agents-a-v1",
        completed_at=now + timedelta(seconds=1),
        score=None,
    )
    _seed_run(
        write=write,
        factory=factory,
        config=config,
        run_id="b-scored",
        strategy_id="agents-b-v1",
        completed_at=now + timedelta(seconds=2),
        score=Decimal("70"),
    )

    store = ExperienceStore(read)
    selector = SelectionPolicy(
        policy_engine=_policy(),
        registered_strategy_ids=("agents-a-v1", "agents-b-v1"),
    )

    class FailIfRead:
        def load_snapshot(self, **kwargs):
            raise AssertionError("disabled mode must not read experience")

    disabled = selector.select(
        run_id="disabled",
        scenario_id=SCENARIO,
        experience_mode=ExperienceMode.DISABLED,
        candidate_strategy_ids=("agents-a-v1", "agents-b-v1"),
        policy_allowed_strategy_ids=("agents-a-v1", "agents-b-v1"),
        configured_strategy_id="agents-b-v1",
        experience_store=FailIfRead(),
    )
    assert disabled.selected_strategy_id == "agents-b-v1"

    exploratory = selector.select(
        run_id="current",
        scenario_id=SCENARIO,
        experience_mode=ExperienceMode.ENABLED_EXPLORATORY,
        candidate_strategy_ids=("agents-a-v1", "agents-b-v1"),
        policy_allowed_strategy_ids=("agents-a-v1", "agents-b-v1"),
        configured_strategy_id="agents-b-v1",
        experience_store=store,
    )
    by_id = {item.strategy_id: item for item in exploratory.observations}
    assert by_id["agents-a-v1"].total_history_count == 2
    assert by_id["agents-a-v1"].scored_history_count == 1
    assert by_id["agents-a-v1"].mean_blue_score == Decimal("80")
    assert exploratory.selected_strategy_id == "agents-a-v1"
    engine.dispose()


def test_experience_summary_cannot_encode_new_capabilities() -> None:
    with pytest.raises(ValidationError):
        from schemas.experience import ExperienceSummary

        ExperienceSummary.model_validate(
            {
                "source_run_id": "run-safe",
                "scenario_id": SCENARIO,
                "strategy_id": "agents-a-v1",
                "run_status": "accepted",
                "blue_score": "90",
                "patch_accepted": True,
                "regression_detected": False,
                "policy_block_count": 0,
                "duplicate_patch_count": 0,
                "attempt_count": 1,
                "target_id": "invented-target",
                "endpoint": "https://example.invalid",
                "tool": "shell",
                "path": "/tmp/escape",
                "max_patch_attempts": 999,
            }
        )


@pytest.mark.parametrize("rq", [ResearchQuestion.RQ1, ResearchQuestion.RQ2])
@pytest.mark.parametrize(
    "mode",
    [ExperienceMode.FROZEN_IDENTICAL, ExperienceMode.ENABLED_EXPLORATORY],
)
def test_final_primary_rq1_rq2_require_experience_disabled(
    rq: ResearchQuestion,
    mode: ExperienceMode,
) -> None:
    kwargs = {
        "config_id": f"{rq.value}-final-{mode.value}",
        "run_type": RunType.FINAL_EVALUATION,
        "research_question": rq,
        "experience_mode": mode,
        "model": ModelConfiguration(provider="mock", model_name="fixture", temperature=0),
    }
    if rq == ResearchQuestion.RQ2:
        kwargs["dataset_id"] = "rq2-dataset"
    else:
        kwargs["scenario_ids"] = (SCENARIO,)
    with pytest.raises(Exception, match="must keep experience-guided selection disabled"):
        ExperimentConfiguration(**kwargs)


def test_frozen_identical_uses_only_supplied_snapshot(tmp_path: Path) -> None:
    write, read, factory, engine = _repositories(tmp_path)
    config = _config()
    write.create_configuration(config)
    now = datetime(2026, 9, 9, tzinfo=UTC)
    _seed_run(
        write=write,
        factory=factory,
        config=config,
        run_id="frozen-a",
        strategy_id="agents-a-v1",
        completed_at=now,
        score=Decimal("90"),
    )
    snapshot = ExperienceStore(read).load_snapshot(
        scenario_id=SCENARIO,
        registered_strategy_ids=("agents-a-v1", "agents-b-v1"),
    )

    class FailIfRead:
        def load_snapshot(self, **kwargs):
            raise AssertionError("frozen mode must not consult live experience")

    selector = SelectionPolicy(
        policy_engine=_policy(),
        registered_strategy_ids=("agents-a-v1", "agents-b-v1"),
    )
    decision = selector.select(
        run_id="frozen-current",
        scenario_id=SCENARIO,
        experience_mode=ExperienceMode.FROZEN_IDENTICAL,
        candidate_strategy_ids=("agents-a-v1", "agents-b-v1"),
        policy_allowed_strategy_ids=("agents-a-v1", "agents-b-v1"),
        configured_strategy_id="agents-b-v1",
        experience_store=FailIfRead(),
        frozen_snapshot=snapshot,
    )
    assert decision.selected_strategy_id == "agents-a-v1"
    engine.dispose()


def test_duplicate_and_policy_blocked_history_is_penalized_and_decision_is_canonical(tmp_path: Path) -> None:
    write, read, factory, engine = _repositories(tmp_path)
    config = _config()
    write.create_configuration(config)
    now = datetime(2026, 9, 9, tzinfo=UTC)
    _seed_run(
        write=write,
        factory=factory,
        config=config,
        run_id="clean",
        strategy_id="agents-a-v1",
        completed_at=now,
        score=Decimal("80"),
        accepted=True,
    )
    _seed_run(
        write=write,
        factory=factory,
        config=config,
        run_id="penalized",
        strategy_id="agents-b-v1",
        completed_at=now + timedelta(seconds=1),
        score=Decimal("80"),
        accepted=True,
        duplicate=True,
        blocked=2,
    )
    write.create_run(
        run_id="current",
        config_id=config.config_id,
        repetition_index=1,
        baseline_commit=BASE,
        scenario_id=SCENARIO,
        started_at=now + timedelta(seconds=2),
    )

    selector = SelectionPolicy(
        policy_engine=_policy(),
        registered_strategy_ids=("agents-a-v1", "agents-b-v1"),
    )
    decision = selector.select(
        run_id="current",
        scenario_id=SCENARIO,
        experience_mode=ExperienceMode.ENABLED_EXPLORATORY,
        candidate_strategy_ids=("agents-a-v1", "agents-b-v1"),
        policy_allowed_strategy_ids=("agents-a-v1", "agents-b-v1"),
        configured_strategy_id="agents-b-v1",
        experience_store=ExperienceStore(read),
    )
    assert decision.selected_strategy_id == "agents-a-v1"
    assert decision.snapshot_sha256 is not None

    table_count_before = len(Base.metadata.tables)
    artifact_id = write.record_selection_decision(decision)
    assert len(Base.metadata.tables) == table_count_before == 20
    with factory() as session:
        artifact = session.get(ResultArtifactRow, artifact_id)
        assert artifact.artifact_type == ArtifactType.SELECTION_DECISION.value
        assert artifact.payload_sha256 == canonical_sha256(artifact.payload_json)
        assert session.scalar(
            select(func.count()).select_from(ResultArtifactRow).where(
                ResultArtifactRow.artifact_type == ArtifactType.SELECTION_DECISION.value
            )
        ) == 1
    engine.dispose()
