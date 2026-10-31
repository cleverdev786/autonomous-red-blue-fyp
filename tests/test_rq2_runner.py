"""Focused Milestone 20 Part-A truth-isolated RQ2 execution tests."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import func, select

from experiments.rq2_dataset import RQ2_DATASET_ID, seed_evaluation_truth
from experiments.rq2_runner import RQ2ExperimentRunner
from llm.mock_provider import MockProvider
from orchestrator.policy_engine import PolicyEngine
from schemas.common import ClassificationLabel, ResearchQuestion, RunType
from schemas.experiments import (
    ClassificationMode,
    ExperimentConfiguration,
    ExperimentLimits,
    ModelConfiguration,
)
from services.audit_service import AuditService
from services.target_registry import TargetRegistry
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.models import AgentCallRow, EventClassificationRow
from storage.repositories import (
    EvaluationTruthRepository,
    ExperimentExecutionReadRepository,
    ExperimentWriteRepository,
)


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "experiments" / "datasets" / "rq2-classification-v1"
BASE = "a" * 40
TARGET_ID = "vulnerable-store"


def _registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


def _seed(tmp_path: Path, *, mode: ClassificationMode):
    database = tmp_path / f"rq2-{mode.value}.db"
    engine = create_database_engine(f"sqlite:///{database}", project_root=tmp_path)
    initialize_database(engine)
    factory = make_session_factory(engine)
    write = ExperimentWriteRepository(factory)
    seed_evaluation_truth(EvaluationTruthRepository(factory), dataset_dir=DATASET)
    config = ExperimentConfiguration(
        config_id=f"rq2-{mode.value}-development",
        run_type=RunType.DEVELOPMENT,
        research_question=ResearchQuestion.RQ2,
        dataset_id=RQ2_DATASET_ID,
        classification_mode=mode,
        model=ModelConfiguration(provider="mock", model_name="fixture", temperature=0),
        limits=ExperimentLimits(max_model_calls=100),
    )
    write.create_configuration(config)
    run_id = f"run-{mode.value}"
    write.create_run(
        run_id=run_id,
        config_id=config.config_id,
        repetition_index=1,
        baseline_commit=BASE,
        dataset_id=RQ2_DATASET_ID,
    )
    write.mark_running(run_id)
    return run_id, factory, write


def _runner(tmp_path: Path, factory, write, provider):
    registry = _registry()
    return RQ2ExperimentRunner(
        target_registry=registry,
        policy_engine=PolicyEngine(registry=registry, project_root=ROOT),
        provider=provider,
        audit_service=AuditService(project_root=tmp_path),
        execution_repository=ExperimentExecutionReadRepository(factory),
        write_repository=write,
    )


def test_rule_only_processes_all_frozen_inputs_without_a_provider(tmp_path: Path) -> None:
    run_id, factory, write = _seed(tmp_path, mode=ClassificationMode.RULE_ONLY)
    result = _runner(tmp_path, factory, write, provider=None).run(
        run_id=run_id,
        dataset_dir=DATASET,
        target_id=TARGET_ID,
    )
    assert result.observation_count == 60
    with factory() as session:
        observations = session.scalar(select(func.count()).select_from(EventClassificationRow))
        model_calls = session.scalar(select(func.count()).select_from(AgentCallRow))
    assert observations == 60
    assert model_calls == 0


def test_llm_only_records_one_model_call_per_observation_with_explicit_missing_usage(
    tmp_path: Path,
) -> None:
    run_id, factory, write = _seed(tmp_path, mode=ClassificationMode.LLM_ONLY)
    provider = MockProvider(
        blue_classification=ClassificationLabel.BENIGN,
        blue_confidence=0.75,
    )
    result = _runner(tmp_path, factory, write, provider=provider).run(
        run_id=run_id,
        dataset_dir=DATASET,
        target_id=TARGET_ID,
    )
    assert result.observation_count == 60
    with factory() as session:
        calls = tuple(
            session.scalars(select(AgentCallRow).order_by(AgentCallRow.sequence_number.asc()))
        )
        observations = session.scalar(select(func.count()).select_from(EventClassificationRow))
    assert observations == 60
    assert len(calls) == 60
    assert all(call.classification_observation_id is not None for call in calls)
    assert all(call.token_usage_status == "not_reported" for call in calls)
    assert all(call.input_tokens is None and call.output_tokens is None for call in calls)
    assert all(call.cost_status == "not_reported" for call in calls)
