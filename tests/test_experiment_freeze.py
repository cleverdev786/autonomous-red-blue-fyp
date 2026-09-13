"""Focused Milestone 20 Part-A freeze/preflight infrastructure tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from git import Actor, Repo

from experiments.freeze import (
    ExperimentFreezeError,
    FinalEvaluationPreflightValidator,
    canonical_sha256,
    file_sha256,
    validate_rq2_configuration_set,
    validate_run_plan,
)
from llm.interface import (
    ProviderBindingError,
    require_research_recording_for_final_capable,
    validate_provider_binding,
)
from llm.research_provider import ResearchRecordingProvider
from llm.mock_provider import MockProvider
from schemas.common import AgentRole, ResearchQuestion, RunType
from schemas.experiment_freeze import (
    EnvironmentManifest,
    ExperimentFreezeManifest,
    ExperimentRunPlan,
    FrozenConfigurationReference,
    FrozenFileKind,
    FrozenFileReference,
    PromptAssetReference,
    RunPlanEntry,
)
from schemas.experiments import (
    ClassificationMode,
    ExperimentConfiguration,
    ExperimentLimits,
    ModelConfiguration,
    ProviderDescriptor,
)
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.repositories import ExperimentWriteRepository, ResearchStorageError


def _rq2_config(*, config_id: str, mode: ClassificationMode, repetitions: int = 1):
    return ExperimentConfiguration(
        config_id=config_id,
        run_type=RunType.FINAL_EVALUATION,
        research_question=ResearchQuestion.RQ2,
        dataset_id="rq2-classification",
        repetitions=repetitions,
        classification_mode=mode,
        model=ModelConfiguration(provider="mock", model_name="fixture", temperature=0),
        limits=ExperimentLimits(max_model_calls=100),
    )


def _freeze_repo(tmp_path: Path):
    repo = Repo.init(tmp_path)
    actor = Actor("M20 Test", "m20@example.invalid")
    (tmp_path / "parent.txt").write_text("parent\n", encoding="utf-8")
    repo.index.add(["parent.txt"])
    parent = repo.index.commit("parent", author=actor, committer=actor)

    (tmp_path / "frozen.txt").write_text("frozen\n", encoding="utf-8")
    (tmp_path / "prompt.json").write_text('{"prompt":"fixture"}\n', encoding="utf-8")
    repo.index.add(["frozen.txt", "prompt.json"])
    frozen = repo.index.commit("freeze", author=actor, committer=actor)
    repo.create_tag("freeze-v1", ref=frozen)
    return repo, parent.hexsha, frozen.hexsha


def _freeze_bundle(tmp_path: Path, config: ExperimentConfiguration):
    _, parent_sha, _ = _freeze_repo(tmp_path)
    environment = EnvironmentManifest(python_version="3.12", software_versions={})
    plan = ExperimentRunPlan(
        freeze_id="final-evaluation-v1",
        entries=(
            RunPlanEntry(
                entry_id="rq2-rule-1",
                config_id=config.config_id,
                research_question=ResearchQuestion.RQ2,
                repetition_index=1,
                baseline_git_commit=parent_sha,
                subject_version="v1",
                dataset_id="rq2-classification",
            ),
        ),
    )
    manifest = ExperimentFreezeManifest(
        freeze_id="final-evaluation-v1",
        framework_ref="freeze-v1",
        source_parent_commit=parent_sha,
        configuration_refs=(
            FrozenConfigurationReference(
                config_id=config.config_id,
                configuration_sha256=canonical_sha256(config),
            ),
        ),
        run_plan_sha256=canonical_sha256(plan),
        environment_manifest_sha256=canonical_sha256(environment),
        prompt_set_version="prompts-v1",
        schema_set_version="schemas-v1",
        agent_configuration_version="agents-v1",
        context_policy_version="context-v1",
        rule_version="rules-v1",
        test_suite_version="tests-v1",
        verification_policy_version="verify-v1",
        prompt_assets=(
            PromptAssetReference(
                prompt_id="blue-triage",
                version="triage-v1",
                role=AgentRole.BLUE_TRIAGE,
                path="prompt.json",
                sha256=file_sha256(tmp_path / "prompt.json"),
            ),
        ),
        frozen_files=(
            FrozenFileReference(
                path="frozen.txt",
                sha256=file_sha256(tmp_path / "frozen.txt"),
                kind=FrozenFileKind.SOURCE,
            ),
        ),
    )
    return parent_sha, environment, plan, manifest


def test_rq2_configuration_set_allows_only_classification_treatment_difference() -> None:
    configs = tuple(
        _rq2_config(config_id=f"rq2-{mode.value}", mode=mode)
        for mode in ClassificationMode
    )
    validate_rq2_configuration_set(configs)

    changed = configs[2].model_copy(
        update={"limits": ExperimentLimits(max_model_calls=99)}
    )
    with pytest.raises(ExperimentFreezeError, match="limits"):
        validate_rq2_configuration_set((configs[0], configs[1], changed))


def test_run_plan_requires_exact_configured_subject_and_repetition_coverage() -> None:
    config = _rq2_config(
        config_id="rq2-rule-plan",
        mode=ClassificationMode.RULE_ONLY,
        repetitions=2,
    )
    complete = ExperimentRunPlan(
        freeze_id="freeze-plan",
        entries=tuple(
            RunPlanEntry(
                entry_id=f"slot-{index}",
                config_id=config.config_id,
                research_question=ResearchQuestion.RQ2,
                repetition_index=index,
                baseline_git_commit="a" * 40,
                subject_version="v1",
                dataset_id="rq2-classification",
            )
            for index in (1, 2)
        ),
    )
    validate_run_plan(plan=complete, configurations=(config,))

    incomplete = complete.model_copy(update={"entries": complete.entries[:1]})
    with pytest.raises(ExperimentFreezeError, match="exactly cover"):
        validate_run_plan(plan=incomplete, configurations=(config,))


def test_rule_only_preflight_requires_no_provider_and_binds_exact_slot(tmp_path: Path) -> None:
    config = _rq2_config(config_id="rq2-rule-final", mode=ClassificationMode.RULE_ONLY)
    baseline, environment, plan, manifest = _freeze_bundle(tmp_path, config)
    receipt = FinalEvaluationPreflightValidator(
        project_root=tmp_path,
        manifest=manifest,
        run_plan=plan,
        configurations=(config,),
    ).validate(
        entry_id="rq2-rule-1",
        provider=None,
        baseline_git_commit=baseline,
        environment_manifest=environment,
    )
    assert receipt.config_id == config.config_id
    assert receipt.dataset_id == "rq2-classification"
    assert receipt.dataset_version == "v1"
    assert receipt.repetition_index == 1
    assert receipt.prompt_versions == {AgentRole.BLUE_TRIAGE: "triage-v1"}

    database = tmp_path / "evidence" / "final.db"
    database.parent.mkdir()
    engine = create_database_engine(f"sqlite:///{database}", project_root=tmp_path)
    initialize_database(engine)
    write = ExperimentWriteRepository(make_session_factory(engine))
    write.create_configuration(config)
    with pytest.raises(ResearchStorageError, match="preflight receipt"):
        write.create_run(
            run_id="blocked-without-preflight",
            config_id=config.config_id,
            repetition_index=1,
            baseline_commit=baseline,
            dataset_id="rq2-classification",
        )
    write.create_run(
        run_id="allowed-with-preflight",
        config_id=config.config_id,
        repetition_index=1,
        baseline_commit=baseline,
        dataset_id="rq2-classification",
        final_preflight=receipt,
    )


def test_mock_provider_can_never_satisfy_final_capable_binding() -> None:
    expected = ModelConfiguration(provider="mock", model_name="fixture", temperature=0)
    validate_provider_binding(provider=MockProvider(), expected=expected)
    with pytest.raises(ProviderBindingError, match="final_capable"):
        validate_provider_binding(
            provider=MockProvider(),
            expected=expected,
            require_final_capable=True,
        )


class _FinalCapableFixtureProvider:
    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider="fixture-provider",
            model_name="fixture-model",
            temperature=0,
            max_output_tokens=100,
            final_capable=True,
            identity_verified=True,
        )

    def generate_structured(self, **kwargs):
        return {}


def test_final_capable_provider_requires_common_research_wrapper_at_flow_boundary() -> None:
    raw = _FinalCapableFixtureProvider()
    with pytest.raises(ProviderBindingError, match="ResearchRecordingProvider"):
        require_research_recording_for_final_capable(raw)

    wrapped = ResearchRecordingProvider(
        delegate=raw,
        run_id="fixture-run",
        model_configuration=ModelConfiguration(
            provider="fixture-provider",
            model_name="fixture-model",
            temperature=0,
            max_output_tokens=100,
        ),
        write_repository=None,
        require_verified_binding=True,
    )
    assert wrapped.descriptor.research_recording is True
    require_research_recording_for_final_capable(wrapped)
