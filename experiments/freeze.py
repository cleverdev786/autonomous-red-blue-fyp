"""Milestone 20 deterministic experiment-freeze validation infrastructure."""

from __future__ import annotations

import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform

from git import Repo

from llm.interface import StructuredGenerationProvider, validate_provider_binding
from schemas.common import ResearchQuestion, RunType
from schemas.experiment_freeze import (
    EnvironmentManifest,
    ExperimentFreezeManifest,
    ExperimentRunPlan,
    FinalEvaluationPreflightReceipt,
    RunPlanEntry,
)
from schemas.experiment_results import RunProvenance
from schemas.experiments import ClassificationMode, ExperimentConfiguration


class ExperimentFreezeError(RuntimeError):
    """Raised when a freeze artifact or final-run precondition is invalid."""


def canonical_json(model) -> str:
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_sha256(model) -> str:
    return hashlib.sha256(canonical_json(model).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def capture_environment_manifest(
    *,
    package_names: tuple[str, ...],
    docker_version: str | None = None,
    compose_version: str | None = None,
) -> EnvironmentManifest:
    """Capture installed package versions without selecting any final model/provider."""
    versions: dict[str, str] = {}
    for package_name in package_names:
        try:
            versions[package_name] = metadata.version(package_name)
        except metadata.PackageNotFoundError as exc:
            raise ExperimentFreezeError(
                f"required package is not installed: {package_name}"
            ) from exc
    return EnvironmentManifest(
        python_version=platform.python_version(),
        software_versions=dict(sorted(versions.items())),
        docker_version=docker_version,
        compose_version=compose_version,
    )


def validate_rq2_configuration_set(
    configurations: tuple[ExperimentConfiguration, ...],
) -> None:
    """Require the three RQ2 treatments to differ only by ID/classification mode."""
    if len(configurations) != 3:
        raise ExperimentFreezeError("RQ2 final comparison requires exactly three configurations")
    if any(config.research_question != ResearchQuestion.RQ2 for config in configurations):
        raise ExperimentFreezeError("RQ2 configuration set contains a non-RQ2 configuration")
    modes = {config.classification_mode for config in configurations}
    if modes != set(ClassificationMode):
        raise ExperimentFreezeError("RQ2 configuration set must contain rule_only, llm_only, and hybrid")

    ignored = {"config_id", "classification_mode"}
    baseline = configurations[0].model_dump(mode="json", exclude=ignored)
    for config in configurations[1:]:
        candidate = config.model_dump(mode="json", exclude=ignored)
        if candidate != baseline:
            differing = tuple(
                sorted(key for key in baseline if baseline.get(key) != candidate.get(key))
            )
            raise ExperimentFreezeError(
                "RQ2 configurations differ outside classification treatment: "
                + ", ".join(differing)
            )


def validate_run_plan(
    *,
    plan: ExperimentRunPlan,
    configurations: tuple[ExperimentConfiguration, ...],
) -> None:
    by_id = {config.config_id: config for config in configurations}
    if len(by_id) != len(configurations):
        raise ExperimentFreezeError("configuration IDs must be unique")
    for entry in plan.entries:
        config = by_id.get(entry.config_id)
        if config is None:
            raise ExperimentFreezeError(f"run-plan entry uses unknown config: {entry.config_id}")
        if config.research_question != entry.research_question:
            raise ExperimentFreezeError("run-plan RQ does not match configuration")
        if entry.repetition_index > config.repetitions:
            raise ExperimentFreezeError("run-plan repetition exceeds configured repetitions")
        if entry.research_question == ResearchQuestion.RQ2:
            if entry.dataset_id != config.dataset_id or entry.scenario_id is not None:
                raise ExperimentFreezeError("RQ2 run-plan subject does not match configuration")
        else:
            if entry.scenario_id not in config.scenario_ids or entry.dataset_id is not None:
                raise ExperimentFreezeError("RQ1/RQ3 run-plan subject does not match configuration")

    expected_slots: set[tuple[str, int, str | None, str | None]] = set()
    for config in configurations:
        for repetition in range(1, config.repetitions + 1):
            if config.research_question == ResearchQuestion.RQ2:
                expected_slots.add((config.config_id, repetition, None, config.dataset_id))
            else:
                for scenario_id in config.scenario_ids:
                    expected_slots.add((config.config_id, repetition, scenario_id, None))
    actual_slots = {
        (entry.config_id, entry.repetition_index, entry.scenario_id, entry.dataset_id)
        for entry in plan.entries
    }
    if len(actual_slots) != len(plan.entries):
        raise ExperimentFreezeError("run plan contains duplicate experimental slots")
    if actual_slots != expected_slots:
        raise ExperimentFreezeError("run plan does not exactly cover configured subjects/repetitions")


def validate_manifest_files(*, project_root: Path, manifest: ExperimentFreezeManifest) -> None:
    root = project_root.resolve()
    for reference in manifest.frozen_files:
        candidate = (root / reference.path).resolve()
        if root not in candidate.parents:
            raise ExperimentFreezeError("frozen file escaped project root")
        if not candidate.is_file():
            raise ExperimentFreezeError(f"frozen file is missing: {reference.path}")
        if file_sha256(candidate) != reference.sha256:
            raise ExperimentFreezeError(f"frozen file hash mismatch: {reference.path}")
    for prompt in manifest.prompt_assets:
        candidate = (root / prompt.path).resolve()
        if root not in candidate.parents or not candidate.is_file():
            raise ExperimentFreezeError(f"prompt asset is missing: {prompt.path}")
        if file_sha256(candidate) != prompt.sha256:
            raise ExperimentFreezeError(f"prompt asset hash mismatch: {prompt.path}")


def validate_configuration_references(
    *,
    manifest: ExperimentFreezeManifest,
    configurations: tuple[ExperimentConfiguration, ...],
) -> None:
    expected = {item.config_id: item.configuration_sha256 for item in manifest.configuration_refs}
    actual = {config.config_id: canonical_sha256(config) for config in configurations}
    if actual != expected:
        raise ExperimentFreezeError("final configuration set/hash does not match freeze manifest")


def validate_final_provenance(
    *,
    provenance: RunProvenance,
    receipt: FinalEvaluationPreflightReceipt,
) -> None:
    expected = {
        "experiment_freeze_id": receipt.freeze_id,
        "freeze_manifest_sha256": receipt.freeze_manifest_sha256,
        "framework_git_commit": receipt.framework_git_commit,
        "baseline_git_commit": receipt.baseline_git_commit,
        "scenario_version": receipt.scenario_version,
        "dataset_version": receipt.dataset_version,
        "random_seed": receipt.random_seed,
        "prompt_set_version": receipt.prompt_set_version,
        "prompt_versions": receipt.prompt_versions,
        "schema_set_version": receipt.schema_set_version,
        "agent_configuration_version": receipt.agent_configuration_version,
        "context_policy_version": receipt.context_policy_version,
        "rule_version": receipt.rule_version,
        "test_suite_version": receipt.test_suite_version,
        "verification_policy_version": receipt.verification_policy_version,
        "python_version": receipt.python_version,
        "software_versions": receipt.software_versions,
        "docker_version": receipt.docker_version,
        "compose_version": receipt.compose_version,
    }
    mismatches = tuple(
        key for key, value in expected.items() if getattr(provenance, key) != value
    )
    if mismatches:
        raise ExperimentFreezeError(
            "run provenance differs from freeze preflight receipt: " + ", ".join(mismatches)
        )


class FinalEvaluationPreflightValidator:
    """Fail closed before a real final run can create experiment state."""

    def __init__(
        self,
        *,
        project_root: Path,
        manifest: ExperimentFreezeManifest,
        run_plan: ExperimentRunPlan,
        configurations: tuple[ExperimentConfiguration, ...],
    ) -> None:
        self.project_root = project_root.resolve()
        self.manifest = manifest
        self.run_plan = run_plan
        self.configurations = configurations
        if run_plan.freeze_id != manifest.freeze_id:
            raise ExperimentFreezeError("run plan and manifest freeze IDs differ")
        if canonical_sha256(run_plan) != manifest.run_plan_sha256:
            raise ExperimentFreezeError("run-plan hash does not match freeze manifest")
        validate_configuration_references(
            manifest=manifest,
            configurations=configurations,
        )
        validate_run_plan(plan=run_plan, configurations=configurations)

    def validate(
        self,
        *,
        entry_id: str,
        provider: StructuredGenerationProvider | None,
        baseline_git_commit: str,
        environment_manifest: EnvironmentManifest,
    ) -> FinalEvaluationPreflightReceipt:
        entry = self._entry(entry_id)
        config = self._config(entry)
        if config.run_type != RunType.FINAL_EVALUATION:
            raise ExperimentFreezeError("preflight accepts FINAL_EVALUATION configurations only")
        if canonical_sha256(environment_manifest) != self.manifest.environment_manifest_sha256:
            raise ExperimentFreezeError("environment manifest hash does not match freeze manifest")
        validate_manifest_files(project_root=self.project_root, manifest=self.manifest)
        requires_model = not (
            config.research_question == ResearchQuestion.RQ2
            and config.classification_mode == ClassificationMode.RULE_ONLY
        )
        if requires_model:
            if provider is None:
                raise ExperimentFreezeError("final model-using condition requires a provider")
            validate_provider_binding(
                provider=provider,
                expected=config.model,
                require_final_capable=True,
            )
        if baseline_git_commit != entry.baseline_git_commit:
            raise ExperimentFreezeError("requested baseline does not match frozen run-plan entry")

        repo = Repo(self.project_root)
        if repo.is_dirty(untracked_files=True):
            raise ExperimentFreezeError("final evaluation requires a clean Git worktree/index")
        framework_commit = repo.head.commit.hexsha
        try:
            frozen_commit = repo.commit(self.manifest.framework_ref).hexsha
        except Exception as exc:
            raise ExperimentFreezeError("freeze framework_ref cannot be resolved") from exc
        if framework_commit != frozen_commit:
            raise ExperimentFreezeError("HEAD does not match the frozen framework revision")
        frozen = repo.commit(frozen_commit)
        if not frozen.parents or frozen.parents[0].hexsha != self.manifest.source_parent_commit:
            raise ExperimentFreezeError("frozen framework parent does not match manifest source parent")

        prompt_versions = {item.role: item.version for item in self.manifest.prompt_assets}
        return FinalEvaluationPreflightReceipt(
            freeze_id=self.manifest.freeze_id,
            freeze_manifest_sha256=canonical_sha256(self.manifest),
            run_plan_entry_id=entry.entry_id,
            config_id=config.config_id,
            configuration_sha256=canonical_sha256(config),
            research_question=entry.research_question,
            repetition_index=entry.repetition_index,
            framework_git_commit=framework_commit,
            baseline_git_commit=baseline_git_commit,
            scenario_id=entry.scenario_id,
            dataset_id=entry.dataset_id,
            scenario_version=(
                entry.subject_version
                if entry.research_question != ResearchQuestion.RQ2
                else None
            ),
            dataset_version=(
                entry.subject_version
                if entry.research_question == ResearchQuestion.RQ2
                else None
            ),
            random_seed=entry.random_seed,
            prompt_set_version=self.manifest.prompt_set_version,
            prompt_versions=prompt_versions,
            schema_set_version=self.manifest.schema_set_version,
            agent_configuration_version=self.manifest.agent_configuration_version,
            context_policy_version=self.manifest.context_policy_version,
            rule_version=self.manifest.rule_version,
            test_suite_version=self.manifest.test_suite_version,
            verification_policy_version=self.manifest.verification_policy_version,
            environment_manifest_sha256=self.manifest.environment_manifest_sha256,
            python_version=environment_manifest.python_version,
            software_versions=environment_manifest.software_versions,
            docker_version=environment_manifest.docker_version,
            compose_version=environment_manifest.compose_version,
        )

    def _entry(self, entry_id: str) -> RunPlanEntry:
        matches = tuple(item for item in self.run_plan.entries if item.entry_id == entry_id)
        if len(matches) != 1:
            raise ExperimentFreezeError("run-plan entry ID is not uniquely approved")
        return matches[0]

    def _config(self, entry: RunPlanEntry) -> ExperimentConfiguration:
        matches = tuple(item for item in self.configurations if item.config_id == entry.config_id)
        if len(matches) != 1:
            raise ExperimentFreezeError("run-plan configuration is not uniquely available")
        return matches[0]
