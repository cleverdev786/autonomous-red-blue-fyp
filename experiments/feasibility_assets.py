"""Load and verify the DEVELOPMENT-only M20 feasibility assets.

Candidate-visible inputs, evaluator-only truth, and provider candidate descriptors
are stored in separate roots and hashed independently. Nothing in this module
selects a final provider/model or creates final-evaluation configuration.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from experiments.feasibility import validate_synthetic_fixture_package
from schemas.feasibility import (
    ProviderCandidateCategory,
    SyntheticFixtureInput,
    SyntheticFixtureInputManifest,
    SyntheticFixtureTruth,
    SyntheticFixtureTruthManifest,
)
from schemas.feasibility_gate import (
    FeasibilityCandidateDescriptor,
    FeasibilityCandidateManifest,
    FeasibilityGateExecutionPlan,
    SyntheticEvaluatorTruthRecord,
)
from schemas.feasibility_role_calls import (
    FeasibilityPromptManifest,
    FeasibilityRoleTask,
)
from schemas.prompts import PromptAsset
from experiments.feasibility_role_calls import (
    canonical_model_sha256,
    response_schema_id_for_task,
    response_schema_sha256,
)


class FeasibilityAssetError(ValueError):
    """Raised when DEVELOPMENT feasibility assets fail integrity validation."""


@dataclass(frozen=True)
class LoadedFeasibilityAssets:
    """Integrity-checked DEVELOPMENT assets with truth kept separate from inputs."""

    input_manifest: SyntheticFixtureInputManifest
    inputs: tuple[SyntheticFixtureInput, ...]
    truth_manifest: SyntheticFixtureTruthManifest
    truth_records: tuple[SyntheticEvaluatorTruthRecord, ...]
    candidate_manifest: FeasibilityCandidateManifest
    candidates: tuple[FeasibilityCandidateDescriptor, ...]
    prompt_manifest: FeasibilityPromptManifest
    prompts: tuple[PromptAsset, ...]
    execution_plan: FeasibilityGateExecutionPlan

    @property
    def prompts_by_task(self) -> dict[FeasibilityRoleTask, PromptAsset]:
        by_id = {item.prompt_id: item for item in self.prompts}
        return {reference.task: by_id[reference.prompt_id] for reference in self.prompt_manifest.references}

    @property
    def truths(self) -> tuple[SyntheticFixtureTruth, ...]:
        return tuple(record.truth for record in self.truth_records)


_JSON_OBJECT = TypeAdapter(dict[str, Any])


def canonical_sha256(models: tuple[object, ...]) -> str:
    """Hash Pydantic-compatible values as sorted canonical JSON in tuple order."""
    values: list[Any] = []
    for model in models:
        if hasattr(model, "model_dump"):
            values.append(model.model_dump(mode="json"))
        else:
            values.append(model)
    payload = json.dumps(
        values,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_feasibility_assets(
    asset_root: Path, *, candidate_set_version: str = "v1"
) -> LoadedFeasibilityAssets:
    """Load frozen v1 fixtures/prompts with an explicitly versioned candidate set."""
    if candidate_set_version not in {"v1", "v2", "v4"}:
        raise FeasibilityAssetError("unsupported feasibility candidate-set version")
    root = asset_root.resolve(strict=True)
    input_root = root / "m20-feasibility-fixtures" / "v1" / "candidate_input"
    truth_root = root / "m20-feasibility-fixtures" / "v1" / "evaluator_truth"
    candidate_root = root / "candidates" / candidate_set_version
    prompt_root = root / "prompts" / "v1"

    input_manifest = SyntheticFixtureInputManifest.model_validate(
        _read_json(input_root / "manifest.json")
    )
    truth_manifest = SyntheticFixtureTruthManifest.model_validate(
        _read_json(truth_root / "manifest.json")
    )
    candidate_manifest = FeasibilityCandidateManifest.model_validate(
        _read_json(candidate_root / "manifest.json")
    )
    prompt_manifest = FeasibilityPromptManifest.model_validate(
        _read_json(prompt_root / "manifest.json")
    )
    execution_plan = FeasibilityGateExecutionPlan.model_validate(
        _read_json(root / f"execution-plan-{candidate_set_version}.json")
    )

    inputs = tuple(
        SyntheticFixtureInput.model_validate(_read_json(input_root / f"{fixture_id}.json"))
        for fixture_id in input_manifest.fixture_ids
    )
    truth_records = tuple(
        SyntheticEvaluatorTruthRecord.model_validate(
            _read_json(truth_root / f"{fixture_id}.json")
        )
        for fixture_id in truth_manifest.fixture_ids
    )
    candidates = tuple(
        FeasibilityCandidateDescriptor.model_validate(
            _read_json(candidate_root / f"{candidate_id}.json")
        )
        for candidate_id in candidate_manifest.candidate_ids
    )
    prompts = tuple(
        PromptAsset.model_validate(_read_json(prompt_root / reference.path))
        for reference in prompt_manifest.references
    )

    if canonical_sha256(inputs) != input_manifest.input_bundle_sha256:
        raise FeasibilityAssetError("candidate-input bundle SHA-256 does not match manifest")
    if canonical_sha256(truth_records) != truth_manifest.truth_bundle_sha256:
        raise FeasibilityAssetError("evaluator-truth bundle SHA-256 does not match manifest")
    if canonical_sha256(candidates) != candidate_manifest.descriptor_bundle_sha256:
        raise FeasibilityAssetError("candidate-descriptor bundle SHA-256 does not match manifest")
    if any(item.descriptor_version != candidate_manifest.manifest_version for item in candidates):
        raise FeasibilityAssetError("candidate descriptor versions differ from candidate manifest")
    _validate_prompt_assets(
        prompt_root=prompt_root, manifest=prompt_manifest, prompts=prompts
    )

    truths = tuple(record.truth for record in truth_records)
    validate_synthetic_fixture_package(inputs=inputs, truths=truths)
    _validate_truth_records(inputs=inputs, records=truth_records)
    _validate_candidate_slots(candidates)
    _validate_plan(
        plan=execution_plan,
        input_manifest=input_manifest,
        candidate_manifest=candidate_manifest,
        prompt_manifest=prompt_manifest,
        truth_records=truth_records,
    )

    return LoadedFeasibilityAssets(
        input_manifest=input_manifest,
        inputs=inputs,
        truth_manifest=truth_manifest,
        truth_records=truth_records,
        candidate_manifest=candidate_manifest,
        candidates=candidates,
        prompt_manifest=prompt_manifest,
        prompts=prompts,
        execution_plan=execution_plan,
    )


def _validate_truth_records(
    *,
    inputs: tuple[SyntheticFixtureInput, ...],
    records: tuple[SyntheticEvaluatorTruthRecord, ...],
) -> None:
    input_map = {item.fixture_id: item for item in inputs}
    if len(records) != len(input_map):
        raise FeasibilityAssetError("truth records must match candidate-input cardinality")
    for record in records:
        fixture = input_map.get(record.truth.fixture_id)
        if fixture is None:
            raise FeasibilityAssetError("truth record references unknown candidate fixture")
        if fixture.fixture_version != record.truth.fixture_version:
            raise FeasibilityAssetError("candidate input/truth fixture versions differ")
        truth = record.truth
        if truth.expected_source_file is not None:
            visible_paths = {item.file_path for item in fixture.source_files}
            if truth.expected_source_file not in visible_paths:
                raise FeasibilityAssetError("truth source file is absent from candidate context")
        if truth.expected_registered_test_id is not None:
            visible_tests = {item.test_id for item in fixture.registered_tests}
            if truth.expected_registered_test_id not in visible_tests:
                raise FeasibilityAssetError("truth test ID is absent from candidate catalogue")


def _validate_candidate_slots(candidates: tuple[FeasibilityCandidateDescriptor, ...]) -> None:
    categories = [item.spec.category for item in candidates]
    if set(categories) != set(ProviderCandidateCategory) or len(categories) != 3:
        raise FeasibilityAssetError("candidate set must contain exactly L1/L2/C1 categories")
    if len({item.spec.candidate_id for item in candidates}) != 3:
        raise FeasibilityAssetError("candidate IDs must be unique")
    if any("final" in item.spec.candidate_id.lower() for item in candidates):
        raise FeasibilityAssetError("feasibility candidate IDs cannot imply final selection")


def _validate_prompt_assets(
    *,
    prompt_root: Path,
    manifest: FeasibilityPromptManifest,
    prompts: tuple[PromptAsset, ...],
) -> None:
    if len(prompts) != 4:
        raise FeasibilityAssetError("feasibility prompt set must contain exactly four prompts")
    prompt_map = {item.prompt_id: item for item in prompts}
    for reference in manifest.references:
        path = prompt_root / reference.path
        if _file_sha256(path) != reference.file_sha256:
            raise FeasibilityAssetError("feasibility prompt file SHA-256 does not match manifest")
        prompt = prompt_map.get(reference.prompt_id)
        if prompt is None:
            raise FeasibilityAssetError("prompt manifest references an unknown prompt")
        if prompt.version != reference.version or prompt.role != reference.role:
            raise FeasibilityAssetError("prompt metadata differs from prompt manifest")
        if response_schema_id_for_task(reference.task) != reference.response_schema_id:
            raise FeasibilityAssetError("response schema ID differs from prompt manifest")
        if response_schema_sha256(reference.task) != reference.response_schema_sha256:
            raise FeasibilityAssetError("response schema SHA-256 differs from prompt manifest")
    bundle = canonical_model_sha256(tuple(item.model_dump(mode="json") for item in prompts))
    if bundle != manifest.prompt_bundle_sha256:
        raise FeasibilityAssetError("feasibility prompt bundle SHA-256 does not match manifest")


def _validate_plan(
    *,
    plan: FeasibilityGateExecutionPlan,
    input_manifest: SyntheticFixtureInputManifest,
    candidate_manifest: FeasibilityCandidateManifest,
    prompt_manifest: FeasibilityPromptManifest,
    truth_records: tuple[SyntheticEvaluatorTruthRecord, ...],
) -> None:
    if plan.fixture_set_id != input_manifest.fixture_set_id:
        raise FeasibilityAssetError("execution plan fixture-set ID differs from input manifest")
    if plan.fixture_set_version != input_manifest.fixture_set_version:
        raise FeasibilityAssetError("execution plan fixture-set version differs from manifest")
    if plan.candidate_manifest_id != candidate_manifest.manifest_id:
        raise FeasibilityAssetError("execution plan candidate manifest ID differs")
    if plan.candidate_ids != candidate_manifest.candidate_ids:
        raise FeasibilityAssetError("execution plan candidate IDs differ from candidate manifest")
    if plan.prompt_manifest_id != prompt_manifest.manifest_id:
        raise FeasibilityAssetError("execution plan prompt manifest ID differs")
    if plan.prompt_set_id != prompt_manifest.prompt_set_id:
        raise FeasibilityAssetError("execution plan prompt-set ID differs")
    if plan.prompt_set_version != prompt_manifest.version:
        raise FeasibilityAssetError("execution plan prompt-set version differs")
    from experiments.feasibility_role_calls import generation_settings_sha256
    if generation_settings_sha256(plan.generation_settings) != plan.generation_settings_sha256:
        raise FeasibilityAssetError("execution plan generation-settings SHA-256 differs")
    if plan.f2_fixture_ids != input_manifest.fixture_ids:
        raise FeasibilityAssetError(
            "execution plan F2 fixtures differ from candidate-input manifest"
        )
    truth_map = {record.truth.fixture_id: record.truth for record in truth_records}
    malicious_f2 = tuple(
        fixture_id
        for fixture_id in plan.f2_fixture_ids
        if truth_map[fixture_id].expected_classification.value != "benign"
    )
    malicious_f3 = tuple(
        fixture_id
        for fixture_id in plan.f3_fixture_ids
        if truth_map[fixture_id].expected_classification.value != "benign"
    )
    if plan.f2_patch_fixture_ids != malicious_f2:
        raise FeasibilityAssetError("F2 evaluator-side patch schedule differs from frozen truth")
    if plan.f3_patch_fixture_ids != malicious_f3:
        raise FeasibilityAssetError("F3 evaluator-side patch schedule differs from frozen truth")


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise FeasibilityAssetError(f"cannot hash feasibility asset: {path}") from exc


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FeasibilityAssetError(f"cannot read feasibility asset: {path}") from exc
    return _JSON_OBJECT.validate_python(payload)
