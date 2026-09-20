"""Tests for concrete M20 DEVELOPMENT feasibility fixture/candidate assets."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from experiments.feasibility_assets import (
    FeasibilityAssetError,
    load_feasibility_assets,
)
from schemas.common import ClassificationLabel
from schemas.feasibility import ProviderCandidateCategory
from schemas.feasibility_gate import FeasibilityRuntimeKind, SyntheticVerificationProfile
from schemas.feasibility_role_calls import FeasibilityRoleTask


ASSET_ROOT = Path("experiments/development_assets")


def test_fixture_package_is_exactly_eight_and_truth_is_physically_separate() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    assert len(assets.inputs) == 8
    assert len(assets.truth_records) == 8
    assert assets.input_manifest.input_bundle_sha256 == (
        "fa8d1209710d7782f58395f8ffe678aa6abbd2590275fc63e15f95e433012595"
    )
    assert assets.truth_manifest.truth_bundle_sha256 == (
        "c3927af2124361cc145dc766307059f904369ad3f86445e9124af88d92176e70"
    )
    assert assets.truth_manifest.evaluator_only is True

    input_root = ASSET_ROOT / "m20-feasibility-fixtures" / "v1" / "candidate_input"
    for fixture_id in assets.input_manifest.fixture_ids:
        payload = json.loads((input_root / f"{fixture_id}.json").read_text(encoding="utf-8"))
        assert not any(key.startswith("expected_") for key in payload)
        assert "verification" not in payload

    labels = [record.truth.expected_classification for record in assets.truth_records]
    assert labels.count(ClassificationLabel.SQL_INJECTION) == 2
    assert labels.count(ClassificationLabel.XSS) == 2
    assert labels.count(ClassificationLabel.PATH_TRAVERSAL) == 2
    assert labels.count(ClassificationLabel.BENIGN) == 2


def test_truth_package_predefines_source_function_test_and_verification_profile() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    malicious = [
        record
        for record in assets.truth_records
        if record.truth.expected_classification != ClassificationLabel.BENIGN
    ]
    assert len(malicious) == 6
    for record in malicious:
        truth = record.truth
        assert truth.expected_source_file is not None
        assert truth.expected_function_or_route is not None
        assert truth.expected_registered_test_id is not None
        assert truth.expected_pre_patch_attack_confirmed is True
        assert truth.expected_patch_decision is not None
        assert record.verification.profile != SyntheticVerificationProfile.BENIGN_NO_ACTION

    benign = [record for record in assets.truth_records if record not in malicious]
    assert len(benign) == 2
    assert all(
        record.verification.profile == SyntheticVerificationProfile.BENIGN_NO_ACTION
        for record in benign
    )


def test_candidate_manifest_binds_exact_l1_l2_c1_without_selecting_one() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    assert assets.candidate_manifest.descriptor_bundle_sha256 == (
        "26c4387067c9ecb01c921b0efc4055ec123b5023321b891a1252e8dde58c5de3"
    )
    assert assets.candidate_manifest.final_selection_made is False
    by_category = {candidate.spec.category: candidate for candidate in assets.candidates}

    l1 = by_category[ProviderCandidateCategory.REALISTIC_LOCAL]
    assert l1.spec.candidate_id == "l1-qwen3-8b-q4-k-m"
    assert l1.spec.artifact_sha256 == (
        "d98cdcbd03e17ce47681435b5150e34c1417f50b5c0019dd560e4882c5745785"
    )
    assert l1.artifact_file == "Qwen3-8B-Q4_K_M.gguf"
    assert l1.runtime_kind == FeasibilityRuntimeKind.LOCAL_LLAMA_CPP
    assert l1.runtime_version == "v0.4.1"
    assert l1.runtime_commit == "b29c606"
    assert l1.backend == "cpu-x86_64"
    assert l1.gpu_offload_layers == 0
    assert l1.bind_host == "127.0.0.1"

    l2 = by_category[ProviderCandidateCategory.SMALLER_LOCAL]
    assert l2.spec.candidate_id == "l2-qwen3-4b-q4-k-m"
    assert l2.spec.artifact_sha256 == (
        "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
    )
    assert l2.artifact_file == "Qwen3-4B-Q4_K_M.gguf"
    assert l2.gpu_offload_layers == 0

    cloud = by_category[ProviderCandidateCategory.ZERO_COST_CLOUD]
    assert cloud.spec.candidate_id == "c1-gemini-3.5-flash-lite"
    assert cloud.api_model_id == "gemini-3.5-flash-lite"
    assert cloud.spec.artifact_sha256 is None
    assert cloud.zero_cost_required is True
    assert cloud.free_tier_reverify_before_run is True
    assert cloud.tools_enabled is False
    assert cloud.grounding_enabled is False
    assert cloud.automatic_retries == 0

    assert all(candidate.feasibility_only for candidate in assets.candidates)
    assert all("context_window" in candidate.unresolved_settings for candidate in assets.candidates)
    assert all(
        "max_output_tokens" in candidate.unresolved_settings
        for candidate in assets.candidates
    )


def test_execution_plan_is_development_only_fixed_f1_f4_and_defers_selection() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    plan = assets.execution_plan
    assert plan.run_type.value == "development"
    assert plan.provider_selection_deferred is True
    assert plan.final_setting_derivation_deferred is True
    assert plan.final_evaluation_forbidden is True
    assert plan.f2_fixture_ids == assets.input_manifest.fixture_ids
    assert plan.f3_fixture_ids == (
        "dev-sqli-member-lookup-01",
        "dev-xss-badge-preview-01",
        "dev-path-export-download-01",
        "dev-benign-product-lookup-01",
    )
    assert tuple(stage.value for stage in plan.stages) == (
        "f1_integration",
        "f2_semantic",
        "f3_stability",
        "f4_resource",
    )
    assert plan.f2_logical_call_slots == 30
    assert plan.f3_logical_call_slots == 45
    assert plan.logical_call_slots_per_candidate == 75
    assert len(plan.f2_patch_fixture_ids) == 6
    assert len(plan.f3_patch_fixture_ids) == 3
    assert plan.prompt_manifest_id == "m20-feasibility-prompts-v1"
    assert plan.prompt_set_id == "m20-feasibility-prompts"
    assert plan.prompt_set_version == "v1"
    assert plan.generation_settings.context_window == 8192
    assert plan.generation_settings.max_output_tokens == 4096
    assert plan.generation_settings.automatic_retries == 0


def test_asset_loader_fails_closed_on_candidate_input_hash_tamper(tmp_path: Path) -> None:
    copied = tmp_path / "assets"
    shutil.copytree(ASSET_ROOT, copied)
    fixture = (
        copied
        / "m20-feasibility-fixtures"
        / "v1"
        / "candidate_input"
        / "dev-benign-product-lookup-01.json"
    )
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    payload["normalized_event"]["sample_value"] = "tampered"
    fixture.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(FeasibilityAssetError, match="candidate-input bundle SHA-256"):
        load_feasibility_assets(copied)


def test_asset_loader_fails_closed_on_evaluator_truth_hash_tamper(tmp_path: Path) -> None:
    copied = tmp_path / "assets"
    shutil.copytree(ASSET_ROOT, copied)
    truth_file = (
        copied
        / "m20-feasibility-fixtures"
        / "v1"
        / "evaluator_truth"
        / "dev-sqli-member-lookup-01.json"
    )
    payload = json.loads(truth_file.read_text(encoding="utf-8"))
    payload["verification"]["sql_placeholder"] = "%s"
    truth_file.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(FeasibilityAssetError, match="evaluator-truth bundle SHA-256"):
        load_feasibility_assets(copied)


def test_four_zero_shot_prompt_assets_are_hash_bound_to_role_schemas() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    assert len(assets.prompts) == 4
    assert assets.prompt_manifest.development_only is True
    assert assets.prompt_manifest.final_evaluation_forbidden is True
    assert assets.prompt_manifest.prompt_set_id == "m20-feasibility-prompts"
    assert {ref.task for ref in assets.prompt_manifest.references} == set(FeasibilityRoleTask)
    assert all(prompt.system_prompt.endswith("/no_think") for prompt in assets.prompts)
    assert all("example" not in prompt.system_prompt.lower() for prompt in assets.prompts)


def test_asset_loader_fails_closed_on_prompt_file_tamper(tmp_path: Path) -> None:
    copied = tmp_path / "assets"
    shutil.copytree(ASSET_ROOT, copied)
    prompt = copied / "prompts" / "v1" / "blue-classification-triage.json"
    payload = json.loads(prompt.read_text(encoding="utf-8"))
    payload["system_prompt"] += "\nTAMPER"
    prompt.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(FeasibilityAssetError, match="prompt file SHA-256"):
        load_feasibility_assets(copied)
