"""Contract tests for M20 DEVELOPMENT prompt bytes, schemas, and call preparation."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from experiments.feasibility_assets import load_feasibility_assets
from experiments.feasibility_role_calls import (
    build_role_call_slots,
    prepare_role_call,
    response_model_for_task,
    response_schema_sha256,
)
from schemas.feasibility_role_calls import (
    FeasibilityClassificationResponse,
    FeasibilityPatchResponse,
    FeasibilityRoleTask,
    FeasibilitySourceAnalysisResponse,
    FeasibilityTestSelectionResponse,
)


ASSET_ROOT = Path("experiments/development_assets")


def test_four_response_contracts_forbid_extra_fields_and_patch_fields_are_paired() -> None:
    with pytest.raises(ValidationError):
        FeasibilityTestSelectionResponse(
            fixture_id="fixture-1",
            selected_registered_test_id=None,
            extra_field="forbidden",
        )
    with pytest.raises(ValidationError):
        FeasibilityClassificationResponse(
            fixture_id="fixture-1",
            predicted_classification="sql_injection",
            confidence=0.9,
        )
    with pytest.raises(ValidationError):
        FeasibilitySourceAnalysisResponse(
            fixture_id="fixture-1",
            predicted_source_file=None,
            predicted_function_or_route=None,
            rationale="forbidden",
        )
    with pytest.raises(ValidationError, match="supplied together"):
        FeasibilityPatchResponse(
            fixture_id="fixture-1",
            replacement_file_path="synthetic_lab/app/example.py",
            replacement_source=None,
        )


def test_prompt_manifest_hashes_match_current_pydantic_response_schemas() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    for reference in assets.prompt_manifest.references:
        assert reference.response_schema_sha256 == response_schema_sha256(reference.task)
        assert response_model_for_task(reference.task).model_config.get("extra") == "forbid"


def test_prepared_model_visible_bytes_are_candidate_independent_and_repetition_independent() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    slots = build_role_call_slots(assets.execution_plan)
    fixture = next(item for item in assets.inputs if item.fixture_id == "dev-sqli-member-lookup-01")
    prompt = assets.prompts_by_task[FeasibilityRoleTask.CLASSIFICATION]
    f3_slots = [
        slot
        for slot in slots
        if slot.phase.value == "f3"
        and slot.fixture_id == fixture.fixture_id
        and slot.task == FeasibilityRoleTask.CLASSIFICATION
    ]
    prepared = [
        prepare_role_call(
            slot=slot,
            fixture=fixture,
            prompt=prompt,
            generation_settings=assets.execution_plan.generation_settings,
        )
        for slot in f3_slots
    ]
    assert len(prepared) == 3
    assert len({item.system_prompt_sha256 for item in prepared}) == 1
    assert len({item.canonical_user_payload_sha256 for item in prepared}) == 1
    assert len({item.response_schema_sha256 for item in prepared}) == 1
    assert len({item.generation_settings_sha256 for item in prepared}) == 1
    assert all("candidate" not in item.canonical_user_payload for item in prepared)
    assert all("repetition_index" not in item.canonical_user_payload for item in prepared)
    assert all("phase" not in item.canonical_user_payload for item in prepared)


def test_common_generation_settings_are_exact_and_development_only() -> None:
    assets = load_feasibility_assets(ASSET_ROOT)
    settings = assets.execution_plan.generation_settings
    assert settings.model_dump(mode="json") == {
        "context_window": 8192,
        "max_output_tokens": 4096,
        "temperature": 0.7,
        "top_p": 0.8,
        "top_k": 20,
        "seed": None,
        "streaming": False,
        "automatic_retries": 0,
        "tools_enabled": False,
        "grounding_enabled": False,
        "request_timeout_seconds": 600,
    }
    assert assets.execution_plan.final_evaluation_forbidden is True
    assert assets.execution_plan.provider_selection_deferred is True
    assert assets.execution_plan.final_setting_derivation_deferred is True
